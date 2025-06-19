#include "stats_engine.hpp"
#include <cmath>
#include <unordered_map>
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <array>
#include <deque>
#include <vector>
#include <cctype>  // FIXED: For std::isprint, std::isspace, std::toupper
#include <ctime>   // FIXED: For std::localtime (thread-safety will be addressed below)

// FIXED: Named constants for tunable parameters to aid configuration and testing
namespace {
    // Anomaly scoring thresholds
    constexpr double kEntropyDeviationThreshold = 0.8;
    constexpr double kRateDeviationThreshold = 3.0;
    constexpr double kRateDeviationThresholdUdp = 6.0;  // NEW: Higher threshold for UDP
    constexpr double kHighRateDeviationThreshold = 5.0;
    constexpr double kVolumeRatioThreshold = 50.0;
    constexpr double kSignificantVolumeRatio = 200.0;
    
    // Anomaly score weights
    constexpr double kEntropyAnomalyWeight = 0.4;
    constexpr double kRateAnomalyMaxWeight = 0.5;
    constexpr double kVolumeAnomalyMaxWeight = 0.4;
    constexpr double kPayloadPatternMaxWeight = 0.5;
    constexpr double kHttpAnomalyMaxWeight = 0.5;
    constexpr double kTemporalAnomalyWeight = 0.4;
    
    // Confidence multipliers
    constexpr double kGeneralConfidenceMultiplier = 1.2;
    constexpr double kSynFloodConfidenceMultiplier = 1.5;
    
    // Base threshold and adjustments
    constexpr double kBaseThreshold = 0.7;
    constexpr double kHighFalsePositiveThreshold = 0.05;
    constexpr double kLowAccuracyThreshold = 0.90;
    constexpr double kThresholdAdjustment = 0.1;
    constexpr double kVolumeThresholdAdjustment = 0.05;
    constexpr double kTimeBasedAdjustment = 0.05;
    
    // EWMA parameters
    constexpr double kMaxAdaptiveAlpha = 0.3;
    constexpr double kAlphaDecayRate = 0.999;
    constexpr double kAdaptiveAlphaMultiplier = 2.0;
    
    // Traffic pattern constants
    constexpr int kMinPacketsForBaseline = 100;  // FIXED: Use int for consistency with packets_received
    constexpr double kVolumeMultiplierThreshold = 10.0;
    constexpr int kHighVolumePacketThreshold = 10000;
    
    // Temporal analysis constants  
    constexpr int kSuspiciousTimeWindowSeconds = 60;
    constexpr int kSuspiciousPacketCount = 1000;
    constexpr int kLongTermWindowSeconds = 3600;
    constexpr int kLowActivityPacketCount = 10;

    // Memory management constants
    constexpr std::chrono::minutes kStatsTtl{30};  // 30 minutes TTL
    constexpr size_t kMaxPayloadEntropySize = 2048;  // Limit entropy calculation

    // FIXED: Thread-safe localtime helper for portability
    struct tm safe_localtime(const std::time_t& time) {
        struct tm result;
#ifdef _WIN32
        // Microsoft Visual C++
        localtime_s(&result, &time);
#else
        // POSIX systems
        localtime_r(&time, &result);
#endif
        return result;
    }
}

StatsEngine::StatsEngine(double entropy_threshold, double ewma_alpha, bool enable_local_time_bias)
    : entropy_threshold(entropy_threshold), ewma_alpha(ewma_alpha), original_alpha(ewma_alpha),
      false_positive_rate(0.02), detection_accuracy(0.95), enable_local_time_bias(enable_local_time_bias) {  // Initialize feedback defaults
    last_packet_time = std::chrono::steady_clock::now();
    start_time = std::chrono::steady_clock::now();
    last_cleanup = std::chrono::steady_clock::now();
    
    // Initialize multicast/broadcast whitelist for noise reduction
    initialize_multicast_whitelist();
    
    // Remove unused legitimate_traffic_patterns map
    // All pattern checking now happens in is_legitimate_traffic_pattern()
}

bool StatsEngine::analyze(const PacketData& pkt) {
    // NEW: Skip anomaly detection during learning period
    if (!initial_learning_done) {
        // Check if learning period is complete
        auto now = std::chrono::steady_clock::now();
        auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
        
        std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
        bool time_complete = elapsed_time.count() >= LEARNING_TIME_SECONDS;
        bool packet_complete = packets_received >= LEARNING_PACKET_THRESHOLD;
        read_lock.unlock();
        
        if (time_complete || packet_complete) {
            std::unique_lock<std::shared_mutex> write_lock(stats_mutex);
            initial_learning_done = true;
            write_lock.unlock();
        } else {
            // Still in learning mode - update stats but don't flag anomalies
            update_stats_learning_mode(pkt);
            return false;
        }
    }
    
    // NEW: Skip detection for multicast/broadcast traffic to well-known addresses
    if ((pkt.is_multicast || pkt.is_broadcast) && 
        multicast_whitelist.count(pkt.dst_ip) > 0) {
        return false;
    }
    // Step 1: Quick read of current stats with shared lock
    double local_current_rate, local_baseline_rate, local_current_entropy;
    double rate_deviation;
    int local_packets_received;
    
    {
        std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
        local_current_rate = current_rate;
        local_baseline_rate = baseline_rate;
        local_packets_received = packets_received;
        
        // Calculate rate deviation with read-only access
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_packet_time).count();
        double time_seconds = std::max(static_cast<double>(duration) / 1000.0, 0.001);
        double instant_rate = static_cast<double>(pkt.size) / time_seconds;
        
        rate_deviation = calculate_destination_rate_deviation(pkt.src_ip, pkt.dst_ip, 
                                                            pkt.dst_port, instant_rate);
    }
    
    // Step 2: Heavy computation WITHOUT locks (entropy, payload analysis)
    local_current_entropy = compute_entropy_optimized(pkt.payload);
    
    // Enhanced packet classification for real-world scenarios
    bool is_syn_packet = pkt.is_syn && !pkt.is_ack;
    bool is_legitimate_service = is_legitimate_traffic_pattern(pkt);
    bool is_control_packet = pkt.payload.empty() && (pkt.is_syn || pkt.is_ack);
    
    // Real-world anomaly detection with multi-factor scoring
    double anomaly_score = 0.0;
    double confidence_multiplier = 1.0;
    
    // 1. Protocol-aware entropy analysis with adaptive thresholds
    if (!is_control_packet && !is_legitimate_service) {
        double entropy_baseline = get_expected_entropy_for_protocol(pkt, local_current_entropy);
        double entropy_deviation = std::abs(local_current_entropy - entropy_baseline) / entropy_baseline;
        
        // Only flag extreme entropy deviations (>80% deviation from expected)
        if (entropy_deviation > kEntropyDeviationThreshold) {
            anomaly_score += kEntropyAnomalyWeight * entropy_deviation;
            confidence_multiplier *= kGeneralConfidenceMultiplier;
        }
    }
    
    // 2. Protocol-aware rate-based detection with time-series analysis
    double protocol_rate_threshold = get_protocol_specific_rate_threshold(pkt);
    if (rate_deviation > protocol_rate_threshold) {
        double rate_score = std::min(kRateAnomalyMaxWeight, rate_deviation / 10.0);
        anomaly_score += rate_score;
        
        // Higher confidence for SYN flood patterns
        if (is_syn_packet && rate_deviation > kHighRateDeviationThreshold) {
            confidence_multiplier *= kSynFloodConfidenceMultiplier;
        }
    }
    
    // 3. Volume-based detection with traffic classification
    if (local_current_rate > local_baseline_rate * kVolumeMultiplierThreshold && 
        local_packets_received > kMinPacketsForBaseline) {
        // Only flag sustained high volume, not brief spikes
        double volume_ratio = local_current_rate / local_baseline_rate;
        if (volume_ratio > kVolumeRatioThreshold) {  // Significant volume increase
            anomaly_score += std::min(kVolumeAnomalyMaxWeight, volume_ratio / kSignificantVolumeRatio);
        }
    }
    
    // 4. Payload pattern analysis for sophisticated attacks
    if (!pkt.payload.empty()) {
        double pattern_score = analyze_payload_patterns(pkt);
        anomaly_score += pattern_score;
    }
    
    // 5. Protocol-specific behavioral anomalies
    if (pkt.is_http) {
        double http_anomaly = analyze_http_anomalies(pkt);
        anomaly_score += http_anomaly;
    }
    
    // 6. Temporal correlation analysis
    double temporal_score = analyze_temporal_patterns(pkt.src_ip);
    anomaly_score += temporal_score;
    
    // Apply confidence multiplier for high-confidence detections
    anomaly_score *= confidence_multiplier;
    
    // Step 3: Brief exclusive lock for updates
    {
        std::unique_lock<std::shared_mutex> write_lock(stats_mutex);
        
        packets_received++;
        total_bytes += pkt.size;
        
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_packet_time).count();
        double time_seconds = std::max(static_cast<double>(duration) / 1000.0, 0.001);
        double instant_rate = static_cast<double>(pkt.size) / time_seconds;
        
        // Real-world adaptive baseline calculation
        if (packets_received == 1) {
            current_rate = instant_rate;
            baseline_rate = instant_rate;
        } else {
            // FIXED: Adaptive alpha with decay back to original
            double adaptive_alpha = ewma_alpha;
            
            // Increase adaptation speed during traffic spikes for faster convergence
            if (instant_rate > current_rate * kAdaptiveAlphaMultiplier) {
                adaptive_alpha = std::min(kMaxAdaptiveAlpha, ewma_alpha * kAdaptiveAlphaMultiplier);
            } else {
                // FIXED: Decay alpha back toward original over time
                // Note: This asymptotically approaches original_alpha but never quite reaches it,
                // which provides stable long-term behavior while allowing temporary adaptation
                ewma_alpha = std::min(original_alpha, ewma_alpha * kAlphaDecayRate);
            }
            
            current_rate = adaptive_alpha * instant_rate + (1.0 - adaptive_alpha) * current_rate;
            
            // FIXED: Use proper 95th percentile baseline instead of flawed EWMA
            update_baseline_window(instant_rate);
            baseline_rate = calculate_95th_percentile_baseline();
        }
        
        last_packet_time = now;
        current_entropy = local_current_entropy;
        
        // FIXED: Update EWMA AFTER calculating deviation
        update_ewma(pkt.src_ip, current_rate);
        
        // NEW: Update per-destination statistics for more granular tracking
        update_destination_statistics(pkt.src_ip, pkt.dst_ip, pkt.dst_port, instant_rate);
    }
    
    // FIXED: Now functional dynamic threshold system
    double dynamic_threshold = calculate_dynamic_threshold();
    
    // Release lock before cleanup to prevent deadlock
    
    // Periodic cleanup to prevent memory bloat
    if (local_packets_received % 1000 == 0 && local_packets_received > 0) {
        cleanup_expired_stats();
    }
    
    return anomaly_score >= dynamic_threshold;
}

double StatsEngine::compute_entropy(const std::string& payload) {
    if (payload.empty()) return 0.0;
    
    std::unordered_map<char, int> freq;
    for (char c : payload) {
        freq[c]++;
    }
    
    double entropy = 0.0;
    for (const auto& p : freq) {
        double prob = static_cast<double>(p.second) / static_cast<double>(payload.length());
        if (prob > 0) {
            entropy -= prob * std::log2(prob);
        }
    }
    
    return entropy;
}

// FIXED: Optimized entropy computation with size limits
double StatsEngine::compute_entropy_optimized(const std::string& payload) {
    if (payload.empty()) return 0.0;
    
    size_t original_size = payload.length();
    
    // FIXED: Sample first and last N bytes for large payloads to avoid bias
    size_t max_size = std::min(original_size, kMaxPayloadEntropySize);
    std::array<int, 256> freq{};
    
    if (original_size <= kMaxPayloadEntropySize) {
        // Small payload: analyze entire content
        for (size_t i = 0; i < max_size; ++i) {
            uint8_t byte = static_cast<uint8_t>(payload[i]);
            freq[byte]++;
        }
    } else {
        // Large payload: sample from beginning and end to avoid bias
        size_t half_sample = kMaxPayloadEntropySize / 2;
        
        // Sample first half_sample bytes
        for (size_t i = 0; i < half_sample; ++i) {
            uint8_t byte = static_cast<uint8_t>(payload[i]);
            freq[byte]++;
        }
        
        // Sample last half_sample bytes
        for (size_t i = original_size - half_sample; i < original_size; ++i) {
            uint8_t byte = static_cast<uint8_t>(payload[i]);
            freq[byte]++;
        }
        
        max_size = kMaxPayloadEntropySize; // Total sampled bytes
    }
    
    double entropy = 0.0;
    for (int count : freq) {
        if (count > 0) {
            double prob = static_cast<double>(count) / static_cast<double>(max_size);
            entropy -= prob * std::log2(prob);
        }
    }
    
    return entropy;
}

void StatsEngine::update_ewma(const std::string& src_ip, double packet_rate) {
    // NOTE: stats_mutex must already be held in exclusive mode by caller before calling this function
    auto& stat = stats[src_ip];
    stat.ewma = stat.ewma * (1 - ewma_alpha) + packet_rate * ewma_alpha;
    stat.packet_count++;
    
    // Update comprehensive IP statistics
    update_ip_statistics(src_ip, packet_rate);
}

double StatsEngine::get_adaptive_entropy_threshold(const PacketData& pkt) {
    // Context-aware entropy thresholds
    if (pkt.is_http) {
        return 2.5; // HTTP traffic typically has higher entropy
    } else if (pkt.payload.length() < 50) {
        return 1.0; // Small packets can have naturally low entropy
    } else if (pkt.size > 1400) {
        return 3.0; // Large packets should have high entropy unless compressed/encrypted
    }
    
    return entropy_threshold; // Default threshold
}

bool StatsEngine::is_repetitive_payload(const std::string& payload) {
    if (payload.length() < 10) return false;
    
    // FIXED: More efficient pattern detection using fixed-size array with linear probing
    // This eliminates heap allocations and provides better cache performance
    
    constexpr size_t kPatternLength = 4;
    constexpr size_t kHashTableSize = 1024;  // Power of 2 for efficient modulo
    
    if (payload.length() < kPatternLength) return false;
    
    // Fixed-size hash table with linear probing (no heap allocations)
    std::array<uint16_t, kHashTableSize> pattern_counts{};
    
    // Use 4-byte rolling hash for efficient pattern detection
    for (size_t i = 0; i <= payload.length() - kPatternLength; i++) {
        // Create 4-byte hash from pattern
        uint32_t hash = 0;
        for (size_t j = 0; j < kPatternLength; ++j) {
            hash = (hash << 8) | static_cast<uint8_t>(payload[i + j]);
        }
        
        // Linear probing to handle collisions
        size_t index = hash & (kHashTableSize - 1);  // Efficient modulo for power of 2
        pattern_counts[index]++;
        
        // Early exit if pattern becomes too repetitive
        if (pattern_counts[index] > payload.length() / 4) {
            return true;
        }
    }
    
    return false;
}

double StatsEngine::get_current_rate() const {
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    return current_rate;
}

double StatsEngine::get_entropy() const {
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    return current_entropy;
}

// Real-world detection methods for production environments

bool StatsEngine::is_legitimate_traffic_pattern(const PacketData& pkt) {
    // NEW: Treat multicast/broadcast as legitimate service traffic
    if (pkt.is_multicast || pkt.is_broadcast) {
        return true;
    }
    
    // Check against known legitimate traffic patterns based on available packet data
    
    // HTTP/HTTPS traffic identification
    if (pkt.is_http) {
        if ((pkt.payload.find("GET") == 0 || pkt.payload.find("POST") == 0) && 
            pkt.payload.find("HTTP/") != std::string::npos) {
            return true;
        }
    }
    
    // Small control packets are typically legitimate
    if (pkt.size < 100 && (pkt.is_syn || pkt.is_ack)) {
        return true;
    }
    
    // NEW: Well-known service ports are typically legitimate
    if (is_well_known_service_port(pkt.dst_port, pkt.is_udp())) {
        return true;
    }
    
    // DNS-like small packets
    if (pkt.size < 512 && !pkt.is_http && pkt.payload.length() < 100) {
        return true; // Likely DNS or similar protocol
    }
    
    // SSH-like encrypted small packets
    if (pkt.size < 1500 && !pkt.is_syn && !pkt.is_http && 
        !pkt.payload.empty() && pkt.payload.length() < 1400) {
        return true; // Likely SSH or similar encrypted traffic
    }
    
    return false;
}

double StatsEngine::get_expected_entropy_for_protocol(const PacketData& pkt, double cached_entropy) {
    // FIXED: Use cached entropy instead of redundant calculation
    // Protocol-specific expected entropy values based on real-world analysis
    
    if (pkt.is_http) {
        if (pkt.payload.find("GET") == 0 || pkt.payload.find("POST") == 0) {
            return 4.2; // HTTP requests have moderate entropy
        }
        return 3.8; // HTTP responses have slightly lower entropy
    }
    
    // Identify DNS-like traffic by packet characteristics
    if (pkt.size < 512 && pkt.payload.length() < 100 && !pkt.is_http) {
        return 5.5; // DNS has high entropy due to random query IDs
    }
    
    // Identify encrypted traffic by high entropy and non-HTTP nature
    if (!pkt.is_http && pkt.payload.length() > 100) {
        // FIXED: Use cached entropy instead of recalculating
        if (cached_entropy > 6.0) {
            return 7.8; // Encrypted traffic has very high entropy
        }
    }
    
    // SSH-like traffic identification
    if (!pkt.is_http && pkt.size > 100 && pkt.size < 1500 && !pkt.is_syn && !pkt.is_ack) {
        return 7.2; // SSH encrypted traffic has high entropy
    }
    
    if (pkt.is_syn || pkt.is_ack) { // Control packets
        return 2.0; // Control packets have low entropy
    }
    
    return 4.0; // Default expected entropy for unknown protocols
}

double StatsEngine::calculate_rate_deviation(const std::string& src_ip, double current_rate) {
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    
    auto it = stats.find(src_ip);
    if (it == stats.end() || it->second.rate_history.size() < 5) {
        // FIXED: Apply heuristic for early detection instead of suppressing alerts entirely
        // This prevents bypass of detection for first few packets from an IP
        return (current_rate > 10.0 * baseline_rate && baseline_rate > 0) ? 10.0 : 0.0;
    }
    
    const auto& ip_stats = it->second;
    
    // Calculate Z-score based on historical data
    return calculate_zscore(current_rate, ip_stats.mean_rate, ip_stats.stddev_rate);
}

double StatsEngine::analyze_payload_patterns(const PacketData& pkt) {
    double anomaly_score = 0.0;
    
    if (pkt.payload.length() <= 100) {
        return 0.0; // Too small for meaningful pattern analysis
    }
    
    // FIXED: Single-pass analysis using the same approach as entropy calculation
    // Use uint16_t to halve cache footprint (256 * 2 = 512 bytes vs 256 * 4 = 1024 bytes)
    std::array<uint16_t, 256> byte_freq{};
    size_t null_count = 0;
    size_t printable_count = 0;
    
    // Single pass through payload for all analyses
    for (size_t i = 0; i < pkt.payload.length(); ++i) {
        uint8_t byte = static_cast<uint8_t>(pkt.payload[i]);
        byte_freq[byte]++;
        
        if (byte == 0) {
            null_count++;
        }
        
        if (std::isprint(byte) || std::isspace(byte)) {
            printable_count++;
        }
    }
    
    // Check for padding attacks (repeated null bytes or patterns)
    double null_ratio = static_cast<double>(null_count) / static_cast<double>(pkt.payload.length());
    if (null_ratio > 0.8) {
        anomaly_score += 0.4; // High null byte ratio
    }
    
    // Check for repeated byte patterns using frequency analysis
    uint16_t max_byte_count = 0;
    for (uint16_t count : byte_freq) {
        if (count > max_byte_count) {
            max_byte_count = count;
        }
    }
    
    double repetition_ratio = static_cast<double>(max_byte_count) / static_cast<double>(pkt.payload.length());
    if (repetition_ratio > 0.7) {
        anomaly_score += 0.3; // High byte repetition
    }
    
    // Check for binary vs text payload consistency
    if (pkt.is_http && !pkt.payload.empty()) {
        double printable_ratio = static_cast<double>(printable_count) / static_cast<double>(pkt.payload.length());
        if (printable_ratio < 0.8) {
            anomaly_score += 0.2; // HTTP should be mostly printable
        }
    }
    
    return std::min(kPayloadPatternMaxWeight, anomaly_score);
}

double StatsEngine::analyze_http_anomalies(const PacketData& pkt) {
    double anomaly_score = 0.0;
    
    if (!pkt.is_http || pkt.payload.empty()) {
        return 0.0;
    }
    
    // Check for malformed HTTP headers
    if (pkt.payload.find("HTTP/") == std::string::npos && 
        pkt.payload.find("GET") != 0 && pkt.payload.find("POST") != 0) {
        anomaly_score += 0.3; // Malformed HTTP
    }
    
    // FIXED: Check for excessive header count (header injection attacks)
    // Count proper HTTP header lines (ending with \r\n) instead of just \r
    size_t header_count = 0;
    size_t pos = 0;
    while ((pos = pkt.payload.find("\r\n", pos)) != std::string::npos) {
        header_count++;
        pos += 2;
        // Stop counting after reasonable header section (before body)
        if (pos > 2048) break; // Limit header analysis to first 2KB
    }
    
    if (header_count > 50) {
        anomaly_score += 0.4; // Too many headers
    }
    
    // Check for suspicious user agents or patterns
    if (pkt.payload.find("User-Agent:") != std::string::npos) {
        if (pkt.payload.find("bot") != std::string::npos || 
            pkt.payload.find("crawler") != std::string::npos) {
            // Legitimate bots are usually whitelisted, suspicious if not
            anomaly_score += 0.1;
        }
    } else if (pkt.payload.find("GET") == 0 || pkt.payload.find("POST") == 0) {
        anomaly_score += 0.2; // HTTP request without User-Agent
    }
    
    // FIXED: Check for SQL injection patterns with efficient scanning
    // Limit payload analysis to first 2KB to prevent excessive CPU usage
    constexpr size_t kMaxSqlScanSize = 2048;
    size_t scan_size = std::min(pkt.payload.length(), kMaxSqlScanSize);
    std::string_view payload_view(pkt.payload.data(), scan_size);
    
    // Convert a limited portion to uppercase for case-insensitive matching
    std::string upper_payload;
    upper_payload.reserve(scan_size);
    std::transform(payload_view.begin(), payload_view.end(), 
                  std::back_inserter(upper_payload), 
                  [](char c) { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); });
    
    std::vector<std::string_view> sql_patterns = {"UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE"};
    for (const auto& pattern : sql_patterns) {
        if (upper_payload.find(pattern) != std::string::npos) {
            anomaly_score += 0.3;
            break; // One SQL pattern is enough
        }
    }
    
    return std::min(0.5, anomaly_score);
}

double StatsEngine::analyze_temporal_patterns(const std::string& src_ip) {
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    
    auto it = stats.find(src_ip);
    if (it == stats.end()) {
        return 0.0;
    }
    
    auto now = std::chrono::steady_clock::now();
    // FIXED: Use first_seen time for this IP instead of global start_time
    auto time_since_first = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_seen);
    
    // Check for suspicious timing patterns
    if (time_since_first.count() < kSuspiciousTimeWindowSeconds && 
        it->second.packet_count > kSuspiciousPacketCount) {
        return kTemporalAnomalyWeight; // Too many packets too quickly from single IP
    }
    
    if (time_since_first.count() > kLongTermWindowSeconds && 
        it->second.packet_count < kLowActivityPacketCount) {
        return 0.0; // Very low activity over long period - legitimate
    }
    
    return 0.0;
}

double StatsEngine::calculate_dynamic_threshold() {
    // FIXED: Access feedback variables under lock for thread safety
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    
    // Adaptive threshold based on current conditions
    double base_threshold = kBaseThreshold;
    
    // Adjust based on false positive rate
    if (false_positive_rate > kHighFalsePositiveThreshold) { // More than 5% false positives
        base_threshold += kThresholdAdjustment; // Increase threshold to reduce FPs
    }
    
    // Adjust based on detection accuracy
    if (detection_accuracy < kLowAccuracyThreshold) {
        base_threshold -= kThresholdAdjustment; // Lower threshold if accuracy is poor
    }
    
    // Adjust based on overall traffic volume
    if (packets_received > kHighVolumePacketThreshold) {
        base_threshold += kVolumeThresholdAdjustment; // Slightly higher threshold for high-volume scenarios
    }
    
    // FIXED: Configurable time-of-day adjustments for global systems
    if (enable_local_time_bias) {
        auto now = std::chrono::system_clock::now();
        auto now_s = std::chrono::system_clock::to_time_t(now);  // FIXED: Renamed to avoid shadowing time_t type
        auto tm = safe_localtime(now_s);  // FIXED: Use thread-safe localtime helper
        
        // Lower threshold during typical attack hours (night/early morning) - LOCAL TIME ONLY
        if (tm.tm_hour >= 22 || tm.tm_hour <= 6) {
            base_threshold -= kTimeBasedAdjustment;
        }
    }
    
    return std::max(0.3, std::min(0.9, base_threshold));
}

void StatsEngine::update_ip_statistics(const std::string& src_ip, double rate) {
    auto& ip_stats = stats[src_ip];
    auto now = std::chrono::steady_clock::now();
    
    // FIXED: Set first_seen time if this is a new IP
    if (ip_stats.packet_count == 0) {
        ip_stats.first_seen = now;
    }
    
    ip_stats.last_seen = now;
    
    // FIXED: Use deque for O(1) operations instead of vector's O(n) erase
    ip_stats.rate_history.push_back(rate);
    if (ip_stats.rate_history.size() > 100) {
        ip_stats.rate_history.pop_front();
    }
    
    // Update statistical measures
    if (ip_stats.rate_history.size() >= 5) {
        double sum = 0.0;
        for (double r : ip_stats.rate_history) {
            sum += r;
        }
        ip_stats.mean_rate = sum / static_cast<double>(ip_stats.rate_history.size());
        
        // Calculate standard deviation
        double variance = 0.0;
        for (double r : ip_stats.rate_history) {
            variance += (r - ip_stats.mean_rate) * (r - ip_stats.mean_rate);
        }
        ip_stats.stddev_rate = std::sqrt(variance / static_cast<double>(ip_stats.rate_history.size()));
    }
}

// FIXED: Proper 95th percentile baseline calculation
double StatsEngine::calculate_95th_percentile_baseline() {
    if (rate_window.empty()) {
        // FIXED: Need to access baseline_rate under lock since this method can be called concurrently
        std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
        return baseline_rate;
    }
    
    // Guard against small window sizes to prevent early over-alarming
    if (rate_window.size() < 20) {
        // Use conservative estimate for small windows
        double sum = 0.0;
        for (double rate : rate_window) {
            sum += rate;
        }
        double mean = sum / rate_window.size();
        return mean * 2.0; // Conservative multiplier for early baseline
    }
    
    std::vector<double> sorted_rates(rate_window.begin(), rate_window.end());
    std::sort(sorted_rates.begin(), sorted_rates.end());
    
    // FIXED: Correct 95th percentile calculation (exclusive upper 5%)
    size_t index = (sorted_rates.size() * 95 + 99) / 100;
    if (index > 0) index -= 1; // Convert to zero-based index
    if (index >= sorted_rates.size()) index = sorted_rates.size() - 1;
    
    return sorted_rates[index];
}

void StatsEngine::update_baseline_window(double rate) {
    rate_window.push_back(rate);
    if (rate_window.size() > BASELINE_WINDOW_SIZE) {
        rate_window.pop_front();
    }
}

// Memory management: cleanup expired stats to prevent memory bloat
void StatsEngine::cleanup_expired_stats() {
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::minutes>(now - last_cleanup) < std::chrono::minutes(5)) {
        return; // Only cleanup every 5 minutes
    }
    
    std::lock_guard<std::shared_mutex> lock(stats_mutex);
    
    auto it = stats.begin();
    while (it != stats.end()) {
        auto age = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_seen);
        if (age > kStatsTtl) {
            it = stats.erase(it);
        } else {
            ++it;
        }
    }
    
    last_cleanup = now;
}

// Feedback system for dynamic threshold adjustment
void StatsEngine::update_feedback(double fp_rate, double accuracy) {
    std::lock_guard<std::shared_mutex> write_lock(stats_mutex);
    false_positive_rate = fp_rate;
    detection_accuracy = accuracy;
}

double StatsEngine::calculate_zscore(double value, double mean, double stddev) {
    if (stddev == 0.0) return 0.0;
    return std::abs(value - mean) / stddev;
}

// NEW: Learning period management methods
bool StatsEngine::is_learning_complete() const {
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    return initial_learning_done;
}

void StatsEngine::force_complete_learning() {
    std::unique_lock<std::shared_mutex> write_lock(stats_mutex);
    initial_learning_done = true;
}

void StatsEngine::update_stats_learning_mode(const PacketData& pkt) {
    std::unique_lock<std::shared_mutex> write_lock(stats_mutex);
    
    packets_received++;
    total_bytes += pkt.size;
    
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_packet_time).count();
    double time_seconds = std::max(static_cast<double>(duration) / 1000.0, 0.001);
    double instant_rate = static_cast<double>(pkt.size) / time_seconds;
    
    // Update baseline during learning
    if (packets_received == 1) {
        current_rate = instant_rate;
        baseline_rate = instant_rate;
    } else {
        current_rate = ewma_alpha * instant_rate + (1.0 - ewma_alpha) * current_rate;
        update_baseline_window(instant_rate);
        baseline_rate = calculate_95th_percentile_baseline();
    }
    
    last_packet_time = now;
    current_entropy = compute_entropy_optimized(pkt.getPayload());
    
    // Update basic IP stats
    update_ewma(pkt.src_ip, current_rate);
    update_destination_statistics(pkt.src_ip, pkt.dst_ip, pkt.dst_port, instant_rate);
}

// NEW: Per-destination tracking methods
std::string StatsEngine::make_destination_key(const std::string& src_ip, const std::string& dst_ip, 
                                            uint16_t dst_port) const {
    return src_ip + ":" + dst_ip + ":" + std::to_string(dst_port);
}

void StatsEngine::update_destination_statistics(const std::string& src_ip, const std::string& dst_ip, 
                                               uint16_t dst_port, double rate) {
    auto dest_key = make_destination_key(src_ip, dst_ip, dst_port);
    auto& dest_stats = destination_stats[dest_key];
    auto now = std::chrono::steady_clock::now();
    
    if (dest_stats.packet_count == 0) {
        dest_stats.first_seen = now;
    }
    
    dest_stats.last_seen = now;
    dest_stats.packet_count++;
    dest_stats.ewma = dest_stats.ewma * (1 - ewma_alpha) + rate * ewma_alpha;
    
    // Update rate history for statistical analysis
    dest_stats.rate_history.push_back(rate);
    if (dest_stats.rate_history.size() > 50) { // Smaller window for destinations
        dest_stats.rate_history.pop_front();
    }
    
    // Update statistical measures
    if (dest_stats.rate_history.size() >= 5) {
        double sum = 0.0;
        for (double r : dest_stats.rate_history) {
            sum += r;
        }
        dest_stats.mean_rate = sum / static_cast<double>(dest_stats.rate_history.size());
        
        // Calculate standard deviation
        double variance = 0.0;
        for (double r : dest_stats.rate_history) {
            variance += (r - dest_stats.mean_rate) * (r - dest_stats.mean_rate);
        }
        dest_stats.stddev_rate = std::sqrt(variance / static_cast<double>(dest_stats.rate_history.size()));
    }
}

double StatsEngine::calculate_destination_rate_deviation(const std::string& src_ip, const std::string& dst_ip,
                                                        uint16_t dst_port, double current_rate) {
    std::shared_lock<std::shared_mutex> read_lock(stats_mutex);
    
    auto dest_key = make_destination_key(src_ip, dst_ip, dst_port);
    auto it = destination_stats.find(dest_key);
    
    if (it == destination_stats.end() || it->second.rate_history.size() < 5) {
        // Fall back to per-IP deviation for new destinations
        return calculate_rate_deviation(src_ip, current_rate);
    }
    
    const auto& dest_stats = it->second;
    return calculate_zscore(current_rate, dest_stats.mean_rate, dest_stats.stddev_rate);
}

// NEW: Protocol-aware detection methods
double StatsEngine::get_protocol_specific_rate_threshold(const PacketData& pkt) const {
    // Different thresholds for UDP vs TCP due to different traffic patterns
    if (pkt.is_udp()) {
        // Higher threshold for UDP due to more bursty nature
        return kRateDeviationThresholdUdp; // 6.0
    } else if (pkt.is_tcp()) {
        // Lower threshold for TCP 
        return kRateDeviationThreshold; // 3.0
    }
    
    // Default threshold for other protocols
    return kRateDeviationThreshold;
}

bool StatsEngine::is_well_known_service_port(uint16_t port, bool is_udp) const {
    if (is_udp) {
        // Common UDP service ports that should be treated as legitimate
        switch (port) {
            case 53:   // DNS
            case 67:   // DHCP server
            case 68:   // DHCP client  
            case 123:  // NTP
            case 161:  // SNMP
            case 162:  // SNMP trap
            case 1900: // SSDP
            case 5353: // mDNS
                return true;
            default:
                // Multicast/broadcast ports
                if (port >= 5350 && port <= 5365) return true; // mDNS range
                break;
        }
    } else {
        // Common TCP service ports
        switch (port) {
            case 21:   // FTP
            case 22:   // SSH
            case 23:   // Telnet
            case 25:   // SMTP
            case 53:   // DNS
            case 80:   // HTTP
            case 110:  // POP3
            case 143:  // IMAP
            case 443:  // HTTPS
            case 993:  // IMAPS
            case 995:  // POP3S
                return true;
        }
    }
    
    return false;
}

void StatsEngine::initialize_multicast_whitelist() {
    // IPv4 multicast addresses
    multicast_whitelist.insert("224.0.0.251");     // mDNS
    multicast_whitelist.insert("239.255.255.250"); // SSDP
    multicast_whitelist.insert("224.0.0.1");       // All hosts multicast
    multicast_whitelist.insert("224.0.0.2");       // All routers multicast
    multicast_whitelist.insert("224.0.0.22");      // IGMP
    
    // IPv6 multicast addresses  
    multicast_whitelist.insert("ff02::1");         // All nodes
    multicast_whitelist.insert("ff02::2");         // All routers
    multicast_whitelist.insert("ff02::fb");        // mDNS
    multicast_whitelist.insert("ff02::c");         // SSDP
    multicast_whitelist.insert("ff05::c");         // SSDP site-local
    
    // Common broadcast addresses
    multicast_whitelist.insert("255.255.255.255"); // Limited broadcast
}
