#include "behavior_tracker.hpp"
#include "ddos_inspector.hpp"  // For g_threshold_tuning
#include <atomic>  // FIXED: Add missing atomic header
#include <vector>
#include <cmath>
#include <unordered_set>
#include <algorithm>
#include <string>     // FIXED: Explicit include for string operations
#include <chrono>     // FIXED: Explicit include for time operations  
#include <unordered_map>  // FIXED: Explicit include for unordered_map
#include <deque>      // FIXED: Explicit include for deque operations
#include <utility>    // FIXED: Explicit include for std::move, std::pair

#ifdef TESTING
#include "testing_config.hpp"
#endif

BehaviorTracker::BehaviorTracker() : behaviors(MAX_TRACKED_IPS) {
    last_cleanup = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    last_global_reset_ns.store(detail::time_point_to_ns(now));
    last_distributed_check_ns.store(detail::time_point_to_ns(now));
    
    // Initialize patterns timestamp under mutex protection
    {
        std::lock_guard<std::mutex> lock(patterns_mutex);
        patterns_timestamp = now;
    }
}

bool BehaviorTracker::inspect(const PacketData& pkt) {
    auto now = std::chrono::steady_clock::now();
    
    // Periodic cleanup to prevent memory growth
    if (std::chrono::duration_cast<std::chrono::minutes>(now - last_cleanup) >= CLEANUP_INTERVAL) {
        cleanup_expired_behaviors();
    }
    
    // Force cleanup if we're approaching memory limits
    if (static_cast<double>(behaviors.size()) > static_cast<double>(MAX_TRACKED_IPS) * 0.9) {
        force_cleanup_if_needed();
    }
    
    // FIXED: Use safer in-place update pattern to avoid lost updates/races
    bool behavior_exists = behaviors.with_write(pkt.src_ip, [&](Behavior& b) {
        // Update behavior safely within locked context
        b.last_seen = now;
        b.hot_.total_packets.fetch_add(1);  // FIXED: Use hot_ structure for cache efficiency
        b.packet_size_sum += pkt.size;
        
        // Track unique sessions for diversity analysis with bounds enforcement
        if (!pkt.session_id.empty() && b.seen_sessions.find(pkt.session_id) == b.seen_sessions.end()) {
            // Enforce session limit per IP to prevent memory exhaustion
            if (b.seen_sessions.size() >= BehaviorConfig::MAX_SEEN_SESSIONS) {
                // Remove oldest session (simple FIFO approach)
                auto it = b.seen_sessions.begin();
                b.seen_sessions.erase(it);
            }
            b.seen_sessions.insert(pkt.session_id);
            b.unique_session_count++;
        }
        
        // Track packet types and events with enhanced analysis
        std::string event_type;
        double packet_interval = 0.0;
        
        // Calculate time interval between packets for timing analysis
        if (!b.recent_events.empty()) {
            auto last_event_time = b.recent_events.back().timestamp;
            packet_interval = std::chrono::duration<double>(now - last_event_time).count();
            b.packet_intervals.push(packet_interval); // Use ring buffer push
        }
        
        // Track packet sizes for distribution analysis
        b.packet_sizes.push(pkt.size); // Use ring buffer push
        
        if (pkt.is_syn && !pkt.is_ack) {
            b.hot_.syn_count.fetch_add(1);  // FIXED: Use hot_ structure
            b.hot_.half_open.fetch_add(1);  // FIXED: Use hot_ structure
            event_type = "SYN";
        } else if (pkt.is_ack && !pkt.is_syn) {
            b.hot_.ack_count.fetch_add(1);  // FIXED: Use hot_ structure
            event_type = "ACK";
            
            // Check if this ACK has a corresponding SYN (legitimate connection)
            std::string conn_id = generateConnectionId(pkt, b);
            if (b.established_connections.find(conn_id) == b.established_connections.end()) {
                // ACK without prior SYN - potential ACK flood
                event_type = "ORPHAN_ACK";
            } else {
                // Legitimate ACK, reduce half-open count and increase legitimacy score
                int current_half_open = b.hot_.half_open.load();
                if (current_half_open > 0) {
                    b.hot_.half_open.fetch_sub(1);  // FIXED: Use atomic decrement
                }
                double current_score = b.hot_.legitimate_traffic_score.load();
                b.hot_.legitimate_traffic_score.store(current_score + 0.1); // Increment for legitimate behavior
            }
        } else if (pkt.is_syn && pkt.is_ack) {
            // SYN-ACK response, track connection
            std::string conn_id = generateConnectionId(pkt, b);
            b.established_connections.insert(conn_id);
            event_type = "SYN_ACK";
            double current_score = b.hot_.legitimate_traffic_score.load();
            b.hot_.legitimate_traffic_score.store(current_score + 0.05); // Small increment for proper handshake
        }
        
        if (pkt.is_http) {
            b.hot_.http_requests.fetch_add(1);  // FIXED: Use hot_ structure
            event_type = "HTTP";
            
            // Track HTTP sessions for slowloris detection with bounds enforcement
            if (b.http_sessions.size() >= BehaviorConfig::MAX_SEEN_SESSIONS) {
                // Remove oldest HTTP session when limit reached
                auto oldest = std::min_element(b.http_sessions.begin(), b.http_sessions.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; });
                if (oldest != b.http_sessions.end()) {
                    b.http_sessions.erase(oldest);
                }
            }
            b.http_sessions[pkt.session_id] = now;
            
            // Enhanced HTTP analysis for legitimate vs attack traffic
            // Check for incomplete requests (slowloris pattern) with bounds enforcement
            if (pkt.session_id.find("incomplete") != std::string::npos || 
                pkt.payload.find("\r\n\r\n") == std::string::npos) {
                
                // Enforce bounds on incomplete requests
                if (b.incomplete_requests.size() >= BehaviorConfig::MAX_INCOMPLETE_REQUESTS) {
                    // Remove oldest incomplete request
                    auto it = b.incomplete_requests.begin();
                    b.incomplete_requests.erase(it);
                }
                b.incomplete_requests.insert(pkt.session_id);
            } else {
                // Complete HTTP request - legitimate behavior
                double current_score = b.hot_.legitimate_traffic_score.load();  // FIXED: Use hot_ structure
                b.hot_.legitimate_traffic_score.store(current_score + 0.05);  // FIXED: Use hot_ structure
            }
            
            // Analyze HTTP request patterns for legitimacy
            if (!pkt.payload.empty()) {
                // Check for common legitimate HTTP patterns
                if (pkt.payload.find("User-Agent:") != std::string::npos ||
                    pkt.payload.find("Accept:") != std::string::npos ||
                    pkt.payload.find("Host:") != std::string::npos) {
                    double current_score = b.hot_.legitimate_traffic_score.load();  // FIXED: Use hot_ structure
                    b.hot_.legitimate_traffic_score.store(current_score + 0.02); // Small bonus for proper headers  // FIXED: Use hot_ structure
                }
                
                // Check for suspicious patterns common in HTTP floods
                if (pkt.payload.find("GET / HTTP") != std::string::npos && 
                    pkt.payload.length() < 100) {
                    // Very short GET requests might be flood traffic
                    event_type = "HTTP_SUSPICIOUS";
                }
            }
        }
        
        // Update baseline traffic rate dynamically
        updateBaselineRateOptimized(b, now);
        
        // Calculate legitimacy decay over time (suspicious IPs lose score) - fixed atomic operation
        auto last_baseline_ns = b.last_baseline_update_ns.load(); // FIXED: Use nanoseconds
        auto last_baseline_time = detail::ns_to_time_point(last_baseline_ns);
        auto time_since_baseline = std::chrono::duration_cast<std::chrono::minutes>(now - last_baseline_time);
        if (time_since_baseline >= std::chrono::minutes(5)) {
            double current_score = b.hot_.legitimate_traffic_score.load();  // FIXED: Use hot_ structure
            // Apply legitimacy decay more aggressively to prevent untouchable IPs
            double new_score = current_score * BehaviorConfig::LEGITIMACY_DECAY_RATE;
            // Cap the maximum legitimacy score to prevent untouchable IPs
            new_score = std::min(new_score, 10.0);
            b.hot_.legitimate_traffic_score.store(new_score);  // FIXED: Use hot_ structure
            b.last_baseline_update_ns.store(detail::time_point_to_ns(now)); // FIXED: Use nanoseconds
        }
        
        // FIXED: Add hard cap to recent_events deque to prevent unbounded growth
        if (b.recent_events.size() >= BehaviorConfig::MAX_RECENT_EVENTS) {
            b.recent_events.pop_front();  // Remove oldest event
        }
        
        // Add timestamped event
        b.recent_events.push_back({now, event_type});
        
        // Update rolling counters for efficient detection (avoid multiple passes)
        updateRollingCounters(b, event_type, now);
        
        // Enforce bounds on unbounded containers
        enforceBehaviorBounds(b);
        
        // Cleanup old events (now working with local copy)
        cleanupOldEvents(b);
    });
    
    if (!behavior_exists) {
        // Initialize new behavior with enhanced tracking
        Behavior new_behavior;
        new_behavior.first_seen = now;
        new_behavior.last_seen = now;
        // Initialize hot counters to 0 (they default to 0 anyway)
        new_behavior.packet_size_sum = 0;
        new_behavior.unique_session_count = 0;
        new_behavior.baseline_rate.store(0.0);
        new_behavior.cached_baseline_rate.store(0.0);
        new_behavior.last_baseline_update_ns.store(detail::time_point_to_ns(now)); // FIXED: Use nanoseconds
        new_behavior.hot_.last_update_ns.store(detail::time_point_to_ns(now));  // FIXED: Use hot_ structure with nanoseconds
        new_behavior.connection_id_counter.store(0);
        
        // Add initial event
        std::string event_type = pkt.is_syn ? "SYN" : (pkt.is_http ? "HTTP" : "OTHER");
        new_behavior.recent_events.push_back({now, event_type});
        
        behaviors.put(pkt.src_ip, new_behavior);
        
        // Process the packet again with the in-place update pattern for the new behavior
        behaviors.with_write(pkt.src_ip, [&](Behavior& b) {
            // Same processing logic as above for consistency
            b.hot_.total_packets.fetch_add(1);  // FIXED: Use hot_ structure
            b.packet_size_sum += pkt.size;
            
            if (pkt.is_syn && !pkt.is_ack) {
                b.hot_.syn_count.fetch_add(1);  // FIXED: Use hot_ structure
                b.hot_.half_open.fetch_add(1);  // FIXED: Use hot_ structure
            } else if (pkt.is_ack && !pkt.is_syn) {
                b.hot_.ack_count.fetch_add(1);  // FIXED: Use hot_ structure
            } else if (pkt.is_http) {
                b.hot_.http_requests.fetch_add(1);  // FIXED: Use hot_ structure
                b.http_sessions[pkt.session_id] = now;
            }
            
            updateRollingCounters(b, event_type, now);
        });
    }
    
    total_global_packets.fetch_add(1);
    
    // Enhanced detection with real-world traffic awareness
    // Get the updated behavior for detection analysis
    Behavior current_behavior;
    bool found_for_detection = behaviors.get(pkt.src_ip, current_behavior);
    if (!found_for_detection) {
        return false; // Shouldn't happen, but safety check
    }
    
    int detection_score = 0;
    std::vector<std::string> detected_patterns;
    double legitimacy_factor = calculateLegitimacyFactor(current_behavior);
    
    // Check for legitimate traffic patterns first (flash crowd detection)
    if (isLegitimateTrafficPattern(current_behavior) || detectFlashCrowdPattern(current_behavior)) {
        // Apply legitimacy boost to prevent false positives
        legitimacy_factor += 1.0; // Reduced from 2.0 to 1.0
    }
    
    // Run all detection algorithms and accumulate scores
    if (detectSynFlood(current_behavior)) {
        detection_score += 3;
        detected_patterns.emplace_back("SYN_FLOOD");
    }
    if (detectAckFlood(current_behavior)) {
        detection_score += 3;
        detected_patterns.emplace_back("ACK_FLOOD");
    }
    if (detectHttpFlood(current_behavior)) {
        detection_score += 3;
        detected_patterns.emplace_back("HTTP_FLOOD");
    }
    if (detectSlowloris(current_behavior)) {
        detection_score += 4; // Slowloris is more sophisticated, higher score
        detected_patterns.emplace_back("SLOWLORIS");
    }
    if (detectVolumeAttack(current_behavior)) {
        detection_score += 3;
        detected_patterns.emplace_back("VOLUME_ATTACK");
    }
    
    // Only run distributed attack detection on timer to avoid O(n*m) complexity
    if (shouldRunDistributedCheck() && detectDistributedAttack()) {
        detection_score += 5; // Distributed attacks are serious
        detected_patterns.emplace_back("DISTRIBUTED_ATTACK");
    }
    
    // Advanced evasion detection (higher scores for sophisticated techniques)
    if (detectPulseAttack(current_behavior)) {
        detection_score += 4; // Pulse attacks indicate sophisticated evasion
        detected_patterns.emplace_back("PULSE_ATTACK");
    }
    if (detectProtocolMixing(current_behavior)) {
        detection_score += 4; // Protocol mixing shows advanced knowledge
        detected_patterns.emplace_back("PROTOCOL_MIXING");
    }
    if (detectGeoDistributedAttack()) {
        detection_score += 6; // Global coordination is highly suspicious
        detected_patterns.emplace_back("GEO_DISTRIBUTED");
    }
    if (detectLowAndSlowAttack(current_behavior)) {
        detection_score += 5; // Low-and-slow attacks are stealthy and dangerous
        detected_patterns.emplace_back("LOW_AND_SLOW");
    }
    if (detectRandomizedPayloads(current_behavior)) {
        detection_score += 3; // Randomization indicates evasion attempts
        detected_patterns.emplace_back("RANDOMIZED_PAYLOADS");
    }
    if (detectLegitimateTrafficMixing(current_behavior)) {
        detection_score += 5; // Mixing with legitimate traffic is very sophisticated
        detected_patterns.emplace_back("LEGITIMATE_MIXING");
    }
    if (detectDynamicSourceRotation()) {
        detection_score += 4; // Source rotation shows botnet-like behavior
        detected_patterns.emplace_back("DYNAMIC_ROTATION");
    }
    
    // Enhanced pattern correlation - require multiple patterns for higher confidence
    if (detected_patterns.size() >= 2) {
        detection_score += 2; // Multiple attack patterns increase confidence
    }
    
    // Apply legitimacy factor more conservatively and ensure detection_score cannot go negative
    #ifdef TESTING
        // In testing, be less aggressive with legitimacy adjustments
        if (legitimacy_factor > 2.0) {
            detection_score = static_cast<int>(std::max(0.0, detection_score * 0.8)); // Prevent negative scores
        }
    #else
        // In production, apply legitimacy factor with minimum score protection
        if (legitimacy_factor > 1.0) {
            // Cap the minimum score before division to prevent over-suppression
            int min_protected_score = std::max(detection_score, 2);
            detection_score = static_cast<int>(std::max(1.0, min_protected_score / legitimacy_factor));
        }
    #endif
    
    // Store detected patterns with timestamp for classification (both protected by same mutex)
    {
        std::lock_guard<std::mutex> lock(patterns_mutex);
        last_detected_patterns = detected_patterns; // This automatically replaces old patterns
        patterns_timestamp = std::chrono::steady_clock::now(); // Mark when patterns were detected
    }
    
    // Adaptive threshold based on network context and legitimacy
    int threshold = calculateAdaptiveThreshold(current_behavior, legitimacy_factor);
    
    return detection_score >= threshold;
}

void BehaviorTracker::cleanupOldEvents(Behavior& b) {
    auto now = std::chrono::steady_clock::now();
    
    // Remove events older than 60 seconds
    while (!b.recent_events.empty()) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - b.recent_events.front().timestamp);
        if (duration.count() > 60) {
            b.recent_events.pop_front();
        } else {
            break;
        }
    }
    
    // Cleanup old HTTP sessions
    for (auto it = b.http_sessions.begin(); it != b.http_sessions.end(); ) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (duration.count() > 600) {
            it = b.http_sessions.erase(it);
        } else {
            ++it;
        }
    }
    
    // Reset global counters every 5 minutes instead of 1 minute for distributed attack detection
    auto last_reset_ns = last_global_reset_ns.load(); // FIXED: Use nanoseconds
    auto last_reset = detail::ns_to_time_point(last_reset_ns);
    auto global_duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_reset);
    if (global_duration.count() > 300) { // Changed from 60 to 300 seconds
        total_global_packets.store(0);
        last_global_reset_ns.store(detail::time_point_to_ns(now)); // FIXED: Use nanoseconds
    }
}

void BehaviorTracker::cleanup_expired_behaviors() {
    std::lock_guard<std::mutex> lock(cleanup_mutex);
    auto now = std::chrono::steady_clock::now();
    
    // Note: With LRU cache, old entries are automatically evicted
    // This method can be used for additional cleanup logic if needed
    last_cleanup = now;
}

void BehaviorTracker::force_cleanup_if_needed() {
    // Implement aggressive cleanup when approaching memory limits
    std::lock_guard<std::mutex> lock(cleanup_mutex);
    
    size_t current_size = behaviors.size();
    size_t threshold = static_cast<size_t>(BehaviorConfig::MAX_TRACKED_IPS * 0.95); // 95% full
    
    if (current_size >= threshold) {
        // Force eviction of old entries - LRU cache handles this automatically
        // But we can also clean up based on activity level
        std::vector<std::string> candidates_for_removal;
        
        auto cutoff_time = std::chrono::steady_clock::now() - std::chrono::minutes(30);
        
        behaviors.for_each([&](const std::string& ip, const Behavior& b) {
            if (b.last_seen < cutoff_time) {
                candidates_for_removal.push_back(ip);
            }
        });
        
        // Remove inactive IPs
        for (const auto& ip : candidates_for_removal) {
            behaviors.erase(ip);
            if (behaviors.size() < threshold) {
                break; // Stop when we're under threshold
            }
        }
    }
}

bool BehaviorTracker::detectSynFlood(const Behavior& b) const {
    // NEW: Adaptive thresholds based on baseline and environmental factors
    double adaptive_threshold = calculateAdaptiveSynFloodThreshold(b);
    double time_factor = calculateTimeOfDayFactor();
    double network_factor = calculateNetworkLoadFactor();
    double legitimacy_multiplier = calculateLegitimacyMultiplier(b);
    
    // Apply environmental adjustments
    adaptive_threshold *= time_factor * network_factor * legitimacy_multiplier;
    
    // Ensure minimum threshold for security
    adaptive_threshold = std::max(adaptive_threshold, g_threshold_tuning.min_syn_flood_threshold);
    
    #ifdef TESTING
        const int syn_window_seconds = g_testing_config.isLoaded() ? 
            g_testing_config.getDetectionWindows().syn_window_seconds : 10;
        adaptive_threshold = g_testing_config.isLoaded() ? 
            std::max(adaptive_threshold * g_testing_config.getBehavioralThreshold("syn_flood").adaptive_factor, 
                     g_testing_config.getBehavioralThreshold("syn_flood").min_threshold) :
            std::max(adaptive_threshold * 0.1, 100.0); // Lower for testing
    #else
        const int syn_window_seconds = 60;
    #endif
    
    // Multi-factor SYN flood detection with adaptive considerations
    
    // 1. Classic SYN flood: too many half-open connections
    if (b.hot_.half_open.load() > adaptive_threshold) {
        return true;
    }
    
    // 2. Rate-based SYN flood with adaptive baseline comparison
    uint64_t syn_count_recent = b.hot_.syn_count_recent.load(std::memory_order_relaxed);
    uint64_t total_events_recent = b.hot_.total_events_recent.load(std::memory_order_relaxed);
    uint64_t legitimate_acks = b.hot_.ack_count_recent.load(std::memory_order_relaxed);
    auto now = std::chrono::steady_clock::now();
    
    // Reset rolling counters if they're stale
    auto last_update_ns = b.hot_.last_update_ns.load();
    auto last_update = detail::ns_to_time_point(last_update_ns);
    auto time_since_update = std::chrono::duration_cast<std::chrono::seconds>(now - last_update);
    if (time_since_update.count() > syn_window_seconds) {
        // Counters are stale, fall back to event scanning
        syn_count_recent = 0;
        total_events_recent = 0;
        legitimate_acks = 0;
        
        for (const auto& event : b.recent_events) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
            if (duration.count() <= syn_window_seconds) {
                total_events_recent++;
                if (event.event_type == "SYN") {
                    syn_count_recent++;
                } else if (event.event_type == "ACK") {
                    legitimate_acks++;
                }
            }
        }
    }
    
    // 3. Enhanced SYN ratio analysis with legitimacy consideration
    if (total_events_recent > 100) {
        double syn_ratio = static_cast<double>(syn_count_recent) / total_events_recent;
        double ack_ratio = static_cast<double>(legitimate_acks) / total_events_recent;
        
        // Adaptive SYN count threshold based on baseline
        double adaptive_syn_count_threshold = adaptive_threshold * 0.5;
        
        if (syn_ratio > 0.7 && ack_ratio < 0.2 && syn_count_recent > adaptive_syn_count_threshold) {
            return true;
        }
    }
    
    // 4. Sustained attack detection with adaptive baseline comparison
    double adaptive_count_threshold = adaptive_threshold * 2.0;
    if (syn_count_recent > adaptive_count_threshold) {
        double current_rate = static_cast<double>(syn_count_recent) / syn_window_seconds;
        double baseline_rate = b.baseline_rate.load();
        
        // Use adaptive multiplier instead of fixed 10x
        double rate_multiplier = std::max(5.0, g_threshold_tuning.syn_flood_baseline_multiplier);
        if (current_rate > baseline_rate * rate_multiplier) {
            return true;
        }
    }
    
    // 5. Packet timing analysis with adaptive variance threshold
    if (syn_count_recent > adaptive_threshold * 0.25 && !b.packet_intervals.empty()) {
        double interval_variance = calculatePacketIntervalVariance(b.packet_intervals);
        double adaptive_variance_threshold = 0.01 * legitimacy_multiplier;
        
        if (interval_variance < adaptive_variance_threshold && syn_count_recent > 500) {
            return true;
        }
    }
    
    return false;
}

bool BehaviorTracker::detectAckFlood(const Behavior& b) const {
    // NEW: Adaptive thresholds based on baseline and environmental factors
    double adaptive_threshold = calculateAdaptiveAckFloodThreshold(b);
    double time_factor = calculateTimeOfDayFactor();
    double network_factor = calculateNetworkLoadFactor();
    double legitimacy_multiplier = calculateLegitimacyMultiplier(b);
    
    // Apply environmental adjustments
    adaptive_threshold *= time_factor * network_factor * legitimacy_multiplier;
    
    // Ensure minimum threshold for security
    adaptive_threshold = std::max(adaptive_threshold, g_threshold_tuning.min_ack_flood_threshold);
    
    #ifdef TESTING
        const int ack_window_seconds = g_testing_config.isLoaded() ? 
            g_testing_config.getDetectionWindows().ack_window_seconds : 5;
        adaptive_threshold = g_testing_config.isLoaded() ? 
            std::max(adaptive_threshold * g_testing_config.getBehavioralThreshold("ack_flood").adaptive_factor, 
                     g_testing_config.getBehavioralThreshold("ack_flood").min_threshold) :
            std::max(adaptive_threshold * 0.1, 50.0); // Lower for testing
    #else
        const int ack_window_seconds = 30;
    #endif
    
    // Enhanced ACK flood detection with adaptive pattern analysis
    uint64_t orphan_ack_count = 0;
    uint64_t total_ack_count = 0;
    uint64_t syn_count = 0;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (duration.count() <= ack_window_seconds) {
            if (event.event_type == "ORPHAN_ACK") {
                orphan_ack_count++;
            } else if (event.event_type == "ACK") {
                total_ack_count++;
            } else if (event.event_type == "SYN") {
                syn_count++;
            }
        }
    }
    
    // 1. Direct orphan ACK detection with adaptive threshold
    double adaptive_orphan_threshold = adaptive_threshold * 0.8;
    if (orphan_ack_count > adaptive_orphan_threshold) {
        return true;
    }
    
    // 2. ACK:SYN ratio analysis with adaptive thresholds
    if (syn_count > 0 && total_ack_count > 0) {
        double ack_syn_ratio = static_cast<double>(total_ack_count) / syn_count;
        double adaptive_count_threshold = adaptive_threshold * 0.5;
        
        // Adaptive ratio threshold based on legitimacy
        double ratio_threshold = 5.0 / legitimacy_multiplier;
        if (ack_syn_ratio > ratio_threshold && total_ack_count > adaptive_count_threshold) {
            return true;
        }
    } else if (total_ack_count > adaptive_threshold && syn_count < 10) {
        // Many ACKs with very few SYNs is suspicious
        return true;
    }
    
    return false;
}

bool BehaviorTracker::detectHttpFlood(const Behavior& b) const {
    // NEW: Adaptive thresholds based on baseline and environmental factors
    double adaptive_threshold = calculateAdaptiveHttpFloodThreshold(b);
    double time_factor = calculateTimeOfDayFactor();
    double network_factor = calculateNetworkLoadFactor();
    double legitimacy_multiplier = calculateLegitimacyMultiplier(b);
    
    // Apply environmental adjustments
    adaptive_threshold *= time_factor * network_factor * legitimacy_multiplier;
    
    // Ensure minimum threshold for security
    adaptive_threshold = std::max(adaptive_threshold, g_threshold_tuning.min_http_flood_threshold);
    
    #ifdef TESTING
        const int http_window_seconds = g_testing_config.isLoaded() ? 
            g_testing_config.getDetectionWindows().http_window_seconds : 10;
        adaptive_threshold = g_testing_config.isLoaded() ? 
            std::max(adaptive_threshold * g_testing_config.getBehavioralThreshold("http_flood").adaptive_factor, 
                     g_testing_config.getBehavioralThreshold("http_flood").min_threshold) :
            std::max(adaptive_threshold * 0.05, 100.0); // Much lower for testing
    #else
        const int http_window_seconds = 120;
    #endif
    
    // Calculate adaptive sub-thresholds
    double adaptive_burst_threshold = adaptive_threshold * 0.2;
    double adaptive_sustained_threshold = adaptive_threshold * 0.5;
    
    // Multi-timeframe HTTP flood detection with adaptive considerations
    uint64_t http_count_recent = 0;
    uint64_t http_count_burst = 0;  // Last 30 seconds
    int unique_sessions_recent = 0;
    std::unordered_set<std::string> recent_sessions;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (event.event_type == "HTTP" || event.event_type == "HTTP_SUSPICIOUS") {
            if (duration.count() <= http_window_seconds) {
                http_count_recent++;
                // Track session diversity for legitimacy analysis
                if (!b.http_sessions.empty()) {
                    for (const auto& session : b.http_sessions) {
                        auto session_age = std::chrono::duration_cast<std::chrono::seconds>(now - session.second);
                        if (session_age.count() <= http_window_seconds) {
                            recent_sessions.insert(session.first);
                        }
                    }
                }
            }
            if (duration.count() <= 30) // 30-second burst window
                http_count_burst++;
        }
    }
    
    unique_sessions_recent = static_cast<int>(recent_sessions.size());
    
    // 1. Burst detection with adaptive threshold
    if (http_count_burst > adaptive_burst_threshold) {
        // Flash crowd vs attack distinction with adaptive thresholds
        double session_diversity = static_cast<double>(unique_sessions_recent) / std::max(http_count_burst, static_cast<uint64_t>(1));
        double legitimacy_score = b.hot_.legitimate_traffic_score.load();
        
        // More lenient for high legitimacy scores and good session diversity
        if (unique_sessions_recent > 20 && legitimacy_score > 2.0 && session_diversity > 0.3) {
            return false; // Likely legitimate flash crowd
        }
        
        // Stricter detection for suspicious patterns
        if (unique_sessions_recent < 5 && http_count_burst > adaptive_burst_threshold * 2) {
            return true;
        }
        return true;
    }
    
    // 2. Sustained high-rate detection with adaptive analysis
    if (http_count_recent > adaptive_sustained_threshold) {
        // Adaptive session diversity analysis
        double session_diversity = static_cast<double>(unique_sessions_recent) / std::max(http_count_recent, static_cast<uint64_t>(1));
        double diversity_threshold = 0.1 * legitimacy_multiplier; // Higher legitimacy = higher tolerance
        
        if (session_diversity < diversity_threshold) {
            return true; // Likely bot/flood traffic
        }
        
        // Adaptive baseline comparison
        double current_rate = static_cast<double>(http_count_recent) / http_window_seconds;
        double baseline_rate = b.baseline_rate.load();
        double rate_multiplier = std::max(10.0, g_threshold_tuning.http_flood_baseline_multiplier);
        
        if (current_rate > baseline_rate * rate_multiplier) {
            return true;
        }
    }
    
    // 3. Extreme volume detection with adaptive threshold
    if (http_count_recent > adaptive_threshold) {
        return true;
    }
    
    // 4. Enhanced pattern analysis with adaptive suspicious ratio
    if (http_count_recent > 200) {
        int suspicious_count = 0;
        for (const auto& event : b.recent_events) {
            if (event.event_type == "HTTP_SUSPICIOUS") {
                suspicious_count++;
            }
        }
        
        double suspicious_ratio = static_cast<double>(suspicious_count) / http_count_recent;
        double suspicious_threshold = 0.3 / legitimacy_multiplier; // Adjust based on legitimacy
        
        if (suspicious_ratio > suspicious_threshold) {
            return true;
        }
    }
    
    // 5. Packet size analysis - flood attacks often have uniform small packets
    if (http_count_recent > 500 && !b.packet_sizes.empty()) {
        double size_variance = calculateSizeVariance(b.packet_sizes);
        double avg_size = static_cast<double>(b.packet_size_sum) / b.hot_.total_packets.load();  // FIXED: Use hot_ structure
        
        // Very low variance and small average size suggests flood
        if (size_variance < 100.0 && avg_size < 200.0) {
            return true;
        }
    }
    
    return false;
}

bool BehaviorTracker::detectSlowloris(const Behavior& b) const {
    auto now = std::chrono::steady_clock::now();
    
    // Enhanced Slowloris detection with real-world considerations
    
    // Check for many long-lived HTTP sessions
    int long_sessions = 0;
    int very_long_sessions = 0;
    int active_sessions = 0;
    
    for (const auto& session : b.http_sessions) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - session.second);
        active_sessions++;
        
        if (duration.count() > 300) { // Sessions longer than 5 minutes
            long_sessions++;
        }
        if (duration.count() > 900) { // Sessions longer than 15 minutes
            very_long_sessions++;
        }
    }
    
    // Real Slowloris has specific characteristics:
    // 1. Many concurrent long-lived connections
    // 2. High ratio of incomplete to complete requests
    // 3. Low data transfer rate per session
    
    #ifdef TESTING
        const int long_session_threshold = 20;
        const int incomplete_threshold = 50;
        const int concurrent_threshold = 30;
    #else
        const int long_session_threshold = 500;  // Much higher for production
        const int incomplete_threshold = 1000;   // Higher threshold
        const int concurrent_threshold = 800;    // High concurrent sessions needed
    #endif
    
    // Enhanced detection criteria
    
    // 1. Basic Slowloris pattern: many long sessions with incomplete requests
    if (long_sessions > long_session_threshold && 
        b.incomplete_requests.size() > incomplete_threshold) {
        
        // Additional verification: check if most sessions are incomplete
        double incomplete_ratio = static_cast<double>(b.incomplete_requests.size()) / 
                                 std::max(static_cast<int>(b.http_sessions.size()), 1);
        
        if (incomplete_ratio > 0.8) { // More than 80% incomplete
            return true;
        }
    }
    
    // 2. High concurrent sessions with low completion rate
    if (active_sessions > concurrent_threshold) {
        // Check HTTP request to session ratio (should be low for Slowloris)
        double request_per_session = static_cast<double>(b.hot_.http_requests.load()) / active_sessions;
        
        if (request_per_session < 2.0 && b.incomplete_requests.size() > concurrent_threshold / 2) {
            return true; // Few requests per session + many incompletes = Slowloris
        }
    }
    
    // 3. Advanced pattern: very long sessions with minimal data transfer
    if (very_long_sessions > 100 && b.hot_.total_packets.load() > 1000) {
        // Calculate average packet size
        double avg_packet_size = static_cast<double>(b.packet_size_sum) / b.hot_.total_packets.load();
        
        // Slowloris typically sends very small packets to keep connections alive
        if (avg_packet_size < 100.0 && 
            b.incomplete_requests.size() > static_cast<size_t>(very_long_sessions)) {
            return true;
        }
    }
    
    // 4. Timing pattern analysis for Slowloris
    if (long_sessions > 200 && !b.packet_intervals.empty()) {
        double avg_interval = 0.0;
        for (double interval : b.packet_intervals) {
            avg_interval += interval;
        }
        avg_interval /= static_cast<double>(b.packet_intervals.size());
        
        // Slowloris has characteristic slow, regular intervals
        if (avg_interval > 10.0 && avg_interval < 30.0) { // 10-30 second intervals
            double variance = calculatePacketIntervalVariance(b.packet_intervals);
            if (variance < 5.0) // Low variance = regular timing
                return true;
        }
    }
    
    return false;
}

bool BehaviorTracker::detectVolumeAttack(const Behavior& b) const {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - b.first_seen);
    
    // Standard volume-based detection: too many packets in short time
    if (duration.count() > 0 && duration.count() <= 30) {
        double packets_per_second = static_cast<double>(b.hot_.total_packets.load()) / static_cast<double>(duration.count());
        #ifdef TESTING
        double volume_threshold = g_testing_config.isLoaded() ? 
            g_testing_config.getVolumeAttackThresholds().packets_per_second_threshold : 5000.0;
        return packets_per_second > volume_threshold; // Use testing config threshold
        #else
        return packets_per_second > 20000;
        #endif
    }
    
    // Enhanced evasion detection for sophisticated attackers
    if (b.hot_.total_packets.load() > 500) {  // Increased threshold from 50 to 500
        // Check for mixed packet types (common evasion tactic)
        bool has_syn = b.hot_.syn_count.load() > 0;
        bool has_ack = b.hot_.ack_count.load() > 0;
        bool has_http = b.hot_.http_requests.load() > 0;
        int packet_type_diversity = (has_syn ? 1 : 0) + (has_ack ? 1 : 0) + (has_http ? 1 : 0);
        
        // Evasive pattern: mixed types + distributed coordination
        if (packet_type_diversity >= 2) {
            // Lower threshold when part of coordinated distributed attack
            if (behaviors.size() >= 50 && total_global_packets > 10000) {  // Much higher thresholds
                return true; // Sophisticated distributed evasion
            }
        }
        
        // Standard distributed attack detection
        if (detectDistributedAttack() && b.hot_.total_packets.load() > 200) {  // Increased from 40 to 200
            return true; // Part of distributed evasive attack
        }
    }
    
    return false;
}

bool BehaviorTracker::detectDistributedAttack() const {
    // Enhanced distributed attack detection with real-world considerations
    
    // Count IPs with suspicious activity patterns
    int attacking_ips = 0;
    int coordinated_ips = 0;
    int legitimate_ips = 0;
    std::vector<std::chrono::steady_clock::time_point> attack_start_times;
    
    auto now = std::chrono::steady_clock::now();
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        // Enhanced criteria for considering an IP as attacking
        bool is_attacking = false;
        bool is_legitimate = false;
        
        // Check for legitimacy first
        if (b.hot_.legitimate_traffic_score > 3.0 || isLegitimateTrafficPattern(b)) {
            is_legitimate = true;
            legitimate_ips++;
        }
        
        // Volume-based indicators (higher thresholds for real-world)
        if (b.hot_.total_packets.load() > 1000 && 
            (b.hot_.syn_count.load() > 500 || b.hot_.http_requests.load() > 800 || b.hot_.ack_count.load() > 500)) {
            is_attacking = true;
        }
        
        // Rate-based indicators
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - b.first_seen);
        if (duration.count() > 0) {
            double packets_per_second = static_cast<double>(b.hot_.total_packets.load()) / static_cast<double>(duration.count());
            if (packets_per_second > 1000) { // Very high rate indicator
                is_attacking = true;
            }
        }
        
        // Pattern-based indicators (mixed attack types suggest coordination)
        int attack_types = 0;
        if (b.hot_.syn_count.load() > 200) attack_types++;
        if (b.hot_.ack_count.load() > 200) attack_types++;
        if (b.hot_.http_requests.load() > 300) attack_types++;
        
        if (attack_types >= 2) {
            is_attacking = true;
        }
        
        // Override attacking classification if highly legitimate
        if (is_legitimate && b.hot_.legitimate_traffic_score > 5.0) {
            is_attacking = false;
        }
        
        if (is_attacking) {
            attacking_ips++;
            attack_start_times.push_back(b.first_seen);
            
            // Check for temporal coordination (attacks starting within similar timeframes)
            auto time_since_start = std::chrono::duration_cast<std::chrono::seconds>(now - b.first_seen);
            if (time_since_start.count() <= 300) { // Started within last 5 minutes
                coordinated_ips++;
            }
        }
    });
    
    // Temporal correlation analysis
    bool temporal_correlation = false;
    if (attack_start_times.size() >= 10) { // Need more IPs for meaningful correlation
        // Check if multiple attacks started within a narrow time window
        std::sort(attack_start_times.begin(), attack_start_times.end());
        
        for (size_t i = 0; i < attack_start_times.size() - 9; i++) {
            auto time_span = std::chrono::duration_cast<std::chrono::seconds>(
                attack_start_times[i + 9] - attack_start_times[i]);
            
            if (time_span.count() <= 120) { // 10 attacks within 2 minutes
                temporal_correlation = true;
                break;
            }
        }
    }
    
    // Calculate legitimacy ratio
    double total_analyzed_ips = attacking_ips + legitimate_ips;
    double legitimacy_ratio = (total_analyzed_ips > 0) ? 
        static_cast<double>(legitimate_ips) / total_analyzed_ips : 0.0;
    
    // Enhanced distributed attack criteria with legitimacy consideration
    
    // 1. High number of attacking IPs with high global traffic, but low legitimacy
    if (attacking_ips >= 50 && total_global_packets.load(std::memory_order_relaxed) > 200000 && legitimacy_ratio < 0.3) {
        return true;
    }
    
    // 2. Moderate number of IPs with temporal correlation and low legitimacy
    if (attacking_ips >= 20 && coordinated_ips >= 15 && temporal_correlation && legitimacy_ratio < 0.5) {
        return true;
    }
    
    // 3. Large number of coordinated IPs with high traffic volume
    if (coordinated_ips >= 30 && total_global_packets.load(std::memory_order_relaxed) > 100000) {
        return true;
    }
    
    // 4. Sophisticated low-and-slow distributed attack
    if (attacking_ips >= 100 && behaviors.size() >= 150 && legitimacy_ratio < 0.4) {
        // Many IPs with suspicious but not individually high activity
        return true;
    }
    
    // 5. Flash crowd vs. DDoS distinction
    // If high legitimacy ratio, likely flash crowd, not attack
    if (legitimacy_ratio > 0.7 && attacking_ips > 0) {
        return false; // Likely legitimate flash crowd
    }
    
    return false;
}

// ===============================================
// Advanced DDoS/Evasion Detection Implementations
// ===============================================

bool BehaviorTracker::detectPulseAttack(const Behavior& b) const {
    // Pulse attacks: Intermittent bursts separated by quiet periods to evade detection
    if (b.packet_intervals.size() < 20) return false; // Need sufficient data
    
    int burst_periods = 0;
    int quiet_periods = 0;
    double burst_threshold = 0.1;  // Less than 100ms = burst
    double quiet_threshold = 3.0;  // More than 3s = quiet period
    
    for (double interval : b.packet_intervals) {
        if (interval < burst_threshold) {
            burst_periods++;
        } else if (interval > quiet_threshold) {
            quiet_periods++;
        }
    }
    
    // Pulse pattern: alternating bursts and quiet periods
    double burst_ratio = static_cast<double>(burst_periods) / b.packet_intervals.size();
    double quiet_ratio = static_cast<double>(quiet_periods) / b.packet_intervals.size();
    
    // Flag as pulse if we see both significant bursts and quiet periods
    return (burst_ratio > 0.3 && quiet_ratio > 0.2 && burst_periods > 5 && quiet_periods > 3);
}

bool BehaviorTracker::detectProtocolMixing(const Behavior& b) const {
    // Protocol mixing: Combining TCP/UDP/ICMP simultaneously to confuse detection
    if (b.hot_.total_packets.load() < 100) return false; // Need significant sample
    
    int distinct_attack_types = 0;
    
    // Count distinct attack-oriented protocol types with higher thresholds
    if (b.hot_.syn_count.load() > 50) distinct_attack_types++;        // TCP SYN floods (higher threshold)
    if (b.hot_.ack_count.load() > 50) distinct_attack_types++;        // TCP ACK floods (higher threshold)
    if (b.hot_.http_requests.load() > 20) distinct_attack_types++;    // HTTP floods
    // Note: In real implementation, would also check UDP floods, ICMP floods, etc.
    
    // Only flag as protocol mixing if truly using multiple ATTACK types
    if (distinct_attack_types >= 2) {
        // Strict validation: ensure it's not just SYN flood with responses
        double syn_ratio = static_cast<double>(b.hot_.syn_count.load()) / b.hot_.total_packets.load();
        double ack_ratio = static_cast<double>(b.hot_.ack_count.load()) / b.hot_.total_packets.load();
        double http_ratio = static_cast<double>(b.hot_.http_requests.load()) / b.hot_.total_packets.load();
        
        // If SYN dominates heavily (>80%), it's definitely a SYN flood, not mixing
        if (syn_ratio > 0.8) {
            return false; // This is a SYN flood, not protocol mixing
        }
        
        // Even stricter: require balanced attack types for true protocol mixing
        // No single protocol should dominate more than 50%
        double max_ratio = std::max({syn_ratio, ack_ratio, http_ratio});
        
        // Require true diversity - at least 2 protocols with significant representation
        int significant_protocols = 0;
        if (syn_ratio > 0.2) significant_protocols++;
        if (ack_ratio > 0.2) significant_protocols++;  
        if (http_ratio > 0.2) significant_protocols++;
        
        return (max_ratio < 0.5 && significant_protocols >= 2);
    }
    
    return false;
}

bool BehaviorTracker::detectGeoDistributedAttack() const {
    // Geographically distributed: Different IP ranges/countries attacking simultaneously
    std::unordered_set<std::string> subnet_c_classes;
    std::unordered_set<std::string> subnet_b_classes;
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        if (b.hot_.total_packets.load() > 50) { // Only count active attackers
            // Extract /24 subnet (C-class)
            size_t last_dot = ip.find_last_of('.');
            if (last_dot != std::string::npos) {
                subnet_c_classes.insert(ip.substr(0, last_dot));
                
                // Extract /16 subnet (B-class) 
                size_t second_last_dot = ip.find_last_of('.', last_dot - 1);
                if (second_last_dot != std::string::npos) {
                    subnet_b_classes.insert(ip.substr(0, second_last_dot));
                }
            }
        }
    });
    
    // Flag as geo-distributed if many diverse subnets are attacking
    return (subnet_c_classes.size() > 30 && subnet_b_classes.size() > 10);
}

bool BehaviorTracker::detectLowAndSlowAttack(const Behavior& b) const {
    // Low-and-slow attacks: Extended duration with minimal rates to stay under radar
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - b.first_seen);
    
    // Long duration (>15 minutes) with low rate but sustained activity
    if (duration.count() > 15) {
        double packets_per_minute = static_cast<double>(b.hot_.total_packets.load()) / duration.count();
        
        // Low rate (1-10 packets/minute) but sustained over long period
        if (packets_per_minute >= 1.0 && packets_per_minute <= 10.0) {
            // Additional checks for low-and-slow characteristics
            
            // 1. Consistent low-rate pattern
            if (!b.packet_intervals.empty()) {
                double avg_interval = 0.0;
                for (double interval : b.packet_intervals) {
                    avg_interval += interval;
                }
                avg_interval /= b.packet_intervals.size();
                
                // Intervals between 6-60 seconds indicate low-and-slow
                if (avg_interval >= 6.0 && avg_interval <= 60.0) {
                    return true;
                }
            }
            
            // 2. HTTP-specific low-and-slow (like Slowloris variations)
            if (b.hot_.http_requests.load() > 0 && b.incomplete_requests.size() > 5) {
                return true;
            }
        }
    }
    
    return false;
}

bool BehaviorTracker::detectRandomizedPayloads(const Behavior& b) const {
    // Randomized payloads: To defeat entropy analysis and signature detection
    if (b.packet_sizes.size() < 15) return false; // Need sufficient samples
    
    // Calculate statistical variance in packet sizes
    double mean_size = 0.0;
    for (size_t size : b.packet_sizes) {
        mean_size += size;
    }
    mean_size /= b.packet_sizes.size();
    
    double variance = 0.0;
    for (size_t size : b.packet_sizes) {
        double diff = static_cast<double>(size) - mean_size;
        variance += diff * diff;
    }
    variance /= b.packet_sizes.size();
    double std_deviation = std::sqrt(variance);
    
    // High standard deviation indicates randomized payload sizes
    if (std_deviation > 300.0) {
        // Additional entropy check: ensure sizes are truly random, not just bimodal
        std::unordered_set<size_t> unique_sizes(b.packet_sizes.begin(), b.packet_sizes.end());
        double size_diversity = static_cast<double>(unique_sizes.size()) / b.packet_sizes.size();
        
        // High diversity (>70% unique sizes) suggests randomization
        return size_diversity > 0.7;
    }
    
    return false;
}

bool BehaviorTracker::detectLegitimateTrafficMixing(const Behavior& b) const {
    // Legitimate traffic mixing: Attacks hidden in normal traffic patterns
    if (b.hot_.total_packets.load() < 200) return false; // Need significant traffic
    
    // Calculate legitimacy indicators
    double session_diversity = static_cast<double>(b.unique_session_count) / b.hot_.total_packets.load();
    double established_ratio = static_cast<double>(b.established_connections.size()) / 
                              std::max(1, static_cast<int>(b.seen_sessions.size()));
    
    // Mixed traffic characteristics:
    // 1. High session diversity (many different sessions)
    // 2.  Some established connections (legitimate handshakes)
    // 3. But overall volume is still suspicious
    if (session_diversity > 0.4 && established_ratio > 0.1) {
        // Check if traffic volume is still attack-level despite legitimacy mixing
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - b.first_seen);
        
        if (duration.count() > 0) {
            double pps = static_cast<double>(b.hot_.total_packets.load()) / duration.count();
            
            // Moderate rate (50-500 pps) with high legitimacy mixing is suspicious
            if (pps > 50 && pps < 500) {
                return true;
            }
        }
    }
    
    return false;
}

bool BehaviorTracker::detectDynamicSourceRotation() const {
    // Dynamic source rotation: Faster IP switching to evade IP-based blocking
    auto now = std::chrono::steady_clock::now();
    std::unordered_set<std::string> recent_active_ips;
    std::unordered_set<std::string> short_lived_ips;
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        auto ip_duration = std::chrono::duration_cast<std::chrono::minutes>(now - b.first_seen);
        
        // Count IPs active in last 10 minutes
        if (ip_duration.count() <= 10 && b.hot_.total_packets.load() > 10) {
            recent_active_ips.insert(ip);
            
            // Count IPs that were active for very short periods (rotation pattern)
            if (ip_duration.count() <= 2 && b.hot_.total_packets.load() > 50) {
                short_lived_ips.insert(ip);
            }
        }
    });
    
    // Flag as dynamic rotation if:
    // 1. Many IPs active recently (>25)
    // 2. High proportion of short-lived but active IPs (>40%)
    if (recent_active_ips.size() > 25) {
        double rotation_ratio = static_cast<double>(short_lived_ips.size()) / recent_active_ips.size();
        return rotation_ratio > 0.4;
    }
    
    return false;
}

std::string BehaviorTracker::generateConnectionId(const PacketData& pkt, Behavior& b) {
    // Improved connection ID generation to reduce collisions
    // Use available fields plus global unique counter to prevent collisions across behavior evictions
    static std::atomic<uint64_t> global_conn_counter{0};
    
    auto* mutable_b = const_cast<Behavior*>(&b);
    uint64_t local_id = mutable_b->connection_id_counter.fetch_add(1);
    uint64_t global_id = global_conn_counter.fetch_add(1);
    
    // Include timestamp in microseconds to further reduce collision probability
    auto now = std::chrono::steady_clock::now();
    auto timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    
    return pkt.src_ip + "->" + pkt.dst_ip + ":" + pkt.session_id + 
           "#" + std::to_string(local_id) + "_" + std::to_string(global_id) + "_" + std::to_string(timestamp_us);
}

size_t BehaviorTracker::get_connection_count() const {
    updateConnectionCount();
    return active_connections.load();
}

void BehaviorTracker::updateConnectionCount() const {
    size_t total_connections = 0;
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        total_connections += b.established_connections.size();
    });
    active_connections.store(total_connections);
}

size_t BehaviorTracker::get_tracked_ips_count() const {
    return behaviors.size();
}

// NEW: Behavioral metrics for adaptive thresholds
double BehaviorTracker::getGlobalSynRate() const {
    double total_syn_rate = 0.0;
    size_t active_ips = 0;
    
    auto now = std::chrono::steady_clock::now();
    auto start_time = std::chrono::steady_clock::time_point(now - std::chrono::minutes(5)); // 5-minute window
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        if (b.last_seen > start_time) {
            total_syn_rate += static_cast<double>(b.hot_.syn_count_recent.load());
            active_ips++;
        }
    });
    
    return active_ips > 0 ? (total_syn_rate / 300.0) : 0.0; // Rate per second over 5 minutes
}

double BehaviorTracker::getGlobalAckRate() const {
    double total_ack_rate = 0.0;
    size_t active_ips = 0;
    
    auto now = std::chrono::steady_clock::now();
    auto start_time = std::chrono::steady_clock::time_point(now - std::chrono::minutes(5)); // 5-minute window
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        if (b.last_seen > start_time) {
            total_ack_rate += static_cast<double>(b.hot_.ack_count_recent.load());
            active_ips++;
        }
    });
    
    return active_ips > 0 ? (total_ack_rate / 300.0) : 0.0; // Rate per second over 5 minutes
}

double BehaviorTracker::getGlobalHttpRate() const {
    double total_http_rate = 0.0;
    size_t active_ips = 0;
    
    auto now = std::chrono::steady_clock::now();
    auto start_time = std::chrono::steady_clock::time_point(now - std::chrono::minutes(5)); // 5-minute window
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        if (b.last_seen > start_time) {
            total_http_rate += static_cast<double>(b.hot_.http_count_recent.load());
            active_ips++;
        }
    });
    
    return active_ips > 0 ? (total_http_rate / 300.0) : 0.0; // Rate per second over 5 minutes
}

double BehaviorTracker::getAverageBaselineSynRate() const {
    double total_baseline = 0.0;
    size_t count = 0;
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        double baseline = b.baseline_rate.load();
        if (baseline > 0.0) {
            // Estimate SYN baseline as a fraction of total baseline rate
            total_baseline += baseline * 0.1; // Assume ~10% of traffic is SYN packets
            count++;
        }
    });
    
    return count > 0 ? (total_baseline / count) : 1.0; // Default 1 SYN/sec
}

double BehaviorTracker::getAverageBaselineAckRate() const {
    double total_baseline = 0.0;
    size_t count = 0;
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        double baseline = b.baseline_rate.load();
        if (baseline > 0.0) {
            // Estimate ACK baseline as a fraction of total baseline rate
            total_baseline += baseline * 0.15; // Assume ~15% of traffic is ACK packets
            count++;
        }
    });
    
    return count > 0 ? (total_baseline / count) : 1.0; // Default 1 ACK/sec
}

double BehaviorTracker::getAverageBaselineHttpRate() const {
    double total_baseline = 0.0;
    size_t count = 0;
    
    behaviors.for_each([&](const std::string& ip, const Behavior& b) {
        double baseline = b.baseline_rate.load();
        if (baseline > 0.0) {
            // Estimate HTTP baseline as a fraction of total baseline rate
            total_baseline += baseline * 0.05; // Assume ~5% of traffic is HTTP
            count++;
        }
    });
    
    return count > 0 ? (total_baseline / count) : 0.1; // Default 0.1 HTTP req/sec
}

// Pattern detection methods
std::vector<std::string> BehaviorTracker::getLastDetectedPatterns() const {
    std::lock_guard<std::mutex> lock(patterns_mutex);
    return last_detected_patterns;
}

void BehaviorTracker::clearLastDetectedPatterns() {
    std::lock_guard<std::mutex> lock(patterns_mutex);
    last_detected_patterns.clear();
    patterns_timestamp = std::chrono::steady_clock::now();
}

// Adaptive threshold calculation methods
double BehaviorTracker::calculateAdaptiveSynFloodThreshold(const Behavior& b) const {
    // Get baseline rate (use cached value if available)
    double baseline = b.baseline_rate.load();
    if (baseline <= 0.0) {
        baseline = 1.0; // Default baseline
    }
    
    // Start with a base multiplier applied to baseline
    double threshold = baseline * g_threshold_tuning.syn_flood_baseline_multiplier;
    
    return std::max(threshold, g_threshold_tuning.min_syn_flood_threshold);
}

double BehaviorTracker::calculateAdaptiveAckFloodThreshold(const Behavior& b) const {
    // Get baseline rate (use cached value if available)
    double baseline = b.baseline_rate.load();
    if (baseline <= 0.0) {
        baseline = 1.0; // Default baseline
    }
    
    // Start with a base multiplier applied to baseline
    double threshold = baseline * g_threshold_tuning.ack_flood_baseline_multiplier;
    
    return std::max(threshold, g_threshold_tuning.min_ack_flood_threshold);
}

double BehaviorTracker::calculateAdaptiveHttpFloodThreshold(const Behavior& b) const {
    // Get baseline rate (use cached value if available)
    double baseline = b.baseline_rate.load();
    if (baseline <= 0.0) {
        baseline = 0.1; // Default baseline for HTTP
    }
    
    // Start with a base multiplier applied to baseline
    double threshold = baseline * g_threshold_tuning.http_flood_baseline_multiplier;
    
    return std::max(threshold, g_threshold_tuning.min_http_flood_threshold);
}

double BehaviorTracker::calculateTimeOfDayFactor() const {
    if (!g_threshold_tuning.enable_time_of_day_adaptation) {
        return 1.0;
    }
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto* tm = std::localtime(&time_t);
    
    int hour = tm->tm_hour;
    
    // Business hours (9 AM - 5 PM): Lower thresholds (more sensitive)
    // Night hours: Higher thresholds (less sensitive)
    if (hour >= 9 && hour <= 17) {
        return 0.8; // More sensitive during business hours
    } else if (hour >= 22 || hour <= 6) {
        return 1.5; // Less sensitive during night hours
    } else {
        return 1.0; // Normal sensitivity
    }
}

double BehaviorTracker::calculateNetworkLoadFactor() const {
    if (!g_threshold_tuning.enable_network_load_adaptation) {
        return 1.0;
    }
    
    // Calculate network load based on total active connections
    size_t total_connections = active_connections.load();
    size_t active_ips = behaviors.size();
    
    if (active_ips == 0) {
        return 1.0;
    }
    
    double avg_connections_per_ip = static_cast<double>(total_connections) / active_ips;
    
    // High network load: Lower thresholds (more sensitive to anomalies)
    // Low network load: Higher thresholds (less sensitive)
    if (avg_connections_per_ip > 50) {
        return 0.7; // High load - more sensitive
    } else if (avg_connections_per_ip > 20) {
        return 0.9; // Medium load
    } else {
        return 1.2; // Low load - less sensitive
    }
}

double BehaviorTracker::calculateLegitimacyMultiplier(const Behavior& b) const {
    double legitimacy_score = b.hot_.legitimate_traffic_score.load();
    
    // High legitimacy score: Increase thresholds (less sensitive)
    // Low legitimacy score: Decrease thresholds (more sensitive)
    if (legitimacy_score > g_threshold_tuning.legitimacy_factor_threshold) {
        return 1.5; // Less sensitive for legitimate traffic
    } else if (legitimacy_score < 0.5) {
        return 0.6; // More sensitive for suspicious traffic
    } else {
        return 1.0; // Normal sensitivity
    }
}

bool BehaviorTracker::isBusinessHours() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto* tm = std::localtime(&time_t);
    
    int hour = tm->tm_hour;
    int weekday = tm->tm_wday; // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    
    // Business hours: Monday-Friday, 9 AM - 5 PM
    return (weekday >= 1 && weekday <= 5) && (hour >= 9 && hour <= 17);
}

// Additional missing methods
void BehaviorTracker::updateBaselineRateOptimized(Behavior& b, const std::chrono::steady_clock::time_point& now) {
    // Convert to nanoseconds for atomic operations
    uint64_t now_ns = detail::time_point_to_ns(now);
    uint64_t last_update_ns = b.last_baseline_update_ns.load();
    
    // Update baseline every 60 seconds
    if (now_ns - last_update_ns > 60'000'000'000ULL) {
        std::lock_guard<std::mutex> lock(b.baseline_mutex);
        
        // Calculate current rate based on recent activity
        double time_window_seconds = 60.0; // 1 minute window
        double current_rate = static_cast<double>(b.hot_.total_events_recent.load()) / time_window_seconds;
        
        // Update baseline using EWMA
        double old_baseline = b.baseline_rate.load();
        double new_baseline = 0.1 * current_rate + 0.9 * old_baseline; // 10% adaptation rate
        
        b.baseline_rate.store(new_baseline);
        b.cached_baseline_rate.store(new_baseline);
        b.last_baseline_update_ns.store(now_ns);
    }
}

void BehaviorTracker::updateRollingCounters(Behavior& b, const std::string& event_type, 
                                          const std::chrono::steady_clock::time_point& now) {
    // Increment the appropriate recent counter
    if (event_type == "SYN") {
        b.hot_.syn_count_recent.fetch_add(1);
    } else if (event_type == "ACK") {
        b.hot_.ack_count_recent.fetch_add(1);
    } else if (event_type == "HTTP") {
        b.hot_.http_count_recent.fetch_add(1);
    }
    
    b.hot_.total_events_recent.fetch_add(1);
    b.hot_.last_update_ns.store(detail::time_point_to_ns(now));
}

void BehaviorTracker::enforceBehaviorBounds(Behavior& b) {
    // Enforce maximum limits to prevent memory exhaustion
    constexpr size_t MAX_HTTP_SESSIONS = 1000;
    constexpr size_t MAX_INCOMPLETE_REQUESTS = 500;
    constexpr size_t MAX_ESTABLISHED_CONNECTIONS = 2000;
    
    // Clean up HTTP sessions if too many
    if (b.http_sessions.size() > MAX_HTTP_SESSIONS) {
        // Remove oldest sessions
        auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(10);
        for (auto it = b.http_sessions.begin(); it != b.http_sessions.end();) {
            if (it->second < cutoff) {
                it = b.http_sessions.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Limit incomplete requests
    if (b.incomplete_requests.size() > MAX_INCOMPLETE_REQUESTS) {
        b.incomplete_requests.clear(); // Simple cleanup
    }
    
    // Limit established connections
    if (b.established_connections.size() > MAX_ESTABLISHED_CONNECTIONS) {
        b.established_connections.clear(); // Simple cleanup
    }
}

double BehaviorTracker::calculateLegitimacyFactor(const Behavior& b) const {
    double score = 0.0;
    
    // Factor in connection diversity
    size_t unique_sessions = b.seen_sessions.size();
    size_t total_packets = b.hot_.total_packets.load();
    
    if (total_packets > 0) {
        double session_diversity = static_cast<double>(unique_sessions) / total_packets;
        score += session_diversity * 0.3; // Weight session diversity
    }
    
    // Factor in packet size consistency
    if (b.packet_intervals.size() > 10) {
        double variance = calculatePacketIntervalVariance(b.packet_intervals);
        if (variance < 0.5) { // Low variance indicates legitimate traffic
            score += 0.3;
        }
    }
    
    // Factor in established vs half-open connections
    int half_open = b.hot_.half_open.load();
    size_t established = b.established_connections.size();
    
    if (established > 0) {
        double connection_ratio = static_cast<double>(established) / (established + half_open);
        score += connection_ratio * 0.4; // Weight connection completion
    }
    
    return std::min(score, 1.0); // Cap at 1.0
}

int BehaviorTracker::calculateAdaptiveThreshold(const Behavior& b, double legitimacy_factor) const {
    // Base threshold
    int base_threshold = 100;
    
    // Adjust based on legitimacy
    double multiplier = 1.0;
    if (legitimacy_factor > 0.7) {
        multiplier = 1.5; // Higher threshold for legitimate traffic
    } else if (legitimacy_factor < 0.3) {
        multiplier = 0.6; // Lower threshold for suspicious traffic
    }
    
    // Apply time-of-day factor
    double time_factor = calculateTimeOfDayFactor();
    multiplier *= time_factor;
    
    return static_cast<int>(base_threshold * multiplier);
}

bool BehaviorTracker::shouldRunDistributedCheck() const {
    auto now = std::chrono::steady_clock::now();
    uint64_t now_ns = detail::time_point_to_ns(now);
    uint64_t last_check_ns = last_distributed_check_ns.load();
    
    // Run distributed check every 30 seconds
    return (now_ns - last_check_ns) > 30'000'000'000ULL;
}

bool BehaviorTracker::isLegitimateTrafficPattern(const Behavior& b) const {
    // Check for patterns that indicate legitimate traffic
    double legitimacy_score = b.hot_.legitimate_traffic_score.load();
    
    // High legitimacy score
    if (legitimacy_score > 2.0) {
        return true;
    }
    
    // Check for normal connection patterns
    size_t established = b.established_connections.size();
    int half_open = b.hot_.half_open.load();
    
    if (established > 0 && half_open < static_cast<int>(established) / 2) {
        return true; // More established than half-open connections
    }
    
    // Check for reasonable session diversity
    size_t sessions = b.seen_sessions.size();
    uint64_t total_packets = b.hot_.total_packets.load();
    
    return (total_packets > 100 && sessions > total_packets / 10);
}

bool BehaviorTracker::detectFlashCrowdPattern(const Behavior& b) const {
    // Flash crowds have high volume but legitimate patterns
    uint64_t total_packets = b.hot_.total_packets.load();
    
    if (total_packets < 1000) {
        return false; // Not high volume enough
    }
    
    // Check for legitimate characteristics
    double legitimacy_score = b.hot_.legitimate_traffic_score.load();
    size_t unique_sessions = b.seen_sessions.size();
    
    // Flash crowd: high volume + high legitimacy + session diversity
    return (legitimacy_score > 1.5 && unique_sessions > total_packets / 20);
}

double BehaviorTracker::calculatePacketIntervalVariance(const RingBuffer<double, BehaviorConfig::PACKET_HISTORY_SIZE>& intervals) const {
    if (intervals.size() < 2) {
        return 0.0;
    }
    
    // Calculate mean
    double sum = 0.0;
    size_t count = 0;
    for (size_t i = 0; i < intervals.size(); ++i) {
        sum += intervals[i];
        count++;
    }
    double mean = sum / count;
    
    // Calculate variance
    double variance_sum = 0.0;
    for (size_t i = 0; i < intervals.size(); ++i) {
        double diff = intervals[i] - mean;
        variance_sum += diff * diff;
    }
    
    return variance_sum / count;
}

double BehaviorTracker::calculateSizeVariance(const RingBuffer<size_t, BehaviorConfig::PACKET_HISTORY_SIZE>& sizes) const {
    if (sizes.size() < 2) {
        return 0.0;
    }
    
    // Calculate mean
    double sum = 0.0;
    size_t count = 0;
    for (size_t i = 0; i < sizes.size(); ++i) {
        sum += static_cast<double>(sizes[i]);
        count++;
    }
    double mean = sum / count;
    
    // Calculate variance
    double variance_sum = 0.0;
    for (size_t i = 0; i < sizes.size(); ++i) {
        double diff = static_cast<double>(sizes[i]) - mean;
        variance_sum += diff * diff;
    }
    
    return variance_sum / count;
}
