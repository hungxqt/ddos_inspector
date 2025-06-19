#ifndef DDOS_INSPECTOR_HPP
#define DDOS_INSPECTOR_HPP

#include <framework/module.h>
#include <framework/inspector.h>
#include <framework/parameter.h>
#include <framework/value.h>
#include <log/messages.h>
#include <protocols/packet.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>
#include <main/snort_config.h>
#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <chrono>
#include <cstdint>
#include <thread>
#include <mutex>
#include <unordered_map>
#include "packet_data.hpp"

// Forward declarations
class StatsEngine;
class BehaviorTracker;
class FirewallAction;

// Centralized threshold tuning configuration
struct ThresholdTuning {
    double adaptation_factor = 0.1;           // EWMA adaptation rate
    double entropy_multiplier = 0.3;          // Entropy threshold multiplier
    double rate_multiplier = 3.0;             // Rate threshold multiplier
    double min_entropy_threshold = 0.5;       // Minimum entropy threshold
    double min_rate_threshold = 1000.0;       // Minimum rate threshold
    double confidence_base_stats = 0.4;       // Base confidence from stats anomaly
    double confidence_base_behavior = 0.4;    // Base confidence from behavior anomaly
    double confidence_syn_bonus = 0.1;        // SYN flood detection bonus
    double confidence_http_short_bonus = 0.15; // Short HTTP request bonus
    double confidence_rate_high_bonus = 0.2;  // High rate ratio bonus
    double confidence_rate_med_bonus = 0.1;   // Medium rate ratio bonus
    double confidence_entropy_high_bonus = 0.2; // High entropy ratio bonus
    double confidence_entropy_med_bonus = 0.1;  // Medium entropy ratio bonus
    double rate_ratio_high_threshold = 10.0;  // High rate ratio threshold
    double rate_ratio_med_threshold = 5.0;    // Medium rate ratio threshold
    double entropy_ratio_high_threshold = 5.0; // High entropy ratio threshold
    double entropy_ratio_med_threshold = 3.0;  // Medium entropy ratio threshold
    
    // NEW: Adaptive behavioral thresholds
    bool enable_adaptive_behavioral_thresholds = true; // Enable adaptive behavioral thresholds
    double syn_flood_multiplier = 5.0;        // Multiplier for SYN flood threshold
    double ack_flood_multiplier = 3.0;        // Multiplier for ACK flood threshold  
    double http_flood_multiplier = 10.0;      // Multiplier for HTTP flood threshold
    double syn_flood_baseline_multiplier = 5.0;    // Multiplier for SYN flood baseline
    double ack_flood_baseline_multiplier = 3.0;    // Multiplier for ACK flood baseline  
    double http_flood_baseline_multiplier = 10.0;  // Multiplier for HTTP flood baseline
    double legitimacy_factor_threshold = 2.0;      // Legitimacy score threshold for adjustment
    double time_of_day_multiplier = 1.0;           // Time-based threshold adjustment
    double network_load_multiplier = 1.0;          // Network load-based adjustment
    double min_syn_flood_threshold = 100.0;        // Minimum SYN flood threshold
    double min_ack_flood_threshold = 50.0;         // Minimum ACK flood threshold
    double min_http_flood_threshold = 200.0;       // Minimum HTTP flood threshold
    double adaptive_window_minutes = 10.0;         // Window for adaptive updates
    bool enable_time_of_day_adaptation = true;     // Enable time-based adaptation
    bool enable_network_load_adaptation = true;    // Enable load-based adaptation
    
    void logConfiguration() const;
};

// Global tuning parameters instance
extern ThresholdTuning g_threshold_tuning;

// Hash specialization for IPv6 address arrays
namespace std {
    template<>
    struct hash<std::array<uint8_t, 16>> {
        size_t operator()(const std::array<uint8_t, 16>& arr) const {
            size_t h = 0;
            for (size_t i = 0; i < 16; ++i) {
                h ^= std::hash<uint8_t>{}(arr[i]) + 0x9e3779b9 + (h << 6) + (h >> 2);
            }
            return h;
        }
    };
}

// Attack classification structures enhanced for Snort 3.8.1.0
struct AttackInfo {
    enum class Type : std::uint8_t { 
        SYN_FLOOD, 
        HTTP_FLOOD, 
        SLOWLORIS, 
        ACK_FLOOD, 
        UDP_FLOOD, 
        ICMP_FLOOD, 
        VOLUME_ATTACK, 
        DNS_AMPLIFICATION,
        NTP_AMPLIFICATION,
        REFLECTION_ATTACK,
        PULSE_ATTACK,
        PROTOCOL_MIXING,
        GEO_DISTRIBUTED,
        LOW_AND_SLOW,
        RANDOMIZED_PAYLOADS,
        LEGITIMATE_MIXING,
        DYNAMIC_ROTATION,
        UNKNOWN 
    };
    
    enum class Severity : std::uint8_t { 
        SEVERITY_LOW = 1, 
        SEVERITY_MEDIUM = 2, 
        SEVERITY_HIGH = 3, 
        SEVERITY_CRITICAL = 4 
    };
    
    Type type;
    Severity severity;
    double confidence;
    std::string description;
    std::chrono::steady_clock::time_point detection_time;
    uint32_t source_ip;
    uint16_t source_port;
};

class DdosInspectorModule : public snort::Module
{
public:
    DdosInspectorModule();
    ~DdosInspectorModule() override = default;
    
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    
    const snort::Parameter* get_parameters() const;
    
    Usage get_usage() const override
    { return INSPECT; }

    // Configuration profile management
    void applyConfigurationProfile();
    
    // Path validation for security
    bool validateMetricsPath(const std::string& path) const;

    // Enhanced configuration parameters for Snort 3.8.1.0
    bool allow_icmp = false;
    bool enable_amplification_detection = true;
    bool enable_adaptive_thresholds = true;
    bool enable_ipv6 = true;
    bool enable_fragmentation_detection = true;
    bool tarpit_enabled = true;
    bool tcp_reset_enabled = true;
    double entropy_threshold = 2.0;
    double ewma_alpha = 0.1;
    uint32_t block_timeout = 600; // seconds
    uint32_t connection_threshold = 1000;
    uint32_t rate_threshold = 50000;    uint32_t max_tracked_ips = 10000;
    bool use_env_files = true;  // NEW: Enable/disable environment variable support
    std::string metrics_file;
    std::string blocked_ips_file;
    std::string rate_limited_ips_file;
    std::string log_level = "info";
    std::string config_profile = "default";
    std::string protected_networks = "";
    double adaptation_factor = 0.1;
    double entropy_multiplier = 0.3;
    double rate_multiplier = 3.0;
    
    // NEW: Adaptive behavioral threshold parameters
    double syn_flood_baseline_multiplier = 5.0;
    double ack_flood_baseline_multiplier = 3.0;
    double http_flood_baseline_multiplier = 10.0;
    bool enable_time_of_day_adaptation = true;
    bool enable_network_load_adaptation = true;
};

class DdosInspector : public snort::Inspector
{
public:
    explicit DdosInspector(DdosInspectorModule*);
    ~DdosInspector() override;

    void eval(snort::Packet*) override;
    void show_stats(std::ostream&) ;
    
    // Enhanced interface for Snort 3.8.1.0
    bool configure(snort::SnortConfig*) override { return true; }

private:
    // Enhanced adaptive threshold management
    struct AdaptiveThresholds {
        double entropy_threshold = 2.0;
        double rate_threshold = 50000.0;
        std::chrono::steady_clock::time_point last_update;
        double baseline_entropy = 2.0;
        double baseline_rate = 1000.0;
        
        // NEW: Adaptive behavioral thresholds
        double syn_flood_threshold = 5000.0;
        double ack_flood_threshold = 1000.0;
        double http_flood_threshold = 10000.0;
        double baseline_syn_rate = 100.0;
        double baseline_ack_rate = 50.0;
        double baseline_http_rate = 200.0;
        double current_network_load = 1.0;
        double time_of_day_factor = 1.0;
        std::chrono::steady_clock::time_point last_behavioral_update;
    } adaptive_thresholds;

    // Configuration
    bool allow_icmp;
    bool enable_amplification_detection;
    bool enable_adaptive_thresholds;
    uint32_t connection_threshold;
    uint32_t rate_threshold;
    std::string metrics_file_path;
    std::string blocked_ips_file_path;
    std::string rate_limited_ips_file_path;
    std::string log_level;
    std::string config_profile;
    
    // Core components
    std::unique_ptr<StatsEngine> stats_engine;
    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<FirewallAction> firewall_action;
    
    // Enhanced statistics tracking
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_blocked{0};
    std::atomic<uint64_t> packets_rate_limited{0};
    std::atomic<uint64_t> syn_flood_detections{0};
    std::atomic<uint64_t> http_flood_detections{0};
    std::atomic<uint64_t> slowloris_detections{0};
    std::atomic<uint64_t> udp_flood_detections{0};
    std::atomic<uint64_t> icmp_flood_detections{0};
    std::atomic<uint64_t> amplification_detections{0};
    std::atomic<uint64_t> false_positives{0};
    
    // Block rate calculation for metrics
    std::atomic<uint64_t> total_blocks_issued{0};
    std::chrono::steady_clock::time_point block_rate_start_time;
    
    // Current blocked IP count tracking
    std::atomic<uint32_t> current_blocked_count{0};
    
    // LRU cache for rate-limited IPs to preserve long-term offenders
    mutable std::mutex rate_limited_cache_mutex;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> rate_limited_cache;
    std::list<std::string> rate_limited_lru_list;
    std::unordered_map<std::string, std::list<std::string>::iterator> rate_limited_lru_map;
    static constexpr size_t MAX_RATE_LIMITED_ENTRIES = 5000;
    
    // Performance metrics
    std::chrono::steady_clock::time_point last_metrics_update;
    std::chrono::steady_clock::time_point last_ip_list_update;
    std::chrono::steady_clock::time_point detection_start_time;
    std::atomic<uint64_t> total_processing_time_us{0};
    std::atomic<uint64_t> max_processing_time_us{0};
    
    // Address string cache for performance
    mutable std::mutex address_cache_mutex;
    std::unordered_map<uint32_t, std::string> ipv4_cache;
    std::unordered_map<std::array<uint8_t, 16>, std::string> ipv6_cache; // Binary to string mapping
    
    // Background metrics thread with proper memory ordering
    std::atomic<bool> metrics_running{false};
    std::thread metrics_thread;
    mutable std::mutex metrics_mutex;
    mutable std::mutex file_operations_mutex; // Protects all file operations
    
    // Metrics file management
    std::unique_ptr<std::ofstream> persistent_metrics_file;
    
    // Enhanced detection methods
    AttackInfo classifyAttack(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly, uint8_t proto);
    bool detectAmplificationAttack(const PacketData& pkt_data, uint8_t proto);
    bool detectFragmentFlood(const std::string& src_ip);
    void incrementAttackCounter(AttackInfo::Type type);
    
    // I/O optimization methods
    void writeMetrics();
    void writeMetricsToFile(const std::string& temp_path); // Write to temp file first
    void writeMetricsBackground(); // Background metrics writing
    void startMetricsThread();
    void stopMetricsThread();
    void updatePerformanceMetrics(std::chrono::microseconds processing_time);
    
    // Address caching for performance
    std::string getIPv4String(uint32_t addr);
    std::string getIPv6String(const snort::ip::snort_in6_addr* addr);
    
    // Protocol parsing helpers for optimized eval function
    std::pair<std::string, std::string> extractAddresses(snort::Packet* p);
    PacketData extractPacketData(snort::Packet* p, const std::string& src_ip, const std::string& dst_ip, uint32_t packet_size = 0, uint8_t protocol = 0);
    bool checkForFragmentation(snort::Packet* p, const std::string& src_ip);
    
    // Dynamic mitigation methods
    int calculateBlockDuration(AttackInfo::Severity severity, AttackInfo::Type type);
    void logAttackDetection(const AttackInfo& attack_info, const PacketData& pkt_data, 
                           bool stats_anomaly, bool behavior_anomaly);
    
    // IP list file management
    void writeBlockedIpsFile(const std::vector<std::string>& blocked_ips);
    void writeRateLimitedIpsFile(const std::vector<std::string>& rate_limited_ips);
    
    // Block rate calculation
    double calculateBlockRate() const;
    void incrementBlockCounter() { total_blocks_issued.fetch_add(1, std::memory_order_relaxed); }
    
    // LRU rate-limited IP management
    void addToRateLimitedCache(const std::string& ip);
    std::vector<std::string> getRateLimitedIpsFromCache();
    void cleanupExpiredRateLimitedIPs();
    
    // False positive tracking
    void incrementFalsePositiveCounter() { false_positives.fetch_add(1, std::memory_order_relaxed); }
    
    // Adaptive threshold management
    void updateAdaptiveThresholds();
    uint8_t calculateConfidenceScore(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly); // Returns confidence in hundredths (0-100)
};

#endif // DDOS_INSPECTOR_HPP