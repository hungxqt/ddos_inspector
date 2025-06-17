#ifndef STATS_ENGINE_H
#define STATS_ENGINE_H

#include <string>
#include <unordered_map>
#include <chrono>
#include <deque>
#include <shared_mutex>
#include "packet_data.hpp"

class StatsEngine {
public:
    StatsEngine(double entropy_threshold = 2.0, double ewma_alpha = 0.1, bool enable_local_time_bias = true);
    
    [[nodiscard]] bool analyze(const PacketData& pkt);  // FIXED: Add nodiscard to prevent ignoring analysis result
    double get_current_rate() const;
    double get_entropy() const;
    double get_baseline_rate() const { return baseline_rate; }
    
    // Testing hooks
    double calculate_dynamic_threshold();  // Exposed for unit testing
    
    // Maintenance methods
    void cleanup_expired_stats();
    void update_feedback(double fp_rate, double accuracy);
    
private:
    struct IPStats {
        double ewma = 0.0;
        int packet_count = 0;
        std::chrono::steady_clock::time_point last_seen;
        std::chrono::steady_clock::time_point first_seen;  // FIXED: Track first seen time
        std::deque<double> rate_history;  // FIXED: Use deque for O(1) operations
        double mean_rate = 0.0;
        double stddev_rate = 0.0;
    };
    
    struct ProtocolStats {
        double expected_entropy = 0.0;
        int packet_count = 0;
        std::chrono::steady_clock::time_point last_update;
    };
    
    // Thread safety for multi-threaded Snort
    mutable std::shared_mutex stats_mutex;
    std::unordered_map<std::string, IPStats> stats;
    std::unordered_map<std::string, ProtocolStats> protocol_baselines;
    
    double entropy_threshold;
    double ewma_alpha;
    double original_alpha;  // Store original alpha for decay back
    double current_rate = 0.0;
    double current_entropy = 0.0;
    double baseline_rate = 0.0;
    
    // FIXED: Use rolling window for proper 95th percentile baseline
    std::deque<double> rate_window;
    static constexpr size_t BASELINE_WINDOW_SIZE = 300;  // 5 minutes at 1 packet/second
    
    int packets_received = 0;
    size_t total_bytes = 0;
    std::chrono::steady_clock::time_point last_packet_time;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_cleanup;
      // Dynamic threshold system (now functional)
    double false_positive_rate = 0.0;
    double detection_accuracy = 0.95;
    bool enable_local_time_bias = true;  // Configurable time-of-day adjustments
    
    // Enhanced detection methods
    double compute_entropy(const std::string& payload);
    double compute_entropy_optimized(const std::string& payload);  // NEW: Optimized version
    void update_ewma(const std::string& src_ip, double packet_rate);
    double get_adaptive_entropy_threshold(const PacketData& pkt);
    bool is_repetitive_payload(const std::string& payload);
    
    // Real-world detection methods
    bool is_legitimate_traffic_pattern(const PacketData& pkt);
    double get_expected_entropy_for_protocol(const PacketData& pkt, double cached_entropy);  // FIXED: Use cached entropy
    double calculate_rate_deviation(const std::string& src_ip, double current_rate);    double analyze_payload_patterns(const PacketData& pkt);
    double analyze_http_anomalies(const PacketData& pkt);
    double analyze_temporal_patterns(const std::string& src_ip);
    
    // FIXED: Proper baseline calculation
    double calculate_95th_percentile_baseline();
    void update_baseline_window(double rate);    
    // Statistical analysis helpers
    void update_ip_statistics(const std::string& src_ip, double rate);
    double calculate_zscore(double value, double mean, double stddev);
};

#endif // STATS_ENGINE_H