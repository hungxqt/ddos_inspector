#ifndef STATS_ENGINE_H
#define STATS_ENGINE_H

#include <string>
#include <unordered_map>
#include <chrono>
#include <vector>
#include "packet_data.hpp"

class StatsEngine {
public:
    StatsEngine(double entropy_threshold = 2.0, double ewma_alpha = 0.1);
    
    bool analyze(const PacketData& pkt);
    double get_current_rate() const;
    double get_entropy() const;
    double get_baseline_rate() const { return baseline_rate; }
    
private:
    struct IPStats {
        double ewma = 0.0;
        int packet_count = 0;
        std::chrono::steady_clock::time_point last_seen;
        std::vector<double> rate_history;  // For statistical analysis
        double mean_rate = 0.0;
        double stddev_rate = 0.0;
    };
    
    struct ProtocolStats {
        double expected_entropy = 0.0;
        int packet_count = 0;
        std::chrono::steady_clock::time_point last_update;
    };
    
    std::unordered_map<std::string, IPStats> stats;
    std::unordered_map<std::string, ProtocolStats> protocol_baselines;
    
    double entropy_threshold;
    double ewma_alpha;
    double current_rate = 0.0;
    double current_entropy = 0.0;
    double baseline_rate = 0.0;
    
    int packets_received = 0;
    size_t total_bytes = 0;
    std::chrono::steady_clock::time_point last_packet_time;
    std::chrono::steady_clock::time_point start_time;
    
    // Real-world enhancement data
    double false_positive_rate = 0.0;
    double detection_accuracy = 0.95;
    std::unordered_map<std::string, double> legitimate_traffic_patterns;
    
    // Enhanced detection methods
    double compute_entropy(const std::string& payload);
    void update_ewma(const std::string& src_ip, double packet_rate);
    double get_adaptive_entropy_threshold(const PacketData& pkt);
    bool is_repetitive_payload(const std::string& payload);
    
    // New real-world detection methods
    bool is_legitimate_traffic_pattern(const PacketData& pkt);
    double get_expected_entropy_for_protocol(const PacketData& pkt);
    double calculate_rate_deviation(const std::string& src_ip, double current_rate);
    double analyze_payload_patterns(const PacketData& pkt);
    double analyze_http_anomalies(const PacketData& pkt);
    double analyze_temporal_patterns(const std::string& src_ip);
    double calculate_dynamic_threshold();
    
    // Statistical analysis helpers
    void update_ip_statistics(const std::string& src_ip, double rate);
    double calculate_zscore(double value, double mean, double stddev);
};

#endif // STATS_ENGINE_H