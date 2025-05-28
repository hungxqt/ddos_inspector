#ifndef STATS_ENGINE_H
#define STATS_ENGINE_H

#include <string>
#include <deque>
#include <unordered_map>
#include <chrono>
#include "packet_data.hpp"

class StatsEngine {
public:
    StatsEngine(double entropy_threshold = 2.0, double ewma_alpha = 0.1);
    bool analyze(const PacketData& pkt);
    
    double get_current_rate() const;
    double get_entropy() const;

private:
    struct Stat {
        double ewma = 0;
        std::deque<double> entropy_window;
        double last_entropy = 0;
        int packet_count = 0;
    };
    std::unordered_map<std::string, Stat> stats;
    
    double entropy_threshold;
    double ewma_alpha;
    double current_rate = 0;
    double current_entropy = 0;
    int packet_count = 0;
    int packets_received = 0;
    size_t total_bytes = 0;
    std::chrono::steady_clock::time_point last_packet_time;

    double compute_entropy(const std::string& payload);
    void update_ewma(const std::string& src_ip, double packet_rate);
};

#endif // STATS_ENGINE_H