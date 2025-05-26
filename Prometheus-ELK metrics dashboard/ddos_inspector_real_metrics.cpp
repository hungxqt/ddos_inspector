// ddos_inspector_real_metrics.cpp
// Real entropy + packet rate Prometheus exporter (simulated IPs)

#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/gauge.h>

#include <thread>
#include <chrono>
#include <map>
#include <random>
#include <string>
#include <cmath>
#include <mutex>

using namespace prometheus;

std::mutex data_mutex;
std::map<std::string, int> ip_freq;
int packet_counter = 0;

// Simulate IPs for testing
std::string random_ip(std::default_random_engine& gen) {
    std::uniform_int_distribution<int> dist(1, 254);
    return std::to_string(dist(gen)) + "." + std::to_string(dist(gen)) + "." +
           std::to_string(dist(gen)) + "." + std::to_string(dist(gen));
}

// Entropy Calculation
double calculate_entropy(const std::map<std::string, int>& counts) {
    int total = 0;
    for (auto& pair : counts) total += pair.second;

    double entropy = 0.0;
    for (auto& pair : counts) {
        double p = (double)pair.second / total;
        if (p > 0) entropy -= p * std::log2(p);
    }
    return entropy;
}

int main() {
    Exposer exposer{"0.0.0.0:9091"};
    auto registry = std::make_shared<Registry>();
    exposer.RegisterCollectable(registry);

    auto& entropy_family = BuildGauge()
        .Name("ddos_entropy_score")
        .Help("Entropy score of destination IPs")
        .Register(*registry);
    auto& entropy_gauge = entropy_family.Add({});

    auto& packet_family = BuildGauge()
        .Name("ddos_packet_rate")
        .Help("Incoming packet rate per second")
        .Register(*registry);
    auto& packet_gauge = packet_family.Add({});

    std::default_random_engine generator;
    std::uniform_int_distribution<int> pps_dist(100, 500); // packets per second

    // Simulate packet processing thread
    std::thread packet_thread([&]() {
        while (true) {
            int n = pps_dist(generator);
            {
                std::lock_guard<std::mutex> lock(data_mutex);
                for (int i = 0; i < n; ++i) {
                    std::string ip = random_ip(generator);
                    ip_freq[ip]++;
                    packet_counter++;
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    // Metrics exporter loop (every 5s)
    while (true) {
        double entropy = 0.0;
        double rate = 0.0;

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            entropy = calculate_entropy(ip_freq);
            rate = packet_counter / 5.0;
            ip_freq.clear();
            packet_counter = 0;
        }

        entropy_gauge.Set(entropy);
        packet_gauge.Set(rate);

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    packet_thread.join();
    return 0;
}
