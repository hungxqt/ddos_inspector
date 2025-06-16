#include <cmath>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <thread>
#include <chrono>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <prometheus/histogram.h>

class DDoSInspectorMetricsExporter {
private:
    std::shared_ptr<prometheus::Registry> registry;
    prometheus::Exposer exposer;
    
    // Metrics
    prometheus::Family<prometheus::Counter>& packets_processed_family;
    prometheus::Family<prometheus::Counter>& packets_blocked_family;
    prometheus::Family<prometheus::Counter>& syn_floods_family;
    prometheus::Family<prometheus::Counter>& slowloris_attacks_family;
    prometheus::Family<prometheus::Counter>& udp_floods_family;
    prometheus::Family<prometheus::Counter>& icmp_floods_family;
    
    prometheus::Family<prometheus::Gauge>& entropy_family;
    prometheus::Family<prometheus::Gauge>& rate_family;
    prometheus::Family<prometheus::Gauge>& connections_family;
    prometheus::Family<prometheus::Gauge>& blocked_ips_family;
    prometheus::Family<prometheus::Gauge>& detection_time_family;
    
    // Metric instances
    prometheus::Counter& packets_processed;
    prometheus::Counter& packets_blocked;
    prometheus::Counter& syn_floods;
    prometheus::Counter& slowloris_attacks;
    prometheus::Counter& udp_floods;
    prometheus::Counter& icmp_floods;
    
    prometheus::Gauge& entropy;
    prometheus::Gauge& rate;
    prometheus::Gauge& connections;
    prometheus::Gauge& blocked_ips;
    prometheus::Gauge& detection_time;
    
    std::string stats_file_path;
    std::map<std::string, double> previous_values;
    
public:
    DDoSInspectorMetricsExporter(const std::string& bind_address = "0.0.0.0:9091", 
                                const std::string& stats_file = "/var/log/ddos_inspector/ddos_inspector_stats")
        : registry{std::make_shared<prometheus::Registry>()}
        , exposer{bind_address}
        , packets_processed_family{prometheus::BuildCounter()
                                 .Name("ddos_inspector_packets_processed_total")
                                 .Help("Total number of packets processed by DDoS Inspector")
                                 .Register(*registry)}
        , packets_blocked_family{prometheus::BuildCounter()
                               .Name("ddos_inspector_packets_blocked_total")
                               .Help("Total number of packets blocked by DDoS Inspector")
                               .Register(*registry)}
        , syn_floods_family{prometheus::BuildCounter()
                          .Name("ddos_inspector_syn_floods_total")
                          .Help("Total number of SYN flood attacks detected")
                          .Register(*registry)}
        , slowloris_attacks_family{prometheus::BuildCounter()
                                 .Name("ddos_inspector_slowloris_attacks_total")
                                 .Help("Total number of Slowloris attacks detected")
                                 .Register(*registry)}
        , udp_floods_family{prometheus::BuildCounter()
                          .Name("ddos_inspector_udp_floods_total")
                          .Help("Total number of UDP flood attacks detected")
                          .Register(*registry)}
        , icmp_floods_family{prometheus::BuildCounter()
                           .Name("ddos_inspector_icmp_floods_total")
                           .Help("Total number of ICMP flood attacks detected")
                           .Register(*registry)}
        , entropy_family{prometheus::BuildGauge()
                       .Name("ddos_inspector_entropy")
                       .Help("Current entropy value from statistical analysis")
                       .Register(*registry)}
        , rate_family{prometheus::BuildGauge()
                    .Name("ddos_inspector_packet_rate")
                    .Help("Current packet rate (packets per second)")
                    .Register(*registry)}
        , connections_family{prometheus::BuildGauge()
                           .Name("ddos_inspector_active_connections")
                           .Help("Number of active connections being tracked")
                           .Register(*registry)}
        , blocked_ips_family{prometheus::BuildGauge()
                           .Name("ddos_inspector_blocked_ips")
                           .Help("Number of currently blocked IP addresses")
                           .Register(*registry)}
        , detection_time_family{prometheus::BuildGauge()
                              .Name("ddos_inspector_detection_time_ms")
                              .Help("Time taken for latest detection in milliseconds")
                              .Register(*registry)}
        , packets_processed{packets_processed_family.Add({})}
        , packets_blocked{packets_blocked_family.Add({})}
        , syn_floods{syn_floods_family.Add({})}
        , slowloris_attacks{slowloris_attacks_family.Add({})}
        , udp_floods{udp_floods_family.Add({})}
        , icmp_floods{icmp_floods_family.Add({})}
        , entropy{entropy_family.Add({})}
        , rate{rate_family.Add({})}
        , connections{connections_family.Add({})}
        , blocked_ips{blocked_ips_family.Add({})}
        , detection_time{detection_time_family.Add({})}
        , stats_file_path{stats_file}
    {
        exposer.RegisterCollectable(registry);
        std::cout << "DDoS Inspector Metrics Exporter started on " << bind_address << "\n";
        std::cout << "Reading stats from: " << stats_file_path << "\n";
    }
    
    std::map<std::string, double> parseStatsFile() {
        std::map<std::string, double> stats;
        std::ifstream file(stats_file_path);
        
        if (!file.is_open()) {
            std::cerr << "Warning: Could not open stats file: " << stats_file_path << '\n';
            return stats;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            size_t delimiter_pos = line.find(':');
            if (delimiter_pos != std::string::npos) {
                std::string key = line.substr(0, delimiter_pos);
                std::string value_str = line.substr(delimiter_pos + 1);
                
                try {
                    double value = std::stod(value_str);
                    stats[key] = value;
                } catch (const std::exception& e) {
                    std::cerr << "Error parsing value for key '" << key << "': " << e.what() << '\n';
                }
            }
        }
        
        file.close();
        return stats;
    }
    
    void updateMetrics() {
        auto stats = parseStatsFile();
        
        if (stats.empty()) {
            // If no stats file, generate some simulated data for testing
            generateSimulatedData(stats);
        }
        
        // Update counters (they should only increase)
        updateCounter("packets_processed", stats, packets_processed);
        updateCounter("packets_blocked", stats, packets_blocked);
        updateCounter("syn_floods", stats, syn_floods);
        updateCounter("slowloris_attacks", stats, slowloris_attacks);
        updateCounter("udp_floods", stats, udp_floods);
        updateCounter("icmp_floods", stats, icmp_floods);
        
        // Update gauges (they can go up or down)
        if (stats.find("entropy") != stats.end()) {
            entropy.Set(stats["entropy"]);
        }
        
        if (stats.find("rate") != stats.end()) {
            rate.Set(stats["rate"]);
        }
        
        if (stats.find("connections") != stats.end()) {
            connections.Set(stats["connections"]);
        }
        
        if (stats.find("blocked_ips") != stats.end()) {
            blocked_ips.Set(stats["blocked_ips"]);
        }
        
        if (stats.find("detection_time") != stats.end()) {
            detection_time.Set(stats["detection_time"]);
        }
        
        // Log current metrics
        std::cout << "Updated metrics - Packets processed: " << stats["packets_processed"] 
                  << ", Blocked: " << stats["packets_blocked"]
                  << ", SYN floods: " << stats["syn_floods"]
                  << ", Entropy: " << stats["entropy"] << '\n';
    }
    
private:
    void updateCounter(const std::string& key, const std::map<std::string, double>& stats, 
                      prometheus::Counter& counter) {
        auto it = stats.find(key);
        if (it != stats.end()) {
            double current_value = it->second;
            double previous_value = previous_values[key];
            
            if (current_value >= previous_value) {
                // Counter should only increase
                double increment = current_value - previous_value;
                if (increment > 0) {
                    counter.Increment(increment);
                }
            } else {
                // If current value is less than previous, assume counter was reset
                counter.Increment(current_value);
            }
            
            previous_values[key] = current_value;
        }
    }
    
    void generateSimulatedData(std::map<std::string, double>& stats) {
        // Generate simulated data when real stats are not available
        static auto start_time = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        // Simulate realistic DDoS detection metrics
        stats["packets_processed"] = elapsed * 1000 + (rand() % 500);
        stats["packets_blocked"] = elapsed * 10 + (rand() % 50);
        stats["syn_floods"] = elapsed / 30.0 + (rand() % 3);
        stats["slowloris_attacks"] = elapsed / 60.0 + (rand() % 2);
        stats["udp_floods"] = elapsed / 45.0 + (rand() % 2);
        stats["icmp_floods"] = elapsed / 90.0 + (rand() % 1);
        
        // Simulate varying entropy and rates
        stats["entropy"] = 2.0 + sin(elapsed * 0.1) * 0.5 + (rand() % 100) / 1000.0;
        stats["rate"] = 1000 + sin(elapsed * 0.05) * 200 + (rand() % 200);
        stats["connections"] = 50 + sin(elapsed * 0.02) * 20 + (rand() % 30);
        stats["blocked_ips"] = elapsed / 20.0 + (rand() % 10);
        stats["detection_time"] = 5 + (rand() % 15); // 5-20ms detection time
        
        std::cout << "Using simulated data (stats file not available)" << '\n';
    }
    
public:
    void run() {
        std::cout << "Starting DDoS Inspector metrics collection..." << '\n';
        
        while (true) {
            try {
                updateMetrics();
                std::this_thread::sleep_for(std::chrono::seconds(5));
            } catch (const std::exception& e) {
                std::cerr << "Error updating metrics: " << e.what() << '\n';
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
};

// Helper function to get environment variable or default
const char* get_env_or_default(const char* env_var, const char* default_val) {
    const char* value = std::getenv(env_var);
    return value ? value : default_val;
}

int main(int argc, char** argv) {
    try {
        const char* bind_address_env = get_env_or_default("BIND_ADDRESS", "0.0.0.0:9091");
        const char* stats_file_env = get_env_or_default("DDOS_STATS_FILE", "/var/log/ddos_inspector/ddos_inspector_stats");

        std::string bind_address = bind_address_env;
        std::string stats_file = stats_file_env;

        // Allow overriding with command-line arguments
        if (argc > 1) {
            stats_file = argv[1];
        }
        if (argc > 2) {
            bind_address = argv[2];
        }
        
        std::cout << "Starting Prometheus Exporter on " << bind_address << "\n";
        std::cout << "Monitoring stats file: " << stats_file << "\n";

        DDoSInspectorMetricsExporter exporter(bind_address, stats_file);
        exporter.run(); // Blocking call

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
