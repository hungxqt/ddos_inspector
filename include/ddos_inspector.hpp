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
#include <atomic>
#include <memory>
#include <string>
#include <chrono>
#include <cstdint>
#include "packet_data.hpp"

// Forward declarations
class StatsEngine;
class BehaviorTracker;
class FirewallAction;

// Attack classification structures enhanced for Snort 3.8.1.0
struct AttackInfo {
    enum Type { 
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
        UNKNOWN 
    };
    
    enum Severity { 
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

    // Enhanced configuration parameters for Snort 3.8.1.0
    bool allow_icmp = false;
    bool enable_amplification_detection = true;
    bool enable_adaptive_thresholds = true;
    double entropy_threshold = 2.0;
    double ewma_alpha = 0.1;
    uint32_t block_timeout = 600; // seconds
    uint32_t connection_threshold = 1000;
    uint32_t rate_threshold = 50000; // packets per second
    std::string metrics_file = "/tmp/ddos_inspector/ddos_inspector_stats";
    std::string log_level = "info";
    std::string config_profile = "default";
    std::string protected_networks = "";
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
    // Configuration
    bool allow_icmp;
    bool enable_amplification_detection;
    bool enable_adaptive_thresholds;
    uint32_t connection_threshold;
    uint32_t rate_threshold;
    std::string metrics_file_path;
    std::string log_level;
    
    // Core components
    std::unique_ptr<StatsEngine> stats_engine;
    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<FirewallAction> firewall_action;
    
    // Enhanced statistics tracking
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_blocked{0};
    std::atomic<uint64_t> packets_rate_limited{0};
    std::atomic<uint64_t> syn_flood_detections{0};
    std::atomic<uint64_t> slowloris_detections{0};
    std::atomic<uint64_t> udp_flood_detections{0};
    std::atomic<uint64_t> icmp_flood_detections{0};
    std::atomic<uint64_t> amplification_detections{0};
    std::atomic<uint64_t> false_positives{0};
    
    // Performance metrics
    std::chrono::steady_clock::time_point last_metrics_update;
    std::chrono::steady_clock::time_point detection_start_time;
    std::atomic<uint64_t> total_processing_time_us{0};
    std::atomic<uint64_t> max_processing_time_us{0};
    
    // Enhanced detection methods
    AttackInfo classifyAttack(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly, uint8_t proto);
    bool detectAmplificationAttack(const PacketData& pkt_data, uint8_t proto);
    void incrementAttackCounter(AttackInfo::Type type);
    void writeMetrics();
    void updatePerformanceMetrics(std::chrono::microseconds processing_time);
    
    // Dynamic mitigation methods
    int calculateBlockDuration(AttackInfo::Severity severity, AttackInfo::Type type);
    void logAttackDetection(const AttackInfo& attack_info, const PacketData& pkt_data, 
                           bool stats_anomaly, bool behavior_anomaly);
    
    // Adaptive threshold management
    void updateAdaptiveThresholds();
    double calculateConfidenceScore(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly);
};

#endif // DDOS_INSPECTOR_HPP