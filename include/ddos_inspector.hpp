#ifndef DDOS_INSPECTOR_HPP
#define DDOS_INSPECTOR_HPP

#include <framework/module.h>
#include <framework/inspector.h>
#include <framework/parameter.h>
#include <log/messages.h>
#include <protocols/packet.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>
#include <atomic>
#include <memory>
#include <string>
#include <chrono>
#include "packet_data.hpp"

// Forward declarations
class StatsEngine;
class BehaviorTracker;
class FirewallAction;

// Attack classification structures
struct AttackInfo {
    enum Type { SYN_FLOOD, HTTP_FLOOD, SLOWLORIS, ACK_FLOOD, UDP_FLOOD, ICMP_FLOOD, VOLUME_ATTACK, UNKNOWN };
    enum Severity { SEVERITY_LOW = 1, SEVERITY_MEDIUM = 2, SEVERITY_HIGH = 3, SEVERITY_CRITICAL = 4 };
    
    Type type;
    Severity severity;
    double confidence;
    std::string description;
};

class DdosInspectorModule : public snort::Module
{
public:
    DdosInspectorModule();
    ~DdosInspectorModule();
    
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    
    const snort::Parameter* get_parameters() const;
    
    Usage get_usage() const override
    { return INSPECT; }

    // Configuration parameters
    bool allow_icmp = false;
    double entropy_threshold = 2.0;
    double ewma_alpha = 0.1;
    uint32_t block_timeout = 600; // seconds
    std::string metrics_file = "/tmp/ddos_inspector_stats";
};

class DdosInspector : public snort::Inspector
{
public:
    DdosInspector(DdosInspectorModule*);
    ~DdosInspector();

    void eval(snort::Packet*) override;
    void show_stats(std::ostream&);

private:
    bool allow_icmp;
    std::string metrics_file_path;
    
    // Core components
    std::unique_ptr<StatsEngine> stats_engine;
    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<FirewallAction> firewall_action;
    
    // Statistics tracking
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_blocked{0};
    std::atomic<uint64_t> syn_flood_detections{0};
    std::atomic<uint64_t> slowloris_detections{0};
    std::atomic<uint64_t> udp_flood_detections{0};
    std::atomic<uint64_t> icmp_flood_detections{0};
    
    // Metrics tracking
    std::chrono::steady_clock::time_point last_metrics_update;
    std::chrono::steady_clock::time_point detection_start_time;
    
    // Enhanced detection methods
    AttackInfo classifyAttack(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly, uint8_t proto);
    void incrementAttackCounter(AttackInfo::Type type);
    void writeMetrics();
};

#endif // DDOS_INSPECTOR_HPP