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

// Forward declarations
class StatsEngine;
class BehaviorTracker;
class FirewallAction;

class DdosInspectorModule : public snort::Module
{
public:
    DdosInspectorModule();
    ~DdosInspectorModule();
    
    bool set(const char*, snort::Value&, snort::SnortConfig*);
    bool begin(const char*, int, snort::SnortConfig*);
    bool end(const char*, int, snort::SnortConfig*);
    
    const snort::Parameter* get_parameters() const;
    
    Usage get_usage() const
    { return INSPECT; }

    // Configuration parameters
    bool allow_icmp = false;
    double entropy_threshold = 2.0;
    double ewma_alpha = 0.1;
    int block_timeout = 600; // seconds
};

class DdosInspector : public snort::Inspector
{
public:
    DdosInspector(DdosInspectorModule*);
    ~DdosInspector();

    void eval(snort::Packet*);
    void show_stats(std::ostream&);

private:
    std::unique_ptr<StatsEngine> stats_engine;
    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<FirewallAction> firewall_action;
    
    bool allow_icmp;
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_blocked{0};
};

#endif // DDOS_INSPECTOR_HPP