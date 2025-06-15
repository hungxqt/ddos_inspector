#include "ddos_inspector.hpp"
#include "stats_engine.hpp"
#include "behavior_tracker.hpp"
#include "firewall_action.hpp"
#include "packet_data.hpp"

#include <framework/snort_api.h>
#include <main/snort_config.h>
#include <protocols/ip.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fstream>
#include <chrono>
#include <iostream>
#include <iomanip>

using namespace snort;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter ddos_params[] =
{
    { "allow_icmp", Parameter::PT_BOOL, nullptr, "false",
      "allow ICMP packets to be processed" },

    { "entropy_threshold", Parameter::PT_REAL, "0.0:10.0", "2.0",
      "entropy threshold for anomaly detection" },

    { "ewma_alpha", Parameter::PT_REAL, "0.0:1.0", "0.1",
      "EWMA smoothing factor" },

    { "block_timeout", Parameter::PT_INT, "1:3600", "600",
      "IP block timeout in seconds" },

    { "metrics_file", Parameter::PT_STRING, nullptr, "/tmp/ddos_inspector/ddos_inspector_stats",
      "path to metrics output file" },

    { "config_profile", Parameter::PT_STRING, nullptr, "default",
      "configuration profile: default, strict, permissive, web_server, game_server" },

    { "protected_networks", Parameter::PT_STRING, nullptr, "",
      "comma-separated list of protected network CIDRs" },

    { "log_level", Parameter::PT_STRING, nullptr, "info",
      "logging level: debug, info, warning, error" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define DDOS_NAME "ddos_inspector"
#define DDOS_HELP "statistical and behavioral DDoS detection plugin"

DdosInspectorModule::DdosInspectorModule() : Module(DDOS_NAME, DDOS_HELP, ddos_params)
{
    std::cout << "\033[0;32m[OK]\033[0m DDoS Inspector Plugin Module loaded successfully!" << std::endl;
}

const Parameter* DdosInspectorModule::get_parameters() const
{
    return ddos_params;
}

bool DdosInspectorModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if (v.is("allow_icmp"))
        allow_icmp = v.get_bool();
    else if (v.is("entropy_threshold"))
        entropy_threshold = v.get_real();
    else if (v.is("ewma_alpha"))
        ewma_alpha = v.get_real();
    else if (v.is("block_timeout"))
        block_timeout = v.get_uint32();
    else if (v.is("metrics_file"))
        metrics_file = v.get_string();
    else if (v.is("config_profile"))
        config_profile = v.get_string();
    else if (v.is("protected_networks"))
        protected_networks = v.get_string();
    else if (v.is("log_level"))
        log_level = v.get_string();
    else
        return false;

    return true;
}

bool DdosInspectorModule::begin(const char*, int, SnortConfig*)
{
    std::cout << "\033[0;34m[CONFIG]\033[0m DDoS Inspector Plugin configuration initialized" << std::endl;
    return true;
}

bool DdosInspectorModule::end(const char*, int, SnortConfig*)
{
    applyConfigurationProfile();
    std::cout << "\033[0;32m[OK]\033[0m DDoS Inspector Plugin configuration completed successfully" << std::endl;
    return true;
}

void DdosInspectorModule::applyConfigurationProfile() {
    std::cout << "\033[0;34m[CONFIG]\033[0m Applying configuration profile: " << config_profile << std::endl;
    
    if (config_profile == "strict") {
        // Strict mode: Lower thresholds, higher sensitivity
        entropy_threshold = 1.5;
        ewma_alpha = 0.15;
        block_timeout = 1800; // 30 minutes
        connection_threshold = 500;
        rate_threshold = 25000;
        std::cout << "  - Applied strict detection thresholds" << std::endl;
    }
    else if (config_profile == "permissive") {
        // Permissive mode: Higher thresholds, lower sensitivity
        entropy_threshold = 3.0;
        ewma_alpha = 0.05;
        block_timeout = 300; // 5 minutes
        connection_threshold = 2000;
        rate_threshold = 100000;
        std::cout << "  - Applied permissive detection thresholds" << std::endl;
    }
    else if (config_profile == "web_server") {
        // Web server optimized: Account for legitimate HTTP bursts
        entropy_threshold = 2.5;
        ewma_alpha = 0.08;
        allow_icmp = false;
        connection_threshold = 1500;
        rate_threshold = 75000;
        std::cout << "  - Applied web server optimized settings" << std::endl;
    }
    else if (config_profile == "game_server") {
        // Game server optimized: Handle UDP bursts, lower latency tolerance
        entropy_threshold = 1.8;
        ewma_alpha = 0.2;
        allow_icmp = true;
        connection_threshold = 800;
        rate_threshold = 40000;
        std::cout << "  - Applied game server optimized settings" << std::endl;
    }
    else {
        // Default profile - no changes needed
        std::cout << "  - Using default configuration settings" << std::endl;
    }
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

DdosInspector::DdosInspector(DdosInspectorModule* mod)
{
    std::cout << "\033[0;33m[INIT]\033[0m DDoS Inspector engine starting with configuration:" << std::endl;
    std::cout << "   - Allow ICMP: " << (mod->allow_icmp ? "enabled" : "disabled") << std::endl;
    std::cout << "   - Entropy threshold: " << mod->entropy_threshold << std::endl;
    std::cout << "   - EWMA alpha: " << mod->ewma_alpha << std::endl;
    std::cout << "   - Block timeout: " << mod->block_timeout << "s" << std::endl;
    std::cout << "   - Metrics file: " << mod->metrics_file << std::endl;
    
    allow_icmp = mod->allow_icmp;
    metrics_file_path = mod->metrics_file;
    
    // Initialize components with configuration
    stats_engine = std::make_unique<StatsEngine>(mod->entropy_threshold, mod->ewma_alpha);
    behavior_tracker = std::make_unique<BehaviorTracker>();
    firewall_action = std::make_unique<FirewallAction>(mod->block_timeout);
    
    // Initialize metrics tracking
    last_metrics_update = std::chrono::steady_clock::now();
    syn_flood_detections = 0;
    slowloris_detections = 0;
    udp_flood_detections = 0;
    icmp_flood_detections = 0;
    
    std::cout << "\033[0;32m[READY]\033[0m DDoS Inspector engine initialized and ready for packet analysis!" << std::endl;
}

DdosInspector::~DdosInspector() = default;

void DdosInspector::writeMetrics()
{
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_metrics_update);
    
    // Update metrics every 5 seconds
    if (duration.count() >= 5) {
        std::ofstream metrics_file(metrics_file_path);
        if (metrics_file.is_open()) {
            // Write current statistics
            metrics_file << "packets_processed:" << packets_processed.load() << std::endl;
            metrics_file << "packets_blocked:" << packets_blocked.load() << std::endl;
            
            if (stats_engine) {
                metrics_file << "entropy:" << stats_engine->get_entropy() << std::endl;
                metrics_file << "rate:" << stats_engine->get_current_rate() << std::endl;
                metrics_file << "baseline_rate:" << stats_engine->get_baseline_rate() << std::endl;
            }
            
            if (behavior_tracker) {
                metrics_file << "connections:" << behavior_tracker->get_connection_count() << std::endl;
            }
            
            if (firewall_action) {
                metrics_file << "blocked_ips:" << firewall_action->get_blocked_count() << std::endl;
                metrics_file << "rate_limited_ips:" << firewall_action->get_rate_limited_count() << std::endl;
            }
            
            // Attack type counters with enhanced tracking
            metrics_file << "syn_floods:" << syn_flood_detections.load() << std::endl;
            metrics_file << "slowloris_attacks:" << slowloris_detections.load() << std::endl;
            metrics_file << "udp_floods:" << udp_flood_detections.load() << std::endl;
            metrics_file << "icmp_floods:" << icmp_flood_detections.load() << std::endl;
            
            // Performance metrics
            auto detection_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - detection_start_time).count();
            metrics_file << "detection_time_ms:" << detection_time << std::endl;
            metrics_file << "avg_processing_time_us:" << 
                (packets_processed.load() > 0 ? total_processing_time_us.load() / packets_processed.load() : 0) << std::endl;
            metrics_file << "max_processing_time_us:" << max_processing_time_us.load() << std::endl;
            
            // Configuration profile info
            metrics_file << "config_profile:" << log_level << std::endl; // Using log_level as a proxy for now
            
            metrics_file.close();
        }
        
        last_metrics_update = now;
    }
}

void DdosInspector::eval(Packet* p)
{
    auto eval_start = std::chrono::high_resolution_clock::now();
    
    if (!p || !p->ptrs.ip_api.is_ip())
        return;

    // Pre-filter: Only handle IPv4 for now
    if (!p->ptrs.ip_api.is_ip4())
        return;

    // Get IP header and protocol
    const snort::ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
    uint8_t proto = (uint8_t)ip4h->proto();
    
    // Only handle TCP/UDP (and optionally ICMP)
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && 
        !(allow_icmp && proto == IPPROTO_ICMP))
        return;

    packets_processed++;
    detection_start_time = std::chrono::steady_clock::now();

    // Extract packet information
    PacketData pkt_data;
    
    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];
    uint32_t src_addr = ip4h->get_src();
    uint32_t dst_addr = ip4h->get_dst();
    inet_ntop(AF_INET, &src_addr, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &dst_addr, dst_buf, sizeof(dst_buf));
    
    pkt_data.src_ip = src_buf;
    pkt_data.dst_ip = dst_buf;
    pkt_data.size = ip4h->len();
    pkt_data.is_syn = false;
    pkt_data.is_ack = false;
    pkt_data.is_http = false;

    // Extract TCP flags if TCP packet
    if (proto == IPPROTO_TCP && p->ptrs.tcph)
    {
        pkt_data.is_syn = (p->ptrs.tcph->th_flags & TH_SYN) != 0;
        pkt_data.is_ack = (p->ptrs.tcph->th_flags & TH_ACK) != 0;
    }

    // Extract payload if available
    if (p->data && p->dsize > 0)
    {
        pkt_data.payload = std::string(reinterpret_cast<const char*>(p->data), p->dsize);
        // Simple HTTP detection
        if (pkt_data.payload.find("HTTP/") != std::string::npos ||
            pkt_data.payload.find("GET ") == 0 ||
            pkt_data.payload.find("POST ") == 0)
        {
            pkt_data.is_http = true;
        }
    }

    // Analyze packet with improved correlation
    bool stats_anomaly = stats_engine->analyze(pkt_data);
    bool behavior_anomaly = behavior_tracker->inspect(pkt_data);

    // Enhanced attack classification with confidence scoring
    if (stats_anomaly || behavior_anomaly) {
        AttackInfo attack_info = classifyAttack(pkt_data, stats_anomaly, behavior_anomaly, proto);
        
        // Lower confidence threshold for SYN floods since they naturally have zero entropy
        double confidence_threshold = 0.5; // Reduced from 0.7 to 0.5
        if (attack_info.type == AttackInfo::SYN_FLOOD) {
            confidence_threshold = 0.4; // Even lower for SYN floods
        }
        
        if (attack_info.confidence >= confidence_threshold) {
            incrementAttackCounter(attack_info.type);
            
            // Progressive blocking with dynamic duration based on severity
            if (attack_info.severity >= AttackInfo::SEVERITY_HIGH) {
                int block_duration = calculateBlockDuration(attack_info.severity, attack_info.type);
                firewall_action->block(pkt_data.src_ip, block_duration);
                packets_blocked++;
            } else if (attack_info.severity >= AttackInfo::SEVERITY_MEDIUM) {
                // Rate limit instead of full block for medium severity
                firewall_action->rate_limit(pkt_data.src_ip, attack_info.severity);
            }
            // Log low severity attacks but don't block
            logAttackDetection(attack_info, pkt_data, stats_anomaly, behavior_anomaly);
        }
    }
    
    // Update metrics file periodically
    writeMetrics();
    
    // Track performance metrics
    auto eval_end = std::chrono::high_resolution_clock::now();
    auto processing_time = std::chrono::duration_cast<std::chrono::microseconds>(eval_end - eval_start);
    updatePerformanceMetrics(processing_time);
}

AttackInfo DdosInspector::classifyAttack(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly, uint8_t proto) {
    AttackInfo attack;
    attack.confidence = 0.0;
    attack.severity = AttackInfo::SEVERITY_LOW;
    attack.type = AttackInfo::UNKNOWN;
    
    // Multi-factor analysis for better accuracy
    double behavioral_score = behavior_anomaly ? 0.6 : 0.0;
    double statistical_score = stats_anomaly ? 0.4 : 0.0;
    
    if (proto == IPPROTO_TCP) {
        if (pkt_data.is_syn && !pkt_data.is_ack) {
            attack.type = AttackInfo::SYN_FLOOD;
            attack.confidence = behavioral_score + statistical_score;
            // Higher confidence if both engines detect anomaly
            if (stats_anomaly && behavior_anomaly) attack.confidence += 0.2;
            
            // Determine severity based on rate and volume
            double current_rate = stats_engine->get_current_rate();
            if (current_rate > 100000) {
                attack.severity = AttackInfo::SEVERITY_CRITICAL;
            } else if (current_rate > 50000) {
                attack.severity = AttackInfo::SEVERITY_HIGH;
            } else {
                attack.severity = AttackInfo::SEVERITY_MEDIUM;
            }
        } else if (pkt_data.is_http) {
            // Distinguish between HTTP flood and Slowloris
            size_t connection_count = behavior_tracker->get_connection_count();
            double current_rate = stats_engine->get_current_rate();
            
            if (connection_count > 1000 && current_rate < 10000) {
                attack.type = AttackInfo::SLOWLORIS;
                attack.confidence = behavioral_score + 0.3; // Behavioral detection more important for Slowloris
            } else {
                attack.type = AttackInfo::HTTP_FLOOD;
                attack.confidence = behavioral_score + statistical_score + 0.1;
            }
            attack.severity = (connection_count > 5000) ? AttackInfo::SEVERITY_HIGH : AttackInfo::SEVERITY_MEDIUM;
        } else if (pkt_data.is_ack && !pkt_data.is_syn) {
            attack.type = AttackInfo::ACK_FLOOD;
            attack.confidence = behavioral_score + statistical_score;
            attack.severity = AttackInfo::SEVERITY_MEDIUM;
        }
    } else if (proto == IPPROTO_UDP) {
        attack.type = AttackInfo::UDP_FLOOD;
        attack.confidence = behavioral_score + statistical_score;
        attack.severity = (stats_engine->get_current_rate() > 75000) ? AttackInfo::SEVERITY_HIGH : AttackInfo::SEVERITY_MEDIUM;
    } else if (proto == IPPROTO_ICMP) {
        attack.type = AttackInfo::ICMP_FLOOD;
        attack.confidence = statistical_score + 0.3; // ICMP floods are primarily volume-based
        attack.severity = AttackInfo::SEVERITY_MEDIUM;
    }
    
    return attack;
}

void DdosInspector::incrementAttackCounter(AttackInfo::Type type) {
    switch (type) {
        case AttackInfo::SYN_FLOOD:
            syn_flood_detections++;
            break;
        case AttackInfo::HTTP_FLOOD:
            // Keep HTTP floods separate from Slowloris
            // Note: You may want to add a separate http_flood_detections counter
            break;
        case AttackInfo::SLOWLORIS:
            slowloris_detections++;
            break;
        case AttackInfo::UDP_FLOOD:
            udp_flood_detections++;
            break;
        case AttackInfo::ICMP_FLOOD:
            icmp_flood_detections++;
            break;
        default:
            break;
    }
}

int DdosInspector::calculateBlockDuration(AttackInfo::Severity severity, AttackInfo::Type type) {
    // Base durations in seconds
    int base_duration = 600; // 10 minutes default
    
    // Severity multipliers
    switch (severity) {
        case AttackInfo::SEVERITY_LOW:
            base_duration = 300; // 5 minutes
            break;
        case AttackInfo::SEVERITY_MEDIUM:
            base_duration = 600; // 10 minutes
            break;
        case AttackInfo::SEVERITY_HIGH:
            base_duration = 1800; // 30 minutes
            break;
        case AttackInfo::SEVERITY_CRITICAL:
            base_duration = 3600; // 1 hour
            break;
    }
    
    // Attack type adjustments
    switch (type) {
        case AttackInfo::SYN_FLOOD:
        case AttackInfo::UDP_FLOOD:
            // Volume attacks get longer blocks
            base_duration = static_cast<int>(base_duration * 1.5);
            break;
        case AttackInfo::SLOWLORIS:
            // Sophisticated attacks get much longer blocks
            base_duration = static_cast<int>(base_duration * 2.0);
            break;
        case AttackInfo::HTTP_FLOOD:
            // Standard duration
            break;
        default:
            break;
    }
    
    return base_duration;
}

void DdosInspector::logAttackDetection(const AttackInfo& attack_info, const PacketData& pkt_data, 
                                      bool stats_anomaly, bool behavior_anomaly) {
    // Enhanced logging with detailed attack information
    std::string attack_type_str;
    switch (attack_info.type) {
        case AttackInfo::SYN_FLOOD: attack_type_str = "SYN_FLOOD"; break;
        case AttackInfo::HTTP_FLOOD: attack_type_str = "HTTP_FLOOD"; break;
        case AttackInfo::SLOWLORIS: attack_type_str = "SLOWLORIS"; break;
        case AttackInfo::ACK_FLOOD: attack_type_str = "ACK_FLOOD"; break;
        case AttackInfo::UDP_FLOOD: attack_type_str = "UDP_FLOOD"; break;
        case AttackInfo::ICMP_FLOOD: attack_type_str = "ICMP_FLOOD"; break;
        case AttackInfo::VOLUME_ATTACK: attack_type_str = "VOLUME_ATTACK"; break;
        case AttackInfo::DNS_AMPLIFICATION: attack_type_str = "DNS_AMPLIFICATION"; break;
        case AttackInfo::NTP_AMPLIFICATION: attack_type_str = "NTP_AMPLIFICATION"; break;
        case AttackInfo::REFLECTION_ATTACK: attack_type_str = "REFLECTION_ATTACK"; break;
        default: attack_type_str = "UNKNOWN"; break;
    }
    
    std::string severity_str;
    switch (attack_info.severity) {
        case AttackInfo::SEVERITY_LOW: severity_str = "LOW"; break;
        case AttackInfo::SEVERITY_MEDIUM: severity_str = "MEDIUM"; break;
        case AttackInfo::SEVERITY_HIGH: severity_str = "HIGH"; break;
        case AttackInfo::SEVERITY_CRITICAL: severity_str = "CRITICAL"; break;
    }
    
    // Log to console with color coding
    std::string color_code;
    switch (attack_info.severity) {
        case AttackInfo::SEVERITY_LOW: color_code = "\033[0;33m"; break;    // Yellow
        case AttackInfo::SEVERITY_MEDIUM: color_code = "\033[0;35m"; break; // Magenta
        case AttackInfo::SEVERITY_HIGH: color_code = "\033[0;31m"; break;   // Red
        case AttackInfo::SEVERITY_CRITICAL: color_code = "\033[1;31m"; break; // Bold Red
    }
    
    std::cout << color_code << "[ATTACK DETECTED]\033[0m "
              << "Type: " << attack_type_str 
              << " | Severity: " << severity_str
              << " | Confidence: " << std::fixed << std::setprecision(2) << attack_info.confidence
              << " | Source: " << pkt_data.src_ip
              << " | Target: " << pkt_data.dst_ip
              << " | Size: " << pkt_data.size << " bytes";
    
    if (stats_engine) {
        std::cout << " | Rate: " << std::fixed << std::setprecision(0) << stats_engine->get_current_rate() << " pps"
                  << " | Entropy: " << std::fixed << std::setprecision(2) << stats_engine->get_entropy();
    }
    
    if (behavior_tracker) {
        std::cout << " | Connections: " << behavior_tracker->get_connection_count();
    }
    
    std::cout << " | Triggers: ";
    if (stats_anomaly) std::cout << "STATS ";
    if (behavior_anomaly) std::cout << "BEHAVIOR ";
    
    std::cout << std::endl;
    
    // Also log to syslog if available (basic implementation)
    // In a production environment, you'd want more sophisticated logging
    // using proper syslog facilities or centralized logging systems
}

void DdosInspector::updatePerformanceMetrics(std::chrono::microseconds processing_time) {
    // Update total processing time
    total_processing_time_us.fetch_add(processing_time.count());
    
    // Update maximum processing time
    uint64_t current_max = max_processing_time_us.load();
    uint64_t new_time = processing_time.count();
    
    while (new_time > current_max && 
           !max_processing_time_us.compare_exchange_weak(current_max, new_time)) {
        // CAS loop to update maximum
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new DdosInspectorModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* ddos_ctor(Module* m)
{
    DdosInspectorModule* mod = static_cast<DdosInspectorModule*>(m);
    return new DdosInspector(mod);
}

static void ddos_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi ddos_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DDOS_NAME,
        DDOS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PACKET,  // Changed from IT_PROBE to IT_PACKET
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ddos_ctor,
    ddos_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ddos_api.base,
    nullptr
};

