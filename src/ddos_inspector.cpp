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

    { "protected_networks", Parameter::PT_STRING, nullptr, "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
      "comma-separated list of protected network CIDRs" },

    { "log_level", Parameter::PT_STRING, nullptr, "info",
      "logging level: debug, info, warning, error" },

    { "enable_amplification_detection", Parameter::PT_BOOL, nullptr, "true",
      "enable amplification attack detection" },

    { "enable_adaptive_thresholds", Parameter::PT_BOOL, nullptr, "true",
      "enable adaptive threshold management" },

    { "enable_ipv6", Parameter::PT_BOOL, nullptr, "true",
      "enable IPv6 support" },

    { "enable_fragmentation_detection", Parameter::PT_BOOL, nullptr, "true",
      "enable fragment flood detection" },

    { "max_tracked_ips", Parameter::PT_INT, "100:100000", "10000",
      "maximum number of IPs to track simultaneously" },

    { "tarpit_enabled", Parameter::PT_BOOL, nullptr, "true",
      "enable tarpit for slow down attacks" },

    { "tcp_reset_enabled", Parameter::PT_BOOL, nullptr, "true",
      "enable TCP reset for malicious connections" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define DDOS_NAME "ddos_inspector"
#define DDOS_HELP "statistical and behavioral DDoS detection plugin"

DdosInspectorModule::DdosInspectorModule() : Module(DDOS_NAME, DDOS_HELP, ddos_params)
{
    std::cout << "\033[0;32m[OK]\033[0m DDoS Inspector Plugin Module loaded successfully!" << '\n';
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
    else if (v.is("enable_amplification_detection"))
        enable_amplification_detection = v.get_bool();
    else if (v.is("enable_adaptive_thresholds"))
        enable_adaptive_thresholds = v.get_bool();
    else if (v.is("enable_ipv6"))
        enable_ipv6 = v.get_bool();
    else if (v.is("enable_fragmentation_detection"))
        enable_fragmentation_detection = v.get_bool();
    else if (v.is("max_tracked_ips"))
        max_tracked_ips = v.get_uint32();
    else if (v.is("tarpit_enabled"))
        tarpit_enabled = v.get_bool();
    else if (v.is("tcp_reset_enabled"))
        tcp_reset_enabled = v.get_bool();
    else
        return false;

    return true;
}

bool DdosInspectorModule::begin(const char*, int, SnortConfig*)
{
    std::cout << "\033[0;34m[CONFIG]\033[0m DDoS Inspector Plugin configuration initialized" << '\n';
    return true;
}

bool DdosInspectorModule::end(const char*, int, SnortConfig*)
{
    applyConfigurationProfile();
    std::cout << "\033[0;32m[OK]\033[0m DDoS Inspector Plugin configuration completed successfully" << '\n';
    return true;
}

void DdosInspectorModule::applyConfigurationProfile() {
    std::cout << "\033[0;34m[CONFIG]\033[0m Applying configuration profile: " << config_profile << '\n';
    
    if (config_profile == "strict") {
        // Strict mode: Lower thresholds, higher sensitivity
        entropy_threshold = 1.5;
        ewma_alpha = 0.15;
        block_timeout = 1800; // 30 minutes
        connection_threshold = 500;
        rate_threshold = 25000;
        std::cout << "  - Applied strict detection thresholds" << '\n';
    }
    else if (config_profile == "permissive") {
        // Permissive mode: Higher thresholds, lower sensitivity
        entropy_threshold = 3.0;
        ewma_alpha = 0.05;
        block_timeout = 300; // 5 minutes
        connection_threshold = 2000;
        rate_threshold = 100000;
        std::cout << "  - Applied permissive detection thresholds" << '\n';
    }
    else if (config_profile == "web_server") {
        // Web server optimized: Account for legitimate HTTP bursts
        entropy_threshold = 2.5;
        ewma_alpha = 0.08;
        allow_icmp = false;
        connection_threshold = 1500;
        rate_threshold = 75000;
        std::cout << "  - Applied web server optimized settings" << '\n';
    }
    else if (config_profile == "game_server") {
        // Game server optimized: Handle UDP bursts, lower latency tolerance
        entropy_threshold = 1.8;
        ewma_alpha = 0.2;
        allow_icmp = true;
        connection_threshold = 800;
        rate_threshold = 40000;
        std::cout << "  - Applied game server optimized settings" << '\n';
    }
    else {
        // Default profile - no changes needed
        std::cout << "  - Using default configuration settings" << '\n';
    }
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

DdosInspector::DdosInspector(DdosInspectorModule* mod)
{
    std::cout << "\033[0;33m[INIT]\033[0m DDoS Inspector engine starting with configuration:" << '\n';
    std::cout << "   - Allow ICMP: " << (mod->allow_icmp ? "enabled" : "disabled") << '\n';
    std::cout << "   - Entropy threshold: " << mod->entropy_threshold << '\n';
    std::cout << "   - EWMA alpha: " << mod->ewma_alpha << '\n';
    std::cout << "   - Block timeout: " << mod->block_timeout << "s" << '\n';
    std::cout << "   - Metrics file: " << mod->metrics_file << '\n';
    
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
    amplification_detections = 0;
    
    std::cout << "\033[0;32m[READY]\033[0m DDoS Inspector engine initialized and ready for packet analysis!" << '\n';
    
    // Start background metrics thread
    startMetricsThread();
}

DdosInspector::~DdosInspector() {
    // Stop background metrics thread
    stopMetricsThread();
}

void DdosInspector::writeMetrics()
{
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_metrics_update);
    
    // TODO: IMPROVEMENT - Thread safety issue
    // WARNING: File I/O in packet processing path can cause performance issues
    // Suggested: Move to background thread or use lock-free queue
    
    // Update metrics every 5 seconds
    if (duration.count() >= 5) {
        // TODO: IMPROVEMENT - Use async I/O or background thread
        std::ofstream metrics_file(metrics_file_path);
        if (metrics_file.is_open()) {
            // Write current statistics
            metrics_file << "packets_processed:" << packets_processed.load() << '\n';
            metrics_file << "packets_blocked:" << packets_blocked.load() << '\n';
            
            if (stats_engine) {
                metrics_file << "entropy:" << stats_engine->get_entropy() << '\n';
                metrics_file << "rate:" << stats_engine->get_current_rate() << '\n';
                metrics_file << "baseline_rate:" << stats_engine->get_baseline_rate() << '\n';
            }
            
            if (behavior_tracker) {
                metrics_file << "connections:" << behavior_tracker->get_connection_count() << '\n';
            }
            
            if (firewall_action) {
                metrics_file << "blocked_ips:" << firewall_action->get_blocked_count() << '\n';
                metrics_file << "rate_limited_ips:" << firewall_action->get_rate_limited_count() << '\n';
            }
            
            // Attack type counters with enhanced tracking
            metrics_file << "syn_floods:" << syn_flood_detections.load() << '\n';
            metrics_file << "slowloris_attacks:" << slowloris_detections.load() << '\n';
            metrics_file << "udp_floods:" << udp_flood_detections.load() << '\n';
            metrics_file << "icmp_floods:" << icmp_flood_detections.load() << '\n';
            metrics_file << "amplification_attacks:" << amplification_detections.load() << '\n';
            
            // Performance metrics
            auto detection_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - detection_start_time).count();
            metrics_file << "detection_time_ms:" << detection_time << '\n';
            metrics_file << "avg_processing_time_us:" << 
                (packets_processed.load() > 0 ? total_processing_time_us.load() / packets_processed.load() : 0) << '\n';
            metrics_file << "max_processing_time_us:" << max_processing_time_us.load() << '\n';
            
            // Configuration profile info
            metrics_file << "config_profile:" << log_level << '\n'; // Using log_level as a proxy for now
            
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

    // Enhanced IP version support
    bool is_ipv4 = p->ptrs.ip_api.is_ip4();
    bool is_ipv6 = p->ptrs.ip_api.is_ip6();
    
    if (!is_ipv4 && !is_ipv6)
        return;

    uint8_t proto = 0;
    std::string src_ip, dst_ip;
    uint16_t packet_length = 0;
    
    if (is_ipv4) {
        const snort::ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
        proto = (uint8_t)ip4h->proto();
        packet_length = ip4h->len();
        
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];
        uint32_t src_addr = ip4h->get_src();
        uint32_t dst_addr = ip4h->get_dst();
        inet_ntop(AF_INET, &src_addr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &dst_addr, dst_buf, sizeof(dst_buf));
        src_ip = src_buf;
        dst_ip = dst_buf;
    } else if (is_ipv6) {
        const snort::ip::IP6Hdr* ip6h = p->ptrs.ip_api.get_ip6h();
        proto = static_cast<uint8_t>(ip6h->next());
        packet_length = ip6h->len() + 40; // IPv6 header is 40 bytes
        
        char src_buf[INET6_ADDRSTRLEN];
        char dst_buf[INET6_ADDRSTRLEN];
        const snort::ip::snort_in6_addr* src_addr = ip6h->get_src();
        const snort::ip::snort_in6_addr* dst_addr = ip6h->get_dst();
        inet_ntop(AF_INET6, src_addr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, dst_addr, dst_buf, sizeof(dst_buf));
        src_ip = src_buf;
        dst_ip = dst_buf;
    }
    
    // Only handle TCP/UDP (and optionally ICMP)
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && 
        (!allow_icmp || (proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6)))
        return;

    packets_processed++;
    detection_start_time = std::chrono::steady_clock::now();

    // Extract packet information
    PacketData pkt_data;
    pkt_data.src_ip = src_ip;
    pkt_data.dst_ip = dst_ip;
    pkt_data.size = packet_length;
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
        pkt_data.payload = std::string(static_cast<const char*>(static_cast<const void*>(p->data)), p->dsize);
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
    bool amplification_detected = detectAmplificationAttack(pkt_data, proto);
    bool fragment_flood = detectFragmentFlood(p);
    
    // Update adaptive thresholds periodically
    updateAdaptiveThresholds();

    // Enhanced attack classification with confidence scoring
    if (stats_anomaly || behavior_anomaly || amplification_detected || fragment_flood) {
        AttackInfo attack_info = classifyAttack(pkt_data, stats_anomaly, behavior_anomaly, proto);
        
        // Add amplification and fragment detection to confidence
        if (amplification_detected) {
            attack_info.confidence += 0.3;
            amplification_detections++;
        }
        
        if (fragment_flood) {
            attack_info.confidence += 0.4;
            attack_info.type = AttackInfo::VOLUME_ATTACK; // Fragment floods are volume attacks
        }
        
        // Use adaptive confidence calculation
        double calculated_confidence = calculateConfidenceScore(pkt_data, stats_anomaly, behavior_anomaly);
        attack_info.confidence = std::max(attack_info.confidence, calculated_confidence);
        
        // Lower confidence threshold for SYN floods since they naturally have zero entropy
        double confidence_threshold = 0.5; // Reduced from 0.7 to 0.5
        if (attack_info.type == AttackInfo::SYN_FLOOD) {
            confidence_threshold = 0.4; // Even lower for SYN floods
        }
        
        if (attack_info.confidence >= confidence_threshold) {
            incrementAttackCounter(attack_info.type);
            
            // Enhanced mitigation with granular options
            if (attack_info.severity >= AttackInfo::SEVERITY_HIGH) {
                int block_duration = calculateBlockDuration(attack_info.severity, attack_info.type);
                firewall_action->block(pkt_data.src_ip, block_duration);
                packets_blocked++;
                
                // Apply additional mitigation for sophisticated attacks
                if (attack_info.type == AttackInfo::SLOWLORIS) {
                    firewall_action->apply_tarpit(pkt_data.src_ip);
                } else if (attack_info.type == AttackInfo::SYN_FLOOD) {
                    firewall_action->send_tcp_reset(pkt_data.src_ip);
                }
            } else if (attack_info.severity >= AttackInfo::SEVERITY_MEDIUM) {
                // Rate limit instead of full block for medium severity
                firewall_action->rate_limit(pkt_data.src_ip, attack_info.severity);
            }
            // Log low severity attacks but don't block
            logAttackDetection(attack_info, pkt_data, stats_anomaly, behavior_anomaly);
        }
    }
    
    // Remove the old writeMetrics call since it's now handled by background thread
    // writeMetrics(); // Removed - now handled by background thread
    
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
    
    std::cout << '\n';
    
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

void DdosInspector::updateAdaptiveThresholds() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(
        now - adaptive_thresholds.last_update);
    
    // Update thresholds every 10 minutes
    if (duration.count() >= 10) {
        std::lock_guard<std::mutex> lock(metrics_mutex);
        
        // Update baseline entropy based on recent observations
        if (stats_engine) {
            double current_entropy = stats_engine->get_entropy();
            double current_rate = stats_engine->get_current_rate();
            
            // Gradually adapt baselines using EWMA
            double adaptation_factor = 0.1; // Slow adaptation
            adaptive_thresholds.baseline_entropy = 
                adaptation_factor * current_entropy + 
                (1.0 - adaptation_factor) * adaptive_thresholds.baseline_entropy;
            
            adaptive_thresholds.baseline_rate = 
                adaptation_factor * current_rate + 
                (1.0 - adaptation_factor) * adaptive_thresholds.baseline_rate;
            
            // Adjust detection thresholds based on baselines
            adaptive_thresholds.entropy_threshold = 
                std::max(0.5, adaptive_thresholds.baseline_entropy * 0.3);
            
            adaptive_thresholds.rate_threshold = 
                std::max(1000.0, adaptive_thresholds.baseline_rate * 3.0);
        }
        
        adaptive_thresholds.last_update = now;
    }
}

double DdosInspector::calculateConfidenceScore(const PacketData& pkt_data, 
                                              bool stats_anomaly, bool behavior_anomaly) {
    double confidence = 0.0;
    
    // Base confidence from detection engines
    if (stats_anomaly) confidence += 0.4;
    if (behavior_anomaly) confidence += 0.4;
    
    // Additional confidence factors
    if (stats_engine) {
        double rate_ratio = stats_engine->get_current_rate() / 
                           std::max(adaptive_thresholds.baseline_rate, 1000.0);
        if (rate_ratio > 10.0) confidence += 0.2;
        else if (rate_ratio > 5.0) confidence += 0.1;
        
        double entropy_ratio = adaptive_thresholds.baseline_entropy / 
                              std::max(stats_engine->get_entropy(), 0.1);
        if (entropy_ratio > 5.0) confidence += 0.2;
        else if (entropy_ratio > 3.0) confidence += 0.1;
    }
    
    // Protocol-specific confidence adjustments
    if (pkt_data.is_syn && !pkt_data.is_ack) {
        confidence += 0.1; // SYN floods are easier to detect
    }
    
    if (pkt_data.is_http && pkt_data.payload.length() < 10) {
        confidence += 0.15; // Suspicious short HTTP requests
    }
    
    return std::min(1.0, confidence); // Cap at 1.0
}

bool DdosInspector::detectAmplificationAttack(const PacketData& pkt_data, uint8_t proto) {
    // Detect DNS amplification attacks
    if (proto == IPPROTO_UDP && pkt_data.size > 512) {
        // Check for DNS queries that could be amplified
        if (pkt_data.payload.find("\x01\x00\x00\x01") != std::string::npos || // DNS query
            pkt_data.payload.find("ANY") != std::string::npos) {
            return true;
        }
    }
    
    // Detect NTP amplification (port 123)
    if (proto == IPPROTO_UDP && pkt_data.size > 200) {
        // NTP mode 6 (control) and mode 7 (private) can be amplified
        if (!pkt_data.payload.empty()) {
            uint8_t mode = pkt_data.payload[0] & 0x07;
            if (mode == 6 || mode == 7) {
                return true;
            }
        }
    }
    
    // Detect SSDP amplification (port 1900)
    if (proto == IPPROTO_UDP && pkt_data.payload.find("M-SEARCH") != std::string::npos) {
        return true;
    }
    
    return false;
}

bool DdosInspector::detectFragmentFlood(snort::Packet* p) {
    if (!p || !p->ptrs.ip_api.is_ip()) {
        return false;
    }
    
    // Check for IP fragmentation
    if (p->ptrs.ip_api.is_ip4()) {
        const snort::ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
        uint16_t flags_and_offset = ntohs(ip4h->off_w_flags());
        bool more_fragments = (flags_and_offset & 0x2000) != 0;
        // bool dont_fragment = (flags_and_offset & 0x4000) != 0;  // Reserved for future use
        uint16_t fragment_offset = flags_and_offset & 0x1FFF;
        
        // Detect suspicious fragmentation patterns
        if (more_fragments || fragment_offset > 0) {
            // This is a fragment - could be part of a fragment flood
            fragment_count++;
            
            // Simple threshold-based detection
            if (fragment_count > 1000) { // 1000 fragments in recent time window
                fragment_count = 0; // Reset counter
                return true;
            }
        }
    }
    
    return false;
}

void DdosInspector::startMetricsThread() {
    metrics_running = true;
    metrics_thread = std::thread([this]() {
        while (metrics_running) {
            writeMetrics();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    });
}

void DdosInspector::stopMetricsThread() {
    metrics_running = false;
    if (metrics_thread.joinable()) {
        metrics_thread.join();
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
    DdosInspectorModule* mod = dynamic_cast<DdosInspectorModule*>(m);
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

