#include "firewall_action.hpp"
#include <cstdlib>
#include <algorithm>
#include <arpa/inet.h>

FirewallAction::FirewallAction(int block_timeout_seconds) 
    : block_timeout(block_timeout_seconds)
{
    // Initialize legitimate traffic patterns with common services
    legitimate_patterns = {
        {"80", 0.8},   // HTTP
        {"443", 0.9},  // HTTPS
        {"53", 0.7},   // DNS
        {"22", 0.6},   // SSH
        {"25", 0.5},   // SMTP
        {"110", 0.5},  // POP3
        {"143", 0.5},  // IMAP
        {"993", 0.6},  // IMAPS
        {"995", 0.6}   // POP3S
    };
    
    // Initialize whitelist with common legitimate IP ranges
    initialize_default_whitelist();
}

FirewallAction::~FirewallAction() = default;

void FirewallAction::block(const std::string& ip) {
    block(ip, 0); // Use default duration
}

void FirewallAction::block(const std::string& ip, int custom_duration_seconds) {
    // Check if IP is whitelisted
    if (is_whitelisted(ip)) {
        return; // Don't block whitelisted IPs
    }
    
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = blocked_ips.find(ip);
    
    if (it == blocked_ips.end() || !it->second.is_blocked) {
        // Block new IP or re-block expired IP
        if (execute_block_command(ip)) {
            BlockInfo info = {};
            info.blocked_time = now;
            info.last_seen = now;
            info.is_blocked = true;
            info.rate_limit_level = 0;
            info.custom_block_duration = custom_duration_seconds;
            info.strategy = MitigationStrategy::TEMPORARY_BLOCK;
            info.threat_score = 0.5;
            info.violation_count = 1;
            info.attack_type = "unknown";
            info.is_repeat_offender = is_repeat_offender(ip);
            
            blocked_ips[ip] = info;
            update_ip_reputation(ip, -10); // Decrease reputation for blocking
        }
    } else {
        // Update timestamp and duration for already blocked IP
        it->second.blocked_time = now;
        it->second.last_seen = now;
        it->second.violation_count++;
        if (custom_duration_seconds > 0) {
            it->second.custom_block_duration = custom_duration_seconds;
        }
        
        // Escalate mitigation if repeat violations
        if (it->second.violation_count >= max_violations_before_escalation) {
            it->second.strategy = MitigationStrategy::PERMANENT_BLOCK;
            it->second.is_repeat_offender = true;
        }
    }
    
    // Clean up expired blocks periodically
    cleanup_expired_blocks();
}

void FirewallAction::unblock(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end() && it->second.is_blocked) {
        if (execute_unblock_command(ip)) {
            blocked_ips.erase(it);
        }
    }
}

size_t FirewallAction::get_blocked_count() const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            count++;
        }
    }
    return count;
}

void FirewallAction::cleanup_expired_blocks() {
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = blocked_ips.begin(); it != blocked_ips.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.blocked_time).count();
        
        // Use custom duration if set, otherwise use default
        int effective_timeout = (it->second.custom_block_duration > 0) ? 
                                it->second.custom_block_duration : block_timeout;
        
        // Permanent blocks for repeat offenders last longer
        if (it->second.strategy == MitigationStrategy::PERMANENT_BLOCK && it->second.is_repeat_offender) {
            effective_timeout *= 10;
        }
            
        if (elapsed > effective_timeout && it->second.is_blocked) {
            if (execute_unblock_command(it->first)) {
                // Gradually improve reputation for IPs that served their time
                update_ip_reputation(it->first, 5);
                it = blocked_ips.erase(it);
            } else {
                ++it;
            }
        } else if (elapsed > (effective_timeout / 2) && it->second.rate_limit_level > 0 && !it->second.is_blocked) {
            // Rate limits expire faster than full blocks
            it = blocked_ips.erase(it);
        } else {
            ++it;
        }
    }
    
    // Decay IP reputation over time for rehabilitation
    auto reputation_decay_time = std::chrono::hours(reputation_decay_time_hours);
    for (auto& [ip, reputation] : ip_reputation) {
        auto it = blocked_ips.find(ip);
        if (it != blocked_ips.end()) {
            auto time_since_last_seen = std::chrono::duration_cast<std::chrono::hours>(
                now - it->second.last_seen);
            
            if (time_since_last_seen > reputation_decay_time) {
                reputation = std::min(100, reputation + 1); // Gradual reputation recovery
            }
        }
    }
}

bool FirewallAction::execute_block_command(const std::string& ip) {
    // TODO: IMPROVEMENT - Add more granular mitigation options
    // Current: Only IP blocking
    // Suggested: Rate limiting, tarpitting, TCP RST, challenge-response
    
    // For testing purposes, always return true to simulate successful blocking
    // In production, this would execute actual firewall commands
    #ifdef TESTING
        return true;
    #else
        // TODO: IMPROVEMENT - Better error handling and logging
        // Ensure nftables infrastructure exists before blocking
        std::system("nft add table inet filter 2>/dev/null || true");
        std::system("nft add set inet filter ddos_ip_set '{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }' 2>/dev/null || true");
        std::system("nft add rule inet filter input ip saddr @ddos_ip_set drop 2>/dev/null || true");
        
        // Now block the IP using nftables
        std::string cmd = "nft add element inet filter ddos_ip_set { " + ip + " }";
        
        int result = std::system(cmd.c_str());
        return result == 0;
    #endif
}

bool FirewallAction::execute_unblock_command(const std::string& ip) {
    // For testing purposes, always return true to simulate successful unblocking
    // In production, this would execute actual firewall commands
    #ifdef TESTING
        return true;
    #else
        std::string cmd = "nft delete element inet filter ddos_ip_set { " + ip + " }";
        
        int result = std::system(cmd.c_str());
        return result == 0;
    #endif
}

bool FirewallAction::is_blocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it == blocked_ips.end()) {
        return false;
    }
    
    // Check if the block has expired using custom or default timeout
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second.blocked_time).count();
    
    int effective_timeout = (it->second.custom_block_duration > 0) ? 
                            it->second.custom_block_duration : block_timeout;
    
    // Consider permanent blocks and repeat offenders
    if (it->second.strategy == MitigationStrategy::PERMANENT_BLOCK && it->second.is_repeat_offender) {
        effective_timeout *= 10; // Extend timeout for permanent blocks
    }
    
    return it->second.is_blocked && (elapsed <= effective_timeout);
}

bool FirewallAction::is_rate_limited(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it == blocked_ips.end()) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second.blocked_time).count();
    
    // Rate limits typically last shorter than full blocks
    int rate_limit_timeout = block_timeout / 2;
    
    return (it->second.rate_limit_level > 0) && (elapsed <= rate_limit_timeout);
}

void FirewallAction::rate_limit(const std::string& ip, int severity_level) {
    // Check if IP is whitelisted
    if (is_whitelisted(ip)) {
        return; // Don't rate limit whitelisted IPs
    }
    
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = blocked_ips.find(ip);
    
    if (it == blocked_ips.end()) {
        // Create new rate limit entry
        if (execute_rate_limit_command(ip, severity_level)) {
            BlockInfo info = {};
            info.blocked_time = now;
            info.last_seen = now;
            info.is_blocked = false;
            info.rate_limit_level = severity_level;
            info.custom_block_duration = 0;
            info.strategy = MitigationStrategy::RATE_LIMIT;
            info.threat_score = severity_level * 0.2;
            info.violation_count = 1;
            info.attack_type = "rate_limit_trigger";
            info.is_repeat_offender = is_repeat_offender(ip);
            
            blocked_ips[ip] = info;
            update_ip_reputation(ip, -5); // Slight reputation decrease for rate limiting
        }
    } else {
        // Update existing entry with higher severity if needed
        if (severity_level > it->second.rate_limit_level) {
            it->second.rate_limit_level = severity_level;
            it->second.blocked_time = now;
            it->second.last_seen = now;
            it->second.threat_score = std::max(it->second.threat_score, severity_level * 0.2);
            execute_rate_limit_command(ip, severity_level);
        }
    }
}

void FirewallAction::apply_tarpit(const std::string& ip) {
    // Tarpit implementation using nftables - slow down connections from suspicious IPs
    #ifndef TESTING
        // Use nftables limit rate to implement tarpit-like behavior
        std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                         " limit rate 1/second accept";
        std::system(cmd.c_str());
        
        // Add drop rule after the limit
        std::string drop_cmd = "nft insert rule inet filter input ip saddr " + ip + " drop";
        std::system(drop_cmd.c_str());
    #endif
}

void FirewallAction::send_tcp_reset(const std::string& ip) {
    // Send TCP RST using nftables to reset connections from malicious IPs
    #ifndef TESTING
        std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                         " tcp flags & (fin|syn|rst|ack) == syn reject with tcp reset";
        std::system(cmd.c_str());
    #endif
}

size_t FirewallAction::get_rate_limited_count() const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.rate_limit_level > 0 && !info.is_blocked) {
            count++;
        }
    }
    return count;
}

std::vector<std::string> FirewallAction::get_rate_limited_ips() const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    std::vector<std::string> rate_limited_ips;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.rate_limit_level > 0 && !info.is_blocked) {
            rate_limited_ips.push_back(ip + " (level " + std::to_string(info.rate_limit_level) + ")");
        }
    }
    return rate_limited_ips;
}

std::vector<std::string> FirewallAction::get_blocked_ips() const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    std::vector<std::string> blocked_list;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            // Calculate remaining time
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - info.blocked_time).count();
            int effective_timeout = (info.custom_block_duration > 0) ? info.custom_block_duration : block_timeout;
            int remaining = std::max(0, effective_timeout - static_cast<int>(elapsed));
            
            blocked_list.push_back(ip + " (remaining: " + std::to_string(remaining) + "s, type: " + info.attack_type + ")");
        }
    }
    return blocked_list;
}

bool FirewallAction::execute_rate_limit_command(const std::string& ip, int severity) {
    #ifdef TESTING
        return true;
    #else
        // Create rate limiting rules using nftables based on severity
        std::string rate_limit;
        switch (severity) {
            case 1: rate_limit = "10/second"; break;  // Low severity
            case 2: rate_limit = "5/second"; break;   // Medium severity  
            case 3: rate_limit = "2/second"; break;   // High severity
            case 4: rate_limit = "1/second"; break;   // Critical severity
            default: rate_limit = "5/second"; break;
        }
        
        // Use nftables for consistency with blocking rules
        // First, remove any existing rate limit rule for this IP
        std::string remove_cmd = "nft delete rule inet filter input ip saddr " + ip + " limit rate " + rate_limit + " accept 2>/dev/null || true";
        std::system(remove_cmd.c_str());
        
        // Add new rate limiting rule to nftables
        std::string cmd = "nft insert rule inet filter input ip saddr " + ip + " limit rate " + rate_limit + " accept";
        
        int result = std::system(cmd.c_str());
        if (result == 0) {
            // Also add a drop rule after the rate limit
            std::string drop_cmd = "nft insert rule inet filter input ip saddr " + ip + " drop";
            std::system(drop_cmd.c_str());
        }
        return result == 0;
    #endif
}

void FirewallAction::initialize_default_whitelist() {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    
    // Add critical infrastructure and localhost only
    whitelist.insert("127.0.0.0/8");      // Localhost
    whitelist.insert("169.254.0.0/16");   // Link-local
    
    // Add DNS servers (Google, Cloudflare, OpenDNS)
    whitelist.insert("8.8.8.8");
    whitelist.insert("8.8.4.4");
    whitelist.insert("1.1.1.1");
    whitelist.insert("1.0.0.1");
    whitelist.insert("208.67.222.222");
    whitelist.insert("208.67.220.220");
    
    // Note: In production, you would typically whitelist your own private networks
    // but for testing purposes, we'll allow test IPs to be blocked
    // whitelist.insert("192.168.0.0/16");   // Private networks
    // whitelist.insert("10.0.0.0/8");       // Private networks
    // whitelist.insert("172.16.0.0/12");    // Private networks
}

void FirewallAction::add_to_whitelist(const std::string& ip_or_cidr) {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    whitelist.insert(ip_or_cidr);
    
    // If this IP was blocked, unblock it
    if (blocked_ips.find(ip_or_cidr) != blocked_ips.end()) {
        unblock(ip_or_cidr);
    }
}

void FirewallAction::remove_from_whitelist(const std::string& ip_or_cidr) {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    whitelist.erase(ip_or_cidr);
}

bool FirewallAction::is_whitelisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    
    // Check exact match first
    if (whitelist.find(ip) != whitelist.end()) {
        return true;
    }
    
    // Check CIDR matches
    for (const auto& cidr : whitelist) {
        if (is_cidr_match(ip, cidr)) {
            return true;
        }
    }
    
    return false;
}

bool FirewallAction::is_cidr_match(const std::string& ip, const std::string& cidr) const {
    // Simple CIDR matching implementation
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return ip == cidr; // Exact IP match
    }
    
    std::string network_ip = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
    
    struct sockaddr_in sa_ip, sa_net;
    inet_pton(AF_INET, ip.c_str(), &(sa_ip.sin_addr));
    inet_pton(AF_INET, network_ip.c_str(), &(sa_net.sin_addr));
    
    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    return (ntohl(sa_ip.sin_addr.s_addr) & mask) == (ntohl(sa_net.sin_addr.s_addr) & mask);
}

void FirewallAction::apply_adaptive_mitigation(const std::string& ip, const std::string& attack_type, double intensity) {
    if (is_whitelisted(ip)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    double threat_score = calculate_threat_score(ip, attack_type, intensity);
    MitigationStrategy strategy = determine_mitigation_strategy(ip, attack_type, intensity);
    int adaptive_timeout = calculate_adaptive_timeout(ip, threat_score);
    
    auto it = blocked_ips.find(ip);
    if (it == blocked_ips.end()) {
        // Create new entry with adaptive mitigation
        BlockInfo info = {};
        info.blocked_time = now;
        info.last_seen = now;
        info.is_blocked = (strategy == MitigationStrategy::TEMPORARY_BLOCK || strategy == MitigationStrategy::PERMANENT_BLOCK);
        info.rate_limit_level = (strategy == MitigationStrategy::RATE_LIMIT) ? static_cast<int>(intensity * 4) + 1 : 0;
        info.custom_block_duration = adaptive_timeout;
        info.strategy = strategy;
        info.threat_score = threat_score;
        info.violation_count = 1;
        info.attack_type = attack_type;
        info.is_repeat_offender = is_repeat_offender(ip);
        
        blocked_ips[ip] = info;
        
        // Execute the appropriate mitigation strategy
        execute_mitigation_strategy(ip, strategy);
        update_ip_reputation(ip, -static_cast<int>(threat_score * 20));
    } else {
        // Update existing entry with escalated response if needed
        if (threat_score > it->second.threat_score) {
            it->second.threat_score = threat_score;
            it->second.strategy = strategy;
            it->second.violation_count++;
            it->second.last_seen = now;
            it->second.attack_type = attack_type;
            
            execute_mitigation_strategy(ip, strategy);
        }
    }
}

MitigationStrategy FirewallAction::determine_mitigation_strategy(const std::string& ip, const std::string& attack_type, double intensity) {
    // Determine strategy based on attack type, intensity, and IP reputation
    int reputation = ip_reputation.find(ip) != ip_reputation.end() ? ip_reputation[ip] : 100;
    bool is_repeat = is_repeat_offender(ip);
    
    // Critical intensity or repeat offender -> immediate block
    if (intensity > 0.9 || is_repeat || reputation < 20) {
        return MitigationStrategy::PERMANENT_BLOCK;
    }
    
    // High intensity attacks
    if (intensity > 0.7) {
        if (attack_type == "syn_flood" || attack_type == "udp_flood") {
            return MitigationStrategy::TEMPORARY_BLOCK;
        }
        return MitigationStrategy::TARPIT;
    }
    
    // Medium intensity
    if (intensity > 0.4) {
        if (attack_type == "slowloris" || attack_type == "slow_post") {
            return MitigationStrategy::TARPIT;
        }
        return MitigationStrategy::RATE_LIMIT;
    }
    
    // Low intensity - challenge response for web attacks
    if (attack_type == "http_flood" || attack_type == "get_flood") {
        return MitigationStrategy::CHALLENGE_RESPONSE;
    }
    
    return MitigationStrategy::RATE_LIMIT;
}

int FirewallAction::calculate_adaptive_timeout(const std::string& ip, double threat_score) {
    int base_timeout = block_timeout;
    
    // Adjust timeout based on threat score and global attack intensity
    double multiplier = 1.0 + threat_score + (global_attack_intensity * 0.5);
    
    // Repeat offenders get longer timeouts
    if (is_repeat_offender(ip)) {
        multiplier *= 2.0;
    }
    
    // Consider current threat level
    switch (current_threat_level) {
        case ThreatLevel::CRITICAL:
            multiplier *= 3.0;
            break;
        case ThreatLevel::HIGH:
            multiplier *= 2.0;
            break;
        case ThreatLevel::MEDIUM:
            multiplier *= 1.5;
            break;
        default:
            break;
    }
    
    return static_cast<int>(base_timeout * multiplier);
}

double FirewallAction::calculate_threat_score(const std::string& ip, const std::string& attack_type, double intensity) {
    double base_score = intensity;
    
    // Adjust based on attack type severity
    if (attack_type == "syn_flood" || attack_type == "udp_flood") {
        base_score *= 1.2; // Volume attacks are more severe
    } else if (attack_type == "slowloris" || attack_type == "slow_post") {
        base_score *= 1.1; // Application layer attacks
    }
    
    // Consider IP reputation
    int reputation = ip_reputation.find(ip) != ip_reputation.end() ? ip_reputation[ip] : 100;
    double reputation_factor = (100.0 - reputation) / 100.0;
    base_score += reputation_factor * 0.3;
    
    // Repeat offender penalty
    if (is_repeat_offender(ip)) {
        base_score += 0.2;
    }
    
    return std::min(1.0, base_score);
}

bool FirewallAction::is_repeat_offender(const std::string& ip) {
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end()) {
        return it->second.violation_count >= 3 || it->second.is_repeat_offender;
    }
    return false;
}

void FirewallAction::update_ip_reputation(const std::string& ip, int reputation_change) {
    if (ip_reputation.find(ip) == ip_reputation.end()) {
        ip_reputation[ip] = 100; // Default reputation
    }
    
    ip_reputation[ip] = std::max(0, std::min(100, ip_reputation[ip] + reputation_change));
}

bool FirewallAction::execute_mitigation_strategy(const std::string& ip, MitigationStrategy strategy) {
    switch (strategy) {
        case MitigationStrategy::RATE_LIMIT:
            return execute_rate_limit_command(ip, 2); // Medium rate limit
        case MitigationStrategy::TARPIT:
            apply_tarpit(ip);
            return true;
        case MitigationStrategy::TEMPORARY_BLOCK:
            return execute_block_command(ip);
        case MitigationStrategy::PERMANENT_BLOCK:
            return execute_block_command(ip);
        case MitigationStrategy::CHALLENGE_RESPONSE:
            // Implement challenge-response mechanism using nftables
            #ifndef TESTING
            {
                // Redirect HTTP traffic from this IP to challenge server using nftables
                std::string cmd = "nft insert rule inet nat prerouting ip saddr " + ip + 
                                 " tcp dport 80 redirect to :8080";
                std::system(cmd.c_str());
            }
            #endif
            return true;
        case MitigationStrategy::GEO_BLOCK:
            // Implement geo-blocking if needed
            return execute_block_command(ip);
        default:
            return false;
    }
}

void FirewallAction::update_threat_level(ThreatLevel level) {
    current_threat_level = level;
    
    // Adjust global parameters based on threat level
    switch (level) {
        case ThreatLevel::CRITICAL:
            attack_detection_threshold = 0.3; // More sensitive
            max_violations_before_escalation = 2;
            break;
        case ThreatLevel::HIGH:
            attack_detection_threshold = 0.5;
            max_violations_before_escalation = 3;
            break;
        case ThreatLevel::MEDIUM:
            attack_detection_threshold = 0.6;
            max_violations_before_escalation = 4;
            break;
        case ThreatLevel::LOW:
            attack_detection_threshold = 0.7;
            max_violations_before_escalation = 5;
            break;
        default:
            attack_detection_threshold = 0.7;
            max_violations_before_escalation = 5;
            break;
    }
}

void FirewallAction::learn_legitimate_pattern(const std::string& port, double confidence) {
    if (!legitimate_traffic_learning_enabled) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(learning_mutex);
    
    if (legitimate_patterns.find(port) != legitimate_patterns.end()) {
        // Update existing pattern with exponential moving average
        legitimate_patterns[port] = 0.9 * legitimate_patterns[port] + 0.1 * confidence;
    } else {
        legitimate_patterns[port] = confidence;
    }
}

void FirewallAction::analyze_traffic_patterns(const std::vector<std::string>& recent_ips) {
    if (recent_ips.empty()) {
        return;
    }
    
    // Detect subnet-based attacks
    auto subnet_patterns = extract_subnet_patterns(recent_ips);
    
    // Update global attack intensity based on unique IP diversity
    std::unordered_set<std::string> unique_ips(recent_ips.begin(), recent_ips.end());
    double diversity_ratio = static_cast<double>(unique_ips.size()) / static_cast<double>(recent_ips.size());
    
    // Low diversity indicates botnet or coordinated attack
    if (diversity_ratio < 0.3) {
        global_attack_intensity = std::min(1.0, global_attack_intensity + 0.1);
    } else {
        global_attack_intensity = std::max(0.0, global_attack_intensity - 0.05);
    }
    
    // Auto-escalate threat level based on attack intensity
    if (global_attack_intensity > 0.8) {
        update_threat_level(ThreatLevel::CRITICAL);
    } else if (global_attack_intensity > 0.6) {
        update_threat_level(ThreatLevel::HIGH);
    } else if (global_attack_intensity > 0.4) {
        update_threat_level(ThreatLevel::MEDIUM);
    } else if (global_attack_intensity > 0.2) {
        update_threat_level(ThreatLevel::LOW);
    } else {
        update_threat_level(ThreatLevel::NONE);
    }
}

std::vector<std::string> FirewallAction::extract_subnet_patterns(const std::vector<std::string>& ips) {
    std::unordered_map<std::string, int> subnet_count;
    
    for (const auto& ip : ips) {
        // Extract /24 subnet
        size_t last_dot = ip.rfind('.');
        if (last_dot != std::string::npos) {
            std::string subnet = ip.substr(0, last_dot) + ".0/24";
            subnet_count[subnet]++;
        }
    }
    
    std::vector<std::string> suspicious_subnets;
    for (const auto& [subnet, count] : subnet_count) {
        if (count > 10) { // Threshold for suspicious subnet activity
            suspicious_subnets.push_back(subnet);
        }
    }
    
    return suspicious_subnets;
}

ThreatLevel FirewallAction::get_current_threat_level() const {
    return current_threat_level;
}

void FirewallAction::reset_adaptive_thresholds() {
    attack_detection_threshold = 0.7;
    max_violations_before_escalation = 5;
    current_threat_level = ThreatLevel::NONE;
    global_attack_intensity = 0.0;
    
    // Clear IP reputation for a fresh start
    ip_reputation.clear();
}