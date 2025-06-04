#include "firewall_action.hpp"
#include <cstdlib>

FirewallAction::FirewallAction(int block_timeout_seconds) 
    : block_timeout(block_timeout_seconds)
{
}

FirewallAction::~FirewallAction() = default;

void FirewallAction::block(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = blocked_ips.find(ip);
    
    if (it == blocked_ips.end() || !it->second.is_blocked) {
        // Block new IP or re-block expired IP
        if (execute_block_command(ip)) {
            blocked_ips[ip] = {now, true, 0};  // Initialize all fields including rate_limit_level
        }
    } else {
        // Update timestamp for already blocked IP
        blocked_ips[ip].blocked_time = now;
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
            
        if (elapsed > block_timeout && it->second.is_blocked) {
            if (execute_unblock_command(it->first)) {
                it = blocked_ips.erase(it);
            } else {
                ++it;
            }
        } else {
            ++it;
        }
    }
}

bool FirewallAction::execute_block_command(const std::string& ip) {
    // For testing purposes, always return true to simulate successful blocking
    // In production, this would execute actual firewall commands
    #ifdef TESTING
        return true;
    #else
        // Ensure nftables infrastructure exists before blocking
        std::system("nft add table inet filter 2>/dev/null || true");
        std::system("nft add set inet filter ddos_ip_set '{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }' 2>/dev/null || true");
        std::system("nft add rule inet filter input ip saddr @ddos_ip_set drop 2>/dev/null || true");
        
        // Now block the IP
        std::string cmd = "nft add element inet filter ddos_ip_set { " + ip + " } 2>/dev/null || "
                         "iptables -I INPUT -s " + ip + " -j DROP 2>/dev/null";
        
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
        std::string cmd = "nft delete element inet filter ddos_ip_set { " + ip + " } 2>/dev/null || "
                         "iptables -D INPUT -s " + ip + " -j DROP 2>/dev/null";
        
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
    
    // Check if the block has expired
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second.blocked_time).count();
    
    return it->second.is_blocked && (elapsed <= block_timeout);
}

void FirewallAction::rate_limit(const std::string& ip, int severity_level) {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = blocked_ips.find(ip);
    
    if (it == blocked_ips.end() || it->second.rate_limit_level < severity_level) {
        // Apply new rate limit or upgrade existing one
        if (execute_rate_limit_command(ip, severity_level)) {
            blocked_ips[ip] = {now, false, severity_level};
        }
    } else {
        // Update timestamp for existing rate limit
        blocked_ips[ip].blocked_time = now;
    }
    
    cleanup_expired_blocks();
}

bool FirewallAction::is_rate_limited(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it == blocked_ips.end()) {
        return false;
    }
    
    // Check if the rate limit has expired
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second.blocked_time).count();
    
    return !it->second.is_blocked && it->second.rate_limit_level > 0 && (elapsed <= block_timeout);
}

size_t FirewallAction::get_rate_limited_count() const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : blocked_ips) {
        if (!info.is_blocked && info.rate_limit_level > 0) {
            count++;
        }
    }
    return count;
}

bool FirewallAction::execute_rate_limit_command(const std::string& ip, int severity) {
    #ifdef TESTING
        return true;
    #else
        // Rate limiting based on severity level
        std::string rate_limit;
        switch (severity) {
            case 1: rate_limit = "100/sec"; break;   // Low severity
            case 2: rate_limit = "50/sec"; break;    // Medium severity  
            case 3: rate_limit = "10/sec"; break;    // High severity
            case 4: rate_limit = "1/sec"; break;     // Critical severity
            default: rate_limit = "100/sec"; break;
        }
        
        std::string cmd = "nft add rule inet filter input ip saddr " + ip + 
                         " limit rate " + rate_limit + " accept 2>/dev/null || "
                         "iptables -I INPUT -s " + ip + " -m limit --limit " + 
                         rate_limit + " -j ACCEPT 2>/dev/null";
        
        int result = std::system(cmd.c_str());
        return result == 0;
    #endif
}