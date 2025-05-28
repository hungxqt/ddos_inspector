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
            blocked_ips[ip] = {now, true};
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