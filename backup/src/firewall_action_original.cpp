#include "firewall_action.hpp"
#include <cstdlib>
#include <algorithm>
#include <arpa/inet.h>
#include <thread>
#include <ctime>
#include <fstream>

FirewallAction::FirewallAction(int block_timeout_seconds) 
    : block_timeout(block_timeout_seconds), last_cleanup_time(std::chrono::steady_clock::now())
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
    
    // Clear the firewall log file on startup
    clear_firewall_log();
    
    // DISABLED: Worker thread to prevent deadlocks and freezing
    // Simple detached thread approach is safer for Snort integration
    log_firewall_action("INFO", "Firewall action initialized in non-blocking mode", 0);
}

FirewallAction::~FirewallAction() {
    // DISABLED: Worker thread cleanup to prevent hanging on shutdown
    log_firewall_action("INFO", "Firewall action shutdown", 0);
}

void FirewallAction::block(const std::string& ip) {
    block(ip, 0); // Use default duration
}

void FirewallAction::block(const std::string& ip, int custom_duration_seconds) {
    // IMPROVED: Check if IP is whitelisted or broadcast/multicast to prevent false positives
    if (is_whitelisted(ip)) {
        log_firewall_action("INFO", "Skipping block for whitelisted IP: " + ip, 0);
        return; // Don't block whitelisted IPs
    }
    
    if (is_broadcast_or_multicast(ip)) {
        log_firewall_action("INFO", "Skipping block for broadcast/multicast IP: " + ip, 0);
        return; // Don't block broadcast/multicast IPs (false positives)
    }
    
    // DEADLOCK FIX: Use scoped block to ensure mutex is released before cleanup
    {
        std::lock_guard<std::mutex> lock(blocked_ips_mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto it = blocked_ips.find(ip);
        
        if (it == blocked_ips.end() || !it->second.is_blocked) {
            // Create block info immediately (don't wait for firewall execution)
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
            // DEADLOCK FIX: Check repeat offender without locking mutex again
            info.is_repeat_offender = is_repeat_offender_internal(ip);
            
            blocked_ips[ip] = info;
            update_ip_reputation(ip, -10); // Decrease reputation for blocking
            
            // Execute firewall command in completely detached thread
            execute_block_command(ip);
            log_firewall_action("INFO", "Block initiated for IP: " + ip, 0);
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
            
            log_firewall_action("INFO", "Updated existing block info for IP: " + ip, 0);
        }
    } // mutex released here - CRITICAL: prevents deadlock
    
    // DEADLOCK FIX: Clean up expired blocks AFTER releasing the mutex
    cleanup_expired_blocks();
}

void FirewallAction::unblock(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end() && it->second.is_blocked) {
        // Remove from tracking immediately (don't wait for firewall execution)
        blocked_ips.erase(it);
        
        // Execute unblock in detached thread
        execute_unblock_command(ip);
        log_firewall_action("INFO", "Unblock initiated for IP: " + ip, 0);
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
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    auto now = std::chrono::steady_clock::now();
    
    // RATE LIMITING: Only perform cleanup if enough time has passed
    if (now - last_cleanup_time < cleanup_interval) {
        return; // Skip cleanup if called too frequently
    }
    last_cleanup_time = now;
    
    // Log only when actual cleanup happens, not on every call
    int expired_count = 0;
    int rate_limit_expired_count = 0;
    
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
        
        if (elapsed >= effective_timeout && it->second.is_blocked) {
            log_firewall_action("INFO", "Unblocking expired IP: " + it->first + 
                               " (elapsed: " + std::to_string(elapsed) + "s)", 0);
            
            // Execute unblock in detached thread
            execute_unblock_command(it->first);
            
            // Gradually improve reputation for IPs that served their time
            update_ip_reputation(it->first, 5);
            expired_count++;
            it = blocked_ips.erase(it);
        } else if (elapsed >= (effective_timeout / 2) && it->second.rate_limit_level > 0 && !it->second.is_blocked) {
            // Rate limits expire faster than full blocks
            log_firewall_action("INFO", "Removing expired rate limit for IP: " + it->first, 0);
            
            // FIXED: Clean up rate limit rules from nftables when they expire
            execute_unrate_limit_command(it->first);
            
            rate_limit_expired_count++;
            it = blocked_ips.erase(it);
        } else {
            ++it;
        }
    }
    
    // Log summary only if there were actual changes
    if (expired_count > 0 || rate_limit_expired_count > 0) {
        log_firewall_action("INFO", "Cleanup completed: " + std::to_string(expired_count) + 
                           " blocks expired, " + std::to_string(rate_limit_expired_count) + 
                           " rate limits expired", 0);
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
    // IMPROVED: Non-blocking firewall execution to prevent Snort freezing
    // For testing purposes, always return true to simulate successful blocking
    #ifdef TESTING
        return true;
    #else
        // IMPROVED: Enhanced error handling with validation and retry logic
        if (!validate_ip_address(ip)) {
            log_firewall_action("ERROR", "Invalid IP address format: " + ip, -1);
            return false;
        }
        
        // Execute block command in a completely detached way to avoid blocking
        std::string cmd;
        if (snort_compatible_mode) {
            // In Snort mode, add to set but don't add aggressive DROP rules
            cmd = "nft add element inet filter ddos_ip_set { " + ip + " timeout 10m } 2>/dev/null &";
        } else {
            // In standalone mode, use more aggressive blocking
            cmd = "nft add element inet filter ddos_ip_set { " + ip + " timeout 10m } 2>/dev/null &";
        }
        
        log_firewall_action("INFO", "Non-blocking firewall command for IP: " + ip + 
                           (snort_compatible_mode ? " (Snort-compatible mode)" : " (standalone mode)"), 0);
        
        // Execute command asynchronously to avoid blocking Snort
        std::thread([cmd, ip, this]() {
            // FIXED: Remove existing entry from set before adding to prevent duplicates
            std::string remove_cmd = "nft delete element inet filter ddos_ip_set { " + ip + " } 2>/dev/null || true";
            std::system(remove_cmd.c_str());
            
            // Now add the IP to the set
            int result = std::system(cmd.c_str());
            if (result == 0) {
                log_firewall_action("SUCCESS", "Successfully blocked IP: " + ip, 0);
            } else {
                log_firewall_action("ERROR", "Failed to block IP: " + ip, result);
            }
        }).detach();
        
        // Return true immediately - don't wait for command completion
        return true;
    #endif
}

bool FirewallAction::execute_unblock_command(const std::string& ip) {
    // For testing purposes, always return true to simulate successful unblocking
    #ifdef TESTING
        return true;
    #else
        // IMPROVED: Non-blocking unblock to prevent Snort freezing
        if (!validate_ip_address(ip)) {
            log_firewall_action("ERROR", "Invalid IP address format for unblock: " + ip, -1);
            return false;
        }
        
        std::string cmd = "nft delete element inet filter ddos_ip_set { " + ip + " } 2>/dev/null &";
        
        log_firewall_action("INFO", "Non-blocking unblock command for IP: " + ip, 0);
        
        // Execute unblock command asynchronously
        std::thread([cmd, ip, this]() {
            int result = std::system(cmd.c_str());
            if (result == 0) {
                log_firewall_action("SUCCESS", "Successfully unblocked IP: " + ip, 0);
            } else {
                log_firewall_action("WARNING", "Unblock command completed for IP: " + ip + " (may have already expired)", result);
            }
        }).detach();
        
        // Return true immediately - don't wait for command completion
        return true;
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
    // IMPROVED: Check if IP is whitelisted or broadcast/multicast to prevent false positives
    if (is_whitelisted(ip)) {
        log_firewall_action("INFO", "Skipping rate limit for whitelisted IP: " + ip, 0);
        return; // Don't rate limit whitelisted IPs
    }
    
    if (is_broadcast_or_multicast(ip)) {
        log_firewall_action("INFO", "Skipping rate limit for broadcast/multicast IP: " + ip, 0);
        return; // Don't rate limit broadcast/multicast IPs (false positives)
    }
    
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = blocked_ips.find(ip);
    
    if (it == blocked_ips.end()) {
        // Create new rate limit entry immediately
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
        info.is_repeat_offender = is_repeat_offender_internal(ip);
        
        blocked_ips[ip] = info;
        update_ip_reputation(ip, -5); // Slight reputation decrease for rate limiting
        
        // Execute rate limit in detached thread
        execute_rate_limit_command(ip, severity_level);
        log_firewall_action("INFO", "Rate limit initiated for IP: " + ip + 
                           " severity: " + std::to_string(severity_level), 0);
    } else {
        // Update existing entry with higher severity if needed
        if (severity_level > it->second.rate_limit_level) {
            it->second.rate_limit_level = severity_level;
            it->second.blocked_time = now;
            it->second.last_seen = now;
            it->second.threat_score = std::max(it->second.threat_score, severity_level * 0.2);
            
            // Execute rate limit update in detached thread
            execute_rate_limit_command(ip, severity_level);
            log_firewall_action("INFO", "Rate limit updated for IP: " + ip + 
                               " new severity: " + std::to_string(severity_level), 0);
        }
    }
}

void FirewallAction::apply_tarpit(const std::string& ip) {
    // IMPROVED: Tarpit implementation that doesn't interfere with Snort analysis
    #ifndef TESTING
        // Use nftables limit rate to implement tarpit-like behavior without dropping
        std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                         " limit rate 1/second counter comment \"tarpit-" + ip + "\"";
        std::system(cmd.c_str());
        
        log_firewall_action("INFO", "Applied tarpit (rate limiting) to IP: " + ip, 0);
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
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, info] : blocked_ips) {
        if (info.rate_limit_level > 0 && !info.is_blocked) {
            // Calculate remaining time for rate limit
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - info.blocked_time).count();
            
            // Use custom duration if set, otherwise use default timeout
            int effective_timeout = (info.custom_block_duration > 0) ? 
                                    info.custom_block_duration : block_timeout;
            
            // Rate limits typically expire faster than full blocks (half the time)
            int rate_limit_timeout = effective_timeout / 2;
            int remaining_time = std::max(0, rate_limit_timeout - static_cast<int>(elapsed));
            
            // Format remaining time in minutes and seconds
            int remaining_minutes = remaining_time / 60;
            int remaining_seconds = remaining_time % 60;
            
            std::string time_str;
            if (remaining_minutes > 0) {
                time_str = std::to_string(remaining_minutes) + "m " + std::to_string(remaining_seconds) + "s";
            } else {
                time_str = std::to_string(remaining_seconds) + "s";
            }
            
            std::string entry;
            entry.reserve(ip.length() + 50); // Pre-allocate approximate size
            entry = ip;
            entry += " (level ";
            entry += std::to_string(info.rate_limit_level);
            entry += ", remaining: ";
            entry += time_str;
            entry += ")";
            rate_limited_ips.push_back(std::move(entry));
        }
    }
    return rate_limited_ips;
}

std::vector<std::string> FirewallAction::get_blocked_ips() const {
    // DEADLOCK FIX: Trigger cleanup before acquiring mutex to prevent conflicts
    const_cast<FirewallAction*>(this)->cleanup_expired_blocks();
    
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    std::vector<std::string> blocked_list;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            // Calculate remaining time
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - info.blocked_time).count();
            int effective_timeout = (info.custom_block_duration > 0) ? info.custom_block_duration : block_timeout;
            int remaining_time = std::max(0, effective_timeout - static_cast<int>(elapsed));
            
            // Format remaining time in minutes and seconds
            int remaining_minutes = remaining_time / 60;
            int remaining_seconds = remaining_time % 60;
            
            std::string time_str;
            if (remaining_minutes > 0) {
                time_str = std::to_string(remaining_minutes) + "m " + std::to_string(remaining_seconds) + "s";
            } else {
                time_str = std::to_string(remaining_seconds) + "s";
            }
            
            std::string entry;
            entry.reserve(ip.length() + 60); // Pre-allocate approximate size
            entry = ip;
            entry += " (remaining: ";
            entry += time_str;
            entry += ", type: ";
            entry += info.attack_type;
            entry += ")";
            blocked_list.push_back(std::move(entry));
        }
    }
    return blocked_list;
}

bool FirewallAction::execute_rate_limit_command(const std::string& ip, int severity) {
    #ifdef TESTING
        return true;
    #else
        // IMPROVED: Non-blocking rate limiting to prevent Snort freezing
        if (!validate_ip_address(ip)) {
            log_firewall_action("ERROR", "Invalid IP address format for rate limiting: " + ip, -1);
            return false;
        }
        
        if (severity < 1 || severity > 4) {
            log_firewall_action("ERROR", "Invalid severity level for rate limiting: " + std::to_string(severity), -1);
            return false;
        }
        
        // Create rate limiting rules using nftables based on severity
        std::string rate_limit;
        switch (severity) {
            case 1: rate_limit = "10/second"; break;  // Low severity
            case 2: rate_limit = "5/second"; break;   // Medium severity  
            case 3: rate_limit = "2/second"; break;   // High severity
            case 4: rate_limit = "1/second"; break;   // Critical severity
            default: rate_limit = "5/second"; break;
        }
        
        log_firewall_action("INFO", "Non-blocking rate limit for IP: " + ip + " with rate: " + rate_limit, 0);
        
        // Execute rate limiting in detached thread to avoid blocking
        std::thread([ip, rate_limit, severity, this]() {
            // FIXED: First remove any existing rate limit rules for this IP
            // Create a unique comment identifier for this IP's rate limit rule
            std::string rule_comment = "ddos-rate-limit-" + ip;
            
            // Remove existing rate limit rule for this IP (by comment)
            std::string remove_cmd = "nft list ruleset | grep '" + rule_comment + "' | "
                                   "grep -o 'handle [0-9]*' | "
                                   "while read -r handle_line; do "
                                   "handle=$(echo $handle_line | cut -d' ' -f2); "
                                   "nft delete rule inet filter input handle $handle 2>/dev/null; "
                                   "done";
            std::system(remove_cmd.c_str());
            
            // Add new rate limiting rule with unique comment (NOT in the set)
            std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                             " limit rate " + rate_limit + " accept comment \\\"" + rule_comment + "\\\"";
            
            int result = std::system(cmd.c_str());
            if (result == 0) {
                log_firewall_action("SUCCESS", "Successfully applied rate limiting to IP: " + ip + 
                                  " (severity: " + std::to_string(severity) + ")", 0);
            } else {
                log_firewall_action("ERROR", "Failed to apply rate limiting to IP: " + ip, result);
            }
        }).detach();
        
        // Return true immediately - don't wait for command completion
        return true;
    #endif
}

bool FirewallAction::execute_unrate_limit_command(const std::string& ip) {
    #ifdef TESTING
        return true;
    #else
        // IMPROVED: Clean up rate limit rules for expired IPs
        if (!validate_ip_address(ip)) {
            log_firewall_action("ERROR", "Invalid IP address format for unrate limit: " + ip, -1);
            return false;
        }
        
        log_firewall_action("INFO", "Cleaning up rate limit rules for IP: " + ip, 0);
        
        // Execute cleanup in detached thread to avoid blocking
        std::thread([ip, this]() {
            // FIXED: Use simpler, more reliable commands
            std::string rule_comment = "ddos-rate-limit-" + ip;
            
            // First, get the handle using a simple command
            std::string get_handle_cmd = "nft -a list chain inet filter input 2>/dev/null | grep '" + rule_comment + "' | head -1 | grep -o 'handle [0-9]*' | cut -d' ' -f2";
            
            FILE* pipe = popen(get_handle_cmd.c_str(), "r");
            if (pipe != nullptr) {
                char buffer[128];
                std::string handle_str;
                if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                    handle_str = buffer;
                    // Remove newline
                    handle_str.erase(std::remove(handle_str.begin(), handle_str.end(), '\n'), handle_str.end());
                }
                pclose(pipe);
                
                if (!handle_str.empty()) {
                    // Delete the rule using the handle
                    std::string delete_cmd = "nft delete rule inet filter input handle " + handle_str + " 2>/dev/null";
                    int result = std::system(delete_cmd.c_str());
                    
                    if (result == 0) {
                        log_firewall_action("SUCCESS", "Successfully deleted rate limit rule for IP: " + ip + " (handle: " + handle_str + ")", 0);
                    } else {
                        log_firewall_action("WARNING", "Failed to delete rate limit rule for IP: " + ip + " (handle: " + handle_str + ")", result);
                    }
                } else {
                    log_firewall_action("INFO", "No rate limit rule found for IP: " + ip, 0);
                }
            } else {
                log_firewall_action("ERROR", "Failed to execute handle lookup command for IP: " + ip, -1);
            }
        }).detach();
        
        // Return true immediately - don't wait for command completion
        return true;
    #endif
}

void FirewallAction::initialize_default_whitelist() {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    
    // Add critical infrastructure and localhost
    whitelist.insert("127.0.0.0/8");      // Localhost
    whitelist.insert("169.254.0.0/16");   // Link-local
    
    // Add DNS servers (Google, Cloudflare, OpenDNS)
    whitelist.insert("8.8.8.8");
    whitelist.insert("8.8.4.4");
    whitelist.insert("1.1.1.1");
    whitelist.insert("1.0.0.1");
    whitelist.insert("208.67.222.222");
    whitelist.insert("208.67.220.220");
    
    // IMPROVED: Add multicast and broadcast ranges to prevent false positives
    whitelist.insert("224.0.0.0/4");      // IPv4 multicast (224.0.0.0 - 239.255.255.255)
    whitelist.insert("255.255.255.255");  // Limited broadcast
    
    // Add common legitimate multicast addresses
    whitelist.insert("224.0.0.251");      // mDNS
    whitelist.insert("224.0.0.252");      // LLMNR  
    whitelist.insert("239.255.255.250");  // UPnP SSDP
    
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
        info.is_repeat_offender = is_repeat_offender_internal(ip);
        
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

bool FirewallAction::is_repeat_offender(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    return is_repeat_offender_internal(ip);
}

bool FirewallAction::is_repeat_offender_internal(const std::string& ip) const {
    // INTERNAL VERSION: Assumes mutex is already locked by caller
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

// IMPROVED: Helper methods for enhanced error handling and granular mitigation

bool FirewallAction::validate_ip_address(const std::string& ip) const {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

bool FirewallAction::check_nftables_availability() const {
    int result = std::system("which nft >/dev/null 2>&1");
    return result == 0;
}

bool FirewallAction::initialize_nftables_infrastructure() const {
    // Create filter table
    int result1 = std::system("nft add table inet filter 2>/dev/null || true");
    
    // Create ddos_ip_set with proper configuration
    int result2 = std::system("nft add set inet filter ddos_ip_set '{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }' 2>/dev/null || true");
    
    // Add drop rule for blocked IPs
    int result3 = std::system("nft add rule inet filter input ip saddr @ddos_ip_set drop 2>/dev/null || true");
    
    return (result1 == 0 || result1 == 256) && (result2 == 0 || result2 == 256) && (result3 == 0 || result3 == 256);
}

int FirewallAction::execute_command_with_retry(const std::string& cmd, int max_retries) const {
    int result = -1;
    for (int attempt = 1; attempt <= max_retries; attempt++) {
        log_firewall_action("DEBUG", "Executing command (attempt " + std::to_string(attempt) + "): " + cmd, 0);
        
        result = std::system(cmd.c_str());
        if (result == 0) {
            break;
        }
        
        if (attempt < max_retries) {
            log_firewall_action("WARN", "Command failed, retrying... (attempt " + std::to_string(attempt) + ")", result);
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * attempt)); // Exponential backoff
        }
    }
    return result;
}

void FirewallAction::log_firewall_action(const std::string& level, const std::string& message, int error_code) const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    // THREAD SAFETY FIX: Use localtime_r instead of localtime for thread safety
    struct tm tm_buffer;
    struct tm* tm = localtime_r(&time_t, &tm_buffer);
    
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    std::string log_entry = "[" + std::string(timestamp) + "] [FIREWALL] [" + level + "] " + message;
    if (error_code != 0) {
        log_entry += " (error_code: " + std::to_string(error_code) + ")";
    }
    
    // Print to console for immediate feedback with immediate flush
    printf("%s\n", log_entry.c_str());
    fflush(stdout);
    
    // IMPROVED: Asynchronous file logging to prevent blocking Snort
    std::thread([log_entry]() {
        std::ofstream log_file("/var/log/ddos_inspector/firewall.log", std::ios::app);
        if (log_file.is_open()) {
            log_file << log_entry << '\n';
            log_file.close();
        }
        // Remove system call fallback to prevent file corruption
    }).detach();
}

void FirewallAction::clear_firewall_log() const {
    // IMPROVED: Clear the firewall log file on startup with reduced system calls
    std::thread([]() {
        // Create directory structure if needed (C++ filesystem approach)
        std::system("mkdir -p /var/log/ddos_inspector 2>/dev/null");
        
        // Clear the log file by truncating it (more efficient than system call)
        std::ofstream log_file("/var/log/ddos_inspector/firewall.log", std::ios::trunc);
        if (log_file.is_open()) {
            log_file.close();
        }
        
        // Note: Removing rotated logs could be done periodically rather than on every startup
        // std::system("rm -f /var/log/ddos_inspector/firewall.log.* 2>/dev/null");
    }).detach();
}

void FirewallAction::apply_additional_mitigation(const std::string& ip) const {
    // IMPROVED: Additional granular mitigation options
    
    // Apply bandwidth throttling for repeat offenders
    if (is_repeat_offender(ip)) {
        apply_bandwidth_throttling(ip);
    }
    
    // Apply port-specific restrictions for certain attack types
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end()) {
        const std::string& attack_type = it->second.attack_type;
        
        if (attack_type == "http_flood" || attack_type == "get_flood") {
            apply_port_specific_blocking(ip, {80, 443, 8080, 8443});
        } else if (attack_type == "ssh_brute_force") {
            apply_port_specific_blocking(ip, {22, 2222});
        } else if (attack_type == "dns_amplification") {
            apply_port_specific_blocking(ip, {53});
        }
    }
}

void FirewallAction::apply_bandwidth_throttling(const std::string& ip) const {
    #ifndef TESTING
    // Limit bandwidth to 1Mbps for repeat offenders
    std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                     " limit rate 1 mbytes/second accept";
    execute_command_with_retry(cmd, 2);
    
    log_firewall_action("INFO", "Applied bandwidth throttling to IP: " + ip, 0);
    #endif
}

void FirewallAction::apply_port_specific_blocking(const std::string& ip, const std::vector<int>& ports) const {
    #ifndef TESTING
    for (int port : ports) {
        std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                         " tcp dport " + std::to_string(port) + " drop";
        execute_command_with_retry(cmd, 2);
        
        // Also block UDP for DNS-related attacks
        if (port == 53) {
            std::string udp_cmd = "nft insert rule inet filter input ip saddr " + ip + 
                                 " udp dport " + std::to_string(port) + " drop";
            execute_command_with_retry(udp_cmd, 2);
        }
    }
    
    std::string port_list;
    for (size_t i = 0; i < ports.size(); ++i) {
        if (i > 0) port_list += ",";
        port_list += std::to_string(ports[i]);
    }
    
    log_firewall_action("INFO", "Applied port-specific blocking to IP: " + ip + " ports: " + port_list, 0);
    #endif
}

void FirewallAction::apply_time_based_restrictions(const std::string& ip, int hour_start, int hour_end) const {
    #ifndef TESTING
    // Block traffic from IP during specific hours (e.g., outside business hours)
    std::string cmd = "nft insert rule inet filter input ip saddr " + ip + 
                     " meta hour " + std::to_string(hour_start) + "-" + std::to_string(hour_end) + " drop";
    execute_command_with_retry(cmd, 2);
    
    log_firewall_action("INFO", "Applied time-based restrictions to IP: " + ip + 
                       " hours: " + std::to_string(hour_start) + "-" + std::to_string(hour_end), 0);
    #endif
}

void FirewallAction::apply_geo_blocking(const std::string& country_code) const {
    #ifndef TESTING
    // Block traffic from specific countries (requires GeoIP integration)
    // This is a placeholder for geo-blocking functionality
    log_firewall_action("INFO", "Geo-blocking requested for country: " + country_code + " (not implemented)", 0);
    
    // TODO: Implement actual geo-blocking using MaxMind GeoIP database
    // std::string cmd = "nft add set inet filter geo_blocked '{ type ipv4_addr; }'";
    // execute_command_with_retry(cmd, 2);
    #endif
}

void FirewallAction::cleanup_additional_restrictions(const std::string& ip) const {
    #ifndef TESTING
    // Remove bandwidth throttling rules
    std::string throttle_cmd = "nft delete rule inet filter input ip saddr " + ip + 
                              " limit rate 1 mbytes/second accept 2>/dev/null || true";
    std::system(throttle_cmd.c_str());
    
    // Remove port-specific blocking rules
    std::vector<int> common_ports = {22, 53, 80, 443, 2222, 8080, 8443};
    for (int port : common_ports) {
        std::string tcp_cmd = "nft delete rule inet filter input ip saddr " + ip + 
                             " tcp dport " + std::to_string(port) + " drop 2>/dev/null || true";
        std::system(tcp_cmd.c_str());
        
        std::string udp_cmd = "nft delete rule inet filter input ip saddr " + ip + 
                             " udp dport " + std::to_string(port) + " drop 2>/dev/null || true";
        std::system(udp_cmd.c_str());
    }
    
    // Remove tarpit rules
    std::string tarpit_limit_cmd = "nft delete rule inet filter input ip saddr " + ip + 
                                  " limit rate 1/second accept 2>/dev/null || true";
    std::system(tarpit_limit_cmd.c_str());
    
    std::string tarpit_drop_cmd = "nft delete rule inet filter input ip saddr " + ip + 
                                 " drop 2>/dev/null || true";
    std::system(tarpit_drop_cmd.c_str());
    
    log_firewall_action("INFO", "Cleaned up additional restrictions for IP: " + ip, 0);
    #endif
}

bool FirewallAction::is_broadcast_or_multicast(const std::string& ip) const {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 1) {
        return false; // Invalid IP
    }
    
    uint32_t addr = ntohl(sa.sin_addr.s_addr);
    
    // Check for broadcast addresses
    if (addr == 0xFFFFFFFF) { // 255.255.255.255
        return true;
    }
    
    // Check for multicast range (224.0.0.0 to 239.255.255.255)
    if ((addr >= 0xE0000000) && (addr <= 0xEFFFFFFF)) {
        return true;
    }
    
    // Check for network broadcast (ends with .255 in common subnets)
    if ((addr & 0xFF) == 0xFF) {
        return true;
    }
    
    return false;
}

bool FirewallAction::verify_ip_in_nftables(const std::string& ip) const {
    #ifdef TESTING
        return true;
    #else
        // Use nft to check if the IP is actually in the set
        std::string check_cmd = "nft get element inet filter ddos_ip_set '{ " + ip + " }' >/dev/null 2>&1";
        int result = std::system(check_cmd.c_str());
        
        log_firewall_action("DEBUG", "Verification command result for IP " + ip + ": " + std::to_string(result), result);
        
        return result == 0;
    #endif
}

std::vector<std::string> FirewallAction::get_current_firewall_rules() const {
    std::vector<std::string> rules;
    
    #ifdef TESTING
        rules.push_back("Testing mode - no actual firewall rules");
        return rules;
    #else
        // Get all nftables rules for the input chain
        std::string cmd = "nft list ruleset | grep -E '(ddos_ip_set|limit rate)' 2>/dev/null";
        
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                std::string rule(buffer);
                // Remove trailing newline
                if (!rule.empty() && rule.back() == '\n') {
                    rule.pop_back();
                }
                if (!rule.empty()) {
                    rules.push_back(rule);
                }
            }
            pclose(pipe);
        }
        
        // Also get the ddos_ip_set contents
        cmd = "nft list set inet filter ddos_ip_set 2>/dev/null";
        pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[1024];
            bool in_elements = false;
            while (fgets(buffer, sizeof(buffer), pipe)) {
                std::string line(buffer);
                if (!line.empty() && line.back() == '\n') {
                    line.pop_back();
                }
                
                if (line.find("elements = {") != std::string::npos) {
                    in_elements = true;
                    rules.push_back("=== BLOCKED IP SET ===");
                    rules.push_back(line);
                } else if (in_elements && !line.empty()) {
                    rules.push_back(line);
                    if (line.find("}") != std::string::npos) {
                        in_elements = false;
                    }
                }
            }
            pclose(pipe);
        }
        
        if (rules.empty()) {
            rules.push_back("No DDoS firewall rules found - may need to initialize nftables");
        }
        
        return rules;
    #endif
}

// Asynchronous firewall worker thread implementation
