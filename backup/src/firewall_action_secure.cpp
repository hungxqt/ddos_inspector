#include "firewall_action.hpp"
#include <cstdlib>
#include <algorithm>
#include <arpa/inet.h>
#include <thread>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <iostream>

FirewallAction::FirewallAction(int block_timeout_seconds) 
    : block_timeout(block_timeout_seconds), 
      last_cleanup_time(std::chrono::steady_clock::now()),
      worker_thread(&FirewallAction::worker_thread_main, this),
      logger_thread(&FirewallAction::logger_thread_main, this)
{
    // SECURITY FIX: Initialize IP validation patterns
    ipv4_pattern = std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    ipv6_pattern = std::regex("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$");
    
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
    
    // SECURITY FIX: Drop privileges to minimal required capabilities
    drop_privileges();
    
    enqueue_log("INFO", "Firewall action initialized with secure worker queue system");
}

FirewallAction::~FirewallAction() {
    // Shutdown worker threads safely
    worker_running = false;
    logger_running = false;
    
    queue_cv.notify_all();
    log_cv.notify_all();
    
    if (worker_thread.joinable()) {
        worker_thread.join();
    }
    if (logger_thread.joinable()) {
        logger_thread.join();
    }
    
    enqueue_log("INFO", "Firewall action shutdown complete");
}

void FirewallAction::block(const std::string& ip) {
    block(ip, 0); // Use default duration
}

void FirewallAction::block(const std::string& ip, int custom_duration_seconds) {
    // SECURITY FIX: Strict input validation
    if (!validate_ip_address_strict(ip)) {
        enqueue_log("ERROR", "Invalid IP address format for blocking: " + ip);
        return;
    }
    
    // IMPROVED: Check if IP is whitelisted or broadcast/multicast to prevent false positives
    if (is_whitelisted(ip)) {
        enqueue_log("INFO", "Skipping block for whitelisted IP: " + ip);
        return;
    }
    
    if (is_broadcast_or_multicast(ip)) {
        enqueue_log("INFO", "Skipping block for broadcast/multicast IP: " + ip);
        return;
    }
    
    // DEADLOCK FIX: Use scoped block to ensure mutex is released before cleanup
    {
        std::unique_lock<std::shared_mutex> lock(blocked_ips_mutex);
        
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
            
            // PERFORMANCE FIX: Use worker queue instead of spawning thread
            enqueue_job(FirewallJob(JobType::BLOCK_IP, ip));
            enqueue_log("INFO", "Block initiated for IP: " + ip);
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
            
            enqueue_log("INFO", "Updated existing block info for IP: " + ip);
        }
    } // mutex released here - CRITICAL: prevents deadlock
    
    // Update IP reputation in thread-safe manner
    {
        std::lock_guard<std::mutex> lock(ip_reputation_mutex);
        update_ip_reputation(ip, -10); // Decrease reputation for blocking
    }
    
    // DEADLOCK FIX: Clean up expired blocks AFTER releasing the mutex
    cleanup_expired_blocks();
}

void FirewallAction::unblock(const std::string& ip) {
    // SECURITY FIX: Strict input validation
    if (!validate_ip_address_strict(ip)) {
        enqueue_log("ERROR", "Invalid IP address format for unblocking: " + ip);
        return;
    }
    
    std::unique_lock<std::shared_mutex> lock(blocked_ips_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end() && it->second.is_blocked) {
        // Remove from tracking immediately (don't wait for firewall execution)
        blocked_ips.erase(it);
        
        // PERFORMANCE FIX: Use worker queue instead of spawning thread
        enqueue_job(FirewallJob(JobType::UNBLOCK_IP, ip));
        enqueue_log("INFO", "Unblock initiated for IP: " + ip);
    }
}

void FirewallAction::rate_limit(const std::string& ip, int severity_level) {
    // SECURITY FIX: Strict input validation
    if (!validate_ip_address_strict(ip)) {
        enqueue_log("ERROR", "Invalid IP address format for rate limiting: " + ip);
        return;
    }
    
    if (severity_level < 1 || severity_level > 4) {
        enqueue_log("ERROR", "Invalid severity level for rate limiting: " + std::to_string(severity_level));
        return;
    }
    
    // IMPROVED: Check if IP is whitelisted or broadcast/multicast to prevent false positives
    if (is_whitelisted(ip)) {
        enqueue_log("INFO", "Skipping rate limit for whitelisted IP: " + ip);
        return;
    }
    
    if (is_broadcast_or_multicast(ip)) {
        enqueue_log("INFO", "Skipping rate limit for broadcast/multicast IP: " + ip);
        return;
    }
    
    std::unique_lock<std::shared_mutex> lock(blocked_ips_mutex);
    
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
        
        // PERFORMANCE FIX: Use worker queue
        enqueue_job(FirewallJob(JobType::RATE_LIMIT_IP, ip, severity_level));
        enqueue_log("INFO", "Rate limit initiated for IP: " + ip + 
                   " severity: " + std::to_string(severity_level));
    } else {
        // Update existing entry with higher severity if needed
        if (severity_level > it->second.rate_limit_level) {
            it->second.rate_limit_level = severity_level;
            it->second.blocked_time = now;
            it->second.last_seen = now;
            it->second.threat_score = std::max(it->second.threat_score, severity_level * 0.2);
            
            // PERFORMANCE FIX: Use worker queue
            enqueue_job(FirewallJob(JobType::RATE_LIMIT_IP, ip, severity_level));
            enqueue_log("INFO", "Rate limit updated for IP: " + ip + 
                       " new severity: " + std::to_string(severity_level));
        }
    }
    
    // Update IP reputation in thread-safe manner
    {
        std::lock_guard<std::mutex> lock(ip_reputation_mutex);
        update_ip_reputation(ip, -5); // Slight reputation decrease for rate limiting
    }
}

// PERFORMANCE FIX: Worker thread implementation
void FirewallAction::worker_thread_main() {
    while (worker_running) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        queue_cv.wait(lock, [this] { return !job_queue.empty() || !worker_running; });
        
        if (!worker_running) break;
        
        while (!job_queue.empty()) {
            FirewallJob job = job_queue.front();
            job_queue.pop();
            lock.unlock();
            
            process_job(job);
            
            lock.lock();
        }
    }
}

// SECURITY FIX: Async logging implementation
void FirewallAction::logger_thread_main() {
    while (logger_running) {
        std::unique_lock<std::mutex> lock(log_mutex);
        log_cv.wait(lock, [this] { return !log_queue.empty() || !logger_running; });
        
        if (!logger_running) break;
        
        while (!log_queue.empty()) {
            std::string log_entry = log_queue.front();
            log_queue.pop();
            lock.unlock();
            
            // Write to console immediately
            printf("%s\n", log_entry.c_str());
            fflush(stdout);
            
            // Write to file
            std::ofstream log_file("/var/log/ddos_inspector/firewall.log", std::ios::app);
            if (log_file.is_open()) {
                log_file << log_entry << '\n';
                log_file.close();
            }
            
            lock.lock();
        }
    }
}

void FirewallAction::enqueue_job(const FirewallJob& job) {
    std::lock_guard<std::mutex> lock(queue_mutex);
    job_queue.push(job);
    queue_cv.notify_one();
}

void FirewallAction::enqueue_log(const std::string& level, const std::string& message, int error_code) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    struct tm tm_buffer;
    struct tm* tm = localtime_r(&time_t, &tm_buffer);
    
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    std::string log_entry = "[" + std::string(timestamp) + "] [FIREWALL] [" + level + "] " + message;
    if (error_code != 0) {
        log_entry += " (error_code: " + std::to_string(error_code) + ")";
    }
    
    std::lock_guard<std::mutex> lock(log_mutex);
    log_queue.push(log_entry);
    log_cv.notify_one();
}

void FirewallAction::process_job(const FirewallJob& job) {
    IPFamily family = detect_ip_family(job.ip);
    
    switch (job.type) {
        case JobType::BLOCK_IP:
            execute_block_command_safe(job.ip, family);
            break;
        case JobType::UNBLOCK_IP:
            execute_unblock_command_safe(job.ip, family);
            break;
        case JobType::RATE_LIMIT_IP:
            execute_rate_limit_command_safe(job.ip, job.severity, family);
            break;
        case JobType::UNRATE_LIMIT_IP:
            execute_unrate_limit_command_safe(job.ip, family);
            break;
        case JobType::LOG_MESSAGE:
            // Already handled by logger thread
            break;
    }
}

// SECURITY FIX: Safe command execution using execvp instead of system()
bool FirewallAction::execute_block_command_safe(const std::string& ip, IPFamily family) {
    #ifdef TESTING
        return true;
    #else
        if (!validate_ip_address_strict(ip)) {
            enqueue_log("ERROR", "Invalid IP address format: " + ip);
            return false;
        }
        
        const char* ip_type = (family == IPFamily::IPv6) ? "ipv6_addr" : "ipv4_addr";
        const char* set_name = (family == IPFamily::IPv6) ? "ddos_ipv6_set" : "ddos_ip_set";
        
        // Create the command arguments safely
        std::vector<const char*> args = {
            "nft",
            "add",
            "element",
            "inet",
            "filter",
            set_name,
            NULL, // Will be filled with formatted IP
            NULL
        };
        
        // Format IP safely for nftables
        std::string ip_element = "{ " + ip + " timeout 10m }";
        args[6] = ip_element.c_str();
        
        pid_t pid = fork();
        if (pid == 0) {
            // Child process - execute nft command
            execvp("nft", const_cast<char* const*>(args.data()));
            _exit(127); // execvp failed
        } else if (pid > 0) {
            // Parent process - wait for completion
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                enqueue_log("SUCCESS", "Successfully blocked IP: " + ip);
                return true;
            } else {
                enqueue_log("ERROR", "Failed to block IP: " + ip, WEXITSTATUS(status));
                return false;
            }
        } else {
            enqueue_log("ERROR", "Failed to fork process for blocking IP: " + ip);
            return false;
        }
    #endif
}

bool FirewallAction::execute_unblock_command_safe(const std::string& ip, IPFamily family) {
    #ifdef TESTING
        return true;
    #else
        if (!validate_ip_address_strict(ip)) {
            enqueue_log("ERROR", "Invalid IP address format for unblock: " + ip);
            return false;
        }
        
        const char* set_name = (family == IPFamily::IPv6) ? "ddos_ipv6_set" : "ddos_ip_set";
        
        std::vector<const char*> args = {
            "nft",
            "delete",
            "element",
            "inet",
            "filter",
            set_name,
            NULL, // Will be filled with IP
            NULL
        };
        
        std::string ip_element = "{ " + ip + " }";
        args[6] = ip_element.c_str();
        
        pid_t pid = fork();
        if (pid == 0) {
            execvp("nft", const_cast<char* const*>(args.data()));
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                enqueue_log("SUCCESS", "Successfully unblocked IP: " + ip);
                return true;
            } else {
                enqueue_log("WARNING", "Unblock command completed for IP: " + ip + " (may have already expired)", WEXITSTATUS(status));
                return false;
            }
        } else {
            enqueue_log("ERROR", "Failed to fork process for unblocking IP: " + ip);
            return false;
        }
    #endif
}

// SECURITY FIX: Strict IP validation
bool FirewallAction::validate_ip_address_strict(const std::string& ip) const {
    // Check for empty or too long input
    if (ip.empty() || ip.length() > 45) { // Max IPv6 length is 39, add buffer
        return false;
    }
    
    // SECURITY FIX: Check for shell metacharacters
    if (!sanitize_input(ip)) {
        return false;
    }
    
    // Check IPv4 pattern
    if (std::regex_match(ip, ipv4_pattern)) {
        return true;
    }
    
    // Check IPv6 pattern  
    if (std::regex_match(ip, ipv6_pattern)) {
        return true;
    }
    
    return false;
}

IPFamily FirewallAction::detect_ip_family(const std::string& ip) const {
    if (std::regex_match(ip, ipv4_pattern)) {
        return IPFamily::IPv4;
    } else if (std::regex_match(ip, ipv6_pattern)) {
        return IPFamily::IPv6;
    }
    return IPFamily::IPv4; // Default fallback
}

bool FirewallAction::sanitize_input(const std::string& input) const {
    // SECURITY FIX: Check for shell injection characters
    const std::string dangerous_chars = ";&|`$(){}[]<>*?!'\"\\\\\\n\\r\\t";
    return input.find_first_of(dangerous_chars) == std::string::npos;
}

// SECURITY FIX: Privilege management
void FirewallAction::drop_privileges() {
    #ifndef TESTING
    // Drop to minimal required capabilities (CAP_NET_ADMIN only)
    cap_t caps = cap_init();
    if (caps == NULL) {
        enqueue_log("WARNING", "Failed to initialize capabilities");
        return;
    }
    
    cap_value_t cap_list[] = { CAP_NET_ADMIN };
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_SET) == -1) {
        enqueue_log("WARNING", "Failed to set capabilities");
        cap_free(caps);
        return;
    }
    
    if (cap_set_proc(caps) == -1) {
        enqueue_log("WARNING", "Failed to apply capabilities");
    } else {
        enqueue_log("INFO", "Successfully dropped privileges to CAP_NET_ADMIN only");
    }
    
    cap_free(caps);
    #endif
}

void FirewallAction::restore_privileges() {
    // Implementation for restoring privileges if needed
    // Usually not required for firewall operations
}

// PERFORMANCE FIX: Rate limit command execution
bool FirewallAction::execute_rate_limit_command_safe(const std::string& ip, int severity, IPFamily family) {
    #ifdef TESTING
        return true;
    #else
        if (!validate_ip_address_strict(ip)) {
            enqueue_log("ERROR", "Invalid IP address format for rate limiting: " + ip);
            return false;
        }
        
        if (severity < 1 || severity > 4) {
            enqueue_log("ERROR", "Invalid severity level for rate limiting: " + std::to_string(severity));
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
        
        std::string rule_comment = "ddos-rate-limit-" + ip;
        
        // SECURITY FIX: Use safe command construction
        std::vector<const char*> args = {
            "nft",
            "insert",
            "rule",
            "inet",
            "filter",
            "input",
            "ip",
            "saddr",
            NULL, // ip
            "limit",
            "rate",
            NULL, // rate_limit
            "accept",
            "comment",
            NULL, // rule_comment
            NULL
        };
        
        args[8] = ip.c_str();
        args[11] = rate_limit.c_str();
        args[14] = rule_comment.c_str();
        
        pid_t pid = fork();
        if (pid == 0) {
            execvp("nft", const_cast<char* const*>(args.data()));
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                enqueue_log("SUCCESS", "Successfully applied rate limiting to IP: " + ip + 
                          " (severity: " + std::to_string(severity) + ")");
                return true;
            } else {
                enqueue_log("ERROR", "Failed to apply rate limiting to IP: " + ip, WEXITSTATUS(status));
                return false;
            }
        } else {
            enqueue_log("ERROR", "Failed to fork process for rate limiting IP: " + ip);
            return false;
        }
    #endif
}

bool FirewallAction::execute_unrate_limit_command_safe(const std::string& ip, IPFamily family) {
    #ifdef TESTING
        return true;
    #else
        if (!validate_ip_address_strict(ip)) {
            enqueue_log("ERROR", "Invalid IP address format for unrate limit: " + ip);
            return false;
        }
        
        enqueue_log("INFO", "Cleaning up rate limit rules for IP: " + ip);
        
        // SECURITY FIX: Use safe JSON parsing instead of grep/cut
        std::string rule_comment = "ddos-rate-limit-" + ip;
        
        std::vector<const char*> list_args = {
            "nft",
            "-j",  // JSON output for safe parsing
            "list",
            "chain",
            "inet",
            "filter",
            "input",
            NULL
        };
        
        // TODO: Implement proper JSON parsing here
        // For now, fall back to the safer approach
        std::vector<const char*> delete_args = {
            "nft",
            "delete",
            "rule",
            "inet",
            "filter",
            "input",
            "ip",
            "saddr",
            NULL, // ip
            "limit",
            "rate",
            "*",
            "accept",
            NULL
        };
        
        delete_args[8] = ip.c_str();
        
        pid_t pid = fork();
        if (pid == 0) {
            execvp("nft", const_cast<char* const*>(delete_args.data()));
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                enqueue_log("SUCCESS", "Successfully deleted rate limit rule for IP: " + ip);
                return true;
            } else {
                enqueue_log("INFO", "No rate limit rule found for IP: " + ip);
                return false;
            }
        } else {
            enqueue_log("ERROR", "Failed to fork process for unrate limiting IP: " + ip);
            return false;
        }
    #endif
}

// Core query methods with thread safety fixes
bool FirewallAction::is_blocked(const std::string& ip) const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_mutex);
    
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
    std::shared_lock<std::shared_mutex> lock(blocked_ips_mutex);
    
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

size_t FirewallAction::get_blocked_count() const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            count++;
        }
    }
    return count;
}

size_t FirewallAction::get_rate_limited_count() const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.rate_limit_level > 0 && !info.is_blocked) {
            count++;
        }
    }
    return count;
}

// THREAD SAFETY FIX: Remove const_cast and make cleanup safe
void FirewallAction::cleanup_expired_blocks() {
    std::unique_lock<std::shared_mutex> lock(blocked_ips_mutex);
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
            enqueue_log("INFO", "Unblocking expired IP: " + it->first + 
                       " (elapsed: " + std::to_string(elapsed) + "s)");
            
            // Use worker queue for unblock
            enqueue_job(FirewallJob(JobType::UNBLOCK_IP, it->first));
            
            // Update reputation
            {
                std::lock_guard<std::mutex> rep_lock(ip_reputation_mutex);
                update_ip_reputation(it->first, 5);
            }
            expired_count++;
            it = blocked_ips.erase(it);
        } else if (elapsed >= (effective_timeout / 2) && it->second.rate_limit_level > 0 && !it->second.is_blocked) {
            // Rate limits expire faster than full blocks
            enqueue_log("INFO", "Removing expired rate limit for IP: " + it->first);
            
            // Use worker queue for cleanup
            enqueue_job(FirewallJob(JobType::UNRATE_LIMIT_IP, it->first));
            
            rate_limit_expired_count++;
            it = blocked_ips.erase(it);
        } else {
            ++it;
        }
    }
    
    // Log summary only if there were actual changes
    if (expired_count > 0 || rate_limit_expired_count > 0) {
        enqueue_log("INFO", "Cleanup completed: " + std::to_string(expired_count) + 
                   " blocks expired, " + std::to_string(rate_limit_expired_count) + 
                   " rate limits expired");
    }
}

// Additional essential methods
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
    
    // Add multicast and broadcast ranges to prevent false positives
    whitelist.insert("224.0.0.0/4");      // IPv4 multicast
    whitelist.insert("255.255.255.255");  // Limited broadcast
    
    // Add common legitimate multicast addresses
    whitelist.insert("224.0.0.251");      // mDNS
    whitelist.insert("224.0.0.252");      // LLMNR  
    whitelist.insert("239.255.255.250");  // UPnP SSDP
}

void FirewallAction::clear_firewall_log() const {
    // Create directory structure if needed
    std::system("mkdir -p /var/log/ddos_inspector 2>/dev/null");
    
    // Clear the log file by truncating it
    std::ofstream log_file("/var/log/ddos_inspector/firewall.log", std::ios::trunc);
    if (log_file.is_open()) {
        log_file.close();
    }
}

// Stub implementations for compatibility - these would need full implementation
void FirewallAction::add_to_whitelist(const std::string& ip_or_cidr) {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    whitelist.insert(ip_or_cidr);
}

void FirewallAction::remove_from_whitelist(const std::string& ip_or_cidr) {
    std::lock_guard<std::mutex> lock(whitelist_mutex);
    whitelist.erase(ip_or_cidr);
}

bool FirewallAction::is_cidr_match(const std::string& ip, const std::string& cidr) const {
    // Simple CIDR matching implementation
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return ip == cidr; // Exact IP match
    }
    
    std::string network_ip = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
    
    // SECURITY FIX: Handle /0 CIDR properly
    if (prefix_len == 0) {
        return true; // /0 matches everything
    }
    
    if (prefix_len < 0 || prefix_len > 32) {
        return false; // Invalid prefix length
    }
    
    struct sockaddr_in sa_ip, sa_net;
    if (inet_pton(AF_INET, ip.c_str(), &(sa_ip.sin_addr)) != 1 ||
        inet_pton(AF_INET, network_ip.c_str(), &(sa_net.sin_addr)) != 1) {
        return false;
    }
    
    // SECURITY FIX: Safe mask calculation
    uint32_t mask = htonl(~0u << (32 - prefix_len));
    return (sa_ip.sin_addr.s_addr & mask) == (sa_net.sin_addr.s_addr & mask);
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

bool FirewallAction::is_repeat_offender_internal(const std::string& ip) const {
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end()) {
        return it->second.violation_count >= 3 || it->second.is_repeat_offender;
    }
    return false;
}

void FirewallAction::update_ip_reputation(const std::string& ip, int reputation_change) {
    // NOTE: This assumes ip_reputation_mutex is already locked by caller
    if (ip_reputation.find(ip) == ip_reputation.end()) {
        ip_reputation[ip] = 100; // Default reputation
    }
    
    ip_reputation[ip] = std::max(0, std::min(100, ip_reputation[ip] + reputation_change));
}

// Add stub implementations for remaining required methods
std::vector<std::string> FirewallAction::get_blocked_ips() const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_mutex);
    std::vector<std::string> result;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            result.push_back(ip + " (blocked)");
        }
    }
    return result;
}

std::vector<std::string> FirewallAction::get_rate_limited_ips() const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_mutex);
    std::vector<std::string> result;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.rate_limit_level > 0 && !info.is_blocked) {
            result.push_back(ip + " (rate limited: " + std::to_string(info.rate_limit_level) + ")");
        }
    }
    return result;
}

// Stubs for remaining methods
void FirewallAction::apply_tarpit(const std::string& ip) { /* Implementation */ }
void FirewallAction::send_tcp_reset(const std::string& ip) { /* Implementation */ }
void FirewallAction::apply_adaptive_mitigation(const std::string& ip, const std::string& attack_type, double intensity) { /* Implementation */ }
void FirewallAction::update_threat_level(ThreatLevel level) { current_threat_level = level; }
void FirewallAction::learn_legitimate_pattern(const std::string& port, double confidence) { /* Implementation */ }
void FirewallAction::analyze_traffic_patterns(const std::vector<std::string>& recent_ips) { /* Implementation */ }
ThreatLevel FirewallAction::get_current_threat_level() const { return current_threat_level; }
void FirewallAction::reset_adaptive_thresholds() { /* Implementation */ }
std::vector<std::string> FirewallAction::get_current_firewall_rules() const { return {}; }
bool FirewallAction::execute_mitigation_strategy(const std::string& ip, MitigationStrategy strategy) { return true; }
