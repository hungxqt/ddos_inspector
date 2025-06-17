#include "firewall_action_secure.hpp"
#include <sys/wait.h>
#include <unistd.h>
#include <sys/capability.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>

// Static thread-safe infrastructure for worker and logger queues
std::mutex FirewallAction::worker_mutex;
std::condition_variable FirewallAction::worker_cv;
std::queue<FirewallJob> FirewallAction::job_queue;
std::thread FirewallAction::worker_thread;
std::atomic<bool> FirewallAction::worker_running{false};
std::atomic<bool> FirewallAction::shutdown_requested{false};

std::mutex FirewallAction::logger_mutex;
std::condition_variable FirewallAction::logger_cv;
std::queue<FirewallJob> FirewallAction::log_queue;
std::thread FirewallAction::logger_thread;
std::atomic<bool> FirewallAction::logger_running{false};

// Compile-time IP validation patterns to prevent shell injection
const std::regex FirewallAction::ipv4_regex(
    R"(^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$)"
);
const std::regex FirewallAction::ipv6_regex(
    R"(^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::)$)"
);
const std::regex FirewallAction::shell_metachar_regex(
    R"([;&|`$(){}[\]<>'"\\*?!])"
);

FirewallAction::FirewallAction(int block_timeout_seconds) 
    : block_timeout(block_timeout_seconds), 
      last_cleanup_time(std::chrono::steady_clock::now()),
      cleanup_interval(std::chrono::minutes(1)),
      current_threat_level(ThreatLevel::LOW),
      global_attack_intensity(0.0),
      reputation_decay_time_hours(24),
      privileges_dropped(false)
{
    // Initialize legitimate traffic patterns with common services
    {
        std::lock_guard<std::mutex> lock(legitimate_patterns_mutex);
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
    }
    
    // Initialize whitelist with common legitimate IP ranges
    initialize_default_whitelist();
    
    // Drop privileges to CAP_NET_ADMIN only
    drop_privileges();
    
    // Start single worker and logger threads
    start_worker_thread();
    start_logger_thread();
    
    // Clear and initialize log file
    clear_firewall_log();
    
    // Initialize nftables infrastructure
    initialize_nftables_infrastructure();
    
    log_firewall_action_async("INFO", "Secure firewall action initialized with thread-safe worker queue", 0);
}

FirewallAction::~FirewallAction() {
    shutdown_requested = true;
    
    // Stop worker thread
    if (worker_running) {
        {
            std::lock_guard<std::mutex> lock(worker_mutex);
            worker_running = false;
        }
        worker_cv.notify_all();
        if (worker_thread.joinable()) {
            worker_thread.join();
        }
    }
    
    // Stop logger thread
    if (logger_running) {
        {
            std::lock_guard<std::mutex> lock(logger_mutex);
            logger_running = false;
        }
        logger_cv.notify_all();
        if (logger_thread.joinable()) {
            logger_thread.join();
        }
    }
    
    // Final log message
    log_firewall_action("INFO", "Secure firewall action shutdown complete", 0);
}

void FirewallAction::start_worker_thread() {
    if (!worker_running.exchange(true)) {
        worker_thread = std::thread(&FirewallAction::worker_loop, this);
    }
}

void FirewallAction::start_logger_thread() {
    if (!logger_running.exchange(true)) {
        logger_thread = std::thread(&FirewallAction::logger_loop, this);
    }
}

void FirewallAction::worker_loop() {
    while (worker_running || !job_queue.empty()) {
        std::unique_lock<std::mutex> lock(worker_mutex);
        worker_cv.wait(lock, [this] { 
            return !job_queue.empty() || !worker_running || shutdown_requested; 
        });
        
        if (!job_queue.empty()) {
            FirewallJob job = std::move(job_queue.front());
            job_queue.pop();
            lock.unlock();
            
            // Process job outside of lock to avoid blocking queue
            process_firewall_job(job);
        }
        
        if (shutdown_requested && job_queue.empty()) {
            break;
        }
    }
}

void FirewallAction::logger_loop() {
    while (logger_running || !log_queue.empty()) {
        std::unique_lock<std::mutex> lock(logger_mutex);
        logger_cv.wait(lock, [this] { 
            return !log_queue.empty() || !logger_running || shutdown_requested; 
        });
        
        if (!log_queue.empty()) {
            FirewallJob log_job = std::move(log_queue.front());
            log_queue.pop();
            lock.unlock();
            
            // Write log outside of lock
            write_log_message_safe(log_job.level, log_job.message, log_job.error_code);
        }
        
        if (shutdown_requested && log_queue.empty()) {
            break;
        }
    }
}

void FirewallAction::process_firewall_job(const FirewallJob& job) {
    IPFamily family;
    try {
        family = get_ip_family(job.ip);
    } catch (const std::exception& e) {
        log_firewall_action_async("ERROR", "Invalid IP family for job: " + job.ip + " - " + e.what(), -1);
        return;
    }
    
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
        default:
            log_firewall_action_async("ERROR", "Unknown job type in worker queue", -1);
            break;
    }
}

void FirewallAction::drop_privileges() {
    if (privileges_dropped) return;
    
    // Drop to CAP_NET_ADMIN only using libcap
    cap_t caps = cap_get_proc();
    if (caps == nullptr) {
        log_firewall_action("ERROR", "Failed to get process capabilities", errno);
        return;
    }
    
    // Clear all capabilities
    if (cap_clear(caps) != 0) {
        cap_free(caps);
        log_firewall_action("ERROR", "Failed to clear capabilities", errno);
        return;
    }
    
    // Set only CAP_NET_ADMIN in effective and permitted sets
    cap_value_t cap_values[] = {CAP_NET_ADMIN};
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_values, CAP_SET) != 0 ||
        cap_set_flag(caps, CAP_PERMITTED, 1, cap_values, CAP_SET) != 0) {
        cap_free(caps);
        log_firewall_action("ERROR", "Failed to set CAP_NET_ADMIN flags", errno);
        return;
    }
    
    // Apply the capability restrictions
    if (cap_set_proc(caps) != 0) {
        cap_free(caps);
        log_firewall_action("ERROR", "Failed to apply capability restrictions", errno);
        return;
    }
    
    cap_free(caps);
    privileges_dropped = true;
    log_firewall_action("INFO", "Privileges successfully dropped to CAP_NET_ADMIN only", 0);
}

bool FirewallAction::validate_ip_address(const std::string& ip) {
    // Length check
    if (ip.empty() || ip.length() > 45) {
        return false;
    }
    
    // Shell metacharacter check - critical security fix
    if (std::regex_search(ip, shell_metachar_regex)) {
        return false;
    }
    
    // Validate IPv4 or IPv6 format
    return std::regex_match(ip, ipv4_regex) || std::regex_match(ip, ipv6_regex);
}

IPFamily FirewallAction::get_ip_family(const std::string& ip) {
    if (std::regex_match(ip, ipv4_regex)) {
        return IPFamily::IPv4;
    } else if (std::regex_match(ip, ipv6_regex)) {
        return IPFamily::IPv6;
    } else {
        throw std::invalid_argument("Invalid IP address format: " + ip);
    }
}

void FirewallAction::block(const std::string& ip) {
    block(ip, 0); // Use default duration
}

void FirewallAction::block(const std::string& ip, int custom_duration_seconds) {
    // Strict input validation
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "Invalid IP address format for blocking: " + ip, -1);
        return;
    }
    
    // Check whitelist and broadcast/multicast
    if (is_whitelisted(ip)) {
        log_firewall_action_async("INFO", "Skipping block for whitelisted IP: " + ip, 0);
        return;
    }
    
    if (is_broadcast_or_multicast(ip)) {
        log_firewall_action_async("INFO", "Skipping block for broadcast/multicast IP: " + ip, 0);
        return;
    }
    
    // Thread-safe update of blocked IPs
    {
        std::lock_guard<std::shared_mutex> lock(blocked_ips_shared_mutex);
        auto now = std::chrono::steady_clock::now();
        
        auto& block_info = blocked_ips[ip];
        if (!block_info.is_blocked) {
            block_info.is_blocked = true;
            block_info.blocked_time = now;
            block_info.last_seen = now;
            block_info.custom_block_duration = (custom_duration_seconds > 0) ? 
                custom_duration_seconds : block_timeout;
            block_info.violation_count++;
            block_info.strategy = MitigationStrategy::TEMPORARY_BLOCK;
            
            // Update IP reputation
            update_ip_reputation(ip, -10);
            
            // Queue firewall command for worker thread
            enqueue_job(FirewallJob(JobType::BLOCK_IP, ip));
            
            log_firewall_action_async("INFO", "Block queued for IP: " + ip, 0);
        } else {
            // Update existing block
            block_info.blocked_time = now;
            block_info.last_seen = now;
            block_info.violation_count++;
            if (custom_duration_seconds > 0) {
                block_info.custom_block_duration = custom_duration_seconds;
            }
            log_firewall_action_async("INFO", "Updated existing block for IP: " + ip, 0);
        }
    }
    
    // Clean up expired blocks outside of lock to prevent deadlock
    cleanup_expired_blocks();
}

void FirewallAction::unblock(const std::string& ip) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "Invalid IP address format for unblocking: " + ip, -1);
        return;
    }
    
    std::lock_guard<std::shared_mutex> lock(blocked_ips_shared_mutex);
    
    auto it = blocked_ips.find(ip);
    if (it != blocked_ips.end() && it->second.is_blocked) {
        // Remove from tracking immediately
        blocked_ips.erase(it);
        
        // Queue unblock command for worker thread
        enqueue_job(FirewallJob(JobType::UNBLOCK_IP, ip));
        
        log_firewall_action_async("INFO", "Unblock queued for IP: " + ip, 0);
    }
}

void FirewallAction::rate_limit(const std::string& ip, int severity_level) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "Invalid IP address format for rate limiting: " + ip, -1);
        return;
    }
    
    if (severity_level < 1 || severity_level > 4) {
        log_firewall_action_async("ERROR", "Invalid severity level: " + std::to_string(severity_level), -1);
        return;
    }
    
    if (is_whitelisted(ip)) {
        log_firewall_action_async("INFO", "Skipping rate limit for whitelisted IP: " + ip, 0);
        return;
    }
    
    {
        std::lock_guard<std::shared_mutex> lock(rate_limited_ips_shared_mutex);
        auto now = std::chrono::steady_clock::now();
        
        auto& limit_info = rate_limited_ips[ip];
        limit_info.is_rate_limited = true;
        limit_info.limited_time = now;
        limit_info.severity_level = severity_level;
        
        // Queue rate limit command for worker thread
        enqueue_job(FirewallJob(JobType::RATE_LIMIT_IP, ip, severity_level));
        
        log_firewall_action_async("INFO", "Rate limit queued for IP: " + ip + 
                                  " (severity: " + std::to_string(severity_level) + ")", 0);
    }
}

bool FirewallAction::execute_block_command_safe(const std::string& ip, IPFamily family) {
    // Additional validation at execution time
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_block_command_safe: " + ip, -1);
        return false;
    }
    
    std::string set_name = (family == IPFamily::IPv4) ? "ddos_ip_set_v4" : "ddos_ip_set_v6";
    std::string ip_element = "{ " + ip + " timeout 10m }";
    
    // Use fork/execvp for safe command execution - no shell injection possible
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - execute nft command safely
        const char* args[] = {
            "nft", "add", "element", "inet", "filter", set_name.c_str(),
            ip_element.c_str(), nullptr
        };
        execvp("nft", const_cast<char* const*>(args));
        _exit(127); // execvp failed
    } else if (pid > 0) {
        // Parent process - wait for completion
        int status;
        if (waitpid(pid, &status, 0) == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                log_firewall_action_async("SUCCESS", "Successfully blocked IP: " + ip, 0);
                return true;
            } else {
                log_firewall_action_async("ERROR", "Failed to block IP: " + ip, WEXITSTATUS(status));
                return false;
            }
        } else {
            log_firewall_action_async("ERROR", "waitpid failed for block command", errno);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for block command", errno);
        return false;
    }
}

bool FirewallAction::execute_unblock_command_safe(const std::string& ip, IPFamily family) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_unblock_command_safe: " + ip, -1);
        return false;
    }
    
    std::string set_name = (family == IPFamily::IPv4) ? "ddos_ip_set_v4" : "ddos_ip_set_v6";
    std::string ip_element = "{ " + ip + " }";
    
    pid_t pid = fork();
    if (pid == 0) {
        const char* args[] = {
            "nft", "delete", "element", "inet", "filter", set_name.c_str(),
            ip_element.c_str(), nullptr
        };
        execvp("nft", const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        if (waitpid(pid, &status, 0) == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                log_firewall_action_async("SUCCESS", "Successfully unblocked IP: " + ip, 0);
                return true;
            } else {
                // Unblock failures are often not critical (IP may have already expired)
                log_firewall_action_async("WARNING", "Unblock command for IP: " + ip + 
                                          " completed with status " + std::to_string(WEXITSTATUS(status)), 0);
                return false;
            }
        } else {
            log_firewall_action_async("ERROR", "waitpid failed for unblock command", errno);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for unblock command", errno);
        return false;
    }
}

bool FirewallAction::execute_rate_limit_command_safe(const std::string& ip, int severity, IPFamily family) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_rate_limit_command_safe: " + ip, -1);
        return false;
    }
    
    if (severity < 1 || severity > 4) {
        log_firewall_action_async("ERROR", "Invalid severity for rate limiting: " + std::to_string(severity), -1);
        return false;
    }
    
    // Calculate rate limit (packets per second) based on severity
    int rate_limit = 100 / severity; // Higher severity = lower rate limit
    std::string rate_rule = "{ " + ip + " limit rate " + std::to_string(rate_limit) + "/second }";
    std::string set_name = (family == IPFamily::IPv4) ? "ddos_rate_limit_v4" : "ddos_rate_limit_v6";
    
    pid_t pid = fork();
    if (pid == 0) {
        const char* args[] = {
            "nft", "add", "element", "inet", "filter", set_name.c_str(),
            rate_rule.c_str(), nullptr
        };
        execvp("nft", const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        if (waitpid(pid, &status, 0) == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                log_firewall_action_async("SUCCESS", "Successfully rate limited IP: " + ip + 
                                          " to " + std::to_string(rate_limit) + " pps", 0);
                return true;
            } else {
                log_firewall_action_async("ERROR", "Failed to rate limit IP: " + ip, WEXITSTATUS(status));
                return false;
            }
        } else {
            log_firewall_action_async("ERROR", "waitpid failed for rate limit command", errno);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for rate limit command", errno);
        return false;
    }
}

bool FirewallAction::execute_unrate_limit_command_safe(const std::string& ip, IPFamily family) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_unrate_limit_command_safe: " + ip, -1);
        return false;
    }
    
    std::string set_name = (family == IPFamily::IPv4) ? "ddos_rate_limit_v4" : "ddos_rate_limit_v6";
    std::string ip_element = "{ " + ip + " }";
    
    pid_t pid = fork();
    if (pid == 0) {
        const char* args[] = {
            "nft", "delete", "element", "inet", "filter", set_name.c_str(),
            ip_element.c_str(), nullptr
        };
        execvp("nft", const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        if (waitpid(pid, &status, 0) == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                log_firewall_action_async("SUCCESS", "Successfully removed rate limit for IP: " + ip, 0);
                return true;
            } else {
                log_firewall_action_async("ERROR", "Failed to remove rate limit for IP: " + ip, WEXITSTATUS(status));
                return false;
            }
        } else {
            log_firewall_action_async("ERROR", "waitpid failed for unrate limit command", errno);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for unrate limit command", errno);
        return false;
    }
}

void FirewallAction::enqueue_job(const FirewallJob& job) {
    std::lock_guard<std::mutex> lock(worker_mutex);
    job_queue.push(job);
    worker_cv.notify_one();
}

void FirewallAction::log_firewall_action_async(const std::string& level, 
                                               const std::string& message, 
                                               int error_code) {
    std::lock_guard<std::mutex> lock(logger_mutex);
    log_queue.emplace(JobType::LOG_MESSAGE, level, message, error_code);
    logger_cv.notify_one();
}

void FirewallAction::write_log_message_safe(const std::string& level, 
                                            const std::string& message, 
                                            int error_code) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    // Thread-safe timestamp formatting
    struct tm tm_buffer;
    struct tm* tm = localtime_r(&time_t, &tm_buffer);
    
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    std::string log_entry = "[" + std::string(timestamp) + "] [FIREWALL] [" + level + "] " + message;
    if (error_code != 0) {
        log_entry += " (error_code: " + std::to_string(error_code) + ")";
    }
    
    // Write to console with flush
    printf("%s\n", log_entry.c_str());
    fflush(stdout);
    
    // Write to log file
    std::ofstream log_file("/var/log/ddos_inspector/firewall.log", std::ios::app);
    if (log_file.is_open()) {
        log_file << log_entry << std::endl;
        log_file.close();
    }
}

void FirewallAction::log_firewall_action(const std::string& level, 
                                         const std::string& message, 
                                         int error_code) {
    // Synchronous logging for immediate output
    write_log_message_safe(level, message, error_code);
}

size_t FirewallAction::get_blocked_count() const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_shared_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            count++;
        }
    }
    return count;
}

size_t FirewallAction::get_rate_limited_count() const {
    std::shared_lock<std::shared_mutex> lock(rate_limited_ips_shared_mutex);
    
    size_t count = 0;
    for (const auto& [ip, info] : rate_limited_ips) {
        if (info.is_rate_limited) {
            count++;
        }
    }
    return count;
}

bool FirewallAction::is_blocked(const std::string& ip) const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_shared_mutex);
    auto it = blocked_ips.find(ip);
    return it != blocked_ips.end() && it->second.is_blocked;
}

bool FirewallAction::is_rate_limited(const std::string& ip) const {
    std::shared_lock<std::shared_mutex> lock(rate_limited_ips_shared_mutex);
    auto it = rate_limited_ips.find(ip);
    return it != rate_limited_ips.end() && it->second.is_rate_limited;
}

void FirewallAction::cleanup_expired_blocks() {
    std::lock_guard<std::shared_mutex> blocked_lock(blocked_ips_shared_mutex);
    std::lock_guard<std::shared_mutex> rate_lock(rate_limited_ips_shared_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Rate limiting cleanup
    if (now - last_cleanup_time < cleanup_interval) {
        return;
    }
    last_cleanup_time = now;
    
    int expired_blocks = 0;
    int expired_rate_limits = 0;
    
    // Clean up expired blocked IPs
    for (auto it = blocked_ips.begin(); it != blocked_ips.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.blocked_time).count();
        
        int timeout = (it->second.custom_block_duration > 0) ? 
                      it->second.custom_block_duration : block_timeout;
        
        if (elapsed >= timeout) {
            // Queue unblock command
            enqueue_job(FirewallJob(JobType::UNBLOCK_IP, it->first));
            it = blocked_ips.erase(it);
            expired_blocks++;
        } else {
            ++it;
        }
    }
    
    // Clean up expired rate limits
    for (auto it = rate_limited_ips.begin(); it != rate_limited_ips.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.limited_time).count();
        
        if (elapsed >= block_timeout / 2) { // Rate limits expire faster
            enqueue_job(FirewallJob(JobType::UNRATE_LIMIT_IP, it->first));
            it = rate_limited_ips.erase(it);
            expired_rate_limits++;
        } else {
            ++it;
        }
    }
    
    // Decay IP reputation over time
    {
        std::lock_guard<std::shared_mutex> rep_lock(ip_reputation_shared_mutex);
        for (auto& [ip, reputation] : ip_reputation) {
            if (reputation < 100) {
                reputation = std::min(100, reputation + 1); // Gradual recovery
            }
        }
    }
    
    if (expired_blocks > 0 || expired_rate_limits > 0) {
        log_firewall_action_async("INFO", "Cleanup completed: " + std::to_string(expired_blocks) + 
                                  " blocks expired, " + std::to_string(expired_rate_limits) + 
                                  " rate limits expired", 0);
    }
}

bool FirewallAction::is_cidr_match(const std::string& ip, const std::string& cidr) const {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return ip == cidr; // Exact IP match
    }
    
    std::string network = cidr.substr(0, slash_pos);
    std::string mask_str = cidr.substr(slash_pos + 1);
    
    int prefix_len;
    try {
        prefix_len = std::stoi(mask_str);
    } catch (const std::exception&) {
        return false; // Invalid mask
    }
    
    // SECURITY FIX: Handle /0 mask correctly (matches all IPs)
    if (prefix_len == 0) {
        return true;
    }
    
    // IPv4 CIDR matching
    if (std::regex_match(ip, ipv4_regex) && std::regex_match(network, ipv4_regex)) {
        if (prefix_len < 0 || prefix_len > 32) return false;
        
        struct sockaddr_in sa_ip, sa_net;
        if (inet_pton(AF_INET, ip.c_str(), &sa_ip.sin_addr) != 1 ||
            inet_pton(AF_INET, network.c_str(), &sa_net.sin_addr) != 1) {
            return false;
        }
        
        // SECURITY FIX: Avoid undefined behavior for 32-bit shift
        uint32_t mask = (prefix_len == 32) ? 0xFFFFFFFF : ~((1U << (32 - prefix_len)) - 1);
        return (ntohl(sa_ip.sin_addr.s_addr) & mask) == (ntohl(sa_net.sin_addr.s_addr) & mask);
    }
    
    // IPv6 CIDR matching (simplified implementation)
    if (std::regex_match(ip, ipv6_regex) && std::regex_match(network, ipv6_regex)) {
        if (prefix_len < 0 || prefix_len > 128) return false;
        
        struct sockaddr_in6 sa_ip, sa_net;
        if (inet_pton(AF_INET6, ip.c_str(), &sa_ip.sin6_addr) != 1 ||
            inet_pton(AF_INET6, network.c_str(), &sa_net.sin6_addr) != 1) {
            return false;
        }
        
        // Compare first prefix_len bits
        int bytes_to_check = prefix_len / 8;
        int remaining_bits = prefix_len % 8;
        
        if (memcmp(&sa_ip.sin6_addr, &sa_net.sin6_addr, bytes_to_check) != 0) {
            return false;
        }
        
        if (remaining_bits > 0 && bytes_to_check < 16) {
            uint8_t mask = 0xFF << (8 - remaining_bits);
            if ((sa_ip.sin6_addr.s6_addr[bytes_to_check] & mask) != 
                (sa_net.sin6_addr.s6_addr[bytes_to_check] & mask)) {
                return false;
            }
        }
        
        return true;
    }
    
    return false;
}

bool FirewallAction::is_whitelisted(const std::string& ip) const {
    std::shared_lock<std::shared_mutex> lock(whitelist_shared_mutex);
    
    for (const auto& entry : whitelist) {
        if (is_cidr_match(ip, entry)) {
            return true;
        }
    }
    return false;
}

void FirewallAction::add_to_whitelist(const std::string& ip_or_cidr) {
    // Extract IP part for validation (before any '/')
    std::string ip_part = ip_or_cidr.substr(0, ip_or_cidr.find('/'));
    if (!validate_ip_address(ip_part)) {
        log_firewall_action_async("ERROR", "Invalid IP/CIDR format for whitelist: " + ip_or_cidr, -1);
        return;
    }
    
    std::lock_guard<std::shared_mutex> lock(whitelist_shared_mutex);
    whitelist.insert(ip_or_cidr);
    log_firewall_action_async("INFO", "Added to whitelist: " + ip_or_cidr, 0);
}

void FirewallAction::remove_from_whitelist(const std::string& ip_or_cidr) {
    std::lock_guard<std::shared_mutex> lock(whitelist_shared_mutex);
    auto removed = whitelist.erase(ip_or_cidr);
    if (removed > 0) {
        log_firewall_action_async("INFO", "Removed from whitelist: " + ip_or_cidr, 0);
    }
}

void FirewallAction::initialize_default_whitelist() {
    std::lock_guard<std::shared_mutex> lock(whitelist_shared_mutex);
    
    // RFC 1918 private ranges
    whitelist.insert("10.0.0.0/8");
    whitelist.insert("172.16.0.0/12");  
    whitelist.insert("192.168.0.0/16");
    
    // Loopback ranges
    whitelist.insert("127.0.0.0/8");
    whitelist.insert("::1/128");
    
    // Link-local ranges
    whitelist.insert("169.254.0.0/16");
    whitelist.insert("fe80::/10");
    
    // Multicast ranges to prevent false positives
    whitelist.insert("224.0.0.0/4");   // IPv4 multicast
    whitelist.insert("ff00::/8");      // IPv6 multicast
    
    log_firewall_action("INFO", "Initialized default whitelist with private/loopback/multicast ranges", 0);
}

bool FirewallAction::is_broadcast_or_multicast(const std::string& ip) const {
    // IPv4 checks
    if (std::regex_match(ip, ipv4_regex)) {
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1) {
            uint32_t addr = ntohl(sa.sin_addr.s_addr);
            
            // Broadcast address
            if (addr == 0xFFFFFFFF) return true;
            
            // Multicast range (224.0.0.0 to 239.255.255.255)
            if ((addr >= 0xE0000000) && (addr <= 0xEFFFFFFF)) return true;
            
            // Limited broadcast (ends with .255)
            if ((addr & 0xFF) == 0xFF) return true;
        }
    }
    
    // IPv6 checks
    if (std::regex_match(ip, ipv6_regex)) {
        struct sockaddr_in6 sa;
        if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) == 1) {
            // Multicast (starts with ff)
            if (sa.sin6_addr.s6_addr[0] == 0xff) return true;
        }
    }
    
    return false;
}

void FirewallAction::update_ip_reputation(const std::string& ip, int reputation_change) {
    std::lock_guard<std::shared_mutex> lock(ip_reputation_shared_mutex);
    
    if (ip_reputation.find(ip) == ip_reputation.end()) {
        ip_reputation[ip] = 100; // Default reputation
    }
    
    ip_reputation[ip] = std::max(0, std::min(100, ip_reputation[ip] + reputation_change));
}

bool FirewallAction::initialize_nftables_infrastructure() const {
    // Create filter table and sets for dual-stack support
    const char* setup_commands[] = {
        "nft add table inet filter",
        "nft add set inet filter ddos_ip_set_v4 '{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }'",
        "nft add set inet filter ddos_ip_set_v6 '{ type ipv6_addr; flags dynamic,timeout; timeout 10m; }'",
        "nft add set inet filter ddos_rate_limit_v4 '{ type ipv4_addr; flags dynamic,timeout; timeout 5m; }'", 
        "nft add set inet filter ddos_rate_limit_v6 '{ type ipv6_addr; flags dynamic,timeout; timeout 5m; }'",
        "nft add rule inet filter input ip saddr @ddos_ip_set_v4 drop",
        "nft add rule inet filter input ip6 saddr @ddos_ip_set_v6 drop",
        nullptr
    };
    
    for (int i = 0; setup_commands[i] != nullptr; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Split command string for execvp
            std::string cmd(setup_commands[i]);
            std::vector<std::string> args;
            std::istringstream iss(cmd);
            std::string token;
            
            while (iss >> token) {
                args.push_back(token);
            }
            
            std::vector<const char*> argv;
            for (const auto& arg : args) {
                argv.push_back(arg.c_str());
            }
            argv.push_back(nullptr);
            
            execvp(argv[0], const_cast<char* const*>(argv.data()));
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            // Continue even if setup commands fail (they may already exist)
        }
    }
    
    // Simple logging for const method
    printf("[INFO] nftables infrastructure initialization completed\n");
    return true;
}

void FirewallAction::clear_firewall_log() {
    // Create log directory with proper permissions
    pid_t pid = fork();
    if (pid == 0) {
        const char* args[] = {"mkdir", "-p", "/var/log/ddos_inspector", nullptr};
        execvp("mkdir", const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
    
    // Initialize log file
    std::ofstream log_file("/var/log/ddos_inspector/firewall.log", std::ios::trunc);
    if (log_file.is_open()) {
        log_file << "=== DDoS Inspector Firewall Log (Secure Mode) ===" << std::endl;
        log_file.close();
        
        // Set file permissions to 0600 (owner read/write only)
        chmod("/var/log/ddos_inspector/firewall.log", S_IRUSR | S_IWUSR);
    }
}

// Placeholder implementations for advanced features
void FirewallAction::apply_tarpit(const std::string& ip) {
    log_firewall_action_async("INFO", "Tarpit requested for IP: " + ip + " (placeholder)", 0);
}

void FirewallAction::send_tcp_reset(const std::string& ip) {
    log_firewall_action_async("INFO", "TCP reset requested for IP: " + ip + " (placeholder)", 0);
}

void FirewallAction::apply_adaptive_mitigation(const std::string& ip, const std::string& attack_type, double intensity) {
    log_firewall_action_async("INFO", "Adaptive mitigation requested for IP: " + ip + 
                              " attack: " + attack_type + " intensity: " + std::to_string(intensity) + " (placeholder)", 0);
}

void FirewallAction::update_threat_level(ThreatLevel level) {
    current_threat_level = level;
    log_firewall_action_async("INFO", "Threat level updated to: " + std::to_string(static_cast<int>(level)), 0);
}

void FirewallAction::learn_legitimate_pattern(const std::string& port, double confidence) {
    std::lock_guard<std::mutex> lock(legitimate_patterns_mutex);
    legitimate_patterns[port] = confidence;
    log_firewall_action_async("INFO", "Learned legitimate pattern for port " + port + 
                              " with confidence " + std::to_string(confidence), 0);
}

void FirewallAction::analyze_traffic_patterns(const std::vector<std::string>& recent_ips) {
    log_firewall_action_async("INFO", "Traffic pattern analysis requested for " + 
                              std::to_string(recent_ips.size()) + " IPs (placeholder)", 0);
}

std::vector<std::string> FirewallAction::get_blocked_ips() const {
    std::shared_lock<std::shared_mutex> lock(blocked_ips_shared_mutex);
    
    std::vector<std::string> blocked_list;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, info] : blocked_ips) {
        if (info.is_blocked) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - info.blocked_time).count();
            int remaining = info.custom_block_duration - static_cast<int>(elapsed);
            
            blocked_list.push_back(ip + " (remaining: " + std::to_string(std::max(0, remaining)) + "s)");
        }
    }
    
    return blocked_list;
}

std::vector<std::string> FirewallAction::get_rate_limited_ips() const {
    std::shared_lock<std::shared_mutex> lock(rate_limited_ips_shared_mutex);
    
    std::vector<std::string> rate_limited_list;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, info] : rate_limited_ips) {
        if (info.is_rate_limited) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - info.limited_time).count();
            int remaining = (block_timeout / 2) - static_cast<int>(elapsed);
            
            rate_limited_list.push_back(ip + " (level " + std::to_string(info.severity_level) + 
                                       ", remaining: " + std::to_string(std::max(0, remaining)) + "s)");
        }
    }
    
    return rate_limited_list;
}
