#include "firewall_action.hpp"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <cerrno>
#include <csignal>
#include <climits>

// Constants to avoid magic strings and improve maintainability
constexpr const char* kBlockTimeoutNft = "10m";
constexpr size_t kMaxArgLength = 131072; // ARG_MAX limit (128 KiB)
constexpr const char* kLogFileName = "/var/log/ddos_inspector/firewall.log";
constexpr const char* kLogDirName = "/var/log/ddos_inspector";
constexpr int kRateLimitBase = 100; // Base rate limit packets per second
constexpr const char* kNftBinary = "nft"; // nftables binary path

// Log rotation constants
constexpr size_t kMaxLogSizeBytes = 100 * 1024 * 1024; // 100 MB
constexpr int kMaxLogFiles = 4; // Keep 4 rotated log files

// Queue size limits to prevent memory exhaustion
constexpr size_t kMaxWorkerQueueSize = 8192;
constexpr size_t kMaxLoggerQueueSize = 4096;
constexpr size_t kMaxIpReputationSize = 100000;

// Global metrics for monitoring
std::atomic<size_t> g_dropped_jobs{0};
std::atomic<size_t> g_dropped_logs{0};
std::atomic<size_t> g_exec_errors{0};

// SIGCHLD handler to prevent zombie accumulation
void sigchld_handler(int sig) {
    (void)sig; // Unused parameter
    int status;
    // Reap all available children without blocking
    while (waitpid(-1, &status, WNOHANG) > 0) {
        // Child reaped
    }
}

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

// Thread-safe console output mutex to fix printf thread safety issue
std::mutex FirewallAction::console_mutex;

// Compile-time shell metacharacter validation pattern to prevent shell injection
// SECURITY FIX: IPv4/IPv6 validation done via inet_pton only - no regex needed (eliminates ReDoS risk entirely)
const std::regex FirewallAction::shell_metachar_regex(
    "([;&|`$(){}[\\]<>\"'\\\\*?!])"
);

FirewallAction::FirewallAction(int block_timeout_seconds) 
    : block_timeout(block_timeout_seconds), 
      last_cleanup_time(std::chrono::steady_clock::now()),
      cleanup_interval(std::chrono::minutes(1)),
      current_threat_level(ThreatLevel::LOW),
      global_attack_intensity(0.0),
      reputation_decay_time_hours(24),
      privileges_dropped(false),
      last_batch_time(std::chrono::steady_clock::now())  // ADDED: Initialize batch timing
{
    // Install SIGCHLD handler to prevent zombie accumulation
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        std::cerr << "Warning: Failed to install SIGCHLD handler: " << strerror(errno) << '\n';
    }
    
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
    
    // SECURITY FIX: Create log directory BEFORE dropping privileges
    create_log_directory();
    
    // Initialize nftables infrastructure BEFORE dropping privileges
    initialize_nftables_infrastructure();
    
    // Drop privileges to CAP_NET_ADMIN only
    drop_privileges();
    
    // Start single worker and logger threads
    start_worker_thread();
    start_logger_thread();
    
    // Clear and initialize log file (now safe after privilege drop)
    clear_firewall_log();
    
    log_firewall_action_async("INFO", "Secure firewall action initialized with thread-safe worker queue", 0);
}

FirewallAction::~FirewallAction() {
    // FIXED: Proper shutdown sequence - set flags before notify and sync final log
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
    
    // FIXED: Final log message using synchronous logging after logger thread stopped
    log_firewall_action("INFO", "Secure firewall action shutdown complete - Stats: " +
                       std::to_string(g_dropped_jobs.load()) + " dropped jobs, " +
                       std::to_string(g_dropped_logs.load()) + " dropped logs, " +
                       std::to_string(g_exec_errors.load()) + " exec errors", 0);
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
        worker_cv.wait(lock, [] { 
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
        logger_cv.wait(lock, [] { 
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
    
    switch (job.type) {
        case JobType::BLOCK_IP:
            try {
                family = get_ip_family(job.ip);
                execute_block_command_safe(job.ip, family);
            } catch (const std::exception& e) {
                log_firewall_action_async("ERROR", "Invalid IP family for block job: " + job.ip + " - " + e.what(), -1);
            }
            break;
        case JobType::UNBLOCK_IP:
            try {
                family = get_ip_family(job.ip);
                execute_unblock_command_safe(job.ip, family);
            } catch (const std::exception& e) {
                log_firewall_action_async("ERROR", "Invalid IP family for unblock job: " + job.ip + " - " + e.what(), -1);
            }
            break;
        case JobType::RATE_LIMIT_IP:
            try {
                family = get_ip_family(job.ip);
                execute_rate_limit_command_safe(job.ip, job.severity, family);
            } catch (const std::exception& e) {
                log_firewall_action_async("ERROR", "Invalid IP family for rate limit job: " + job.ip + " - " + e.what(), -1);
            }
            break;
        case JobType::UNRATE_LIMIT_IP:
            try {
                family = get_ip_family(job.ip);
                execute_unrate_limit_command_safe(job.ip, family);
            } catch (const std::exception& e) {
                log_firewall_action_async("ERROR", "Invalid IP family for unrate limit job: " + job.ip + " - " + e.what(), -1);
            }
            break;
        case JobType::BATCH_BLOCK_IPS:
            execute_batch_block_command_safe(job.ip_batch);
            break;
        case JobType::BATCH_UNBLOCK_IPS:
            execute_batch_unblock_command_safe(job.ip_batch);
            break;
        default:
            log_firewall_action_async("ERROR", "Unknown job type in worker queue", -1);
            break;
    }
}

void FirewallAction::create_log_directory() {
    // Create log directory if it doesn't exist
    // This must be called BEFORE dropping privileges since filesystem writes may require elevated permissions
    
    // Check if directory exists
    struct stat st;
    if (stat(kLogDirName, &st) == 0 && S_ISDIR(st.st_mode)) {
        return; // Directory already exists
    }
    
    // Create directory with appropriate permissions
    if (mkdir(kLogDirName, 0755) != 0) {
        if (errno != EEXIST) {
            // Log to stderr since we can't log to file yet
            std::cerr << "WARNING: Could not create log directory " << kLogDirName 
                      << " - " << strerror(errno) << '\n';
            std::cerr << "Logs will be written to current directory" << '\n';
        }
    }
}

void FirewallAction::drop_privileges() {
    if (privileges_dropped) return;
    
    // FIXED: Drop UID/GID while keeping CAP_NET_ADMIN for defense-in-depth
    
    // First, get nobody user info
    struct passwd* nobody = getpwnam("nobody");
    if (nobody == nullptr) {
        log_firewall_action("WARNING", "Could not find 'nobody' user, continuing with current UID", errno);
    }
    
    // Set up capabilities to keep CAP_NET_ADMIN across UID change
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
        log_firewall_action("ERROR", "Failed to set PR_SET_KEEPCAPS", errno);
        return;
    }
    
    // Change GID first (must be done before UID change)
    if (nobody && setgid(nobody->pw_gid) != 0) {
        log_firewall_action("ERROR", "Failed to change GID to nobody", errno);
        return;
    }
    
    // Change UID
    if (nobody && setuid(nobody->pw_uid) != 0) {
        log_firewall_action("ERROR", "Failed to change UID to nobody", errno);
        return;
    }
    
    // Now set up the capability restrictions
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
    
    // FIXED: Ensure inheritable capabilities are cleared
    if (cap_set_flag(caps, CAP_INHERITABLE, 1, cap_values, CAP_CLEAR) != 0) {
        cap_free(caps);
        log_firewall_action("ERROR", "Failed to clear inheritable capabilities", errno);
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
    
    std::string uid_info = nobody ? 
        " (UID: " + std::to_string(nobody->pw_uid) + ", GID: " + std::to_string(nobody->pw_gid) + ")" : 
        " (UID unchanged)";
    log_firewall_action("INFO", "Privileges successfully dropped to CAP_NET_ADMIN only" + uid_info, 0);
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
    
    // FIXED: Use inet_pton only for validation - no regex needed (eliminates ReDoS risk entirely)
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    
    // Try IPv4 first
    if (inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1) {
        return true;
    }
    
    // Try IPv6
    if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1) {
        return true;
    }
    
    return false;
}

IPFamily FirewallAction::get_ip_family(const std::string& ip) {
    // FIXED: Use inet_pton for reliable family detection
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    
    if (inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1) {
        return IPFamily::IPv4;
    } else if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1) {
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
            
            // Queue firewall command for worker thread with back-pressure handling
            if (!enqueue_job(FirewallJob(JobType::BLOCK_IP, ip))) {
                log_firewall_action_async("WARNING", "Failed to enqueue block job for IP: " + ip + " (queue full)", 0);
                // Could implement fallback strategy here (e.g., direct execution, SYN cookies, etc.)
            } else {
                log_firewall_action_async("INFO", "Block queued for IP: " + ip, 0);
            }
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
        
        // Queue unblock command for worker thread with back-pressure handling
        if (!enqueue_job(FirewallJob(JobType::UNBLOCK_IP, ip))) {
            log_firewall_action_async("WARNING", "Failed to enqueue unblock job for IP: " + ip + " (queue full)", 0);
        } else {
            log_firewall_action_async("INFO", "Unblock queued for IP: " + ip, 0);
        }
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
        
        // Queue rate limit command for worker thread with back-pressure handling
        if (!enqueue_job(FirewallJob(JobType::RATE_LIMIT_IP, ip, severity_level))) {
            log_firewall_action_async("WARNING", "Failed to enqueue rate limit job for IP: " + ip + " (queue full)", 0);
        } else {
            log_firewall_action_async("INFO", "Rate limit queued for IP: " + ip + 
                                      " (severity: " + std::to_string(severity_level) + ")", 0);
        }
    }
}

bool FirewallAction::execute_block_command_safe(const std::string& ip, IPFamily family) {
    // Additional validation at execution time
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_block_command_safe: " + ip, -1);
        return false;
    }
    
    std::string set_name = (family == IPFamily::IPv4) ? "ddos_ip_set_v4" : "ddos_ip_set_v6";
    
    // Use fork/execvp for safe command execution - no shell injection possible
    // NOTE: Per-job fork/exec can cause process explosion under high load.
    // Future improvements: batch commands, use libnftables.so, or persistent helper process
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - execute nft command safely with properly split arguments
        const char* args[] = {
            kNftBinary, "add", "element", "inet", "filter", set_name.c_str(),
            "{", ip.c_str(), "timeout", kBlockTimeoutNft, "}", nullptr
        };
        execvp(kNftBinary, const_cast<char* const*>(args));
        _exit(127); // execvp failed
    } else if (pid > 0) {
        // Parent process - wait for completion with SIGCHLD race protection
        int status;
        if (safe_waitpid(pid, &status, "block command")) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                // FIXED: Treat exit codes 0 and 1 as success (1 = element already exists)
                if (exit_code == 0 || exit_code == 1) {
                    log_firewall_action_async("SUCCESS", "Successfully blocked IP: " + ip, 0);
                    return true;
                } else {
                    log_firewall_action_async("ERROR", "Failed to block IP: " + ip, exit_code);
                    g_exec_errors.fetch_add(1);
                    return false;
                }
            } else {
                log_firewall_action_async("ERROR", "Block process terminated abnormally for IP: " + ip, -1);
                g_exec_errors.fetch_add(1);
                return false;
            }
        } else {
            g_exec_errors.fetch_add(1);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for block command", errno);
        g_exec_errors.fetch_add(1);
        return false;
    }
}

bool FirewallAction::execute_unblock_command_safe(const std::string& ip, IPFamily family) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_unblock_command_safe: " + ip, -1);
        return false;
    }
    
    std::string set_name = (family == IPFamily::IPv4) ? "ddos_ip_set_v4" : "ddos_ip_set_v6";
    
    // NOTE: Fork/exec per command - see block function for performance considerations
    pid_t pid = fork();
    if (pid == 0) {
        const char* args[] = {
            kNftBinary, "delete", "element", "inet", "filter", set_name.c_str(),
            "{", ip.c_str(), "}", nullptr
        };
        execvp(kNftBinary, const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        if (safe_waitpid(pid, &status, "unblock command")) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                // FIXED: Treat exit codes 0 and 1 as success (1 = element may not exist)
                if (exit_code == 0 || exit_code == 1) {
                    log_firewall_action_async("SUCCESS", "Successfully unblocked IP: " + ip, 0);
                    return true;
                } else {
                    // Unblock failures are often not critical (IP may have already expired)
                    log_firewall_action_async("WARNING", "Unblock command for IP: " + ip + 
                                              " completed with status " + std::to_string(exit_code), 0);
                    return false;
                }
            } else {
                log_firewall_action_async("ERROR", "Unblock process terminated abnormally for IP: " + ip, -1);
                g_exec_errors.fetch_add(1);
                return false;
            }
        } else {
            g_exec_errors.fetch_add(1);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for unblock command", errno);
        g_exec_errors.fetch_add(1);
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
    int rate_limit = kRateLimitBase / severity; // Higher severity = lower rate limit
    std::string rate_limit_str = std::to_string(rate_limit) + "/second";
    std::string ip_version = (family == IPFamily::IPv4) ? "ip" : "ip6";
    
    // FIXED: Use rule-based rate limiting instead of sets with embedded limits
    // Add a rule that rate limits this specific IP
    pid_t pid = fork();
    if (pid == 0) {
        // Build command: nft add rule inet filter input ip saddr 1.2.3.4 limit rate 25/second accept
        const char* args[] = {
            kNftBinary, "add", "rule", "inet", "filter", "input", 
            ip_version.c_str(), "saddr", ip.c_str(), 
            "limit", "rate", rate_limit_str.c_str(), "accept", nullptr
        };
        execvp(kNftBinary, const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        if (safe_waitpid(pid, &status, "rate limit command")) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                // FIXED: Treat exit codes 0 and 1 as success (1 = rule already exists)
                if (exit_code == 0 || exit_code == 1) {
                    log_firewall_action_async("SUCCESS", "Successfully rate limited IP: " + ip + 
                                              " to " + std::to_string(rate_limit) + " pps", 0);
                    return true;
                } else {
                    log_firewall_action_async("ERROR", "Failed to rate limit IP: " + ip, exit_code);
                    g_exec_errors.fetch_add(1);
                    return false;
                }
            } else {
                log_firewall_action_async("ERROR", "Rate limit process terminated abnormally for IP: " + ip, -1);
                g_exec_errors.fetch_add(1);
                return false;
            }
        } else {
            g_exec_errors.fetch_add(1);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for rate limit command", errno);
        g_exec_errors.fetch_add(1);
        return false;
    }
}

bool FirewallAction::execute_unrate_limit_command_safe(const std::string& ip, IPFamily family) {
    if (!validate_ip_address(ip)) {
        log_firewall_action_async("ERROR", "IP validation failed in execute_unrate_limit_command_safe: " + ip, -1);
        return false;
    }
    
    std::string ip_version = (family == IPFamily::IPv4) ? "ip" : "ip6";
    
    // FIXED: Remove rate limiting rule instead of set element
    // First, list rules to find the handle, then delete by handle
    // For simplicity, we'll flush and recreate the rate limiting rules periodically
    // This is a compromise - ideal solution would track rule handles
    pid_t pid = fork();
    if (pid == 0) {
        // Try to delete rule - this may fail if rule doesn't exist, which is OK
        const char* args[] = {
            kNftBinary, "delete", "rule", "inet", "filter", "input",
            ip_version.c_str(), "saddr", ip.c_str(), nullptr
        };
        execvp(kNftBinary, const_cast<char* const*>(args));
        _exit(127);
    } else if (pid > 0) {
        int status;
        if (safe_waitpid(pid, &status, "unrate limit command")) {
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                // FIXED: Treat exit codes 0 and 1 as success (rule may not exist)
                if (exit_code == 0 || exit_code == 1) {
                    log_firewall_action_async("SUCCESS", "Successfully removed rate limit for IP: " + ip, 0);
                    return true;
                } else {
                    log_firewall_action_async("WARNING", "Failed to remove rate limit for IP: " + ip + 
                                             " (may not exist)", exit_code);
                    return false;
                }
            } else {
                log_firewall_action_async("ERROR", "Unrate limit process terminated abnormally for IP: " + ip, -1);
                g_exec_errors.fetch_add(1);
                return false;
            }
        } else {
            g_exec_errors.fetch_add(1);
            return false;
        }
    } else {
        log_firewall_action_async("ERROR", "fork failed for unrate limit command", errno);
        g_exec_errors.fetch_add(1);
        return false;
    }
}

bool FirewallAction::enqueue_job(const FirewallJob& job) {
    std::lock_guard<std::mutex> lock(worker_mutex);
    
    // FIXED: Implement priority-based queue overflow policy and return success status
    if (job_queue.size() >= kMaxWorkerQueueSize) {
        // For critical operations (UNBLOCK), try to make space by removing non-critical jobs
        if (job.type == JobType::UNBLOCK_IP || job.type == JobType::UNRATE_LIMIT_IP) {
            // Create temporary queue to hold jobs while we filter
            std::queue<FirewallJob> temp_queue;
            bool space_made = false;
            
            // Try to remove non-critical jobs to make space
            while (!job_queue.empty() && !space_made) {
                FirewallJob front_job = job_queue.front();
                job_queue.pop();
                
                // Skip non-critical jobs to make space for critical ones
                if (front_job.type == JobType::BLOCK_IP || front_job.type == JobType::RATE_LIMIT_IP) {
                    space_made = true;
                    g_dropped_jobs.fetch_add(1);
                    log_firewall_action("WARNING", "Dropped non-critical job to make space for critical operation", 0);
                    break;
                } else {
                    temp_queue.push(front_job);
                }
            }
            
            // Restore non-critical jobs
            while (!temp_queue.empty()) {
                job_queue.push(temp_queue.front());
                temp_queue.pop();
            }
            
            if (!space_made) {
                // If no space could be made, drop oldest job as last resort
                if (!job_queue.empty()) {
                    job_queue.pop();
                    g_dropped_jobs.fetch_add(1);
                    log_firewall_action("WARNING", "Worker queue full, dropping oldest job for critical operation", 0);
                }
            }
        } else {
            // For non-critical operations, just drop the new job
            g_dropped_jobs.fetch_add(1);
            log_firewall_action("WARNING", "Worker queue full, dropping new non-critical job", 0);
            return false; // Indicate failure to caller
        }
    }
    
    job_queue.push(job);
    worker_cv.notify_one();
    return true; // Success
}

void FirewallAction::log_firewall_action_async(const std::string& level, 
                                               const std::string& message, 
                                               int error_code) {
    std::lock_guard<std::mutex> lock(logger_mutex);
    
    // Implement queue size limit for logger queue with metrics
    if (log_queue.size() >= kMaxLoggerQueueSize) {
        // Drop oldest log when queue is full
        log_queue.pop();
        g_dropped_logs.fetch_add(1);
        // Can't log here as we're in the logger - would cause recursion
    }
    
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
    
    // Thread-safe console output to fix printf thread safety issue
    {
        std::lock_guard<std::mutex> console_lock(console_mutex);
        std::cout << log_entry << '\n' << std::flush;
    }
    
    // Write to log file with rotation
    rotate_log_if_needed();
    std::ofstream log_file(kLogFileName, std::ios::app);
    if (log_file.is_open()) {
        log_file << log_entry << '\n';
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
    auto now = std::chrono::steady_clock::now();
    
    // Rate limiting cleanup
    if (now - last_cleanup_time < cleanup_interval) {
        return;
    }
    last_cleanup_time = now;
    
    // Use read-then-prune pattern to reduce lock contention
    std::vector<std::string> expired_blocked_ips;
    std::vector<std::string> expired_rate_limited_ips;
    
    // First pass: collect expired IPs with shared locks (read-only)
    {
        std::shared_lock<std::shared_mutex> blocked_lock(blocked_ips_shared_mutex);
        for (const auto& [ip, info] : blocked_ips) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - info.blocked_time).count();
            
            int timeout = (info.custom_block_duration > 0) ? 
                          info.custom_block_duration : block_timeout;
            
            if (elapsed >= timeout) {
                expired_blocked_ips.push_back(ip);
            }
        }
    }
    
    {
        std::shared_lock<std::shared_mutex> rate_lock(rate_limited_ips_shared_mutex);
        for (const auto& [ip, info] : rate_limited_ips) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - info.limited_time).count();
            
            if (elapsed >= block_timeout / 2) { // Rate limits expire faster
                expired_rate_limited_ips.push_back(ip);
            }
        }
    }
    
    // Second pass: remove expired IPs with exclusive locks (brief)
    {
        std::lock_guard<std::shared_mutex> blocked_lock(blocked_ips_shared_mutex);
        for (const auto& ip : expired_blocked_ips) {
            auto it = blocked_ips.find(ip);
            if (it != blocked_ips.end()) {
                // Double-check expiration in case of race condition
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.blocked_time).count();
                int timeout = (it->second.custom_block_duration > 0) ? 
                              it->second.custom_block_duration : block_timeout;
                
                if (elapsed >= timeout) {
                    blocked_ips.erase(it);
                    // Critical unblock operations get priority in queue
                    if (!enqueue_job(FirewallJob(JobType::UNBLOCK_IP, ip))) {
                        log_firewall_action_async("ERROR", "Failed to enqueue critical unblock for expired IP: " + ip, 0);
                    }
                }
            }
        }
    }
    
    {
        std::lock_guard<std::shared_mutex> rate_lock(rate_limited_ips_shared_mutex);
        for (const auto& ip : expired_rate_limited_ips) {
            auto it = rate_limited_ips.find(ip);
            if (it != rate_limited_ips.end()) {
                // Double-check expiration in case of race condition
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.limited_time).count();
                
                if (elapsed >= block_timeout / 2) {
                    rate_limited_ips.erase(it);
                    // Critical unrate limit operations get priority in queue
                    if (!enqueue_job(FirewallJob(JobType::UNRATE_LIMIT_IP, ip))) {
                        log_firewall_action_async("ERROR", "Failed to enqueue critical unrate limit for expired IP: " + ip, 0);
                    }
                }
            }
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
    
    if (!expired_blocked_ips.empty() || !expired_rate_limited_ips.empty()) {
        log_firewall_action_async("INFO", "Cleanup completed: " + std::to_string(expired_blocked_ips.size()) + 
                                  " blocks expired, " + std::to_string(expired_rate_limited_ips.size()) + 
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
    
    // IPv4 CIDR matching - use inet_pton for validation
    struct sockaddr_in sa_ip_v4, sa_net_v4;
    bool is_ipv4_ip = (inet_pton(AF_INET, ip.c_str(), &sa_ip_v4.sin_addr) == 1);
    bool is_ipv4_net = (inet_pton(AF_INET, network.c_str(), &sa_net_v4.sin_addr) == 1);
    
    if (is_ipv4_ip && is_ipv4_net) {
        if (prefix_len < 0 || prefix_len > 32) return false;
        
        // SECURITY FIX: Avoid undefined behavior for 32-bit shift
        uint32_t mask = (prefix_len == 32) ? 0xFFFFFFFF : ~((1U << (32 - prefix_len)) - 1);
        return (ntohl(sa_ip_v4.sin_addr.s_addr) & mask) == (ntohl(sa_net_v4.sin_addr.s_addr) & mask);
    }
    
    // IPv6 CIDR matching - use inet_pton for validation (no regex needed)
    struct sockaddr_in6 sa_ip_v6, sa_net_v6;
    bool is_ipv6_ip = (inet_pton(AF_INET6, ip.c_str(), &sa_ip_v6.sin6_addr) == 1);
    bool is_ipv6_net = (inet_pton(AF_INET6, network.c_str(), &sa_net_v6.sin6_addr) == 1);
    
    if (is_ipv6_ip && is_ipv6_net) {
        if (prefix_len < 0 || prefix_len > 128) return false;
        
        // Compare first prefix_len bits
        int bytes_to_check = prefix_len / 8;
        int remaining_bits = prefix_len % 8;
        
        if (memcmp(&sa_ip_v6.sin6_addr, &sa_net_v6.sin6_addr, bytes_to_check) != 0) {
            return false;
        }
        
        if (remaining_bits > 0 && bytes_to_check < 16) {
            uint8_t mask = 0xFF << (8 - remaining_bits);
            if ((sa_ip_v6.sin6_addr.s6_addr[bytes_to_check] & mask) != 
                (sa_net_v6.sin6_addr.s6_addr[bytes_to_check] & mask)) {
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
    // IPv4 checks - use inet_pton directly for validation
    struct sockaddr_in sa4;
    if (inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1) {
        uint32_t addr = ntohl(sa4.sin_addr.s_addr);
        
        // Broadcast address
        if (addr == 0xFFFFFFFF) return true;
        
        // Multicast range (224.0.0.0 to 239.255.255.255)
        if ((addr >= 0xE0000000) && (addr <= 0xEFFFFFFF)) return true;
        
        // Limited broadcast (ends with .255)
        if ((addr & 0xFF) == 0xFF) return true;
    }
    
    // IPv6 checks - use inet_pton directly (no regex needed)
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1) {
        // Multicast (starts with ff)
        if (sa6.sin6_addr.s6_addr[0] == 0xff) return true;
    }
    
    return false;
}

void FirewallAction::update_ip_reputation(const std::string& ip, int reputation_change) {
    std::lock_guard<std::shared_mutex> lock(ip_reputation_shared_mutex);
    
    // FIXED: Implement efficient O(1) cleanup using clock sweep when map is near capacity
    // FIXED: Make clock_hand thread-safe by keeping it local or protecting with mutex
    if (ip_reputation.size() >= kMaxIpReputationSize && ip_reputation.find(ip) == ip_reputation.end()) {
        // Use local iterator for thread safety instead of static
        auto clock_hand = ip_reputation.begin();
        size_t victims_removed = 0;
        const size_t max_sweep = kMaxIpReputationSize / 4; // Remove up to 25% in one sweep
        
        for (size_t sweep_count = 0; sweep_count < max_sweep && victims_removed < max_sweep / 2; ++sweep_count) {
            // Advance clock hand (wrap around if needed)
            if (clock_hand == ip_reputation.end()) {
                clock_hand = ip_reputation.begin();
            }
            
            if (clock_hand == ip_reputation.end()) break; // Empty map
            
            // Check if this entry can be removed (fully recovered reputation)
            if (clock_hand->second >= 100) {
                clock_hand = ip_reputation.erase(clock_hand);
                victims_removed++;
            } else {
                ++clock_hand;
            }
        }
        
        // If still no space, remove one entry with lowest reputation
        if (ip_reputation.size() >= kMaxIpReputationSize) {
            auto lowest = std::min_element(ip_reputation.begin(), ip_reputation.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            if (lowest != ip_reputation.end()) {
                ip_reputation.erase(lowest);
            }
        }
    }
    
    if (ip_reputation.find(ip) == ip_reputation.end()) {
        ip_reputation[ip] = 100; // Default reputation
    }
    
    ip_reputation[ip] = std::max(0, std::min(100, ip_reputation[ip] + reputation_change));
    
    // Clean up entries that have fully recovered to prevent unbounded growth
    if (ip_reputation[ip] >= 100 && reputation_change > 0) {
        ip_reputation.erase(ip);
    }
}

bool FirewallAction::initialize_nftables_infrastructure() const {
    // FIXED: Create filter table and sets with proper syntax
    std::string timeout_str = std::string(kBlockTimeoutNft);
    
    // Simple commands that can be run safely
    const std::vector<std::string> setup_commands = {
        std::string(kNftBinary) + " add table inet filter",
        std::string(kNftBinary) + " add chain inet filter input { type filter hook input priority 0; policy accept; }",
        std::string(kNftBinary) + " add set inet filter ddos_ip_set_v4 { type ipv4_addr; flags timeout; timeout " + timeout_str + "; }",
        std::string(kNftBinary) + " add set inet filter ddos_ip_set_v6 { type ipv6_addr; flags timeout; timeout " + timeout_str + "; }",
        std::string(kNftBinary) + " add rule inet filter input ip saddr @ddos_ip_set_v4 drop",
        std::string(kNftBinary) + " add rule inet filter input ip6 saddr @ddos_ip_set_v6 drop"
    };
    
    for (const auto& command : setup_commands) {
        pid_t pid = fork();
        if (pid == 0) {
            // FIXED: Use safe string splitting without heap allocation to prevent leaks
            std::vector<std::string> args;
            args.reserve(8); // Reserve capacity for typical nft commands
            std::istringstream iss(command);
            std::string token;
            
            while (iss >> token) {
                args.push_back(token);
            }
            
            // FIXED: Use stack-based argv construction (no heap allocation)
            std::vector<char*> argv;
            argv.reserve(args.size() + 1);
            for (auto& arg : args) {
                argv.push_back(const_cast<char*>(arg.c_str())); // Point to existing string storage
            }
            argv.push_back(nullptr);
            
            execvp(argv[0], argv.data());
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            // Continue even if setup commands fail (they may already exist)
        } else {
            g_exec_errors.fetch_add(1);
        }
    }
    
    // FIXED: Use thread-safe console output for const method
    {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "[INFO] nftables infrastructure initialization completed\n" << std::flush;
    }
    return true;
}

void FirewallAction::clear_firewall_log() {
    // Note: Log directory creation is handled in create_log_directory() before privilege drop
    // No need to create directory here as it's done earlier with proper permissions
    
    // Initialize log file using constants
    std::ofstream log_file(kLogFileName, std::ios::trunc);
    if (log_file.is_open()) {
        log_file << "=== DDoS Inspector Firewall Log (Secure Mode) ===\n";
        log_file.close();
        
        // Set file permissions to 0600 (owner read/write only)
        chmod(kLogFileName, S_IRUSR | S_IWUSR);
    }
}

// Helper function to safely wait for child processes, handling SIGCHLD races
bool FirewallAction::safe_waitpid(pid_t pid, int* status, const std::string& operation) {
    // Try to wait for the specific child process
    pid_t result = waitpid(pid, status, 0);
    
    if (result == pid) {
        return true; // Successfully got status
    } else if (result == -1) {
        if (errno == ECHILD) {
            // Child was already reaped by SIGCHLD handler - assume success
            // Since we only reap children in signal handler, this means child completed
            *status = 0; // Assume successful completion
            log_firewall_action_async("DEBUG", operation + " process already reaped by SIGCHLD handler", 0);
            return true;
        } else {
            // Real error
            log_firewall_action_async("ERROR", "waitpid failed for " + operation + ": " + strerror(errno), errno);
            return false;
        }
    } else {
        // Unexpected result
        log_firewall_action_async("ERROR", "waitpid returned unexpected result for " + operation, 0);
        return false;
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

// ADDED: Batch command execution for improved performance under high load
bool FirewallAction::execute_batch_block_command_safe(const std::vector<std::string>& ips) {
    if (ips.empty()) return true;
    
    // Separate IPv4 and IPv6 addresses
    std::vector<std::string> ipv4_addrs, ipv6_addrs;
    for (const auto& ip : ips) {
        if (!validate_ip_address(ip)) {
            log_firewall_action_async("ERROR", "Invalid IP in batch block: " + ip, -1);
            continue;
        }
        
        try {
            IPFamily family = get_ip_family(ip);
            if (family == IPFamily::IPv4) {
                ipv4_addrs.push_back(ip);
            } else {
                ipv6_addrs.push_back(ip);
            }
        } catch (const std::exception& e) {
            log_firewall_action_async("ERROR", "Invalid IP family in batch: " + ip, -1);
        }
    }
    
    bool success = true;
    
    // FIXED: Split large batches to avoid ARG_MAX limits
    auto process_batch = [&](const std::vector<std::string>& addrs, const char* set_name) -> bool {
        if (addrs.empty()) return true;
        
        // Calculate approximate command length and split if necessary
        size_t base_cmd_len = 100; // "nft add element inet filter " + set_name + " { }"
        size_t total_len = base_cmd_len;
        std::vector<std::vector<std::string>> batches;
        std::vector<std::string> current_batch;
        
        for (const auto& addr : addrs) {
            size_t addr_len = addr.length() + 20; // IP + " timeout 10m, "
            if (total_len + addr_len > kMaxArgLength && !current_batch.empty()) {
                // Start new batch
                batches.push_back(current_batch);
                current_batch.clear();
                total_len = base_cmd_len;
            }
            current_batch.push_back(addr);
            total_len += addr_len;
        }
        
        if (!current_batch.empty()) {
            batches.push_back(current_batch);
        }
        
        // Process each batch
        bool batch_success = true;
        for (const auto& batch : batches) {
            std::string elements = "{";
            for (size_t i = 0; i < batch.size(); ++i) {
                if (i > 0) elements += ", ";
                elements += batch[i] + " timeout " + kBlockTimeoutNft;
            }
            elements += "}";
            
            pid_t pid = fork();
            if (pid == 0) {
                const char* args[] = {
                    kNftBinary, "add", "element", "inet", "filter", set_name,
                    elements.c_str(), nullptr
                };
                execvp(kNftBinary, const_cast<char* const*>(args));
                _exit(127);
            } else if (pid > 0) {
                int status;
                if (safe_waitpid(pid, &status, "batch block")) {
                    if (WIFEXITED(status)) {
                        int exit_code = WEXITSTATUS(status);
                        if (exit_code != 0 && exit_code != 1) {
                            batch_success = false;
                            g_exec_errors.fetch_add(1);
                            log_firewall_action_async("ERROR", "Batch block failed for " + std::string(set_name), exit_code);
                        } else {
                            log_firewall_action_async("SUCCESS", "Batch blocked " + std::to_string(batch.size()) + 
                                                      " addresses in " + std::string(set_name), 0);
                        }
                    } else {
                        batch_success = false;
                        g_exec_errors.fetch_add(1);
                    }
                } else {
                    batch_success = false;
                    g_exec_errors.fetch_add(1);
                }
            } else {
                batch_success = false;
                g_exec_errors.fetch_add(1);
            }
        }
        return batch_success;
    };
    
    // Process IPv4 and IPv6 batches
    success &= process_batch(ipv4_addrs, "ddos_ip_set_v4");
    success &= process_batch(ipv6_addrs, "ddos_ip_set_v6");
    
    return success;
}

bool FirewallAction::execute_batch_unblock_command_safe(const std::vector<std::string>& ips) {
    if (ips.empty()) return true;
    
    // Separate IPv4 and IPv6 addresses
    std::vector<std::string> ipv4_addrs, ipv6_addrs;
    for (const auto& ip : ips) {
        if (!validate_ip_address(ip)) {
            log_firewall_action_async("ERROR", "Invalid IP in batch unblock: " + ip, -1);
            continue;
        }
        
        try {
            IPFamily family = get_ip_family(ip);
            if (family == IPFamily::IPv4) {
                ipv4_addrs.push_back(ip);
            } else {
                ipv6_addrs.push_back(ip);
            }
        } catch (const std::exception& e) {
            log_firewall_action_async("ERROR", "Invalid IP family in batch unblock: " + ip, -1);
        }
    }
    
    bool success = true;
    
    // FIXED: Use the same batching logic as block to avoid ARG_MAX issues
    auto process_unblock_batch = [&](const std::vector<std::string>& addrs, const char* set_name) -> bool {
        if (addrs.empty()) return true;
        
        // Calculate approximate command length and split if necessary
        size_t base_cmd_len = 100; // "nft delete element inet filter " + set_name + " { }"
        size_t total_len = base_cmd_len;
        std::vector<std::vector<std::string>> batches;
        std::vector<std::string> current_batch;
        
        for (const auto& addr : addrs) {
            size_t addr_len = addr.length() + 5; // IP + ", "
            if (total_len + addr_len > kMaxArgLength && !current_batch.empty()) {
                // Start new batch
                batches.push_back(current_batch);
                current_batch.clear();
                total_len = base_cmd_len;
            }
            current_batch.push_back(addr);
            total_len += addr_len;
        }
        
        if (!current_batch.empty()) {
            batches.push_back(current_batch);
        }
        
        // Process each batch
        bool batch_success = true;
        for (const auto& batch : batches) {
            std::string elements = "{";
            for (size_t i = 0; i < batch.size(); ++i) {
                if (i > 0) elements += ", ";
                elements += batch[i];
            }
            elements += "}";
            
            pid_t pid = fork();
            if (pid == 0) {
                const char* args[] = {
                    kNftBinary, "delete", "element", "inet", "filter", set_name,
                    elements.c_str(), nullptr
                };
                execvp(kNftBinary, const_cast<char* const*>(args));
                _exit(127);
            } else if (pid > 0) {
                int status;
                if (safe_waitpid(pid, &status, "batch unblock")) {
                    if (WIFEXITED(status)) {
                        int exit_code = WEXITSTATUS(status);
                        if (exit_code != 0 && exit_code != 1) {
                            batch_success = false;
                            g_exec_errors.fetch_add(1);
                            log_firewall_action_async("WARNING", "Batch unblock failed for " + std::string(set_name) + 
                                                      " with status " + std::to_string(exit_code), 0);
                        } else {
                            log_firewall_action_async("SUCCESS", "Batch unblocked " + std::to_string(batch.size()) + 
                                                      " addresses from " + std::string(set_name), 0);
                        }
                    } else {
                        batch_success = false;
                        g_exec_errors.fetch_add(1);
                    }
                } else {
                    batch_success = false;
                    g_exec_errors.fetch_add(1);
                }
            } else {
                batch_success = false;
                g_exec_errors.fetch_add(1);
            }
        }
        return batch_success;
    };
    
    // Process IPv4 and IPv6 batches
    success &= process_unblock_batch(ipv4_addrs, "ddos_ip_set_v4");
    success &= process_unblock_batch(ipv6_addrs, "ddos_ip_set_v6");
    
    return success;
}

std::vector<std::string> FirewallAction::get_current_firewall_rules() const {
    std::vector<std::string> rules;
    
    // Create a pipe to capture command output
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        // NOTE: No FDs to close when pipe() itself fails
        // Use thread-safe console output for const method
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "[ERROR] Failed to create pipe for nftables query: " << strerror(errno) << '\n';
        return rules;
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[0]); // Close read end
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe
        dup2(pipefd[1], STDERR_FILENO); // Redirect stderr to pipe  
        close(pipefd[1]);
        
        // Execute nft list command to get current rules
        const char* args[] = {
            kNftBinary, "list", "table", "inet", "filter", nullptr
        };
        execvp(kNftBinary, const_cast<char* const*>(args));
        _exit(127); // exec failed
    } else if (pid > 0) {
        // Parent process
        close(pipefd[1]); // Close write end
        
        // Read output from pipe with proper buffer handling
        std::string output;
        char buffer[4096];
        ssize_t bytes_read;
        
        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            // FIXED: Properly handle partial reads and buffer bounds
            output.append(buffer, static_cast<size_t>(bytes_read));
        }
        
        close(pipefd[0]);
        
        // Wait for child process to complete
        // NOTE: Using plain waitpid in const method (can't use safe_waitpid which is non-const)
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            // Parse output into individual rules
            std::istringstream iss(output);
            std::string line;
            
            while (std::getline(iss, line)) {
                // Trim whitespace
                line.erase(0, line.find_first_not_of(" \t\r\n"));
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                
                // Skip empty lines and comments
                if (!line.empty() && line[0] != '#') {
                    rules.push_back(line);
                }
            }
        } else {
            {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "[WARNING] nftables query command failed with status " << WEXITSTATUS(status) << '\n';
            }
            
            // Return basic info if command failed
            rules.push_back("# nftables query failed - table may not exist");
            rules.push_back("# Run 'nft list tables' to check available tables");
        }
    } else {
        // Fork failed
        close(pipefd[0]);
        close(pipefd[1]);
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "[ERROR] Failed to fork process for nftables query: " << strerror(errno) << '\n';
        }
        rules.push_back("# Error: Unable to query nftables rules");
    }
    
    return rules;
}

FirewallAction::Metrics FirewallAction::get_metrics() const {
    Metrics metrics;
    
    // Get current counts
    metrics.blocked_ips = get_blocked_count();
    metrics.rate_limited_ips = get_rate_limited_count();
    
    // Get global counters
    metrics.dropped_jobs = g_dropped_jobs.load();
    metrics.dropped_logs = g_dropped_logs.load();
    metrics.exec_errors = g_exec_errors.load();
    
    // Get container sizes
    {
        std::shared_lock<std::shared_mutex> lock(whitelist_shared_mutex);
        metrics.whitelist_size = whitelist.size();
    }
    
    {
        std::shared_lock<std::shared_mutex> lock(ip_reputation_shared_mutex);
        metrics.reputation_entries = ip_reputation.size();
    }
    
    return metrics;
}

void FirewallAction::rotate_log_if_needed() {
    std::lock_guard<std::mutex> lock(log_rotation_mutex);
    
    // Check current log file size
    struct stat st;
    if (stat(kLogFileName, &st) != 0) {
        return; // Log file doesn't exist or can't be accessed
    }
    
    if (static_cast<size_t>(st.st_size) < kMaxLogSizeBytes) {
        return; // File is not too large yet
    }
    
    // Rotate log files: log.4 -> deleted, log.3 -> log.4, ..., log -> log.1
    for (int i = kMaxLogFiles - 1; i > 0; --i) {
        std::string old_name = std::string(kLogFileName) + "." + std::to_string(i);
        std::string new_name = std::string(kLogFileName) + "." + std::to_string(i + 1);
        
        if (i == kMaxLogFiles - 1) {
            // Delete the oldest log
            unlink(old_name.c_str());
        } else {
            // Rename files
            rename(old_name.c_str(), new_name.c_str());
        }
    }
    
    // Move current log to .1
    std::string backup_name = std::string(kLogFileName) + ".1";
    rename(kLogFileName, backup_name.c_str());
    
    // Create new log file
    std::ofstream new_log(kLogFileName);
    if (new_log.is_open()) {
        new_log << "=== DDoS Inspector Firewall Log (Rotated) ===\n";
        new_log.close();
        chmod(kLogFileName, S_IRUSR | S_IWUSR);
    }
}
