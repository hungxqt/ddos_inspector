#ifndef FIREWALL_ACTION_H
#define FIREWALL_ACTION_H

#include <string>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <queue>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <regex>
#include <sys/stat.h>

// Enhanced threat levels for adaptive response
enum class ThreatLevel : std::uint8_t {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Mitigation strategies for different attack patterns
enum class MitigationStrategy : std::uint8_t {
    NONE,
    RATE_LIMIT,
    TARPIT,
    CHALLENGE_RESPONSE,
    TEMPORARY_BLOCK,
    PERMANENT_BLOCK,
    GEO_BLOCK
};

// IP address family enum
enum class IPFamily : std::uint8_t {
    IPv4,
    IPv6
};

// Job types for the worker queue
enum class JobType : std::uint8_t {
    BLOCK_IP,
    UNBLOCK_IP,
    RATE_LIMIT_IP,
    UNRATE_LIMIT_IP,
    LOG_MESSAGE
};

// Job structure for the worker queue
struct FirewallJob {
    JobType type;
    std::string ip;
    std::string message;
    int severity;
    std::string level;
    int error_code;
    
    FirewallJob(JobType t, const std::string& addr) 
        : type(t), ip(addr), severity(0), error_code(0) {}
    FirewallJob(JobType t, const std::string& addr, int sev) 
        : type(t), ip(addr), severity(sev), error_code(0) {}
    FirewallJob(JobType t, const std::string& lvl, const std::string& msg, int err = 0)
        : type(t), message(msg), level(lvl), error_code(err) {}
};

class FirewallAction {
public:
    FirewallAction(int block_timeout_seconds = 600);
    ~FirewallAction();
    
    // Core blocking functionality
    void block(const std::string& ip);
    void block(const std::string& ip, int custom_duration_seconds);
    void unblock(const std::string& ip);
    
    // Advanced mitigation methods
    void rate_limit(const std::string& ip, int severity_level);
    void apply_tarpit(const std::string& ip);
    void send_tcp_reset(const std::string& ip);
    void apply_adaptive_mitigation(const std::string& ip, const std::string& attack_type, double intensity);
    
    // Whitelist management
    void add_to_whitelist(const std::string& ip_or_cidr);
    void remove_from_whitelist(const std::string& ip_or_cidr);
    bool is_whitelisted(const std::string& ip) const;
    
    // Threat intelligence and learning
    void update_threat_level(ThreatLevel level);
    void learn_legitimate_pattern(const std::string& port, double confidence);
    void analyze_traffic_patterns(const std::vector<std::string>& recent_ips);
    
    // Query methods
    bool is_blocked(const std::string& ip) const;
    bool is_rate_limited(const std::string& ip) const;
    size_t get_blocked_count() const;
    size_t get_rate_limited_count() const;
    std::vector<std::string> get_rate_limited_ips() const;
    std::vector<std::string> get_blocked_ips() const;
    ThreatLevel get_current_threat_level() const;
    
    // Maintenance
    void cleanup_expired_blocks();
    
private:
    // Block and rate limit info structures
    struct BlockInfo {
        std::chrono::steady_clock::time_point blocked_time;
        std::chrono::steady_clock::time_point last_seen;
        bool is_blocked = false;
        int custom_block_duration = 0; // Custom duration in seconds, 0 = use default
        MitigationStrategy strategy = MitigationStrategy::NONE;
        double threat_score = 0.0;
        int violation_count = 0;
        std::string attack_type = "unknown";
        bool is_repeat_offender = false;
    };
    
    struct RateLimitInfo {
        std::chrono::steady_clock::time_point limited_time;
        bool is_rate_limited = false;
        int severity_level = 0;
    };
    
    // Thread-safe data structures with shared_mutex for better performance
    mutable std::shared_mutex blocked_ips_shared_mutex;
    std::unordered_map<std::string, BlockInfo> blocked_ips;
    
    mutable std::shared_mutex rate_limited_ips_shared_mutex;
    std::unordered_map<std::string, RateLimitInfo> rate_limited_ips;
    
    mutable std::shared_mutex whitelist_shared_mutex;
    std::unordered_set<std::string> whitelist;
    
    mutable std::shared_mutex ip_reputation_shared_mutex;
    std::unordered_map<std::string, int> ip_reputation;
    
    mutable std::mutex legitimate_patterns_mutex;
    std::unordered_map<std::string, double> legitimate_patterns;
    
    // Static thread infrastructure for worker and logger queues
    static std::mutex worker_mutex;
    static std::condition_variable worker_cv;
    static std::queue<FirewallJob> job_queue;
    static std::thread worker_thread;
    static std::atomic<bool> worker_running;
    static std::atomic<bool> shutdown_requested;
    
    static std::mutex logger_mutex;
    static std::condition_variable logger_cv;
    static std::queue<FirewallJob> log_queue;
    static std::thread logger_thread;
    static std::atomic<bool> logger_running;
    
    // Compile-time validation patterns to prevent shell injection
    static const std::regex ipv4_regex;
    static const std::regex ipv6_regex;
    static const std::regex shell_metachar_regex;
    
    // Configuration
    int block_timeout;
    mutable std::chrono::steady_clock::time_point last_cleanup_time;
    std::chrono::minutes cleanup_interval;
    ThreatLevel current_threat_level;
    double global_attack_intensity;
    int reputation_decay_time_hours;
    bool privileges_dropped;
    
    // Thread management
    void start_worker_thread();
    void start_logger_thread();
    void worker_loop();
    void logger_loop();
    void process_firewall_job(const FirewallJob& job);
    
    // Security and validation
    void drop_privileges();
    static bool validate_ip_address(const std::string& ip);
    IPFamily get_ip_family(const std::string& ip);
    
    // Safe command execution methods
    bool execute_block_command_safe(const std::string& ip, IPFamily family);
    bool execute_unblock_command_safe(const std::string& ip, IPFamily family);
    bool execute_rate_limit_command_safe(const std::string& ip, int severity, IPFamily family);
    bool execute_unrate_limit_command_safe(const std::string& ip, IPFamily family);
    
    // Async logging
    void enqueue_job(const FirewallJob& job);
    void log_firewall_action_async(const std::string& level, const std::string& message, int error_code = 0);
    void write_log_message_safe(const std::string& level, const std::string& message, int error_code);
    void log_firewall_action(const std::string& level, const std::string& message, int error_code = 0);
    
    // Helper methods
    bool is_cidr_match(const std::string& ip, const std::string& cidr) const;
    bool is_broadcast_or_multicast(const std::string& ip) const;
    void update_ip_reputation(const std::string& ip, int reputation_change);
    void initialize_default_whitelist();
    bool initialize_nftables_infrastructure() const;
    void clear_firewall_log();
};

#endif // FIREWALL_ACTION_H
