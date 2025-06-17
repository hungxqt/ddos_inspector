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
    std::vector<std::string> get_rate_limited_ips() const; // New method to list rate-limited IPs
    std::vector<std::string> get_blocked_ips() const; // New method to list blocked IPs
    std::vector<std::string> get_current_firewall_rules() const; // View current nftables rules
    ThreatLevel get_current_threat_level() const;
    
    // Maintenance
    void cleanup_expired_blocks();
    void reset_adaptive_thresholds();
    
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
        std::string attack_type;
        bool is_repeat_offender;
    };
    
    // Core data structures
    std::unordered_map<std::string, BlockInfo> blocked_ips;
    std::unordered_set<std::string> whitelist;
    std::unordered_map<std::string, double> legitimate_patterns; // port -> confidence
    std::unordered_map<std::string, int> ip_reputation; // IP -> reputation score
    
    // SECURITY FIX: Thread safety with proper mutexes
    mutable std::shared_mutex blocked_ips_mutex;  // Allow multiple readers
    mutable std::mutex whitelist_mutex;
    mutable std::mutex learning_mutex;
    mutable std::mutex ip_reputation_mutex;  // FIXED: Protect ip_reputation
    
    // PERFORMANCE FIX: Worker queue system to replace unbounded thread spawning
    std::queue<FirewallJob> job_queue;
    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    std::atomic<bool> worker_running{true};
    std::thread worker_thread;
    
    // SECURITY FIX: Async logging system
    std::queue<std::string> log_queue;
    std::mutex log_mutex;
    std::condition_variable log_cv;
    std::atomic<bool> logger_running{true};
    std::thread logger_thread;
    
    // SECURITY FIX: IP validation patterns
    std::regex ipv4_pattern;
    std::regex ipv6_pattern;

    // Configuration
    int block_timeout;
    
    // Cleanup rate limiting
    mutable std::chrono::steady_clock::time_point last_cleanup_time;
    static constexpr std::chrono::seconds cleanup_interval{60}; // Cleanup every 60 seconds
    int adaptive_threshold_base{100};
    bool legitimate_traffic_learning_enabled{false};
    ThreatLevel current_threat_level{ThreatLevel::NONE};
    double global_attack_intensity{0.0};
    
    // Adaptive parameters
    double attack_detection_threshold{0.7};
    int max_violations_before_escalation{5};
    int reputation_decay_time_hours{24};
    
    // SECURITY FIX: Safe command execution methods
    bool execute_block_command_safe(const std::string& ip, IPFamily family);
    bool execute_unblock_command_safe(const std::string& ip, IPFamily family);
    bool execute_rate_limit_command_safe(const std::string& ip, int severity, IPFamily family);
    bool execute_unrate_limit_command_safe(const std::string& ip, IPFamily family);
    bool execute_mitigation_strategy(const std::string& ip, MitigationStrategy strategy);
    
    // DEPRECATED: Old unsafe methods (kept for compatibility but not used)
    bool execute_block_command(const std::string& ip);
    bool execute_unblock_command(const std::string& ip);
    bool execute_rate_limit_command(const std::string& ip, int severity);
    bool execute_unrate_limit_command(const std::string& ip);
    
    // SECURITY FIX: Enhanced validation methods
    bool validate_ip_address_strict(const std::string& ip) const;
    IPFamily detect_ip_family(const std::string& ip) const;
    bool sanitize_input(const std::string& input) const;
    bool check_nftables_availability() const;
    bool initialize_nftables_infrastructure() const;
    void log_firewall_action_safe(const std::string& level, const std::string& message, int error_code = 0);
    void clear_firewall_log() const;
    bool verify_ip_in_nftables(const std::string& ip) const;
    
    // PERFORMANCE FIX: Worker thread methods
    void worker_thread_main();
    void logger_thread_main();
    void enqueue_job(const FirewallJob& job);
    void enqueue_log(const std::string& level, const std::string& message, int error_code = 0);
    void process_job(const FirewallJob& job);
    
    // Enhanced mitigation methods
    void apply_additional_mitigation(const std::string& ip) const;
    void apply_bandwidth_throttling(const std::string& ip) const;
    void apply_port_specific_blocking(const std::string& ip, const std::vector<int>& ports) const;
    void apply_time_based_restrictions(const std::string& ip, int hour_start, int hour_end) const;
    void apply_geo_blocking(const std::string& country_code) const;
    void cleanup_additional_restrictions(const std::string& ip) const;
    
    // Advanced functionality
    void initialize_default_whitelist();
    MitigationStrategy determine_mitigation_strategy(const std::string& ip, const std::string& attack_type, double intensity);
    int calculate_adaptive_timeout(const std::string& ip, double threat_score);
    double calculate_threat_score(const std::string& ip, const std::string& attack_type, double intensity);
    bool is_repeat_offender(const std::string& ip) const;
    bool is_repeat_offender_internal(const std::string& ip) const; // Internal version that doesn't lock mutex
    void update_ip_reputation(const std::string& ip, int reputation_change);
    bool is_cidr_match(const std::string& ip, const std::string& cidr) const;
    bool is_broadcast_or_multicast(const std::string& ip) const;
    std::vector<std::string> extract_subnet_patterns(const std::vector<std::string>& ips);
      // SECURITY FIX: Privilege management
    void drop_privileges();
    void restore_privileges();
    
    // Snort operation mode - less aggressive to avoid interfering with packet analysis
    bool snort_compatible_mode{true};
};

#endif // FIREWALL_ACTION_H