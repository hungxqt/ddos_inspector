#ifndef FIREWALL_ACTION_H
#define FIREWALL_ACTION_H

#include <string>
#include <mutex>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>

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
    ThreatLevel get_current_threat_level() const;
    
    // Maintenance
    void cleanup_expired_blocks();
    void reset_adaptive_thresholds();
    
private:
    struct BlockInfo {
        std::chrono::steady_clock::time_point blocked_time;
        std::chrono::steady_clock::time_point last_seen;
        bool is_blocked;
        int rate_limit_level; // 0 = no limit, 1-4 = severity levels
        int custom_block_duration; // Custom duration in seconds, 0 = use default
        MitigationStrategy strategy;
        double threat_score;
        int violation_count;
        std::string attack_type;
        bool is_repeat_offender;
    };
    
    // Core data structures
    std::unordered_map<std::string, BlockInfo> blocked_ips;
    std::unordered_set<std::string> whitelist;
    std::unordered_map<std::string, double> legitimate_patterns; // port -> confidence
    std::unordered_map<std::string, int> ip_reputation; // IP -> reputation score
    
    // Thread safety
    mutable std::mutex blocked_ips_mutex;
    mutable std::mutex whitelist_mutex;
    mutable std::mutex learning_mutex;    // Configuration
    int block_timeout;
    int adaptive_threshold_base{100};
    bool legitimate_traffic_learning_enabled{false};
    ThreatLevel current_threat_level{ThreatLevel::NONE};
    double global_attack_intensity{0.0};
      // Adaptive parameters
    double attack_detection_threshold{0.7};
    int max_violations_before_escalation{5};
    int reputation_decay_time_hours{24};
    
    // Private methods
    bool execute_block_command(const std::string& ip);
    bool execute_unblock_command(const std::string& ip);
    bool execute_rate_limit_command(const std::string& ip, int severity);
    bool execute_mitigation_strategy(const std::string& ip, MitigationStrategy strategy);
    
    // Advanced functionality
    void initialize_default_whitelist();
    MitigationStrategy determine_mitigation_strategy(const std::string& ip, const std::string& attack_type, double intensity);
    int calculate_adaptive_timeout(const std::string& ip, double threat_score);
    double calculate_threat_score(const std::string& ip, const std::string& attack_type, double intensity);
    bool is_repeat_offender(const std::string& ip);
    void update_ip_reputation(const std::string& ip, int reputation_change);
    bool is_cidr_match(const std::string& ip, const std::string& cidr) const;
    std::vector<std::string> extract_subnet_patterns(const std::vector<std::string>& ips);
};

#endif // FIREWALL_ACTION_H