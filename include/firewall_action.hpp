#ifndef FIREWALL_ACTION_H
#define FIREWALL_ACTION_H

#include <string>
#include <mutex>
#include <chrono>
#include <unordered_map>

class FirewallAction {
public:
    FirewallAction(int block_timeout_seconds = 600);
    ~FirewallAction();
    
    void block(const std::string& ip);
    void unblock(const std::string& ip);
    void rate_limit(const std::string& ip, int severity_level);
    bool is_blocked(const std::string& ip) const;
    bool is_rate_limited(const std::string& ip) const;
    size_t get_blocked_count() const;
    size_t get_rate_limited_count() const;
    void cleanup_expired_blocks();
    
private:
    struct BlockInfo {
        std::chrono::steady_clock::time_point blocked_time;
        bool is_blocked;
        int rate_limit_level; // 0 = no limit, 1-4 = severity levels
    };
    
    std::unordered_map<std::string, BlockInfo> blocked_ips;
    mutable std::mutex blocked_ips_mutex;
    int block_timeout;
    
    bool execute_block_command(const std::string& ip);
    bool execute_unblock_command(const std::string& ip);
    bool execute_rate_limit_command(const std::string& ip, int severity);
};

#endif // FIREWALL_ACTION_H