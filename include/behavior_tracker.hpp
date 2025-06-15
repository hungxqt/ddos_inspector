#ifndef BEHAVIOR_TRACKER_H
#define BEHAVIOR_TRACKER_H

#include <string>
#include <unordered_map>
#include <chrono>
#include <deque>
#include <unordered_set>
#include <atomic>
#include <list>
#include <mutex>
#include <vector>
#include "packet_data.hpp"

// LRU Cache implementation for memory management
template<typename Key, typename Value>
class LRUCache {
private:
    size_t capacity_;
    std::list<std::pair<Key, Value>> items_;
    std::unordered_map<Key, typename decltype(items_)::iterator> cache_;
    mutable std::mutex mutex_;

public:
    explicit LRUCache(size_t capacity) : capacity_(capacity) {}
    
    void put(const Key& key, const Value& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            items_.erase(it->second);
            cache_.erase(it);
        }
        
        items_.push_front({key, value});
        cache_[key] = items_.begin();
        
        if (cache_.size() > capacity_) {
            auto last = items_.end();
            --last;
            cache_.erase(last->first);
            items_.pop_back();
        }
    }
    
    bool get(const Key& key, Value& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return false;
        }
        
        value = it->second->second;
        items_.splice(items_.begin(), items_, it->second);
        return true;
    }
    
    void erase(const Key& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            items_.erase(it->second);
            cache_.erase(it);
        }
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_.size();
    }
      void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_.clear();
        items_.clear();
    }
    
    // Iterator support for range-based loops
    auto begin() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return items_.begin();
    }
    
    auto end() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return items_.end();
    }
    
    // Thread-safe iteration helper
    template<typename Func>
    void for_each(Func&& func) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& item : items_) {
            func(item.first, item.second);
        }
    }
};

class BehaviorTracker {
public:
    static constexpr size_t MAX_TRACKED_IPS = 10000; // Limit memory usage
    static constexpr std::chrono::minutes CLEANUP_INTERVAL{5}; // Cleanup every 5 minutes
    static constexpr std::chrono::minutes IP_TIMEOUT{30}; // Remove IPs after 30 minutes of inactivity
    
    BehaviorTracker();
    bool inspect(const PacketData& pkt);
    
    // Metrics methods
    size_t get_connection_count() const;
    size_t get_tracked_ips_count() const;
    
    // Memory management
    void cleanup_expired_behaviors();
    void force_cleanup_if_needed();
    
private:
    struct TimestampedEvent {
        std::chrono::steady_clock::time_point timestamp;
        std::string event_type;
    };
      struct Behavior {
        int half_open = 0;
        int total_packets = 0;
        int syn_count = 0;
        int ack_count = 0;
        int http_requests = 0;
        
        // Enhanced real-world traffic metrics
        size_t packet_size_sum = 0;
        int unique_session_count = 0;
        double legitimate_traffic_score = 0.0;
        double baseline_rate = 0.0;
        
        // Time-based tracking
        std::deque<TimestampedEvent> recent_events;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        std::chrono::steady_clock::time_point last_baseline_update;
        
        // HTTP specific tracking
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> http_sessions;
        std::unordered_set<std::string> incomplete_requests;
        std::unordered_set<std::string> seen_sessions;
        
        // Connection state tracking
        std::unordered_set<std::string> established_connections;
        
        // Traffic pattern analysis
        std::vector<double> packet_intervals; // Time between packets for pattern analysis
        std::vector<size_t> packet_sizes;     // Packet size distribution
    };
    
    // Use LRU cache instead of unlimited map
    LRUCache<std::string, Behavior> behaviors;
    mutable std::atomic<size_t> active_connections{0};
    
    // Memory management
    std::chrono::steady_clock::time_point last_cleanup;
    mutable std::mutex cleanup_mutex;
    
    // Global tracking for distributed attacks
    int total_global_packets = 0;
    std::chrono::steady_clock::time_point last_global_reset;
      // Helper methods
    void cleanupOldEvents(Behavior& b);
    bool detectSynFlood(const Behavior& b);
    bool detectAckFlood(const Behavior& b);
    bool detectHttpFlood(const Behavior& b);
    bool detectSlowloris(const Behavior& b);
    bool detectVolumeAttack(const Behavior& b);
    bool detectDistributedAttack();
    std::string generateConnectionId(const PacketData& pkt);
    void updateConnectionCount() const;
      // Enhanced real-world analysis methods
    void updateBaselineRate(Behavior& b, const std::chrono::steady_clock::time_point& now);
    bool isLegitimateTrafficPattern(const Behavior& b);
    double calculatePacketIntervalVariance(const std::vector<double>& intervals);
    double calculateSizeVariance(const std::vector<size_t>& sizes);
    bool detectFlashCrowdPattern(const Behavior& b);
    double calculateLegitimacyFactor(const Behavior& b);
    int calculateAdaptiveThreshold(const Behavior& b, double legitimacy_factor);
};

#endif // BEHAVIOR_TRACKER_H
