#ifndef BEHAVIOR_TRACKER_H
#define BEHAVIOR_TRACKER_H

#include <string>
#include <unordered_map>
#include <chrono>
#include <deque>
#include <unordered_set>
#include <atomic>
#include <array>       // FIXED: Add include for std::array used in RingBuffer
#include <list>
#include <mutex>
#include <vector>
#include <memory>
#include "packet_data.hpp"

// LRU Cache implementation with safer in-place update pattern
template<typename Key, typename Value>
class LRUCache {
private:
    size_t capacity_;
    std::list<std::pair<Key, std::shared_ptr<Value>>> items_;
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
        
        items_.push_front({key, std::make_shared<Value>(value)});
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
        
        value = *(it->second->second);
        items_.splice(items_.begin(), items_, it->second);
        return true;
    }
    
    // FIXED: Safer in-place update pattern to avoid lost updates/races
    template<typename UpdateFunc>
    bool with_write(const Key& key, UpdateFunc&& func) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return false;
        }
        
        // Call the update function with direct access to the shared value
        func(*(it->second->second));
        
        // Move to front (most recently used)
        items_.splice(items_.begin(), items_, it->second);
        return true;
    }
    
    // FIXED: Get shared_ptr for safe concurrent access
    std::shared_ptr<Value> get_shared(const Key& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            return nullptr;
        }
        
        items_.splice(items_.begin(), items_, it->second);
        return it->second->second;
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
    
    // Thread-safe iteration helper
    template<typename Func>
    void for_each(Func&& func) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& item : items_) {
            func(item.first, *(item.second));
        }
    }
};

// Configuration constants and structures for maintainability
struct BehaviorConfig {
    // Memory limits
    static constexpr size_t MAX_TRACKED_IPS = 10000;
    static constexpr size_t MAX_SEEN_SESSIONS = 1000;
    static constexpr size_t MAX_INCOMPLETE_REQUESTS = 500;
    static constexpr size_t MAX_ESTABLISHED_CONNECTIONS = 2000;
    static constexpr size_t PACKET_HISTORY_SIZE = 100;
    static constexpr size_t MAX_RECENT_EVENTS = 1000;  // FIXED: Hard cap for recent_events deque
    
    // Timing constants
    static constexpr std::chrono::minutes CLEANUP_INTERVAL{5};
    static constexpr std::chrono::minutes IP_TIMEOUT{30};
    static constexpr std::chrono::seconds GLOBAL_RESET_INTERVAL{300};
    static constexpr std::chrono::seconds DISTRIBUTED_ATTACK_CHECK_INTERVAL{30};
    
    // Detection thresholds
    static constexpr int SYN_FLOOD_THRESHOLD = 5000;
    static constexpr int HTTP_FLOOD_THRESHOLD = 1000;
    static constexpr double LEGITIMACY_DECAY_RATE = 0.99;
    static constexpr double BASELINE_UPDATE_ALPHA = 0.05;
};

// Detection result with confidence and severity
enum class DetectionConfidence : std::uint8_t {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class AttackSeverity : std::uint8_t {
    MINOR = 1,
    MODERATE = 2,
    SEVERE = 3,
    CRITICAL = 4
};

struct DetectionResult {
    bool is_attack = false;
    DetectionConfidence confidence = DetectionConfidence::LOW;
    AttackSeverity severity = AttackSeverity::MINOR;
    std::string attack_type;
    double score = 0.0;
};

// FIXED: Attack type enum for hot-path efficiency instead of string comparisons
enum class AttackType : std::uint8_t {
    UNKNOWN = 0,
    SYN_FLOOD = 1,
    UDP_FLOOD = 2,
    HTTP_FLOOD = 3,
    SLOWLORIS = 4,
    PORT_SCAN = 5,
    BANDWIDTH_ATTACK = 6,
    SQL_INJECTION = 7,
    XSS_ATTACK = 8,
    REPLAY_ATTACK = 9,
    DISTRIBUTED = 10
};

// FIXED: Helper to convert attack type to string for logging
inline const char* attack_type_to_string(AttackType type) {
    switch (type) {
        case AttackType::SYN_FLOOD: return "SYN_FLOOD";
        case AttackType::UDP_FLOOD: return "UDP_FLOOD";
        case AttackType::HTTP_FLOOD: return "HTTP_FLOOD";
        case AttackType::SLOWLORIS: return "SLOWLORIS";
        case AttackType::PORT_SCAN: return "PORT_SCAN";
        case AttackType::BANDWIDTH_ATTACK: return "BANDWIDTH_ATTACK";
        case AttackType::SQL_INJECTION: return "SQL_INJECTION";
        case AttackType::XSS_ATTACK: return "XSS_ATTACK";
        case AttackType::REPLAY_ATTACK: return "REPLAY_ATTACK";
        case AttackType::DISTRIBUTED: return "DISTRIBUTED";
        default: return "UNKNOWN";
    }
}

// Ring buffer for efficient O(1) operations on packet history
template<typename T, size_t Size>
class RingBuffer {
private:
    std::array<T, Size> buffer_;
    size_t head_ = 0;
    size_t size_ = 0;

public:
    void push(const T& item) {
        buffer_[head_] = item;
        head_ = (head_ + 1) % Size;
        if (size_ < Size) size_++;
    }
    
    bool empty() const { return size_ == 0; }
    size_t size() const { return size_; }
    
    const T& operator[](size_t index) const {
        return buffer_[(head_ + Size - size_ + index) % Size];
    }
    
    void clear() { size_ = 0; head_ = 0; }
    
    // Iterator support
    class iterator {
        const RingBuffer* buffer_;
        size_t index_;
    public:
        iterator(const RingBuffer* buf, size_t idx) : buffer_(buf), index_(idx) {}
        const T& operator*() const { return (*buffer_)[index_]; }
        iterator& operator++() { ++index_; return *this; }
        bool operator!=(const iterator& other) const { return index_ != other.index_; }
    };
    
    iterator begin() const { return iterator(this, 0); }
    iterator end() const { return iterator(this, size_); }
};

class BehaviorTracker {
public:
    static constexpr size_t MAX_TRACKED_IPS = BehaviorConfig::MAX_TRACKED_IPS;
    static constexpr std::chrono::minutes CLEANUP_INTERVAL = BehaviorConfig::CLEANUP_INTERVAL;
    static constexpr std::chrono::minutes IP_TIMEOUT = BehaviorConfig::IP_TIMEOUT;
    
    struct TimestampedEvent {
        std::chrono::steady_clock::time_point timestamp;
        std::string event_type;
    };
      struct Behavior {
        // FIXED: Hot-path cache-friendly layout - pack critical counters together to reduce false sharing
        alignas(64) struct HotCounters {
            // Most frequently accessed atomics in same cache line
            std::atomic<uint64_t> total_packets{0};
            std::atomic<uint64_t> syn_count{0};
            std::atomic<uint64_t> ack_count{0};
            std::atomic<uint64_t> http_requests{0};
            std::atomic<int> half_open{0};
            std::atomic<double> legitimate_traffic_score{0.0};
            
            // Rolling counters for efficient detection (grouped for cache efficiency)
            std::atomic<int> syn_count_recent{0};
            std::atomic<int> ack_count_recent{0};
            std::atomic<int> http_count_recent{0};
            std::atomic<int> total_events_recent{0};
            std::atomic<uint64_t> last_update_ns{0};
        } hot_;
        
        // Less frequently accessed data (separate cache lines to avoid false sharing)
        size_t packet_size_sum = 0;
        int unique_session_count = 0;
        std::atomic<double> baseline_rate{0.0};
        std::atomic<double> cached_baseline_rate{0.0};
        std::atomic<uint64_t> last_baseline_update_ns{0};
        
        // Time-based tracking
        std::deque<TimestampedEvent> recent_events;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        
        // HTTP specific tracking with bounds
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> http_sessions;
        std::unordered_set<std::string> incomplete_requests;
        std::unordered_set<std::string> seen_sessions;
        
        // Connection state tracking with bounds
        std::unordered_set<std::string> established_connections;
          // Efficient ring buffers for O(1) operations
        RingBuffer<double, BehaviorConfig::PACKET_HISTORY_SIZE> packet_intervals;
        RingBuffer<size_t, BehaviorConfig::PACKET_HISTORY_SIZE> packet_sizes;
        
        // Connection tracking improvements
        std::atomic<uint64_t> connection_id_counter{0};
        
        // FIXED: Add mutex for protecting per-IP baseline updates
        mutable std::mutex baseline_mutex;        // FIXED: Custom copy constructor to handle atomic members and new hot_ structure
        Behavior(const Behavior& other) 
            : packet_size_sum(other.packet_size_sum)
            , unique_session_count(other.unique_session_count)
            , baseline_rate(other.baseline_rate.load())
            , cached_baseline_rate(other.cached_baseline_rate.load())
            , last_baseline_update_ns(other.last_baseline_update_ns.load())
            , recent_events(other.recent_events)
            , first_seen(other.first_seen)
            , last_seen(other.last_seen)
            , http_sessions(other.http_sessions)
            , incomplete_requests(other.incomplete_requests)
            , seen_sessions(other.seen_sessions)
            , established_connections(other.established_connections)
            , packet_intervals(other.packet_intervals)
            , packet_sizes(other.packet_sizes)
            , connection_id_counter(other.connection_id_counter.load())
        {
            // Copy hot counters atomically
            hot_.total_packets.store(other.hot_.total_packets.load());
            hot_.syn_count.store(other.hot_.syn_count.load());
            hot_.ack_count.store(other.hot_.ack_count.load());
            hot_.http_requests.store(other.hot_.http_requests.load());
            hot_.half_open.store(other.hot_.half_open.load());
            hot_.legitimate_traffic_score.store(other.hot_.legitimate_traffic_score.load());
            hot_.syn_count_recent.store(other.hot_.syn_count_recent.load());
            hot_.ack_count_recent.store(other.hot_.ack_count_recent.load());
            hot_.http_count_recent.store(other.hot_.http_count_recent.load());
            hot_.total_events_recent.store(other.hot_.total_events_recent.load());
            hot_.last_update_ns.store(other.hot_.last_update_ns.load());
        }        // FIXED: Custom copy assignment operator to handle atomic members and new hot_ structure
        Behavior& operator=(const Behavior& other) {
            if (this != &other) {
                packet_size_sum = other.packet_size_sum;
                unique_session_count = other.unique_session_count;
                baseline_rate.store(other.baseline_rate.load());
                cached_baseline_rate.store(other.cached_baseline_rate.load());
                last_baseline_update_ns.store(other.last_baseline_update_ns.load());
                recent_events = other.recent_events;
                first_seen = other.first_seen;
                last_seen = other.last_seen;
                http_sessions = other.http_sessions;
                incomplete_requests = other.incomplete_requests;
                seen_sessions = other.seen_sessions;
                established_connections = other.established_connections;
                packet_intervals = other.packet_intervals;
                packet_sizes = other.packet_sizes;
                connection_id_counter.store(other.connection_id_counter.load());
                
                // Copy hot counters atomically
                hot_.total_packets.store(other.hot_.total_packets.load());
                hot_.syn_count.store(other.hot_.syn_count.load());
                hot_.ack_count.store(other.hot_.ack_count.load());
                hot_.http_requests.store(other.hot_.http_requests.load());
                hot_.half_open.store(other.hot_.half_open.load());
                hot_.legitimate_traffic_score.store(other.hot_.legitimate_traffic_score.load());
                hot_.syn_count_recent.store(other.hot_.syn_count_recent.load());
                hot_.ack_count_recent.store(other.hot_.ack_count_recent.load());
                hot_.http_count_recent.store(other.hot_.http_count_recent.load());
                hot_.total_events_recent.store(other.hot_.total_events_recent.load());
                hot_.last_update_ns.store(other.hot_.last_update_ns.load());
            }
            return *this;
        }
        
        // Default constructor
        Behavior() = default;
    };
    
    LRUCache<std::string, Behavior> behaviors;
      // Global tracking
    std::atomic<uint64_t> last_global_reset_ns{0};    // FIXED: Use atomic uint64_t for nanoseconds
    std::atomic<uint64_t> last_distributed_check_ns{0}; // FIXED: Use atomic uint64_t for nanoseconds
    std::atomic<uint64_t> total_global_packets{0};
    mutable std::atomic<size_t> active_connections{0};
      std::chrono::steady_clock::time_point last_cleanup;
    
    // Pattern detection state  
    mutable std::mutex patterns_mutex;
    mutable std::mutex cleanup_mutex;
    std::vector<std::string> last_detected_patterns;
    std::chrono::steady_clock::time_point patterns_timestamp;
    
    // Private helper methods with FIXED [[nodiscard]] annotations
    [[nodiscard]] bool checkSynFlood(const Behavior& b) const;
    [[nodiscard]] bool checkUdpFlood(const Behavior& b) const;
    [[nodiscard]] bool checkHttpFlood(const Behavior& b) const;
    [[nodiscard]] bool checkSlowloris(const Behavior& b) const;
    [[nodiscard]] bool checkPortScan(const Behavior& b) const;
    [[nodiscard]] bool checkMultipleRepeatedRequests(const Behavior& b) const;
    [[nodiscard]] bool checkBandwidthConsumption(const Behavior& b) const;
    [[nodiscard]] bool checkTimeBasedPatterns(const Behavior& b) const;
    [[nodiscard]] bool checkAsymmetricTraffic(const Behavior& b) const;
    [[nodiscard]] DetectionResult detectDistributedAttack(const std::string& src_ip, const Behavior& b) const;
    [[nodiscard]] bool isSuspiciousApplicationLayer(const PacketData& pkt, const Behavior& b) const;
      // FIXED: Refactored generateConnectionId to avoid const_cast
    [[nodiscard]] std::string generateConnectionId(const PacketData& pkt, Behavior& b);
    
    void updateConnectionCount() const;
    void updateRollingCounters(Behavior& b, const std::string& event_type, 
                              const std::chrono::steady_clock::time_point& now);
    
    // Missing method declarations
    void cleanupOldEvents(Behavior& b);
    void enforceBehaviorBounds(Behavior& b);
    void updateBaselineRateOptimized(Behavior& b, const std::chrono::steady_clock::time_point& now);
    
    [[nodiscard]] double calculateLegitimacyFactor(const Behavior& b) const;
    [[nodiscard]] int calculateAdaptiveThreshold(const Behavior& b, double legitimacy_factor) const;
    [[nodiscard]] bool shouldRunDistributedCheck() const;
    [[nodiscard]] bool isLegitimateTrafficPattern(const Behavior& b) const;
    [[nodiscard]] bool detectFlashCrowdPattern(const Behavior& b) const;
      // Additional detection methods
    [[nodiscard]] bool detectSynFlood(const Behavior& b) const;
    [[nodiscard]] bool detectAckFlood(const Behavior& b) const;
    [[nodiscard]] bool detectHttpFlood(const Behavior& b) const;
    [[nodiscard]] bool detectSlowloris(const Behavior& b) const;
    [[nodiscard]] bool detectVolumeAttack(const Behavior& b) const;
    [[nodiscard]] bool detectDistributedAttack() const;
    [[nodiscard]] bool detectPulseAttack(const Behavior& b) const;
    [[nodiscard]] bool detectProtocolMixing(const Behavior& b) const;
    [[nodiscard]] bool detectGeoDistributedAttack() const;
    [[nodiscard]] bool detectLowAndSlowAttack(const Behavior& b) const;
    [[nodiscard]] bool detectRandomizedPayloads(const Behavior& b) const;
    [[nodiscard]] bool detectLegitimateTrafficMixing(const Behavior& b) const;
    [[nodiscard]] bool detectDynamicSourceRotation() const;
      // Helper calculation methods
    [[nodiscard]] double calculatePacketIntervalVariance(const RingBuffer<double, BehaviorConfig::PACKET_HISTORY_SIZE>& intervals) const;
    [[nodiscard]] double calculateSizeVariance(const RingBuffer<size_t, BehaviorConfig::PACKET_HISTORY_SIZE>& sizes) const;
    [[nodiscard]] bool isBusinessHours() const;
    
    BehaviorTracker();
    bool inspect(const PacketData& pkt);
    
    // Metrics methods
    size_t get_connection_count() const;
    size_t get_tracked_ips_count() const;
    
    // Memory management
    void cleanup_expired_behaviors();
    void force_cleanup_if_needed();
    
    // Get last detected patterns for classification
    std::vector<std::string> getLastDetectedPatterns() const;
    void clearLastDetectedPatterns();

private:
};

// FIXED: Split detection logic into small helper classes for maintainability
namespace detection {
    struct DetectionResult {
        bool matched = false;
        int score = 0;
        std::string tag;
    };
      class SynFloodDetector {
    public:
        static DetectionResult detect(const BehaviorTracker::Behavior& b) {
            DetectionResult result;
            // Simple SYN flood detection logic - use hot_ counters
            auto syn_count = b.hot_.syn_count.load();
            auto ack_count = b.hot_.ack_count.load();
            if (syn_count > 100 && syn_count > ack_count * 3) {
                result.matched = true;
                result.score = static_cast<int>(syn_count / 10);
                result.tag = "SYN_FLOOD";
            }
            return result;
        }
    };
    
    class SlowLorisDetector {
    public:
        static DetectionResult detect(const BehaviorTracker::Behavior& b) {
            DetectionResult result;
            // Slowloris: many incomplete HTTP connections
            if (b.incomplete_requests.size() > 50 && b.http_sessions.size() > 100) {
                result.matched = true;
                result.score = static_cast<int>(b.incomplete_requests.size());
                result.tag = "SLOWLORIS";
            }
            return result;
        }
    };
    
    class HttpFloodDetector {
    public:
        static DetectionResult detect(const BehaviorTracker::Behavior& b) {
            DetectionResult result;
            // HTTP flood detection - use hot_ counters
            auto http_requests = b.hot_.http_requests.load();
            if (http_requests > 500) {
                result.matched = true;
                result.score = static_cast<int>(http_requests / 50);
                result.tag = "HTTP_FLOOD";
            }
            return result;
        }
    };
    
    // Registry of all detectors
    class DetectorRegistry {
    public:
        static std::vector<DetectionResult> runAll(const BehaviorTracker::Behavior& b) {
            std::vector<DetectionResult> results;
            
            auto syn_result = SynFloodDetector::detect(b);
            if (syn_result.matched) results.push_back(syn_result);
            
            auto slowloris_result = SlowLorisDetector::detect(b);
            if (slowloris_result.matched) results.push_back(slowloris_result);
            
            auto http_result = HttpFloodDetector::detect(b);
            if (http_result.matched) results.push_back(http_result);
            
            return results;
        }
    };
}

// FIXED: Helper functions for time_point to uint64_t conversions to avoid atomic time_point UB
namespace detail {
    inline uint64_t time_point_to_ns(const std::chrono::steady_clock::time_point& tp) {
        return static_cast<uint64_t>(tp.time_since_epoch().count());
    }
    
    inline std::chrono::steady_clock::time_point ns_to_time_point(uint64_t ns) {
        return std::chrono::steady_clock::time_point(std::chrono::steady_clock::duration(ns));
    }
}

#endif // BEHAVIOR_TRACKER_H