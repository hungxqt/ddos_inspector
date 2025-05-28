#ifndef BEHAVIOR_TRACKER_H
#define BEHAVIOR_TRACKER_H

#include <string>
#include <unordered_map>
#include <chrono>
#include <deque>
#include <unordered_set>
#include "packet_data.hpp"

class BehaviorTracker {
public:
    bool inspect(const PacketData& pkt);

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
        
        // Time-based tracking
        std::deque<TimestampedEvent> recent_events;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        
        // HTTP specific tracking
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> http_sessions;
        std::unordered_set<std::string> incomplete_requests;
        
        // Connection state tracking
        std::unordered_set<std::string> established_connections;
    };
    
    std::unordered_map<std::string, Behavior> behaviors;
    
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
};

#endif // BEHAVIOR_TRACKER_H
