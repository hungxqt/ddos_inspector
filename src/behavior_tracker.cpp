#include "behavior_tracker.hpp"

bool BehaviorTracker::inspect(const PacketData& pkt) {
    auto now = std::chrono::steady_clock::now();
    auto& b = behaviors[pkt.src_ip];
    
    // Initialize timing if this is the first packet from this IP
    if (b.total_packets == 0) {
        b.first_seen = now;
        last_global_reset = now;
    }
    b.last_seen = now;
    b.total_packets++;
    total_global_packets++;
    
    // Track packet types and events
    std::string event_type;
    if (pkt.is_syn && !pkt.is_ack) {
        b.syn_count++;
        b.half_open++;
        event_type = "SYN";
    } else if (pkt.is_ack && !pkt.is_syn) {
        b.ack_count++;
        event_type = "ACK";
        
        // Check if this ACK has a corresponding SYN (legitimate connection)
        std::string conn_id = generateConnectionId(pkt);
        if (b.established_connections.find(conn_id) == b.established_connections.end()) {
            // ACK without prior SYN - potential ACK flood
            event_type = "ORPHAN_ACK";
        } else {
            // Legitimate ACK, reduce half-open count
            if (b.half_open > 0) b.half_open--;
        }
    } else if (pkt.is_syn && pkt.is_ack) {
        // SYN-ACK response, track connection
        std::string conn_id = generateConnectionId(pkt);
        b.established_connections.insert(conn_id);
        event_type = "SYN_ACK";
    }
    
    if (pkt.is_http) {
        b.http_requests++;
        event_type = "HTTP";
        
        // Track HTTP sessions for slowloris detection
        b.http_sessions[pkt.session_id] = now;
        
        // Check for incomplete requests (slowloris pattern)
        if (pkt.session_id.find("incomplete") != std::string::npos) {
            b.incomplete_requests.insert(pkt.session_id);
        }
    }
    
    // Add timestamped event
    b.recent_events.push_back({now, event_type});
    
    // Cleanup old events and connections
    cleanupOldEvents(b);
    
    // Run detection algorithms
    if (detectSynFlood(b)) return true;
    if (detectAckFlood(b)) return true;
    if (detectHttpFlood(b)) return true;
    if (detectSlowloris(b)) return true;
    if (detectVolumeAttack(b)) return true;
    if (detectDistributedAttack()) return true;
    
    return false;
}

void BehaviorTracker::cleanupOldEvents(Behavior& b) {
    auto now = std::chrono::steady_clock::now();
    
    // Remove events older than 60 seconds
    while (!b.recent_events.empty()) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - b.recent_events.front().timestamp);
        if (duration.count() > 60) {
            b.recent_events.pop_front();
        } else {
            break;
        }
    }
    
    // Cleanup old HTTP sessions
    for (auto it = b.http_sessions.begin(); it != b.http_sessions.end(); ) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (duration.count() > 600) {
            it = b.http_sessions.erase(it);
        } else {
            ++it;
        }
    }
    
    // Reset global counters every minute
    auto global_duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_global_reset);
    if (global_duration.count() > 60) {
        total_global_packets = 0;
        last_global_reset = now;
    }
}

bool BehaviorTracker::detectSynFlood(const Behavior& b) {
    // Classic SYN flood: too many half-open connections
    if (b.half_open > 20) return true;  // Reduced from 80 to 20
    
    // Rate-based SYN flood: too many SYN packets in short time
    int syn_count_recent = 0;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (duration.count() <= 10 && event.event_type == "SYN") {
            syn_count_recent++;
        }
    }
    
    return syn_count_recent > 15; // Reduced from 50 to 15 SYN packets in 10 seconds
}

bool BehaviorTracker::detectAckFlood(const Behavior& b) {
    // Count orphan ACKs (ACKs without corresponding SYNs)
    int orphan_ack_count = 0;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (duration.count() <= 10 && event.event_type == "ORPHAN_ACK") {
            orphan_ack_count++;
        }
    }
    
    return orphan_ack_count > 10; // Reduced from 30 to 10 orphan ACKs in 10 seconds
}

bool BehaviorTracker::detectHttpFlood(const Behavior& b) {
    // Rate-based HTTP flood detection
    int http_count_recent = 0;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (duration.count() <= 60 && event.event_type == "HTTP") {
            http_count_recent++;
        }
    }
    
    return http_count_recent > 25; // Reduced from 100 to 25 HTTP requests per minute
}

bool BehaviorTracker::detectSlowloris(const Behavior& b) {
    auto now = std::chrono::steady_clock::now();
    
    // Check for many long-lived HTTP sessions
    int long_sessions = 0;
    for (const auto& session : b.http_sessions) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - session.second);
        if (duration.count() > 120) { // Sessions longer than 2 minutes
            long_sessions++;
        }
    }
    
    // Also check for incomplete requests pattern
    if (long_sessions > 10 || b.incomplete_requests.size() > 20) {
        return true;
    }
    
    return false;
}

bool BehaviorTracker::detectVolumeAttack(const Behavior& b) {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - b.first_seen);
    
    // Volume-based detection: too many packets in short time
    if (duration.count() > 0 && duration.count() <= 60) {
        double packets_per_second = static_cast<double>(b.total_packets) / duration.count();
        return packets_per_second > 1000; // More than 1000 packets per second
    }
    
    return false;
}

bool BehaviorTracker::detectDistributedAttack() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_global_reset);
    
    // Check if we're seeing attacks from multiple IPs
    int attacking_ips = 0;
    for (const auto& pair : behaviors) {
        const auto& b = pair.second;
        if (b.total_packets > 100 && 
            (b.syn_count > 20 || b.http_requests > 50 || b.ack_count > 30)) {
            attacking_ips++;
        }
    }
    
    // Distributed attack: multiple IPs showing attack patterns
    if (attacking_ips >= 3 && total_global_packets > 5000) {
        return true;
    }
    
    return false;
}

std::string BehaviorTracker::generateConnectionId(const PacketData& pkt) {
    // Use available fields since src_port/dst_port don't exist in PacketData
    return pkt.src_ip + "->" + pkt.dst_ip + ":" + pkt.session_id;
}
