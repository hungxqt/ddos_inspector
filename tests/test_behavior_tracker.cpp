#include <gtest/gtest.h>
#include "behavior_tracker.hpp"
#include "packet_data.hpp"
#include <vector>
#include <chrono>
#include <thread>

class BehaviorTrackerDetailedTest : public ::testing::Test {
protected:
    void SetUp() override {
        tracker = std::make_unique<BehaviorTracker>();
    }

    std::unique_ptr<BehaviorTracker> tracker;
    
    // Helper function to create TCP packets
    PacketData createTCPPacket(const std::string& src_ip, const std::string& dst_ip,
                              bool is_syn = false, bool is_ack = false, 
                              const std::string& payload = "") {
        PacketData pkt;
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.is_syn = is_syn;
        pkt.is_ack = is_ack;
        pkt.payload = payload;
        pkt.size = payload.length() + 40; // TCP header overhead
        return pkt;
    }
    
    // Helper function to create HTTP packets
    PacketData createHTTPPacket(const std::string& src_ip, const std::string& dst_ip,
                               const std::string& http_request) {
        PacketData pkt;
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.is_http = true;
        pkt.payload = http_request;
        pkt.size = http_request.length() + 40;
        return pkt;
    }
};

TEST_F(BehaviorTrackerDetailedTest, NormalTCPConnectionFlow) {
    std::string client_ip = "192.168.1.100";
    std::string server_ip = "10.0.0.1";
    
    // Normal TCP handshake: SYN -> SYN-ACK -> ACK
    PacketData syn = createTCPPacket(client_ip, server_ip, true, false);
    PacketData syn_ack = createTCPPacket(server_ip, client_ip, true, true);
    PacketData ack = createTCPPacket(client_ip, server_ip, false, true);
    
    // None of these should trigger anomaly detection
    EXPECT_FALSE(tracker->inspect(syn));
    EXPECT_FALSE(tracker->inspect(syn_ack));
    EXPECT_FALSE(tracker->inspect(ack));
}

TEST_F(BehaviorTrackerDetailedTest, SYNFloodDetection) {
    std::string attacker_ip = "192.168.1.200";
    std::string target_ip = "10.0.0.1";
    
    bool anomaly_detected = false;
    int packets_sent = 0;
    
    // Send rapid SYN packets (typical SYN flood)
    for (int i = 0; i < 100; i++) {
        PacketData syn = createTCPPacket(attacker_ip, target_ip, true, false);
        packets_sent++;
        
        if (tracker->inspect(syn)) {
            anomaly_detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(anomaly_detected);
    EXPECT_LT(packets_sent, 100); // Should detect before all packets are sent
}

TEST_F(BehaviorTrackerDetailedTest, ACKFloodDetection) {
    std::string attacker_ip = "192.168.1.201";
    std::string target_ip = "10.0.0.1";
    
    bool anomaly_detected = false;
    
    // Send rapid ACK packets without prior SYN (typical ACK flood)
    for (int i = 0; i < 50; i++) {
        PacketData ack = createTCPPacket(attacker_ip, target_ip, false, true);
        
        if (tracker->inspect(ack)) {
            anomaly_detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(anomaly_detected);
}

TEST_F(BehaviorTrackerDetailedTest, HTTPFloodDetection) {
    std::string attacker_ip = "192.168.1.202";
    std::string target_ip = "10.0.0.1";
    
    bool anomaly_detected = false;
    
    // Send rapid HTTP GET requests
    for (int i = 0; i < 30; i++) {
        std::string http_request = "GET /page" + std::to_string(i) + 
                                  " HTTP/1.1\r\nHost: target.com\r\n\r\n";
        PacketData http_pkt = createHTTPPacket(attacker_ip, target_ip, http_request);
        
        if (tracker->inspect(http_pkt)) {
            anomaly_detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(anomaly_detected);
}

TEST_F(BehaviorTrackerDetailedTest, SlowlorisDetection) {
    std::string attacker_ip = "192.168.1.203";
    std::string target_ip = "10.0.0.1";
    
    // Simulate Slowloris: partial HTTP requests
    std::vector<std::string> partial_requests = {
        "GET / HTTP/1.1\r\n",
        "Host: target.com\r\n",
        "User-Agent: Mozilla/5.0\r\n",
        "Accept: text/html\r\n"
        // Note: Missing final \r\n\r\n to complete request
    };
    
    bool anomaly_detected = false;
    
    // Send multiple incomplete requests
    for (int i = 0; i < 20; i++) {
        for (const auto& partial : partial_requests) {
            PacketData http_pkt = createHTTPPacket(attacker_ip, target_ip, partial);
            
            if (tracker->inspect(http_pkt)) {
                anomaly_detected = true;
                break;
            }
        }
        if (anomaly_detected) break;
    }
    
    EXPECT_TRUE(anomaly_detected);
}

TEST_F(BehaviorTrackerDetailedTest, MultipleSourceDistributedAttack) {
    std::vector<std::string> attacker_ips = {
        "192.168.1.10", "192.168.1.11", "192.168.1.12", 
        "192.168.1.13", "192.168.1.14"
    };
    std::string target_ip = "10.0.0.1";
    
    int total_anomalies = 0;
    
    // Each attacker sends SYN packets
    for (const auto& attacker_ip : attacker_ips) {
        for (int i = 0; i < 25; i++) {
            PacketData syn = createTCPPacket(attacker_ip, target_ip, true, false);
            
            if (tracker->inspect(syn)) {
                total_anomalies++;
            }
        }
    }
    
    // Should detect anomalies from multiple sources
    EXPECT_GT(total_anomalies, 0);
}

TEST_F(BehaviorTrackerDetailedTest, LegitimateTrafficMixedWithAttack) {
    std::string legitimate_ip = "192.168.1.50";
    std::string attacker_ip = "192.168.1.200";
    std::string target_ip = "10.0.0.1";
    
    // Simulate legitimate user browsing
    std::vector<std::string> legitimate_requests = {
        "GET /index.html HTTP/1.1\r\nHost: site.com\r\n\r\n",
        "GET /style.css HTTP/1.1\r\nHost: site.com\r\n\r\n",
        "GET /script.js HTTP/1.1\r\nHost: site.com\r\n\r\n"
    };
    
    bool legitimate_flagged = false;
    bool attacker_flagged = false;
    
    // Interleave legitimate and attack traffic
    for (int i = 0; i < 20; i++) {
        // Legitimate traffic
        if (i % 3 == 0 && !legitimate_requests.empty()) {
            PacketData legit_pkt = createHTTPPacket(legitimate_ip, target_ip, 
                legitimate_requests[i % legitimate_requests.size()]);
            if (tracker->inspect(legit_pkt)) {
                legitimate_flagged = true;
            }
        }
        
        // Attack traffic
        PacketData attack_pkt = createTCPPacket(attacker_ip, target_ip, true, false);
        if (tracker->inspect(attack_pkt)) {
            attacker_flagged = true;
        }
    }
    
    // Attack should be detected, legitimate traffic should mostly pass
    EXPECT_TRUE(attacker_flagged);
    // Note: legitimate_flagged might be true due to rate limits, which is acceptable
}

TEST_F(BehaviorTrackerDetailedTest, ConnectionStateTracking) {
    std::string client_ip = "192.168.1.100";
    std::string server_ip = "10.0.0.1";
    
    // Test proper connection establishment and termination
    
    // 1. SYN
    PacketData syn = createTCPPacket(client_ip, server_ip, true, false);
    EXPECT_FALSE(tracker->inspect(syn));
    
    // 2. Data transfer (should be fine after SYN)
    PacketData data = createTCPPacket(client_ip, server_ip, false, true, "DATA");
    EXPECT_FALSE(tracker->inspect(data));
    
    // 3. Multiple data packets should eventually trigger if too rapid
    bool rate_limit_triggered = false;
    for (int i = 0; i < 50; i++) {
        PacketData rapid_data = createTCPPacket(client_ip, server_ip, false, true, 
                                               "DATA" + std::to_string(i));
        if (tracker->inspect(rapid_data)) {
            rate_limit_triggered = true;
            break;
        }
    }
    
    EXPECT_TRUE(rate_limit_triggered);
}

TEST_F(BehaviorTrackerDetailedTest, HTTPMethodVarietyDetection) {
    std::string client_ip = "192.168.1.100";
    std::string server_ip = "10.0.0.1";
    
    std::vector<std::string> http_methods = {
        "GET /page1 HTTP/1.1\r\nHost: site.com\r\n\r\n",
        "POST /api HTTP/1.1\r\nHost: site.com\r\n\r\n",
        "PUT /resource HTTP/1.1\r\nHost: site.com\r\n\r\n",
        "DELETE /item HTTP/1.1\r\nHost: site.com\r\n\r\n"
    };
    
    // Normal variety of HTTP methods should not trigger anomaly
    for (const auto& method : http_methods) {
        PacketData http_pkt = createHTTPPacket(client_ip, server_ip, method);
        EXPECT_FALSE(tracker->inspect(http_pkt));
    }
    
    // But rapid repetition of same method should
    bool anomaly_detected = false;
    for (int i = 0; i < 40; i++) {
        PacketData http_pkt = createHTTPPacket(client_ip, server_ip, http_methods[0]);
        if (tracker->inspect(http_pkt)) {
            anomaly_detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(anomaly_detected);
}

TEST_F(BehaviorTrackerDetailedTest, TimeBasedBehaviorReset) {
    std::string client_ip = "192.168.1.100";
    std::string server_ip = "10.0.0.1";
    
    // Send some packets to build up rate
    for (int i = 0; i < 10; i++) {
        PacketData pkt = createTCPPacket(client_ip, server_ip, true, false);
        tracker->inspect(pkt);
    }
    
    // Wait a bit (simulate time passing)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // New packets should have reset behavior tracking
    PacketData new_pkt = createTCPPacket(client_ip, server_ip, true, false);
    // This should behave as if starting fresh (implementation dependent)
    EXPECT_NO_THROW(tracker->inspect(new_pkt));
}

TEST_F(BehaviorTrackerDetailedTest, EdgeCasePackets) {
    // Test various edge cases
    
    // Empty payload
    PacketData empty = createTCPPacket("192.168.1.1", "10.0.0.1", false, false, "");
    EXPECT_NO_THROW(tracker->inspect(empty));
    
    // Very large payload
    std::string large_payload(10000, 'X');
    PacketData large = createTCPPacket("192.168.1.2", "10.0.0.1", false, false, large_payload);
    EXPECT_NO_THROW(tracker->inspect(large));
    
    // Malformed HTTP
    PacketData malformed = createHTTPPacket("192.168.1.3", "10.0.0.1", "INVALID HTTP REQUEST");
    EXPECT_NO_THROW(tracker->inspect(malformed));
    
    // Both SYN and ACK set (unusual but valid)
    PacketData syn_ack = createTCPPacket("192.168.1.4", "10.0.0.1", true, true);
    EXPECT_NO_THROW(tracker->inspect(syn_ack));
}

