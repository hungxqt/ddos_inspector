#include <gtest/gtest.h>
#include "behavior_tracker.hpp"
#include "stats_engine.hpp"
#include "packet_data.hpp"
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>

class RealisticAttackTest : public ::testing::Test {
protected:
    void SetUp() override {
        behavior_tracker = std::make_unique<BehaviorTracker>();
        stats_engine = std::make_unique<StatsEngine>(2.0, 0.1);
        
        // Initialize random generator for realistic attack simulation
        random_generator.seed(std::chrono::steady_clock::now().time_since_epoch().count());
    }

    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<StatsEngine> stats_engine;
    std::mt19937 random_generator;
    
    // Helper to generate realistic botnet IP ranges
    std::vector<std::string> generateBotnetIPs(int count) {
        std::vector<std::string> ips;
        std::uniform_int_distribution<int> subnet_dist(1, 254);
        std::uniform_int_distribution<int> host_dist(1, 254);
        
        for (int i = 0; i < count; i++) {
            // Simulate real botnet patterns: residential ISP ranges
            std::string ip = "192.168." + std::to_string(subnet_dist(random_generator)) + 
                           "." + std::to_string(host_dist(random_generator));
            ips.push_back(ip);
        }
        return ips;
    }
    
    // Generate realistic attack payloads with varying entropy
    std::string generateAttackPayload(const std::string& attack_type) {
        if (attack_type == "syn_flood") {
            // SYN floods typically have minimal payload
            return "";
        } else if (attack_type == "http_flood") {
            // HTTP floods use varied but low-entropy requests
            std::vector<std::string> user_agents = {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)"
            };
            std::vector<std::string> requests = {
                "GET / HTTP/1.1", "GET /index.html HTTP/1.1", "POST /api/data HTTP/1.1"
            };
            
            auto& ua = user_agents[random_generator() % user_agents.size()];
            auto& req = requests[random_generator() % requests.size()];
            return req + "\r\nUser-Agent: " + ua + "\r\nHost: target.com\r\n";
        } else if (attack_type == "amplification") {
            // DNS amplification attacks use repetitive queries
            return std::string(100, 'A') + ".example.com";
        }
        return "default_payload";
    }
    
    // Helper functions for creating different packet types
    PacketData createSynPacket(const std::string& src_ip, const std::string& dst_ip) {
        PacketData pkt;
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.is_syn = true;
        pkt.is_ack = false;
        pkt.is_http = false;
        pkt.size = 60;
        pkt.payload = "";
        return pkt;
    }
    
    PacketData createAckPacket(const std::string& src_ip, const std::string& dst_ip) {
        PacketData pkt;
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.is_syn = false;
        pkt.is_ack = true;
        pkt.is_http = false;
        pkt.size = 60;
        pkt.payload = "";
        return pkt;
    }
    
    PacketData createHttpPacket(const std::string& src_ip, const std::string& dst_ip, const std::string& payload) {
        PacketData pkt;
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.is_syn = false;
        pkt.is_ack = false;
        pkt.is_http = true;
        pkt.size = 200 + payload.length();
        pkt.payload = payload;
        return pkt;
    }
};

TEST_F(RealisticAttackTest, MassiveSynFloodSimulation) {
    // Simulate real-world SYN flood: 50,000 packets from 100 IPs in 10 seconds
    // This represents a medium-scale DDoS attack
    
    auto botnet_ips = generateBotnetIPs(100);
    int total_packets = 50000;
    int packets_per_ip = total_packets / botnet_ips.size();
    
    bool attack_detected = false;
    auto start_time = std::chrono::steady_clock::now();
    
    for (const auto& ip : botnet_ips) {
        for (int i = 0; i < packets_per_ip; i++) {
            PacketData syn_pkt;
            syn_pkt.src_ip = ip;
            syn_pkt.dst_ip = "10.0.0.1";
            syn_pkt.is_syn = true;
            syn_pkt.is_ack = false;
            syn_pkt.size = 60;
            syn_pkt.session_id = "conn_" + std::to_string(i);
            syn_pkt.payload = generateAttackPayload("syn_flood");
            
            // Test both behavioral and statistical detection
            bool behavioral_detection = behavior_tracker->inspect(syn_pkt);
            bool statistical_detection = stats_engine->analyze(syn_pkt);
            
            if (behavioral_detection || statistical_detection) {
                attack_detected = true;
                auto detection_time = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    detection_time - start_time).count();
                
                std::cout << "SYN flood detected after " << elapsed << "ms" << '\n';
                std::cout << "Packets processed: " << (botnet_ips.size() * i + 
                    std::distance(botnet_ips.begin(), 
                    std::find(botnet_ips.begin(), botnet_ips.end(), ip))) << '\n';
                break;
            }
        }
        if (attack_detected) break;
    }
    
    EXPECT_TRUE(attack_detected) << "Should detect massive SYN flood attack";
}

TEST_F(RealisticAttackTest, LowAndSlowHTTPFlood) {
    // Simulate low-and-slow HTTP flood: legitimate-looking requests at high rate
    // 1000 requests over 60 seconds from 20 IPs (realistic application layer attack)
    
    auto attacker_ips = generateBotnetIPs(20);
    int requests_per_ip = 50; // 50 requests per IP over time window
    bool attack_detected = false;
    
    for (const auto& ip : attacker_ips) {
        for (int i = 0; i < requests_per_ip; i++) {
            PacketData http_pkt;
            http_pkt.src_ip = ip;
            http_pkt.dst_ip = "10.0.0.1";
            http_pkt.is_http = true;
            http_pkt.size = 300 + (i % 200); // Varying sizes
            http_pkt.session_id = "http_" + std::to_string(i);
            http_pkt.payload = generateAttackPayload("http_flood");
            
            bool behavioral_detection = behavior_tracker->inspect(http_pkt);
            bool statistical_detection = stats_engine->analyze(http_pkt);
            
            if (behavioral_detection || statistical_detection) {
                attack_detected = true;
                std::cout << "HTTP flood detected from IP: " << ip 
                         << " at request " << i << '\n';
                break;
            }
        }
        if (attack_detected) break;
    }
    
    EXPECT_TRUE(attack_detected) << "Should detect distributed HTTP flood";
}

TEST_F(RealisticAttackTest, MultiVectorAttack) {
    // Simulate a sophisticated multi-vector attack
    // This represents a realistic scenario with multiple attack types
    
    std::vector<std::string> attack_ips = {
        "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"
    };
    
    bool syn_detected = false;
    bool http_detected = false;
    bool ack_detected = false;
    
    // Phase 1: SYN flood from multiple IPs
    for (const auto& ip : attack_ips) {
        for (int i = 0; i < 60; i++) {
            PacketData syn_pkt = createSynPacket(ip, "192.168.1.100");
            syn_pkt.session_id = "syn_" + ip + "_" + std::to_string(i);
            
            bool stats_result = stats_engine->analyze(syn_pkt);
            bool behavior_result = behavior_tracker->inspect(syn_pkt);
            
            if (stats_result || behavior_result) {
                syn_detected = true;
            }
        }
    }
    
    // Phase 2: HTTP flood
    for (const auto& ip : attack_ips) {
        for (int i = 0; i < 40; i++) {
            PacketData http_pkt = createHttpPacket(ip, "192.168.1.100", 
                "GET /api/data HTTP/1.1\r\nHost: target.com\r\n\r\n");
            http_pkt.session_id = "http_" + ip + "_" + std::to_string(i);
            
            bool stats_result = stats_engine->analyze(http_pkt);
            bool behavior_result = behavior_tracker->inspect(http_pkt);
            
            if (stats_result || behavior_result) {
                http_detected = true;
            }
        }
    }
    
    // Phase 3: ACK flood
    for (const auto& ip : attack_ips) {
        for (int i = 0; i < 15; i++) {
            PacketData ack_pkt = createAckPacket(ip, "192.168.1.100");
            ack_pkt.session_id = "ack_" + ip + "_" + std::to_string(i);
            
            bool stats_result = stats_engine->analyze(ack_pkt);
            bool behavior_result = behavior_tracker->inspect(ack_pkt);
            
            if (stats_result || behavior_result) {
                ack_detected = true;
            }
        }
    }
    
    // Verify that at least one attack vector was detected
    EXPECT_TRUE(syn_detected || http_detected || ack_detected) 
        << "Multi-vector attack should be detected";
}

TEST_F(RealisticAttackTest, EvasionTechniquesSimulation) {
    // Test against common DDoS evasion techniques
    
    // 1. Randomized source ports and payloads
    auto smart_botnet = generateBotnetIPs(30);
    bool evasion_defeated = false;
    
    for (const auto& ip : smart_botnet) {
        for (int i = 0; i < 80; i++) {
            PacketData evasive_pkt;
            evasive_pkt.src_ip = ip;
            evasive_pkt.dst_ip = "10.0.0.1";
            evasive_pkt.is_syn = (i % 4 == 0); // Mix SYN and other packets
            evasive_pkt.is_ack = (i % 4 == 1);
            evasive_pkt.is_http = (i % 4 == 2);
            
            // Randomize payload to increase entropy
            std::string random_payload;
            for (int j = 0; j < 50; j++) {
                random_payload += static_cast<char>('A' + (random_generator() % 26));
            }
            evasive_pkt.payload = random_payload;
            evasive_pkt.size = 60 + random_payload.length();
            evasive_pkt.session_id = "evasive_" + std::to_string(i);
            
            bool behavioral_detection = behavior_tracker->inspect(evasive_pkt);
            bool statistical_detection = stats_engine->analyze(evasive_pkt);
            
            if (behavioral_detection || statistical_detection) {
                evasion_defeated = true;
                std::cout << "Evasive attack detected despite randomization at packet " 
                         << i << " from IP " << ip << '\n';
                break;
            }
        }
        if (evasion_defeated) break;
    }
    
    EXPECT_TRUE(evasion_defeated) << "Should detect attacks even with evasion techniques";
}

TEST_F(RealisticAttackTest, FlashCrowdVsAttackDistinction) {
    // Test ability to distinguish between legitimate flash crowd and DDoS attack
    
    // Simulate legitimate flash crowd: diverse payloads, normal behavioral patterns
    auto legitimate_users = generateBotnetIPs(100);
    bool false_positive = false;
    
    for (const auto& ip : legitimate_users) {
        // Legitimate users send varied, high-entropy requests
        for (int i = 0; i < 10; i++) { // Only 10 requests per user (normal)
            PacketData legit_pkt;
            legit_pkt.src_ip = ip;
            legit_pkt.dst_ip = "10.0.0.1";
            legit_pkt.is_http = true;
            legit_pkt.size = 500 + (i * 100);
            legit_pkt.session_id = "legit_" + std::to_string(i);
            
            // High-entropy legitimate content
            legit_pkt.payload = "GET /news/breaking-story-" + std::to_string(i) + 
                              " HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (diverse content)\r\n";
            
            if (behavior_tracker->inspect(legit_pkt)) {
                false_positive = true;
                break;
            }
        }
        if (false_positive) break;
    }
    
    EXPECT_FALSE(false_positive) << "Should NOT detect legitimate flash crowd as attack";
    
    // Now simulate actual attack with similar volume but malicious patterns
    bool attack_detected = false;
    auto attackers = generateBotnetIPs(20);
    
    for (const auto& ip : attackers) {
        // Attackers send many repetitive requests
        for (int i = 0; i < 200; i++) { // 200 requests per attacker (suspicious)
            PacketData attack_pkt;
            attack_pkt.src_ip = ip;
            attack_pkt.dst_ip = "10.0.0.1";
            attack_pkt.is_http = true;
            attack_pkt.size = 200;
            attack_pkt.session_id = "attack_" + std::to_string(i);
            
            // Low-entropy attack payload
            attack_pkt.payload = "GET / HTTP/1.1\r\nHost: target.com\r\n";
            
            if (behavior_tracker->inspect(attack_pkt)) {
                attack_detected = true;
                break;
            }
        }
        if (attack_detected) break;
    }
    
    EXPECT_TRUE(attack_detected) << "Should detect actual attack patterns";
    
    std::cout << "Flash crowd distinction results:" << '\n';
    std::cout << "  False positive on legit traffic: " << (false_positive ? "YES" : "NO") << '\n';
    std::cout << "  Attack detection: " << (attack_detected ? "YES" : "NO") << '\n';
}