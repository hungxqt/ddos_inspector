/**
 * Test for advanced DDoS detection patterns implemented.
 * This test verifies the new sophisticated attack detection capabilities.
 */

#include <gtest/gtest.h>
#include "behavior_tracker.hpp"

class AdvancedDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        tracker = std::make_unique<BehaviorTracker>();
    }

    std::unique_ptr<BehaviorTracker> tracker;
};

TEST_F(AdvancedDetectionTest, HighVolumeAttackDetection) {
    // Test high volume attack - should trigger at 5000+ pps in testing mode
    PacketData pkt;
    pkt.src_ip = "192.168.1.100";
    pkt.dst_ip = "10.0.0.1";
    pkt.size = 1000;
    pkt.session_id = "volume_test";
    
    // Simulate high packet rate (6000 packets in 1 second)
    bool detected = false;
    for (int i = 0; i < 6000; i++) {
        pkt.session_id = "volume_" + std::to_string(i);
        if (tracker->inspect(pkt)) {
            detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(detected) << "Should detect volume attack at 6000 pps";
}

TEST_F(AdvancedDetectionTest, ProtocolMixingDetection) {
    // Test protocol mixing attack - mix of SYN, ACK, and HTTP from same IP
    PacketData syn_pkt, ack_pkt, http_pkt;
    
    // Setup common fields
    syn_pkt.src_ip = ack_pkt.src_ip = http_pkt.src_ip = "192.168.1.100";
    syn_pkt.dst_ip = ack_pkt.dst_ip = http_pkt.dst_ip = "10.0.0.1";
    syn_pkt.size = ack_pkt.size = http_pkt.size = 60;
    
    // Setup protocol-specific fields
    syn_pkt.is_syn = true;
    syn_pkt.is_ack = false;
    
    ack_pkt.is_syn = false;
    ack_pkt.is_ack = true;
    
    http_pkt.is_syn = false;
    http_pkt.is_ack = false;
    http_pkt.is_http = true;
    
    // Send mixed traffic - alternating protocols with sufficient volume
    bool detected = false;
    for (int i = 0; i < 150; i++) {
        syn_pkt.session_id = "syn_" + std::to_string(i);
        ack_pkt.session_id = "ack_" + std::to_string(i);
        http_pkt.session_id = "http_" + std::to_string(i);
        
        tracker->inspect(syn_pkt);
        tracker->inspect(ack_pkt);
        
        if (tracker->inspect(http_pkt)) {
            detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(detected) << "Should detect protocol mixing attack";
}

TEST_F(AdvancedDetectionTest, RandomizedPayloadDetection) {
    // Test randomized payload detection
    PacketData pkt;
    pkt.src_ip = "192.168.1.100";
    pkt.dst_ip = "10.0.0.1";
    pkt.is_http = true;
    
    // Send packets with highly variable sizes (randomized payloads)
    bool detected = false;
    for (int i = 0; i < 50; i++) {
        // Create high variance in packet sizes
        pkt.size = 100 + (i * 137) % 1500; // Creates varied sizes
        pkt.session_id = "random_" + std::to_string(i);
        
        if (tracker->inspect(pkt)) {
            detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(detected) << "Should detect randomized payload attack";
}

TEST_F(AdvancedDetectionTest, GeoDistributedDetection) {
    // Test geographically distributed attack detection
    PacketData pkt;
    pkt.dst_ip = "10.0.0.1";
    pkt.size = 100;
    pkt.is_syn = true;
    
    // Simulate many IPs from different subnets (simulating geo-distribution)
    bool detected = false;
    for (int subnet_b = 1; subnet_b <= 15; subnet_b++) {
        for (int subnet_c = 1; subnet_c <= 5; subnet_c++) {
            for (int host = 1; host <= 4; host++) {
                pkt.src_ip = "192." + std::to_string(subnet_b) + "." + 
                           std::to_string(subnet_c) + "." + std::to_string(host);
                pkt.session_id = pkt.src_ip + "_session";
                
                // Send multiple packets from each IP to make it count as active
                for (int p = 0; p < 60; p++) {
                    if (tracker->inspect(pkt)) {
                        detected = true;
                        break;
                    }
                }
                if (detected) break;
            }
            if (detected) break;
        }
        if (detected) break;
    }
    
    EXPECT_TRUE(detected) << "Should detect geo-distributed attack";
}

TEST_F(AdvancedDetectionTest, LegitimateTrafficMixingDetection) {
    // Test detection of attacks mixed with legitimate traffic
    PacketData attack_pkt, legit_pkt;
    
    attack_pkt.src_ip = legit_pkt.src_ip = "192.168.1.100";
    attack_pkt.dst_ip = legit_pkt.dst_ip = "10.0.0.1";
    attack_pkt.size = legit_pkt.size = 500;
    
    // Attack packets
    attack_pkt.is_syn = true;
    
    // Legitimate packets (with proper sessions)
    legit_pkt.is_http = true;
    
    // Mix legitimate and attack traffic with high session diversity
    bool detected = false;
    for (int i = 0; i < 250; i++) {
        attack_pkt.session_id = "attack_" + std::to_string(i);
        legit_pkt.session_id = "legit_" + std::to_string(i);
        
        tracker->inspect(attack_pkt);
        
        if (tracker->inspect(legit_pkt)) {
            detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(detected) << "Should detect legitimate traffic mixing";
}
