/**
 * Test to demonstrate that advanced attack patterns now have proper classification
 */

#include <gtest/gtest.h>
#include "behavior_tracker.hpp"
#include <iostream>

class AttackClassificationTest : public ::testing::Test {
protected:
    void SetUp() override {
        behavior_tracker = std::make_unique<BehaviorTracker>();
    }

    std::unique_ptr<BehaviorTracker> behavior_tracker;
};

TEST_F(AttackClassificationTest, ProtocolMixingClassification) {
    // Test that protocol mixing gets properly classified (not as UNKNOWN)
    
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
    
    // Send mixed traffic to trigger protocol mixing detection
    bool detected = false;
    for (int i = 0; i < 120; i++) {
        syn_pkt.session_id = "syn_" + std::to_string(i);
        ack_pkt.session_id = "ack_" + std::to_string(i);
        http_pkt.session_id = "http_" + std::to_string(i);
        
        behavior_tracker->inspect(syn_pkt);
        behavior_tracker->inspect(ack_pkt);
        
        if (behavior_tracker->inspect(http_pkt)) {
            detected = true;
            
            // Check what patterns were detected
            auto patterns = behavior_tracker->getLastDetectedPatterns();
            std::cout << "Detected patterns: ";
            for (const auto& pattern : patterns) {
                std::cout << pattern << " ";
            }
            std::cout << '\n';
            
            // Should include PROTOCOL_MIXING
            bool has_protocol_mixing = false;
            for (const auto& pattern : patterns) {
                if (pattern == "PROTOCOL_MIXING") {
                    has_protocol_mixing = true;
                    break;
                }
            }
            
            EXPECT_TRUE(has_protocol_mixing) << "Should detect PROTOCOL_MIXING pattern";
            break;
        }
    }
    
    EXPECT_TRUE(detected) << "Should detect protocol mixing attack";
}

TEST_F(AttackClassificationTest, GeoDistributedClassification) {
    // Test geo-distributed attack classification
    
    PacketData pkt;
    pkt.dst_ip = "10.0.0.1";
    pkt.size = 100;
    pkt.is_syn = true;
    
    // Simulate many IPs from different subnets 
    bool detected = false;
    for (int subnet_b = 1; subnet_b <= 12; subnet_b++) {
        for (int subnet_c = 1; subnet_c <= 4; subnet_c++) {
            for (int host = 1; host <= 3; host++) {
                pkt.src_ip = "192." + std::to_string(subnet_b) + "." + 
                           std::to_string(subnet_c) + "." + std::to_string(host);
                pkt.session_id = pkt.src_ip + "_session";
                
                // Send packets to make IPs active
                for (int p = 0; p < 55; p++) {
                    if (behavior_tracker->inspect(pkt)) {
                        detected = true;
                        
                        // Check detected patterns
                        auto patterns = behavior_tracker->getLastDetectedPatterns();
                        std::cout << "Geo-distributed patterns: ";
                        for (const auto& pattern : patterns) {
                            std::cout << pattern << " ";
                        }
                        std::cout << '\n';
                        
                        // Should include GEO_DISTRIBUTED
                        bool has_geo_distributed = false;
                        for (const auto& pattern : patterns) {
                            if (pattern == "GEO_DISTRIBUTED") {
                                has_geo_distributed = true;
                                break;
                            }
                        }
                        
                        EXPECT_TRUE(has_geo_distributed) << "Should detect GEO_DISTRIBUTED pattern";
                        return; // Exit early on detection
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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "\n=== Testing Advanced Attack Pattern Classification ===\n" << '\n';
    std::cout << "This test verifies that advanced attack patterns are properly classified" << '\n';
    std::cout << "instead of showing as 'UNKNOWN' attack types.\n" << '\n';
    
    return RUN_ALL_TESTS();
}
