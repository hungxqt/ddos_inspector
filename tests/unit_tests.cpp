#include <gtest/gtest.h>
#include <memory>
#include "stats_engine.hpp"
#include "behavior_tracker.hpp"
#include "firewall_action.hpp"
#include "packet_data.hpp"

// Test fixture for StatsEngine
class StatsEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine = std::make_unique<StatsEngine>(2.0, 0.1);
    }

    std::unique_ptr<StatsEngine> engine;
};

// Test fixture for BehaviorTracker
class BehaviorTrackerTest : public ::testing::Test {
protected:
    void SetUp() override {
        tracker = std::make_unique<BehaviorTracker>();
    }

    std::unique_ptr<BehaviorTracker> tracker;
};

// Test fixture for FirewallAction
class FirewallActionTest : public ::testing::Test {
protected:
    void SetUp() override {
        firewall = std::make_unique<FirewallAction>(60); // 1 minute timeout for tests
    }

    std::unique_ptr<FirewallAction> firewall;
};

// StatsEngine Tests
TEST_F(StatsEngineTest, InitializationTest) {
    EXPECT_EQ(engine->get_current_rate(), 0.0);
    EXPECT_EQ(engine->get_entropy(), 0.0);
}

TEST_F(StatsEngineTest, NormalTrafficAnalysis) {
    PacketData normal_pkt;
    normal_pkt.src_ip = "192.168.1.100";
    normal_pkt.dst_ip = "10.0.0.1";
    normal_pkt.size = 1500;
    normal_pkt.payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    normal_pkt.is_http = true;
    
    // Normal traffic should not trigger anomaly detection
    bool result = engine->analyze(normal_pkt);
    EXPECT_FALSE(result);
}

TEST_F(StatsEngineTest, LowEntropyDetection) {
    PacketData low_entropy_pkt;
    low_entropy_pkt.src_ip = "192.168.1.200";
    low_entropy_pkt.dst_ip = "10.0.0.1";
    low_entropy_pkt.size = 1000;
    low_entropy_pkt.payload = std::string(500, 'A'); // Very low entropy payload
    
    // Send multiple similar packets to establish baseline
    for (int i = 0; i < 5; i++) {
        engine->analyze(low_entropy_pkt);
    }
    
    // Should detect anomaly after baseline is established
    bool result = engine->analyze(low_entropy_pkt);
    EXPECT_TRUE(result);
}

TEST_F(StatsEngineTest, EWMACalculation) {
    PacketData pkt;
    pkt.src_ip = "192.168.1.50";
    pkt.dst_ip = "10.0.0.1";
    pkt.size = 1000;
    pkt.payload = "Normal packet content";
    
    engine->analyze(pkt);
    double first_rate = engine->get_current_rate();
    EXPECT_GT(first_rate, 0.0);
    
    // Analyze another packet and check EWMA update
    pkt.size = 2000;
    engine->analyze(pkt);
    double second_rate = engine->get_current_rate();
    EXPECT_NE(first_rate, second_rate);
}

// BehaviorTracker Tests
TEST_F(BehaviorTrackerTest, SYNFloodDetection) {
    PacketData syn_pkt;
    syn_pkt.src_ip = "192.168.1.100";
    syn_pkt.dst_ip = "10.0.0.1";
    syn_pkt.is_syn = true;
    syn_pkt.is_ack = false;
    
    // Send multiple SYN packets from same source
    bool anomaly_detected = false;
    for (int i = 0; i < 100; i++) {
        if (tracker->inspect(syn_pkt)) {
            anomaly_detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(anomaly_detected);
}

TEST_F(BehaviorTrackerTest, NormalTCPHandshake) {
    PacketData syn_pkt, ack_pkt;
    
    // SYN packet
    syn_pkt.src_ip = "192.168.1.100";
    syn_pkt.dst_ip = "10.0.0.1";
    syn_pkt.is_syn = true;
    syn_pkt.is_ack = false;
    
    // SYN-ACK response (simulated as ACK)
    ack_pkt.src_ip = "10.0.0.1";
    ack_pkt.dst_ip = "192.168.1.100";
    ack_pkt.is_syn = false;
    ack_pkt.is_ack = true;
    
    // Normal handshake should not trigger anomaly
    EXPECT_FALSE(tracker->inspect(syn_pkt));
    EXPECT_FALSE(tracker->inspect(ack_pkt));
}

TEST_F(BehaviorTrackerTest, HTTPFloodDetection) {
    PacketData http_pkt;
    http_pkt.src_ip = "192.168.1.200";
    http_pkt.dst_ip = "10.0.0.1";
    http_pkt.is_http = true;
    http_pkt.is_syn = false;  // Explicitly set to avoid conflicts
    http_pkt.is_ack = false;  // Explicitly set to avoid conflicts
    http_pkt.payload = "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n";
    
    // Send many HTTP requests rapidly - need more than 150 for new threshold
    bool anomaly_detected = false;
    for (int i = 0; i < 200; i++) {
        http_pkt.session_id = "http_session_" + std::to_string(i); // Unique session for each request
        if (tracker->inspect(http_pkt)) {
            anomaly_detected = true;
            break;
        }
    }
    
    EXPECT_TRUE(anomaly_detected);
}

// FirewallAction Tests
TEST_F(FirewallActionTest, BlockIPFunctionality) {
    std::string test_ip = "192.168.1.100";
    
    // Initial state should have no blocked IPs
    EXPECT_EQ(firewall->get_blocked_count(), 0);
    
    // Block an IP
    firewall->block(test_ip);
    EXPECT_EQ(firewall->get_blocked_count(), 1);
    
    // Blocking same IP again should not increase count
    firewall->block(test_ip);
    EXPECT_EQ(firewall->get_blocked_count(), 1);
}

TEST_F(FirewallActionTest, UnblockIPFunctionality) {
    std::string test_ip = "192.168.1.100";
    
    // Block and then unblock
    firewall->block(test_ip);
    EXPECT_EQ(firewall->get_blocked_count(), 1);
    
    firewall->unblock(test_ip);
    EXPECT_EQ(firewall->get_blocked_count(), 0);
}

TEST_F(FirewallActionTest, MultipleIPBlocking) {
    std::vector<std::string> test_ips = {
        "192.168.1.100", "192.168.1.101", "192.168.1.102"
    };
    
    // Block multiple IPs
    for (const auto& ip : test_ips) {
        firewall->block(ip);
    }
    
    EXPECT_EQ(firewall->get_blocked_count(), test_ips.size());
    
    // Unblock one IP
    firewall->unblock(test_ips[0]);
    EXPECT_EQ(firewall->get_blocked_count(), test_ips.size() - 1);
}

// PacketData Tests
TEST(PacketDataTest, StructInitialization) {
    PacketData pkt;
    EXPECT_TRUE(pkt.src_ip.empty());
    EXPECT_TRUE(pkt.dst_ip.empty());
    EXPECT_EQ(pkt.size, 0);
    EXPECT_FALSE(pkt.is_syn);
    EXPECT_FALSE(pkt.is_ack);
    EXPECT_FALSE(pkt.is_http);
    EXPECT_TRUE(pkt.payload.empty());
}

TEST(PacketDataTest, DataAssignment) {
    PacketData pkt;
    pkt.src_ip = "192.168.1.1";
    pkt.dst_ip = "10.0.0.1";
    pkt.size = 1500;
    pkt.is_syn = true;
    pkt.is_http = false;
    pkt.payload = "Test payload";
    
    EXPECT_EQ(pkt.src_ip, "192.168.1.1");
    EXPECT_EQ(pkt.dst_ip, "10.0.0.1");
    EXPECT_EQ(pkt.size, 1500);
    EXPECT_TRUE(pkt.is_syn);
    EXPECT_FALSE(pkt.is_http);
    EXPECT_EQ(pkt.payload, "Test payload");
}

// Integration Tests
class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        stats_engine = std::make_unique<StatsEngine>(2.0, 0.1);
        behavior_tracker = std::make_unique<BehaviorTracker>();
        firewall_action = std::make_unique<FirewallAction>(60);
    }
    
    std::unique_ptr<StatsEngine> stats_engine;
    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<FirewallAction> firewall_action;
};

TEST_F(IntegrationTest, DDoSDetectionFlow) {
    PacketData attack_pkt;
    attack_pkt.src_ip = "192.168.1.100";
    attack_pkt.dst_ip = "10.0.0.1";
    attack_pkt.size = 64;
    attack_pkt.payload = std::string(32, 'A'); // Low entropy
    attack_pkt.is_syn = true;
    attack_pkt.is_ack = false;
    
    bool stats_anomaly = false;
    bool behavior_anomaly = false;
    
    // Simulate attack traffic
    for (int i = 0; i < 20; i++) {
        if (stats_engine->analyze(attack_pkt)) {
            stats_anomaly = true;
        }
        if (behavior_tracker->inspect(attack_pkt)) {
            behavior_anomaly = true;
        }
        
        // If either engine detects anomaly, block the IP
        if (stats_anomaly || behavior_anomaly) {
            firewall_action->block(attack_pkt.src_ip);
            break;
        }
    }
    
    EXPECT_TRUE(stats_anomaly || behavior_anomaly);
    EXPECT_EQ(firewall_action->get_blocked_count(), 1);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
