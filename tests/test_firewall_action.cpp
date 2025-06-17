#include <gtest/gtest.h>
#include "firewall_action.hpp"
#include <vector>
#include <chrono>
#include <thread>

class FirewallActionDetailedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use short timeout for testing
        firewall = std::make_unique<FirewallAction>(5); // 5 second timeout
        firewall_long = std::make_unique<FirewallAction>(300); // 5 minute timeout
    }

    void TearDown() override {
        // Clean up any remaining blocks
        firewall->cleanup_expired_blocks();
        firewall_long->cleanup_expired_blocks();
    }

    std::unique_ptr<FirewallAction> firewall;
    std::unique_ptr<FirewallAction> firewall_long;
    
    // Test IP addresses
    const std::string test_ip1 = "192.168.1.100";
    const std::string test_ip2 = "192.168.1.101";
    const std::string test_ip3 = "10.0.0.50";
    const std::string invalid_ip = "999.999.999.999";
    const std::string ipv6_test = "2001:db8::1";
};

TEST_F(FirewallActionDetailedTest, BasicBlockUnblockFunctionality) {
    // Initial state
    EXPECT_EQ(firewall->get_blocked_count(), 0);
    EXPECT_FALSE(firewall->is_blocked(test_ip1));
    
    // Block an IP
    firewall->block(test_ip1);
    EXPECT_EQ(firewall->get_blocked_count(), 1);
    EXPECT_TRUE(firewall->is_blocked(test_ip1));
    
    // Unblock the IP
    firewall->unblock(test_ip1);
    EXPECT_EQ(firewall->get_blocked_count(), 0);
    EXPECT_FALSE(firewall->is_blocked(test_ip1));
}

TEST_F(FirewallActionDetailedTest, DuplicateBlockingPrevention) {
    // Block same IP multiple times
    firewall->block(test_ip1);
    firewall->block(test_ip1);
    firewall->block(test_ip1);
    
    // Should only count once
    EXPECT_EQ(firewall->get_blocked_count(), 1);
    EXPECT_TRUE(firewall->is_blocked(test_ip1));
}

TEST_F(FirewallActionDetailedTest, MultipleIPBlocking) {
    std::vector<std::string> test_ips = {test_ip1, test_ip2, test_ip3};
    
    // Block multiple IPs
    for (const auto& ip : test_ips) {
        firewall->block(ip);
    }
    
    EXPECT_EQ(firewall->get_blocked_count(), test_ips.size());
    
    // Verify all are blocked
    for (const auto& ip : test_ips) {
        EXPECT_TRUE(firewall->is_blocked(ip));
    }
    
    // Unblock one IP
    firewall->unblock(test_ip1);
    EXPECT_EQ(firewall->get_blocked_count(), test_ips.size() - 1);
    EXPECT_FALSE(firewall->is_blocked(test_ip1));
    EXPECT_TRUE(firewall->is_blocked(test_ip2));
    EXPECT_TRUE(firewall->is_blocked(test_ip3));
}

TEST_F(FirewallActionDetailedTest, UnblockNonExistentIP) {
    // Try to unblock IP that was never blocked
    firewall->unblock(test_ip1);
    EXPECT_EQ(firewall->get_blocked_count(), 0);
    
    // Block one IP then try to unblock different IP
    firewall->block(test_ip1);
    firewall->unblock(test_ip2);
    EXPECT_EQ(firewall->get_blocked_count(), 1);
    EXPECT_TRUE(firewall->is_blocked(test_ip1));
}

TEST_F(FirewallActionDetailedTest, TimeoutBasedExpiration) {
    // Block IP with short timeout
    firewall->block(test_ip1);
    EXPECT_TRUE(firewall->is_blocked(test_ip1));
    EXPECT_EQ(firewall->get_blocked_count(), 1);
    
    // Wait for timeout to expire
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    // Manually trigger cleanup (in real implementation this might be automatic)
    firewall->cleanup_expired_blocks();
    
    // IP should no longer be blocked
    EXPECT_FALSE(firewall->is_blocked(test_ip1));
    EXPECT_EQ(firewall->get_blocked_count(), 0);
}

TEST_F(FirewallActionDetailedTest, DifferentTimeoutValues) {
    // Block same IP in both short and long timeout firewalls
    firewall->block(test_ip1);      // 5 second timeout
    firewall_long->block(test_ip1); // 5 minute timeout
    
    EXPECT_TRUE(firewall->is_blocked(test_ip1));
    EXPECT_TRUE(firewall_long->is_blocked(test_ip1));
    
    // Wait for short timeout to expire
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    firewall->cleanup_expired_blocks();
    firewall_long->cleanup_expired_blocks();
    
    // Short timeout should have expired, long timeout should still be active
    EXPECT_FALSE(firewall->is_blocked(test_ip1));
    EXPECT_TRUE(firewall_long->is_blocked(test_ip1));
}

TEST_F(FirewallActionDetailedTest, InvalidIPHandling) {
    // Test with invalid IP address
    EXPECT_NO_THROW(firewall->block(invalid_ip));
    
    // Implementation should handle gracefully
    // Behavior may vary - could ignore invalid IPs or handle them
    // The important thing is it doesn't crash
}

TEST_F(FirewallActionDetailedTest, IPv6AddressSupport) {
    // Test IPv6 address handling
    EXPECT_NO_THROW(firewall->block(ipv6_test));
    
    // Check if IPv6 is supported (implementation dependent)
    // At minimum, it should not crash
}

TEST_F(FirewallActionDetailedTest, EmptyAndSpecialIPHandling) {
    std::vector<std::string> special_ips = {
        "",               // Empty string
        "0.0.0.0",       // Any address
        "127.0.0.1",     // Localhost
        "255.255.255.255", // Broadcast
        "192.168.1.1/24"  // CIDR notation
    };
    
    for (const auto& ip : special_ips) {
        EXPECT_NO_THROW(firewall->block(ip));
        EXPECT_NO_THROW(firewall->unblock(ip));
    }
}

TEST_F(FirewallActionDetailedTest, HighVolumeBlocking) {
    const int num_ips = 1000;
    std::vector<std::string> ip_list;
    
    // Pre-allocate capacity to avoid reallocations during push_back
    ip_list.reserve(num_ips);
    
    // Generate many IP addresses
    for (int i = 0; i < num_ips; i++) {
        std::string ip = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
        ip_list.push_back(ip);
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Block all IPs
    for (const auto& ip : ip_list) {
        firewall_long->block(ip);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_EQ(firewall_long->get_blocked_count(), num_ips);
    
    // Performance check - should handle 1000 IPs in reasonable time
    EXPECT_LT(duration.count(), 1000); // Less than 1 second
}

TEST_F(FirewallActionDetailedTest, ConcurrentAccess) {
    const int num_threads = 10;
    const int ips_per_thread = 100;
    std::vector<std::thread> threads;
    
    // Pre-allocate capacity to avoid reallocations during emplace_back
    threads.reserve(num_threads);
    
    // Launch multiple threads that block IPs concurrently
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, t, ips_per_thread]() {
            for (int i = 0; i < ips_per_thread; i++) {
                std::string ip = "172.16." + std::to_string(t) + "." + std::to_string(i);
                firewall_long->block(ip);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should have blocked all unique IPs
    EXPECT_EQ(firewall_long->get_blocked_count(), num_threads * ips_per_thread);
}

TEST_F(FirewallActionDetailedTest, BlockingStatsPersistence) {
    // Block several IPs
    firewall_long->block(test_ip1);
    firewall_long->block(test_ip2);
    firewall_long->block(test_ip3);
    
    int initial_count = firewall_long->get_blocked_count();
    EXPECT_EQ(initial_count, 3);
    
    // Unblock one
    firewall_long->unblock(test_ip1);
    EXPECT_EQ(firewall_long->get_blocked_count(), initial_count - 1);
    
    // Block it again
    firewall_long->block(test_ip1);
    EXPECT_EQ(firewall_long->get_blocked_count(), initial_count);
}

TEST_F(FirewallActionDetailedTest, CleanupFunctionality) {
    // Block multiple IPs with short timeout
    std::vector<std::string> ips = {test_ip1, test_ip2, test_ip3};
    for (const auto& ip : ips) {
        firewall->block(ip);
    }
    
    EXPECT_EQ(firewall->get_blocked_count(), ips.size());
    
    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    // Before cleanup
    EXPECT_EQ(firewall->get_blocked_count(), ips.size()); // Still counted until cleanup
    
    // After cleanup
    firewall->cleanup_expired_blocks();
    EXPECT_EQ(firewall->get_blocked_count(), 0);
    
    // Verify none are blocked
    for (const auto& ip : ips) {
        EXPECT_FALSE(firewall->is_blocked(ip));
    }
}

TEST_F(FirewallActionDetailedTest, MixedTimeoutBehavior) {
    // Block IP, wait a bit, block more IPs
    firewall->block(test_ip1);
    
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    firewall->block(test_ip2);
    firewall->block(test_ip3);
    
    // After 3 more seconds, first IP should expire but others should remain
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    firewall->cleanup_expired_blocks();
    
    EXPECT_FALSE(firewall->is_blocked(test_ip1)); // Should be expired
    EXPECT_TRUE(firewall->is_blocked(test_ip2));  // Should still be blocked
    EXPECT_TRUE(firewall->is_blocked(test_ip3));  // Should still be blocked
    EXPECT_EQ(firewall->get_blocked_count(), 2);
}

TEST_F(FirewallActionDetailedTest, ShowCurrentFirewallRules) {
    // Add some test blocks and rate limits
    firewall->block("192.168.170.1");
    firewall->rate_limit("192.168.170.2", 2);
    
    // Wait a moment for async operations
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Get current firewall rules
    auto rules = firewall->get_current_firewall_rules();
    
    std::cout << "\n=== CURRENT FIREWALL RULES ===\n";
    for (const auto& rule : rules) {
        std::cout << rule << '\n';
    }
    std::cout << "================================\n";
    
    // Get blocked and rate-limited IPs
    auto blocked = firewall->get_blocked_ips();
    auto rate_limited = firewall->get_rate_limited_ips();
    
    std::cout << "=== TRACKED IPs ===\n";
    std::cout << "Blocked IPs (" << blocked.size() << "):\n";
    for (const auto& ip : blocked) {
        std::cout << "  " << ip << '\n';
    }
    
    std::cout << "Rate Limited IPs (" << rate_limited.size() << "):\n";
    for (const auto& ip : rate_limited) {
        std::cout << "  " << ip << '\n';
    }
    std::cout << "==================\n";
}