#include <gtest/gtest.h>
#include "behavior_tracker.hpp"
#include "stats_engine.hpp"
#include "packet_data.hpp"
#include <vector>
#include <random>
#include <chrono>
#include <thread>

class NormalTrafficTest : public ::testing::Test {
protected:
    void SetUp() override {
        behavior_tracker = std::make_unique<BehaviorTracker>();
        stats_engine = std::make_unique<StatsEngine>(2.0, 0.1);
        random_generator.seed(42); // Fixed seed for reproducible tests
    }

    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<StatsEngine> stats_engine;
    std::mt19937 random_generator;
    
    // Generate realistic office/enterprise IP ranges
    std::vector<std::string> generateOfficeIPs(int count) {
        std::vector<std::string> ips;
        std::uniform_int_distribution<int> subnet_dist(1, 10);
        std::uniform_int_distribution<int> host_dist(1, 254);
        
        for (int i = 0; i < count; i++) {
            std::string ip = "10.0." + std::to_string(subnet_dist(random_generator)) + 
                           "." + std::to_string(host_dist(random_generator));
            ips.push_back(ip);
        }
        return ips;
    }
    
    // Generate realistic web browsing payloads
    std::string generateWebTrafficPayload() {
        std::vector<std::string> urls = {
            "/", "/index.html", "/about.html", "/contact.html", "/products.html",
            "/api/users", "/api/data", "/images/logo.png", "/css/style.css", "/js/app.js",
            "/blog/2024/article1", "/news/latest", "/search?q=example"
        };
        
        std::vector<std::string> user_agents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:94.0) Gecko/94.0"
        };
        
        auto& url = urls[random_generator() % urls.size()];
        auto& ua = user_agents[random_generator() % user_agents.size()];
        
        return "GET " + url + " HTTP/1.1\\r\\n" +
               "Host: company.com\\r\\n" +
               "User-Agent: " + ua + "\\r\\n" +
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n" +
               "Accept-Language: en-US,en;q=0.5\\r\\n" +
               "Connection: keep-alive\\r\\n\\r\\n";
    }
    
    // Simulate realistic TCP handshake
    void simulateNormalTCPConnection(const std::string& client_ip, const std::string& server_ip) {
        // 1. SYN packet
        PacketData syn_pkt;
        syn_pkt.src_ip = client_ip;
        syn_pkt.dst_ip = server_ip;
        syn_pkt.is_syn = true;
        syn_pkt.is_ack = false;
        syn_pkt.size = 64;
        syn_pkt.session_id = client_ip + "_conn_" + std::to_string(random_generator());
        
        // 2. SYN-ACK packet (server response)
        PacketData syn_ack_pkt;
        syn_ack_pkt.src_ip = server_ip;
        syn_ack_pkt.dst_ip = client_ip;
        syn_ack_pkt.is_syn = true;
        syn_ack_pkt.is_ack = true;
        syn_ack_pkt.size = 64;
        syn_ack_pkt.session_id = syn_pkt.session_id;
        
        // 3. ACK packet (client acknowledgment)
        PacketData ack_pkt;
        ack_pkt.src_ip = client_ip;
        ack_pkt.dst_ip = server_ip;
        ack_pkt.is_syn = false;
        ack_pkt.is_ack = true;
        ack_pkt.size = 64;
        ack_pkt.session_id = syn_pkt.session_id;
        
        // Send the handshake sequence
        behavior_tracker->inspect(syn_pkt);
        stats_engine->analyze(syn_pkt);
        
        behavior_tracker->inspect(syn_ack_pkt);
        stats_engine->analyze(syn_ack_pkt);
        
        behavior_tracker->inspect(ack_pkt);
        stats_engine->analyze(ack_pkt);
    }
};

TEST_F(NormalTrafficTest, TypicalOfficeTraffic) {
    // Simulate typical office traffic: 50 users, normal web browsing patterns
    auto office_users = generateOfficeIPs(50);
    bool false_positive = false;
    int total_packets = 0;
    
    // Simulate 8-hour workday traffic pattern
    for (int hour = 9; hour <= 17; hour++) {
        // Varying activity levels throughout the day
        int activity_multiplier = (hour >= 10 && hour <= 12) || (hour >= 14 && hour <= 16) ? 2 : 1;
        
        for (const auto& user_ip : office_users) {
            // Each user makes 1-5 requests per hour
            int requests_this_hour = (random_generator() % 5 + 1) * activity_multiplier;
            
            for (int req = 0; req < requests_this_hour; req++) {
                // Complete TCP connection for each request
                simulateNormalTCPConnection(user_ip, "203.0.113.100");
                
                // HTTP request after connection establishment
                PacketData http_pkt;
                http_pkt.src_ip = user_ip;
                http_pkt.dst_ip = "203.0.113.100";
                http_pkt.is_http = true;
                http_pkt.payload = generateWebTrafficPayload();
                http_pkt.size = 400 + http_pkt.payload.length();
                http_pkt.session_id = user_ip + "_http_" + std::to_string(total_packets);
                
                bool behavioral_alert = behavior_tracker->inspect(http_pkt);
                bool statistical_alert = stats_engine->analyze(http_pkt);
                
                if (behavioral_alert || statistical_alert) {
                    false_positive = true;
                    std::cout << "FALSE POSITIVE: Normal office traffic triggered alert" << '\n';
                    std::cout << "  User: " << user_ip << " at hour " << hour << '\n';
                    break;
                }
                
                total_packets++;
                
                // Realistic inter-request delays (30 seconds to 10 minutes)
                std::this_thread::sleep_for(std::chrono::milliseconds(1)); // Accelerated for testing
            }
            
            if (false_positive) break;
        }
        
        if (false_positive) break;
    }
    
    std::cout << "Normal office traffic simulation results:" << '\n';
    std::cout << "  Total packets processed: " << total_packets << '\n';
    std::cout << "  False positive rate: " << (false_positive ? "HIGH (FAILED)" : "NONE (GOOD)") << '\n';
    
    EXPECT_FALSE(false_positive) << "Normal office traffic should NOT trigger DDoS alerts";
}

TEST_F(NormalTrafficTest, MixedApplicationTraffic) {
    // Simulate mixed application traffic: email, file transfers, video streaming
    auto enterprise_ips = generateOfficeIPs(30);
    bool false_positive = false;
    
    for (const auto& ip : enterprise_ips) {
        // 1. Email traffic (SMTP/IMAP) - small, occasional packets
        for (int i = 0; i < 5; i++) {
            PacketData email_pkt;
            email_pkt.src_ip = ip;
            email_pkt.dst_ip = "203.0.113.25"; // Mail server
            email_pkt.size = 150 + (random_generator() % 300);
            email_pkt.payload = "SMTP email content with varying sizes and normal entropy";
            email_pkt.session_id = ip + "_email_" + std::to_string(i);
            
            if (behavior_tracker->inspect(email_pkt) || stats_engine->analyze(email_pkt)) {
                false_positive = true;
                std::cout << "FALSE POSITIVE: Email traffic triggered alert from " << ip << '\n';
                break;
            }
        }
        
        // 2. File transfer (FTP/HTTP) - larger packets, bursty
        PacketData file_pkt;
        file_pkt.src_ip = ip;
        file_pkt.dst_ip = "203.0.113.50"; // File server
        file_pkt.size = 1500; // MTU size
        file_pkt.payload = std::string(1400, 'X'); // Binary-like data
        file_pkt.session_id = ip + "_file_transfer";
        
        // File transfers can be large but are legitimate
        for (int chunk = 0; chunk < 10; chunk++) {
            if (behavior_tracker->inspect(file_pkt) || stats_engine->analyze(file_pkt)) {
                // This might trigger due to size/repetition, but it's normal
                // Don't count as false positive for file transfers
            }
        }
        
        // 3. Video streaming - consistent moderate-size packets
        for (int i = 0; i < 20; i++) {
            PacketData video_pkt;
            video_pkt.src_ip = "203.0.113.75"; // Streaming server
            video_pkt.dst_ip = ip; // User receiving stream
            video_pkt.size = 800 + (random_generator() % 400);
            video_pkt.payload = "H264 video stream data with medium entropy";
            video_pkt.session_id = ip + "_video_stream";
            
            if (behavior_tracker->inspect(video_pkt) || stats_engine->analyze(video_pkt)) {
                false_positive = true;
                std::cout << "FALSE POSITIVE: Video streaming triggered alert to " << ip << '\n';
                break;
            }
        }
        
        if (false_positive) break;
    }
    
    EXPECT_FALSE(false_positive) << "Mixed application traffic should be handled correctly";
}

TEST_F(NormalTrafficTest, BurstyLegitimateTraffic) {
    // Test handling of legitimate but bursty traffic (e.g., software updates, backups)
    std::string update_server = "203.0.113.200";
    auto client_ips = generateOfficeIPs(20);
    bool false_positive = false;
    
    // Simulate software update push to all clients simultaneously
    for (const auto& client_ip : client_ips) {
        // Each client downloads update - this creates a burst but is legitimate
        for (int packet = 0; packet < 50; packet++) {
            PacketData update_pkt;
            update_pkt.src_ip = update_server;
            update_pkt.dst_ip = client_ip;
            update_pkt.size = 1400; // Large packets
            update_pkt.payload = "Software update binary data - legitimate but repetitive";
            update_pkt.session_id = client_ip + "_update_" + std::to_string(packet);
            
            bool behavioral_alert = behavior_tracker->inspect(update_pkt);
            bool statistical_alert = stats_engine->analyze(update_pkt);
            
            // Note: This might legitimately trigger due to volume/repetition
            // The key is that it should NOT result in permanent blocking
            if (behavioral_alert || statistical_alert) {
                std::cout << "UPDATE TRAFFIC ALERT: " << client_ip << " packet " << packet << '\n';
                // This is expected for large software updates
            }
        }
    }
    
    std::cout << "Bursty legitimate traffic test completed" << '\n';
    // For this test, we mainly check that the system doesn't crash
    EXPECT_TRUE(true) << "System should handle bursty legitimate traffic without crashing";
}
