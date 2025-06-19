#pragma once

#include <string>
#include <unordered_map>

/**
 * @brief Testing Configuration Manager for DDoS Inspector
 * 
 * This class loads and manages testing-specific thresholds from testing_config.json
 * when the TESTING flag is enabled. It provides easy access to all testing parameters
 * and can be updated without recompiling the entire project.
 */
class TestingConfig {
public:
    struct StatisticalThresholds {
        double min_entropy_threshold = 0.1;
        double min_rate_threshold = 10.0;
        double entropy_multiplier = 0.15;
        double rate_multiplier = 1.5;
        double adaptation_factor = 0.2;
    };
    
    struct BehavioralThreshold {
        double min_threshold;
        double baseline_multiplier;
        int window_seconds;
        double adaptive_factor;
    };
    
    struct VolumeAttackThresholds {
        double packets_per_second_threshold = 5000;
        double burst_threshold = 2000;
        double sustained_threshold = 1000;
    };
    
    struct DetectionWindows {
        int syn_window_seconds = 10;
        int ack_window_seconds = 5;
        int http_window_seconds = 10;
        int volume_window_seconds = 1;
        int cleanup_interval_seconds = 30;
    };
    
    struct ConfidenceScoring {
        double base_stats_confidence = 0.3;
        double base_behavior_confidence = 0.3;
        double syn_bonus = 0.2;
        double http_bonus = 0.25;
        double rate_bonus = 0.3;
        double entropy_bonus = 0.3;
    };
    
    struct FirewallSettings {
        int block_timeout_seconds = 60;
        int rate_limit_base_pps = 10;
        int queue_size_limit = 100;
        int batch_size_limit = 10;
    };
    
    struct AdvancedDetection {
        int distributed_attack_threshold = 5;
        int geo_distributed_threshold = 3;
        int protocol_mixing_threshold = 2;
        double randomized_payload_entropy = 0.5;
        double pulse_attack_variance = 0.1;
    };
    
    struct MemoryLimits {
        int max_tracked_ips = 1000;
        int max_connections_per_ip = 100;
        int max_events_per_ip = 500;
        int reputation_cache_size = 500;
    };

private:
    StatisticalThresholds statistical_;
    std::unordered_map<std::string, BehavioralThreshold> behavioral_;
    VolumeAttackThresholds volume_;
    DetectionWindows windows_;
    ConfidenceScoring confidence_;
    FirewallSettings firewall_;
    AdvancedDetection advanced_;
    MemoryLimits memory_;
    
    bool loaded_ = false;
    std::string config_file_path_;
    
    /**
     * @brief Parse a key-value pair from the configuration file
     * @param section Current section being parsed
     * @param key Configuration key
     * @param value Configuration value
     */
    void parseValue(const std::string& section, const std::string& key, const std::string& value);

public:
    TestingConfig();
    
    /**
     * @brief Load testing configuration from JSON file
     * @param config_path Path to testing_config.json file
     * @return true if loaded successfully, false otherwise
     */
    bool loadFromFile(const std::string& config_path = "testing_config.json");
    
    /**
     * @brief Check if testing configuration is loaded and available
     * @return true if configuration is loaded
     */
    bool isLoaded() const { return loaded_; }
    
    // Getters for all configuration sections
    const StatisticalThresholds& getStatisticalThresholds() const { return statistical_; }
    const BehavioralThreshold& getBehavioralThreshold(const std::string& type) const;
    const VolumeAttackThresholds& getVolumeAttackThresholds() const { return volume_; }
    const DetectionWindows& getDetectionWindows() const { return windows_; }
    const ConfidenceScoring& getConfidenceScoring() const { return confidence_; }
    const FirewallSettings& getFirewallSettings() const { return firewall_; }
    const AdvancedDetection& getAdvancedDetection() const { return advanced_; }
    const MemoryLimits& getMemoryLimits() const { return memory_; }
    
    /**
     * @brief Get specific threshold value by name
     * @param category Category name (e.g., "syn_flood", "ack_flood")
     * @param parameter Parameter name (e.g., "min_threshold", "baseline_multiplier")
     * @return threshold value or default if not found
     */
    double getThreshold(const std::string& category, const std::string& parameter) const;
    
    /**
     * @brief Reload configuration from file
     * @return true if reloaded successfully
     */
    bool reload();
    
    /**
     * @brief Get configuration summary for logging
     * @return formatted string with configuration details
     */
    std::string getSummary() const;
};

// Global testing configuration instance (only available when TESTING is defined)
#ifdef TESTING
extern TestingConfig g_testing_config;
#endif
