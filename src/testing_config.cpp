#include "testing_config.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstdlib>

#ifdef TESTING

// Global testing configuration instance (only available in testing mode)
TestingConfig g_testing_config;

TestingConfig::TestingConfig() : config_file_path_("testing_config.json") {
    // Set default values - these will be overridden when loading from file
    statistical_.min_entropy_threshold = 0.1;
    statistical_.min_rate_threshold = 10.0;
    statistical_.entropy_multiplier = 0.15;
    statistical_.rate_multiplier = 1.5;
    statistical_.adaptation_factor = 0.2;
    
    // Set default behavioral thresholds
    behavioral_["syn_flood"] = {10.0, 2.0, 10, 0.1};
    behavioral_["ack_flood"] = {5.0, 1.5, 5, 0.1};
    behavioral_["http_flood"] = {20.0, 3.0, 10, 0.05};
    behavioral_["slowloris"] = {5.0, 1.0, 5, 0.1};
    
    // Try to load configuration on construction
    loadFromFile();
}

bool TestingConfig::loadFromFile(const std::string& config_path) {
    config_file_path_ = config_path;
    
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cout << "[TESTING_CONFIG] Warning: Could not open " << config_path 
                  << ", using default testing values\n";
        loaded_ = false;
        return false;
    }
    
    // Simple JSON parsing for our specific structure
    // Note: In production, you might want to use a proper JSON library
    std::string line;
    std::string current_section;
    
    try {
        while (std::getline(file, line)) {
            // Remove whitespace
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            
            // Skip empty lines and comments
            if (line.empty() || line[0] == '/' || line[0] == '#') continue;
            
            // Parse sections
            if (line.find("\"statistical_thresholds\"") != std::string::npos) {
                current_section = "statistical";
            } else if (line.find("\"syn_flood\"") != std::string::npos) {
                current_section = "syn_flood";
            } else if (line.find("\"ack_flood\"") != std::string::npos) {
                current_section = "ack_flood";
            } else if (line.find("\"http_flood\"") != std::string::npos) {
                current_section = "http_flood";
            } else if (line.find("\"volume_attack\"") != std::string::npos) {
                current_section = "volume_attack";
            } else if (line.find("\"detection_windows\"") != std::string::npos) {
                current_section = "detection_windows";
            } else if (line.find("\"confidence_scoring\"") != std::string::npos) {
                current_section = "confidence_scoring";
            } else if (line.find("\"firewall_settings\"") != std::string::npos) {
                current_section = "firewall_settings";
            } else if (line.find("\"advanced_detection\"") != std::string::npos) {
                current_section = "advanced_detection";
            } else if (line.find("\"memory_limits\"") != std::string::npos) {
                current_section = "memory_limits";
            }
            
            // Parse key-value pairs
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string key = line.substr(0, colon_pos);
                std::string value = line.substr(colon_pos + 1);
                
                // Remove quotes and commas
                key.erase(std::remove(key.begin(), key.end(), '"'), key.end());
                value.erase(std::remove(value.begin(), value.end(), '"'), value.end());
                value.erase(std::remove(value.begin(), value.end(), ','), value.end());
                
                // Parse based on current section
                parseValue(current_section, key, value);
            }
        }
        
        loaded_ = true;
        std::cout << "[TESTING_CONFIG] Successfully loaded testing configuration from " 
                  << config_path << "\n";
        return true;
        
    } catch (const std::exception& e) {
        std::cout << "[TESTING_CONFIG] Error parsing " << config_path << ": " 
                  << e.what() << "\n";
        loaded_ = false;
        return false;
    }
}

void TestingConfig::parseValue(const std::string& section, const std::string& key, const std::string& value) {
    try {
        if (section == "statistical") {
            if (key == "min_entropy_threshold") {
                statistical_.min_entropy_threshold = std::stod(value);
            } else if (key == "min_rate_threshold") {
                statistical_.min_rate_threshold = std::stod(value);
            } else if (key == "entropy_multiplier") {
                statistical_.entropy_multiplier = std::stod(value);
            } else if (key == "rate_multiplier") {
                statistical_.rate_multiplier = std::stod(value);
            } else if (key == "adaptation_factor") {
                statistical_.adaptation_factor = std::stod(value);
            }
        } else if (section == "syn_flood" || section == "ack_flood" || section == "http_flood") {
            if (key == "min_threshold") {
                behavioral_[section].min_threshold = std::stod(value);
            } else if (key == "baseline_multiplier") {
                behavioral_[section].baseline_multiplier = std::stod(value);
            } else if (key == "window_seconds") {
                behavioral_[section].window_seconds = std::stoi(value);
            } else if (key == "adaptive_factor") {
                behavioral_[section].adaptive_factor = std::stod(value);
            }
        } else if (section == "volume_attack") {
            if (key == "packets_per_second_threshold") {
                volume_.packets_per_second_threshold = std::stod(value);
            } else if (key == "burst_threshold") {
                volume_.burst_threshold = std::stod(value);
            } else if (key == "sustained_threshold") {
                volume_.sustained_threshold = std::stod(value);
            }
        } else if (section == "detection_windows") {
            if (key == "syn_window_seconds") {
                windows_.syn_window_seconds = std::stoi(value);
            } else if (key == "ack_window_seconds") {
                windows_.ack_window_seconds = std::stoi(value);
            } else if (key == "http_window_seconds") {
                windows_.http_window_seconds = std::stoi(value);
            } else if (key == "volume_window_seconds") {
                windows_.volume_window_seconds = std::stoi(value);
            } else if (key == "cleanup_interval_seconds") {
                windows_.cleanup_interval_seconds = std::stoi(value);
            }
        } else if (section == "confidence_scoring") {
            if (key == "base_stats_confidence") {
                confidence_.base_stats_confidence = std::stod(value);
            } else if (key == "base_behavior_confidence") {
                confidence_.base_behavior_confidence = std::stod(value);
            } else if (key == "syn_bonus") {
                confidence_.syn_bonus = std::stod(value);
            } else if (key == "http_bonus") {
                confidence_.http_bonus = std::stod(value);
            } else if (key == "rate_bonus") {
                confidence_.rate_bonus = std::stod(value);
            } else if (key == "entropy_bonus") {
                confidence_.entropy_bonus = std::stod(value);
            }
        } else if (section == "firewall_settings") {
            if (key == "block_timeout_seconds") {
                firewall_.block_timeout_seconds = std::stoi(value);
            } else if (key == "rate_limit_base_pps") {
                firewall_.rate_limit_base_pps = std::stoi(value);
            } else if (key == "queue_size_limit") {
                firewall_.queue_size_limit = std::stoi(value);
            } else if (key == "batch_size_limit") {
                firewall_.batch_size_limit = std::stoi(value);
            }
        } else if (section == "advanced_detection") {
            if (key == "distributed_attack_threshold") {
                advanced_.distributed_attack_threshold = std::stoi(value);
            } else if (key == "geo_distributed_threshold") {
                advanced_.geo_distributed_threshold = std::stoi(value);
            } else if (key == "protocol_mixing_threshold") {
                advanced_.protocol_mixing_threshold = std::stoi(value);
            } else if (key == "randomized_payload_entropy") {
                advanced_.randomized_payload_entropy = std::stod(value);
            } else if (key == "pulse_attack_variance") {
                advanced_.pulse_attack_variance = std::stod(value);
            }
        } else if (section == "memory_limits") {
            if (key == "max_tracked_ips") {
                memory_.max_tracked_ips = std::stoi(value);
            } else if (key == "max_connections_per_ip") {
                memory_.max_connections_per_ip = std::stoi(value);
            } else if (key == "max_events_per_ip") {
                memory_.max_events_per_ip = std::stoi(value);
            } else if (key == "reputation_cache_size") {
                memory_.reputation_cache_size = std::stoi(value);
            }
        }
    } catch (const std::exception& e) {
        std::cout << "[TESTING_CONFIG] Warning: Could not parse " << section 
                  << "." << key << " = " << value << "\n";
    }
}

const TestingConfig::BehavioralThreshold& TestingConfig::getBehavioralThreshold(const std::string& type) const {
    auto it = behavioral_.find(type);
    if (it != behavioral_.end()) {
        return it->second;
    }
    
    // Return default if not found
    static const BehavioralThreshold default_threshold = {100.0, 5.0, 30, 0.1};
    return default_threshold;
}

double TestingConfig::getThreshold(const std::string& category, const std::string& parameter) const {
    if (category == "syn_flood" || category == "ack_flood" || category == "http_flood") {
        const auto& threshold = getBehavioralThreshold(category);
        if (parameter == "min_threshold") return threshold.min_threshold;
        if (parameter == "baseline_multiplier") return threshold.baseline_multiplier;
        if (parameter == "window_seconds") return static_cast<double>(threshold.window_seconds);
        if (parameter == "adaptive_factor") return threshold.adaptive_factor;
    }
    
    return 0.0; // Default fallback
}

bool TestingConfig::reload() {
    return loadFromFile(config_file_path_);
}

std::string TestingConfig::getSummary() const {
    std::ostringstream oss;
    oss << "[TESTING_CONFIG] Configuration Summary:\n";
    oss << "  Statistical Thresholds:\n";
    oss << "    - Min Entropy: " << statistical_.min_entropy_threshold << "\n";
    oss << "    - Min Rate: " << statistical_.min_rate_threshold << "\n";
    oss << "    - Entropy Multiplier: " << statistical_.entropy_multiplier << "\n";
    oss << "    - Rate Multiplier: " << statistical_.rate_multiplier << "\n";
    
    oss << "  Behavioral Thresholds:\n";
    for (const auto& [type, threshold] : behavioral_) {
        oss << "    - " << type << ": min=" << threshold.min_threshold 
            << ", multiplier=" << threshold.baseline_multiplier 
            << ", window=" << threshold.window_seconds << "s\n";
    }
    
    oss << "  Volume Attack: " << volume_.packets_per_second_threshold << " pps\n";
    oss << "  Firewall Timeout: " << firewall_.block_timeout_seconds << "s\n";
    
    return oss.str();
}

#endif // TESTING
