#include "ddos_inspector.hpp"
#include <sstream>
#include <iostream>

#ifdef TESTING
#include "testing_config.hpp"
#endif

// Global threshold tuning configuration instance
ThresholdTuning g_threshold_tuning;

// Store production thresholds for restoration
struct ProductionThresholds {
    double min_entropy_threshold = 0.5;
    double min_rate_threshold = 1000.0;
    double min_syn_flood_threshold = 100.0;
    double min_ack_flood_threshold = 50.0;
    double min_http_flood_threshold = 200.0;
    double syn_flood_baseline_multiplier = 5.0;
    double ack_flood_baseline_multiplier = 3.0;
    double http_flood_baseline_multiplier = 10.0;
    double entropy_multiplier = 0.3;
    double rate_multiplier = 3.0;
    double adaptation_factor = 0.1;
    double confidence_base_stats = 0.4;
    double confidence_base_behavior = 0.4;
    double confidence_syn_bonus = 0.1;
    double confidence_http_short_bonus = 0.15;
    double confidence_rate_high_bonus = 0.2;
    double confidence_entropy_high_bonus = 0.2;
};

static ProductionThresholds production_defaults;

#ifdef TESTING
void ThresholdTuning::applyTestingThresholds() {
    // Load testing configuration from file if available
    if (g_testing_config.isLoaded()) {
        std::cout << "[CONFIG] Loading testing thresholds from testing_config.json\n";
        
        // Apply statistical thresholds
        const auto& stats = g_testing_config.getStatisticalThresholds();
        min_entropy_threshold = stats.min_entropy_threshold;
        min_rate_threshold = stats.min_rate_threshold;
        entropy_multiplier = stats.entropy_multiplier;
        rate_multiplier = stats.rate_multiplier;
        adaptation_factor = stats.adaptation_factor;
        
        // Apply behavioral thresholds
        const auto& syn_config = g_testing_config.getBehavioralThreshold("syn_flood");
        min_syn_flood_threshold = syn_config.min_threshold;
        syn_flood_baseline_multiplier = syn_config.baseline_multiplier;
        
        const auto& ack_config = g_testing_config.getBehavioralThreshold("ack_flood");
        min_ack_flood_threshold = ack_config.min_threshold;
        ack_flood_baseline_multiplier = ack_config.baseline_multiplier;
        
        const auto& http_config = g_testing_config.getBehavioralThreshold("http_flood");
        min_http_flood_threshold = http_config.min_threshold;
        http_flood_baseline_multiplier = http_config.baseline_multiplier;
        
        // Apply confidence scoring
        const auto& confidence = g_testing_config.getConfidenceScoring();
        confidence_base_stats = confidence.base_stats_confidence;
        confidence_base_behavior = confidence.base_behavior_confidence;
        confidence_syn_bonus = confidence.syn_bonus;
        confidence_http_short_bonus = confidence.http_bonus;
        confidence_rate_high_bonus = confidence.rate_bonus;
        confidence_entropy_high_bonus = confidence.entropy_bonus;
        
        std::cout << g_testing_config.getSummary();
    } else {
        std::cout << "[CONFIG] Using fallback testing thresholds (testing_config.json not found)\n";
        
        // Fallback testing thresholds (same as before)
        min_entropy_threshold = 0.1;
        min_rate_threshold = 10.0;
        min_syn_flood_threshold = 10.0;
        min_ack_flood_threshold = 5.0;
        min_http_flood_threshold = 20.0;
        syn_flood_baseline_multiplier = 2.0;
        ack_flood_baseline_multiplier = 1.5;
        http_flood_baseline_multiplier = 3.0;
    }
}
#endif

// NEW: Runtime testing mode methods
void ThresholdTuning::applyRuntimeTestingThresholds() {
    if (runtime_testing_mode) {
        return; // Already in testing mode
    }
    
    runtime_testing_mode = true;
    std::cout << "[CONFIG] Switching to RUNTIME testing mode - applying low testing thresholds\n";
    
    // Apply the same testing thresholds as compile-time TESTING mode
    #ifdef TESTING
    if (g_testing_config.isLoaded()) {
        // Use JSON configuration if available
        const auto& stats = g_testing_config.getStatisticalThresholds();
        min_entropy_threshold = stats.min_entropy_threshold;
        min_rate_threshold = stats.min_rate_threshold;
        entropy_multiplier = stats.entropy_multiplier;
        rate_multiplier = stats.rate_multiplier;
        adaptation_factor = stats.adaptation_factor;
        
        const auto& syn_config = g_testing_config.getBehavioralThreshold("syn_flood");
        min_syn_flood_threshold = syn_config.min_threshold;
        syn_flood_baseline_multiplier = syn_config.baseline_multiplier;
        
        const auto& ack_config = g_testing_config.getBehavioralThreshold("ack_flood");
        min_ack_flood_threshold = ack_config.min_threshold;
        ack_flood_baseline_multiplier = ack_config.baseline_multiplier;
        
        const auto& http_config = g_testing_config.getBehavioralThreshold("http_flood");
        min_http_flood_threshold = http_config.min_threshold;
        http_flood_baseline_multiplier = http_config.baseline_multiplier;
        
        const auto& confidence = g_testing_config.getConfidenceScoring();
        confidence_base_stats = confidence.base_stats_confidence;
        confidence_base_behavior = confidence.base_behavior_confidence;
        confidence_syn_bonus = confidence.syn_bonus;
        confidence_http_short_bonus = confidence.http_bonus;
        confidence_rate_high_bonus = confidence.rate_bonus;
        confidence_entropy_high_bonus = confidence.entropy_bonus;
    } else {
    #endif
        // Fallback testing thresholds
        min_entropy_threshold = 0.1;
        min_rate_threshold = 10.0;
        min_syn_flood_threshold = 10.0;
        min_ack_flood_threshold = 5.0;
        min_http_flood_threshold = 20.0;
        syn_flood_baseline_multiplier = 2.0;
        ack_flood_baseline_multiplier = 1.5;
        http_flood_baseline_multiplier = 3.0;
        entropy_multiplier = 0.15;
        rate_multiplier = 1.5;
        adaptation_factor = 0.2;
        confidence_base_stats = 0.3;
        confidence_base_behavior = 0.3;
        confidence_syn_bonus = 0.2;
        confidence_http_short_bonus = 0.25;
        confidence_rate_high_bonus = 0.3;
        confidence_entropy_high_bonus = 0.3;
    #ifdef TESTING
    }
    #endif
    
    std::cout << "[CONFIG] Runtime testing mode applied successfully\n";
}

void ThresholdTuning::restoreProductionThresholds() {
    if (!runtime_testing_mode) {
        return; // Already in production mode
    }
    
    runtime_testing_mode = false;
    std::cout << "[CONFIG] Restoring PRODUCTION mode thresholds\n";
    
    // Restore production defaults
    min_entropy_threshold = production_defaults.min_entropy_threshold;
    min_rate_threshold = production_defaults.min_rate_threshold;
    min_syn_flood_threshold = production_defaults.min_syn_flood_threshold;
    min_ack_flood_threshold = production_defaults.min_ack_flood_threshold;
    min_http_flood_threshold = production_defaults.min_http_flood_threshold;
    syn_flood_baseline_multiplier = production_defaults.syn_flood_baseline_multiplier;
    ack_flood_baseline_multiplier = production_defaults.ack_flood_baseline_multiplier;
    http_flood_baseline_multiplier = production_defaults.http_flood_baseline_multiplier;
    entropy_multiplier = production_defaults.entropy_multiplier;
    rate_multiplier = production_defaults.rate_multiplier;
    adaptation_factor = production_defaults.adaptation_factor;
    confidence_base_stats = production_defaults.confidence_base_stats;
    confidence_base_behavior = production_defaults.confidence_base_behavior;
    confidence_syn_bonus = production_defaults.confidence_syn_bonus;
    confidence_http_short_bonus = production_defaults.confidence_http_short_bonus;
    confidence_rate_high_bonus = production_defaults.confidence_rate_high_bonus;
    confidence_entropy_high_bonus = production_defaults.confidence_entropy_high_bonus;
    
    std::cout << "[CONFIG] Production mode restored successfully\n";
}

void ThresholdTuning::setRuntimeTestingMode(bool enabled) {
    if (enabled) {
        applyRuntimeTestingThresholds();
    } else {
        restoreProductionThresholds();
    }
}

// Initialize configuration with testing thresholds if TESTING is defined
struct ConfigurationInitializer {
    ConfigurationInitializer() {
        #ifdef TESTING
        std::cout << "[CONFIG] TESTING mode detected - applying low testing thresholds\n";
        g_threshold_tuning.applyTestingThresholds();
        #else
        std::cout << "[CONFIG] PRODUCTION mode - using production thresholds\n";
        #endif
    }
};

// Global initializer to apply testing configuration at startup
static ConfigurationInitializer config_init;

void ThresholdTuning::logConfiguration() const {
    std::ostringstream config_msg;
    config_msg << "Threshold Tuning Configuration:\n"
               << "  - Mode: " << (runtime_testing_mode ? "RUNTIME TESTING" : "PRODUCTION") << "\n"
               << "  - Adaptation Factor: " << adaptation_factor << "\n"
               << "  - Entropy Multiplier: " << entropy_multiplier << "\n" 
               << "  - Rate Multiplier: " << rate_multiplier << "\n"
               << "  - Min Entropy Threshold: " << min_entropy_threshold << "\n"
               << "  - Min Rate Threshold: " << min_rate_threshold << "\n"
               << "  - Min SYN Flood Threshold: " << min_syn_flood_threshold << "\n"
               << "  - Min ACK Flood Threshold: " << min_ack_flood_threshold << "\n"
               << "  - Min HTTP Flood Threshold: " << min_http_flood_threshold << "\n"
               << "  - Base Confidence (Stats): " << confidence_base_stats << "\n"
               << "  - Base Confidence (Behavior): " << confidence_base_behavior;
    // Note: DDosLogger::info would require including the logger header
    // For now, this is just a placeholder implementation
}
