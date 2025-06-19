#include "ddos_inspector.hpp"
#include <sstream>

// Global threshold tuning configuration instance
ThresholdTuning g_threshold_tuning;

void ThresholdTuning::logConfiguration() const {
    std::ostringstream config_msg;
    config_msg << "Threshold Tuning Configuration:\n"
               << "  - Adaptation Factor: " << adaptation_factor << "\n"
               << "  - Entropy Multiplier: " << entropy_multiplier << "\n" 
               << "  - Rate Multiplier: " << rate_multiplier << "\n"
               << "  - Min Entropy Threshold: " << min_entropy_threshold << "\n"
               << "  - Min Rate Threshold: " << min_rate_threshold << "\n"
               << "  - Base Confidence (Stats): " << confidence_base_stats << "\n"
               << "  - Base Confidence (Behavior): " << confidence_base_behavior;
    // Note: DDosLogger::info would require including the logger header
    // For now, this is just a placeholder implementation
}
