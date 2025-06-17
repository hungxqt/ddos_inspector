#include "detector_interface.hpp"
#include <algorithm>

namespace detection {
    template<typename BehaviorType>
    void DetectorRegistry<BehaviorType>::registerDetector(std::unique_ptr<IDetector<BehaviorType>> detector) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        detectors_.push_back(std::move(detector));
        sortByPriority();
    }
    
    template<typename BehaviorType>
    void DetectorRegistry<BehaviorType>::unregisterDetector(const std::string& name) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        detectors_.erase(
            std::remove_if(detectors_.begin(), detectors_.end(),
                [&name](const auto& detector) { return detector->getName() == name; }),
            detectors_.end()
        );
    }
    
    template<typename BehaviorType>
    void DetectorRegistry<BehaviorType>::enableDetector(const std::string& name, bool enabled) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        for (auto& detector : detectors_) {
            if (detector->getName() == name) {
                detector->setEnabled(enabled);
                break;
            }
        }
    }
    
    template<typename BehaviorType>
    std::vector<DetectionResult> DetectorRegistry<BehaviorType>::runAll(const BehaviorType& behavior) const {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::vector<DetectionResult> results;
        results.reserve(detectors_.size());
        
        for (const auto& detector : detectors_) {
            auto result = detector->detect(behavior);
            if (result.matched) {
                results.push_back(std::move(result));
            }
        }
        return results;
    }
    
    template<typename BehaviorType>
    std::vector<DetectionResult> DetectorRegistry<BehaviorType>::runEnabled(const BehaviorType& behavior) const {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::vector<DetectionResult> results;
        
        for (const auto& detector : detectors_) {
            if (detector->isEnabled()) {
                auto result = detector->detect(behavior);
                if (result.matched) {
                    results.push_back(std::move(result));
                }
            }
        }
        return results;
    }
    
    template<typename BehaviorType>
    void DetectorRegistry<BehaviorType>::sortByPriority() {
        std::sort(detectors_.begin(), detectors_.end(),
            [](const auto& a, const auto& b) {
                return a->getPriority() > b->getPriority(); // Higher priority first
            });
    }
    
    template<typename BehaviorType>
    std::vector<std::string> DetectorRegistry<BehaviorType>::getDetectorNames() const {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::vector<std::string> names;
        names.reserve(detectors_.size());
        
        for (const auto& detector : detectors_) {
            names.push_back(detector->getName());
        }
        return names;
    }
    
    template<typename BehaviorType>
    std::vector<std::string> DetectorRegistry<BehaviorType>::getEnabledDetectors() const {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::vector<std::string> names;
        
        for (const auto& detector : detectors_) {
            if (detector->isEnabled()) {
                names.push_back(detector->getName());
            }
        }
        return names;
    }
    
    template<typename BehaviorType>
    size_t DetectorRegistry<BehaviorType>::getDetectorCount() const {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        return detectors_.size();
    }
}
