#ifndef DETECTOR_INTERFACE_H
#define DETECTOR_INTERFACE_H

#include <string>
#include <memory>
#include <vector>
#include <mutex>

// Forward declaration - we'll use template/auto to avoid circular dependency
namespace detection {
    struct DetectionResult {
        bool matched = false;
        int confidence = 0;  // 0-100
        int severity = 0;    // 0-100  
        std::string attack_type;
        std::string description;
        double score = 0.0;
    };
    
    template<typename BehaviorType>
    class IDetector {
    public:
        virtual ~IDetector() = default;
        virtual DetectionResult detect(const BehaviorType& behavior) const = 0;
        virtual std::string getName() const = 0;
        virtual bool isEnabled() const = 0;
        virtual void setEnabled(bool enabled) = 0;
        virtual int getPriority() const = 0; // Higher priority detectors run first
    };
    
    // Registry for managing detectors at runtime
    template<typename BehaviorType>
    class DetectorRegistry {
    private:
        std::vector<std::unique_ptr<IDetector<BehaviorType>>> detectors_;
        mutable std::mutex registry_mutex_;
        
    public:
        void registerDetector(std::unique_ptr<IDetector<BehaviorType>> detector);
        void unregisterDetector(const std::string& name);
        void enableDetector(const std::string& name, bool enabled);
        std::vector<DetectionResult> runAll(const BehaviorType& behavior) const;
        std::vector<DetectionResult> runEnabled(const BehaviorType& behavior) const;
        void sortByPriority();
        
        // Get detector info
        std::vector<std::string> getDetectorNames() const;
        std::vector<std::string> getEnabledDetectors() const;
        size_t getDetectorCount() const;
    };
    
    // Base implementation for common detector functionality
    template<typename BehaviorType>
    class BaseDetector : public IDetector<BehaviorType> {
    private:
        std::string name_;
        bool enabled_;
        int priority_;
        
    public:
        BaseDetector(std::string name, int priority = 100) 
            : name_(std::move(name)), enabled_(true), priority_(priority) {}
            
        std::string getName() const override { return name_; }
        bool isEnabled() const override { return enabled_; }
        void setEnabled(bool enabled) override { enabled_ = enabled; }
        int getPriority() const override { return priority_; }
    };
}

#endif // DETECTOR_INTERFACE_H
