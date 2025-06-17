#ifndef DETECTORS_H
#define DETECTORS_H

#include "detector_interface.hpp"

// Forward declaration for BehaviorTracker::Behavior
namespace BehaviorTracker { struct Behavior; }

namespace detection {
    // Concrete detector implementations
    class SynFloodDetector : public BaseDetector<BehaviorTracker::Behavior> {
    public:
        SynFloodDetector() : BaseDetector("SYN_FLOOD", 90) {}
        DetectionResult detect(const BehaviorTracker::Behavior& behavior) const override;
    };
    
    class HttpFloodDetector : public BaseDetector<BehaviorTracker::Behavior> {
    public:
        HttpFloodDetector() : BaseDetector("HTTP_FLOOD", 85) {}
        DetectionResult detect(const BehaviorTracker::Behavior& behavior) const override;
    };
    
    class SlowLorisDetector : public BaseDetector<BehaviorTracker::Behavior> {
    public:
        SlowLorisDetector() : BaseDetector("SLOWLORIS", 80) {}
        DetectionResult detect(const BehaviorTracker::Behavior& behavior) const override;
    };
    
    class UdpFloodDetector : public BaseDetector<BehaviorTracker::Behavior> {
    public:
        UdpFloodDetector() : BaseDetector("UDP_FLOOD", 75) {}
        DetectionResult detect(const BehaviorTracker::Behavior& behavior) const override;
    };
    
    class PortScanDetector : public BaseDetector<BehaviorTracker::Behavior> {
    public:
        PortScanDetector() : BaseDetector("PORT_SCAN", 70) {}
        DetectionResult detect(const BehaviorTracker::Behavior& behavior) const override;
    };
    
    class BandwidthAttackDetector : public BaseDetector<BehaviorTracker::Behavior> {
    public:
        BandwidthAttackDetector() : BaseDetector("BANDWIDTH_ATTACK", 65) {}
        DetectionResult detect(const BehaviorTracker::Behavior& behavior) const override;
    };
    
    // Factory for creating and registering all detectors
    class DetectorFactory {
    public:
        static void registerAllDetectors(DetectorRegistry<BehaviorTracker::Behavior>& registry);
        static std::unique_ptr<DetectorRegistry<BehaviorTracker::Behavior>> createDefaultRegistry();
    };
}

#endif // DETECTORS_H
