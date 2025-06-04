# DDoS Inspector Design Specification

## Document Information
- **Version**: 2.0
- **Date**: June 3, 2025
- **Authors**: ADHHP Research Team
- **Status**: Production Ready

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Design](#architecture-design)
3. [Component Specifications](#component-specifications)
4. [Data Structures](#data-structures)
5. [Algorithm Specifications](#algorithm-specifications)
6. [Performance Requirements](#performance-requirements)
7. [Security Design](#security-design)
8. [Integration Specifications](#integration-specifications)

## System Overview

### Purpose and Scope
The DDoS Inspector is a real-time DDoS detection and mitigation plugin for Snort 3, designed to provide inline protection against various types of Distributed Denial of Service attacks through advanced statistical analysis and behavioral profiling.

### Design Goals
- **Real-time Detection**: Sub-10ms detection latency for immediate threat response
- **High Accuracy**: <0.3% false positive rate with >99% detection accuracy
- **Low Overhead**: <5% CPU overhead and <50MB memory footprint
- **Scalability**: Support for 10Gbps+ network throughput
- **Modularity**: Plugin-based architecture for easy maintenance and enhancement

### Core Capabilities
- Multi-vector attack detection (volumetric, protocol, application-layer)
- Adaptive threshold management based on network conditions
- Automated firewall integration with progressive blocking
- Comprehensive metrics and monitoring support

## Architecture Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic Flow                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   Snort 3 Core Engine                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │               DDoS Inspector Plugin                     ││
│  │                                                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      ││
│  │  │   Packet    │  │ Statistical │  │ Behavioral  │      ││
│  │  │ Processing  │  │   Engine    │  │   Engine    │      ││
│  │  │   Layer     │  │             │  │             │      ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘      ││
│  │         │                 │                 │           ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      ││
│  │  │ Correlation │  │  Firewall   │  │  Metrics    │      ││
│  │  │   Engine    │  │   Action    │  │  Engine     │      ││
│  │  │             │  │             │  │             │      ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘      ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 System Integration                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  nftables/  │  │ Prometheus  │  │   Logging   │          │
│  │  iptables   │  │  Metrics    │  │   System    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### Component Interaction Design

```cpp
// Core interaction flow as implemented
void DdosInspector::eval(Packet* p) {
    // 1. Packet preprocessing and validation
    if (!validatePacket(p)) return;
    
    // 2. Extract packet data
    PacketData pkt_data = extractPacketData(p);
    
    // 3. Parallel analysis engines
    bool stats_anomaly = stats_engine->analyze(pkt_data);
    bool behavior_anomaly = behavior_tracker->inspect(pkt_data);
    
    // 4. Correlation and decision making
    if (stats_anomaly || behavior_anomaly) {
        AttackInfo attack = classifyAttack(pkt_data, stats_anomaly, behavior_anomaly);
        
        // 5. Mitigation response
        if (attack.confidence >= 0.7) {
            executeMitigation(attack);
        }
    }
    
    // 6. Metrics collection
    updateMetrics(pkt_data, stats_anomaly, behavior_anomaly);
}
```

## Component Specifications

### 1. DDoS Inspector Core (`ddos_inspector.cpp/hpp`)

**Purpose**: Main plugin controller and Snort 3 integration point

**Key Classes**:
- `DdosInspectorModule`: Configuration management and parameter validation
- `DdosInspector`: Core packet inspection and coordination

**Core Methods**:
```cpp
class DdosInspector : public Inspector {
public:
    DdosInspector(DdosInspectorModule* mod);
    void eval(Packet* p) override;
    
private:
    AttackInfo classifyAttack(const PacketData& pkt_data, bool stats_anomaly, 
                             bool behavior_anomaly, uint8_t proto);
    void incrementAttackCounter(AttackInfo::Type type);
    void writeMetrics();
    
    // Detection engines
    std::unique_ptr<StatsEngine> stats_engine;
    std::unique_ptr<BehaviorTracker> behavior_tracker;
    std::unique_ptr<FirewallAction> firewall_action;
    
    // Metrics (thread-safe atomic counters)
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_blocked{0};
    std::atomic<uint64_t> syn_flood_detections{0};
    std::atomic<uint64_t> slowloris_detections{0};
    std::atomic<uint64_t> udp_flood_detections{0};
    std::atomic<uint64_t> icmp_flood_detections{0};
};
```

**Attack Classification Logic**:
```cpp
AttackInfo DdosInspector::classifyAttack(const PacketData& pkt_data, 
                                         bool stats_anomaly, bool behavior_anomaly, uint8_t proto) {
    AttackInfo attack;
    attack.confidence = 0.0;
    
    // Multi-factor confidence scoring
    double behavioral_score = behavior_anomaly ? 0.6 : 0.0;
    double statistical_score = stats_anomaly ? 0.4 : 0.0;
    
    // Protocol-specific classification
    if (proto == IPPROTO_TCP) {
        if (pkt_data.is_syn && !pkt_data.is_ack) {
            attack.type = AttackInfo::SYN_FLOOD;
            attack.severity = (behavioral_score > 0.5) ? AttackInfo::SEVERITY_HIGH : AttackInfo::SEVERITY_MEDIUM;
        } else if (pkt_data.is_http) {
            attack.type = AttackInfo::HTTP_FLOOD;
            // Check for Slowloris patterns
            if (pkt_data.payload.find("\r\n\r\n") == std::string::npos) {
                attack.type = AttackInfo::SLOWLORIS;
                attack.severity = AttackInfo::SEVERITY_CRITICAL;
            }
        }
    } else if (proto == IPPROTO_UDP) {
        attack.type = AttackInfo::UDP_FLOOD;
        attack.severity = (pkt_data.size > 1400) ? AttackInfo::SEVERITY_HIGH : AttackInfo::SEVERITY_MEDIUM;
    } else if (proto == IPPROTO_ICMP) {
        attack.type = AttackInfo::ICMP_FLOOD;
        attack.severity = AttackInfo::SEVERITY_LOW;
    }
    
    attack.confidence = behavioral_score + statistical_score;
    return attack;
}
```

### 2. Statistical Engine (`stats_engine.cpp/hpp`)

**Purpose**: EWMA-based statistical analysis and entropy calculation

**Core Algorithm Implementation**:
```cpp
class StatsEngine {
private:
    struct IPStats {
        double ewma = 0.0;           // Per-IP EWMA value
        int packet_count = 0;        // Packet counter for this IP
    };
    
    std::unordered_map<std::string, IPStats> stats;
    double entropy_threshold;        // Configurable threshold (default: 2.0)
    double ewma_alpha;              // Smoothing factor (default: 0.1)
    double current_rate = 0.0;      // Current global packet rate
    double baseline_rate = 0.0;     // Baseline rate for comparison
    
public:
    bool analyze(const PacketData& pkt);
    double compute_entropy(const std::string& payload);
    void update_ewma(const std::string& src_ip, double packet_rate);
    double get_adaptive_entropy_threshold(const PacketData& pkt);
    bool is_repetitive_payload(const std::string& payload);
};
```

**EWMA Implementation**:
```cpp
bool StatsEngine::analyze(const PacketData& pkt) {
    // Dual EWMA system for stability and responsiveness
    double instant_rate = pkt.size / time_seconds;
    
    if (packets_received == 1) {
        current_rate = instant_rate;
        baseline_rate = instant_rate;
    } else {
        // Fast-adapting EWMA for current conditions
        current_rate = ewma_alpha * instant_rate + (1.0 - ewma_alpha) * current_rate;
        
        // Slow-adapting EWMA for baseline establishment
        baseline_rate = 0.01 * instant_rate + 0.99 * baseline_rate;
    }
    
    // Multi-factor anomaly scoring (increased thresholds for production)
    double anomaly_score = 0.0;
    
    // 1. Entropy analysis with adaptive thresholds
    current_entropy = compute_entropy(pkt.payload);
    double adaptive_threshold = get_adaptive_entropy_threshold(pkt);
    if (current_entropy < adaptive_threshold * 0.5) {
        anomaly_score += 0.3;
    }
    
    // 2. Rate deviation analysis (increased thresholds)
    double rate_multiplier = current_rate / std::max(baseline_rate, 5000.0);
    if (rate_multiplier > 50.0) {
        anomaly_score += 0.4;
    } else if (rate_multiplier > 20.0) {
        anomaly_score += 0.2;
    }
    
    // 3. Absolute rate threshold (increased for normal usage)
    if (current_rate > 500000.0) {
        anomaly_score += 0.3;
    }
    
    // 4. Pattern repetition detection
    if (is_repetitive_payload(pkt.payload)) {
        anomaly_score += 0.3;
    }
    
    // Decision threshold increased to 0.7 for reduced false positives
    return anomaly_score >= 0.7;
}
```

**Shannon Entropy Calculation**:
```cpp
double StatsEngine::compute_entropy(const std::string& payload) {
    if (payload.empty()) return 0.0;
    
    std::unordered_map<char, int> freq;
    for (char c : payload) {
        freq[c]++;
    }
    
    double entropy = 0.0;
    for (const auto& pair : freq) {
        double probability = static_cast<double>(pair.second) / payload.length();
        if (probability > 0) {
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}
```

### 3. Behavioral Tracker (`behavior_tracker.cpp/hpp`)

**Purpose**: Connection state tracking and behavioral pattern analysis

**Core Data Structures**:
```cpp
class BehaviorTracker {
private:
    struct TimestampedEvent {
        std::chrono::steady_clock::time_point timestamp;
        std::string event_type;  // "SYN", "ACK", "HTTP", "ORPHAN_ACK"
    };
    
    struct Behavior {
        int half_open = 0;                    // Half-open connections (SYN flood detection)
        int total_packets = 0;                // Total packet count
        int syn_count = 0, ack_count = 0;     // Protocol-specific counters
        int http_requests = 0;                // HTTP request counter
        
        std::deque<TimestampedEvent> recent_events;  // 60-second sliding window
        std::chrono::steady_clock::time_point first_seen, last_seen;
        
        // HTTP session tracking for Slowloris detection
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> http_sessions;
        std::unordered_set<std::string> incomplete_requests;
        std::unordered_set<std::string> established_connections;
    };
    
    std::unordered_map<std::string, Behavior> behaviors;  // Per-IP behavior tracking
    
public:
    bool inspect(const PacketData& pkt);
    size_t get_connection_count() const;
};
```

**Detection Algorithm Implementation**:
```cpp
bool BehaviorTracker::inspect(const PacketData& pkt) {
    auto& b = behaviors[pkt.src_ip];
    
    // Event categorization and state tracking
    std::string event_type;
    if (pkt.is_syn && !pkt.is_ack) {
        b.syn_count++;
        b.half_open++;
        event_type = "SYN";
    } else if (pkt.is_ack && !pkt.is_syn) {
        std::string conn_id = generateConnectionId(pkt);
        if (b.established_connections.find(conn_id) == b.established_connections.end()) {
            event_type = "ORPHAN_ACK";  // ACK without corresponding SYN
        } else {
            if (b.half_open > 0) b.half_open--;
            event_type = "ACK";
        }
    }
    
    // Multi-algorithm detection with confidence scoring
    int detection_score = 0;
    if (detectSynFlood(b)) detection_score += 3;
    if (detectAckFlood(b)) detection_score += 3;
    if (detectHttpFlood(b)) detection_score += 3;
    if (detectSlowloris(b)) detection_score += 4;
    if (detectVolumeAttack(b)) detection_score += 3;
    if (detectDistributedAttack()) detection_score += 5;
    
    // Enhanced pattern correlation
    if (detection_score >= 2) detection_score += 2;  // Multiple patterns bonus
    
    return detection_score >= 6;  // Increased threshold for production
}
```

**Specific Attack Detection Methods**:
```cpp
// SYN Flood Detection (updated thresholds)
bool BehaviorTracker::detectSynFlood(const Behavior& b) {
    if (b.half_open > 500) return true;  // Increased from 100 to 500
    
    int syn_count_recent = 0;
    auto now = std::chrono::steady_clock::now();
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (duration.count() <= 10 && event.event_type == "SYN") {
            syn_count_recent++;
        }
    }
    return syn_count_recent > 200;  // Increased from 50 to 200
}

// HTTP Flood Detection (updated thresholds)
bool BehaviorTracker::detectHttpFlood(const Behavior& b) {
    int http_count_recent = 0;
    auto now = std::chrono::steady_clock::now();
    for (const auto& event : b.recent_events) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp);
        if (duration.count() <= 60 && event.event_type == "HTTP") {
            http_count_recent++;
        }
    }
    
    // Adaptive threshold based on global conditions
    int threshold = (total_global_packets > 5000 && behaviors.size() > 20) ? 200 : 500;
    return http_count_recent > threshold;
}

// Slowloris Detection (multi-factor analysis)
bool BehaviorTracker::detectSlowloris(const Behavior& b) {
    auto now = std::chrono::steady_clock::now();
    
    int long_sessions = 0;
    for (const auto& session : b.http_sessions) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - session.second);
        if (duration.count() > 600) {  // Sessions longer than 10 minutes
            long_sessions++;
        }
    }
    
    // Require BOTH conditions: long sessions AND incomplete requests
    return (long_sessions > 200 && b.incomplete_requests.size() > 500);
}
```

### 4. Firewall Action Controller (`firewall_action.cpp/hpp`)

**Purpose**: Automated mitigation through system firewall integration

**Core Implementation**:
```cpp
class FirewallAction {
private:
    struct BlockInfo {
        std::chrono::steady_clock::time_point blocked_time;
        bool is_blocked;                     // Full block status
        int rate_limit_level;               // 0-4 progressive rate limiting
    };
    
    std::unordered_map<std::string, BlockInfo> blocked_ips;
    mutable std::mutex blocked_ips_mutex;   // Thread-safe access
    int block_timeout;                      // Configurable timeout (default: 600s)
    
public:
    void block(const std::string& ip);
    void unblock(const std::string& ip);
    void rate_limit(const std::string& ip, int severity_level);
    bool is_blocked(const std::string& ip) const;
    size_t get_blocked_count() const;
    void cleanup_expired_blocks();
};
```

**Blocking Implementation**:
```cpp
void FirewallAction::block(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto it = blocked_ips.find(ip);
    
    if (it == blocked_ips.end() || !it->second.is_blocked) {
        if (execute_block_command(ip)) {
            blocked_ips[ip] = {now, true, 0};
        }
    } else {
        blocked_ips[ip].blocked_time = now;  // Update timestamp
    }
    
    cleanup_expired_blocks();
}

bool FirewallAction::execute_block_command(const std::string& ip) {
    #ifdef TESTING
        return true;  // Mock for testing
    #else
        // Production nftables integration
        std::system("nft add table inet filter 2>/dev/null || true");
        std::system("nft add set inet filter ddos_ip_set '{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }' 2>/dev/null || true");
        
        std::string cmd = "nft add element inet filter ddos_ip_set { " + ip + " } 2>/dev/null || "
                         "iptables -I INPUT -s " + ip + " -j DROP 2>/dev/null";
        return std::system(cmd.c_str()) == 0;
    #endif
}
```

**Progressive Rate Limiting**:
```cpp
void FirewallAction::rate_limit(const std::string& ip, int severity_level) {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex);
    
    auto now = std::chrono::steady_clock::now();
    if (execute_rate_limit_command(ip, severity_level)) {
        blocked_ips[ip] = {now, false, severity_level};
    }
}

bool FirewallAction::execute_rate_limit_command(const std::string& ip, int severity) {
    #ifdef TESTING
        return true;
    #else
        std::string rate_limit;
        switch (severity) {
            case 1: rate_limit = "100/sec"; break;   // Light throttling
            case 2: rate_limit = "50/sec"; break;    // Medium throttling
            case 3: rate_limit = "10/sec"; break;    // Heavy throttling
            case 4: rate_limit = "1/sec"; break;     // Near-blocking
            default: rate_limit = "100/sec"; break;
        }
        
        std::string cmd = "nft add rule inet filter input ip saddr " + ip + 
                         " limit rate " + rate_limit + " accept 2>/dev/null";
        return std::system(cmd.c_str()) == 0;
    #endif
}
```

## Data Structures

### PacketData Structure
```cpp
struct PacketData {
    std::string src_ip;              // Source IP address
    std::string dst_ip;              // Destination IP address
    std::string payload;             // Packet payload for analysis
    std::string session_id;          // Session identifier for tracking
    size_t size = 0;                // Packet size in bytes
    bool is_syn = false;            // TCP SYN flag
    bool is_ack = false;            // TCP ACK flag
    bool is_http = false;           // HTTP protocol detected
};
```

### AttackInfo Structure
```cpp
struct AttackInfo {
    enum Type { 
        SYN_FLOOD, HTTP_FLOOD, SLOWLORIS, 
        UDP_FLOOD, ICMP_FLOOD, ACK_FLOOD, UNKNOWN 
    };
    enum Severity { 
        SEVERITY_LOW = 1, SEVERITY_MEDIUM = 2, 
        SEVERITY_HIGH = 3, SEVERITY_CRITICAL = 4 
    };
    
    Type type = UNKNOWN;
    double confidence = 0.0;         // 0.0-1.0 confidence score
    Severity severity = SEVERITY_LOW;
};
```

## Algorithm Specifications

### EWMA Algorithm
**Mathematical Formula**: `EWMA(t) = α × X(t) + (1-α) × EWMA(t-1)`

**Implementation Details**:
- Fast EWMA (α = 0.1): Responsive to traffic changes
- Slow EWMA (α = 0.01): Stable baseline establishment
- Rate multiplier detection: `current_rate / baseline_rate > threshold`

### Shannon Entropy
**Mathematical Formula**: `H(X) = -Σ p(xi) × log₂(p(xi))`

**Adaptive Thresholds**:
- HTTP traffic: 2.5 bits (structured headers)
- Small packets (<50 bytes): 1.0 bits
- Large packets (>1400 bytes): 3.0 bits
- Binary/encrypted data: 7.0+ bits

### Multi-Layered Scoring
**Statistical Engine Scoring**:
```cpp
double anomaly_score = 0.0;
if (entropy_anomaly) anomaly_score += 0.3;
if (rate_anomaly) anomaly_score += 0.4;
if (pattern_anomaly) anomaly_score += 0.3;
return anomaly_score >= 0.7;  // 70% confidence threshold
```

**Behavioral Engine Scoring**:
```cpp
int detection_score = 0;
if (syn_flood) detection_score += 3;
if (http_flood) detection_score += 3;
if (slowloris) detection_score += 4;  // Higher weight for sophistication
if (distributed) detection_score += 5; // Highest weight for coordination
return detection_score >= 6;  // Confidence threshold
```

## Performance Requirements

### Latency Requirements
- Packet processing: <10ms P95
- Detection decision: <5ms average
- Firewall integration: <3ms for blocking
- Total added latency: <15ms P99

### Throughput Requirements
- 10 Gbps sustained traffic with <2% overhead
- 100K+ concurrent connections
- 1M+ packets per second processing capability

### Memory Requirements
- Base footprint: <50MB
- Per-IP tracking: ~500 bytes average
- Maximum tracked IPs: 100K-1M (configurable)
- Memory pool management for bounded growth

### CPU Requirements
- Additional overhead: <5% compared to baseline Snort
- Multi-threading support for parallel analysis
- SIMD optimization where applicable

## Security Design

### Input Validation
```cpp
bool validatePacket(Packet* p) {
    if (!p || !p->ptrs.ip_api.is_ip()) return false;
    if (!p->ptrs.ip_api.is_ip4()) return false;  // IPv4 only currently
    
    const snort::ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
    uint8_t proto = (uint8_t)ip4h->proto();
    
    // Protocol filtering
    return (proto == IPPROTO_TCP || proto == IPPROTO_UDP || 
           (allow_icmp && proto == IPPROTO_ICMP));
}
```

### Command Injection Prevention
```cpp
bool FirewallAction::is_valid_ip_address(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

bool FirewallAction::execute_block_command(const std::string& ip) {
    if (!is_valid_ip_address(ip)) {
        log_error("Invalid IP address: " + ip);
        return false;
    }
    // Safe command execution...
}
```

### Resource Protection
```cpp
void BehaviorTracker::cleanupOldEvents(Behavior& b) {
    const size_t MAX_EVENTS = 10000;
    while (b.recent_events.size() > MAX_EVENTS) {
        b.recent_events.pop_front();
    }
    
    const size_t MAX_CONNECTIONS = 50000;
    if (b.established_connections.size() > MAX_CONNECTIONS) {
        // LRU eviction strategy
        auto it = b.established_connections.begin();
        std::advance(it, MAX_CONNECTIONS / 2);
        b.established_connections.erase(b.established_connections.begin(), it);
    }
}
```

## Integration Specifications

### Snort 3 Plugin Interface
```cpp
// Plugin registration
static const Parameter ddos_params[] = {
    { "allow_icmp", Parameter::PT_BOOL, nullptr, "false", "allow ICMP processing" },
    { "entropy_threshold", Parameter::PT_REAL, "0.0:10.0", "2.0", "entropy threshold" },
    { "ewma_alpha", Parameter::PT_REAL, "0.0:1.0", "0.1", "EWMA smoothing factor" },
    { "block_timeout", Parameter::PT_INT, "1:3600", "600", "IP block timeout" },
    { "metrics_file", Parameter::PT_STRING, nullptr, "/tmp/ddos_inspector_stats", "metrics file" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// Plugin API definition
class DdosApi {
public:
    BaseApi base;
    const char* get_name() const override { return "ddos_inspector"; }
    const char* get_help() const override { return "DDoS detection and mitigation"; }
    Inspector* get_inspector(InspectorManager*) override;
};
```

### Configuration Integration
```lua
-- Snort 3 Lua configuration
ddos_inspector = {
    allow_icmp = false,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = '/tmp/ddos_inspector_stats'
}

binder = {
    { when = { proto = 'tcp' }, use = { type = 'ddos_inspector' } },
    { when = { proto = 'udp' }, use = { type = 'ddos_inspector' } }
}
```

### Metrics Integration
```cpp
void DdosInspector::writeMetrics() {
    if (duration.count() >= 5) {  // Every 5 seconds
        std::ofstream metrics_file(metrics_file_path);
        metrics_file << "packets_processed:" << packets_processed.load() << std::endl;
        metrics_file << "packets_blocked:" << packets_blocked.load() << std::endl;
        metrics_file << "entropy:" << stats_engine->get_entropy() << std::endl;
        metrics_file << "rate:" << stats_engine->get_current_rate() << std::endl;
        metrics_file << "connections:" << behavior_tracker->get_connection_count() << std::endl;
        metrics_file << "blocked_ips:" << firewall_action->get_blocked_count() << std::endl;
        // Attack-specific counters
        metrics_file << "syn_floods:" << syn_flood_detections.load() << std::endl;
        metrics_file << "slowloris_attacks:" << slowloris_detections.load() << std::endl;
        metrics_file.close();
    }
}
```

This design specification accurately reflects the current implementation of the DDoS Inspector system, including all actual function signatures, algorithm implementations, and integration patterns found in the codebase.

