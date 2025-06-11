# Architecture Guide

This guide provides a comprehensive overview of DDoS Inspector's system architecture, design decisions, and technical implementation details.

## System Overview

DDoS Inspector is a high-performance, real-time DDoS detection and mitigation system built as a Snort 3 plugin. It combines statistical analysis, behavioral tracking, and machine learning techniques to identify and respond to various types of DDoS attacks.

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                 Snort 3 Engine                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │   Packet    │ │   Packet    │ DDoS Inspector     │ │
│  │ing   │ │        Plugin         │
│  │   (DAQ)     │ │             │ │                         │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
└─────────────────────────────────────┬───────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────┐
│                DDoS Inspector Core                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │  Traffic    │ │  Behavior   │ │    Statistics Engine   │ │
│  │  Analyzer   │ │  Tracker    │ │                         │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│  │  Attack     │ │  Firewal │    Metrter     │ │
│  │  Detector   │ │  Controller │ │                         │ │
│  └─────────────┘ └─────────────┘ └─────────────────────────┘ │
└─────────────────────────────────────┬───────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────┐
│                 Output Systems                              │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐  │
│ │   Alerts    │ │   Metrics   │ │      Firewall Rules     │  │
│ │             │ │    File     │ │      (nftables/         │  │
│ │             │ │             │ │       iptables)         │  │
│ └─────────────┘ └─────────────┘ └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Component Architecture

### c Analyzer

**Purpose**: Real-time packet analysis and feature extraction

**Key Components**:
- **Packet Inspector**: Extrrk layer information
- **Protocol Analyzer**: Deep packet inspecti application protocols
- acker**: Maintains connection state infor
- **Entropy Calculator**: Shannon entropy analysis for anomaly detection

**Data Flow**:
```
Raw Packets → Protocol Parsing → Feature Extraction → Statistical Analysis
```

**Technical Details**:
- Processes packets at line speed (1Gbps+)
- Maintains per-IP and per-connection state
- Calculates real-time statistics (packet rates, connection counts, etc.)
- Performs deep packet inspection for HTTP, DNS, and other protocols

### 2. Behavior Tracker

**Purpose**: Long-term behavioral analysis and pattern recognition

**Key Components**:
- **Connection State Machine**: Tracks TCP connection lifecycle
- **Session Analyzer**: Analyzes application-layer sessions
- **Pattern Detector**: Identifies abnormal behavioral patterns
- **Baseline Manager**: Maintains normal traffic baselines

**Algorithms Used**:
- **EWMA (Exponentially Weighted Moving Average)**: For trend analysis
- **Z-Score Analysis**: For outlier detection
- **Time Series Analysis**: For temporal pattern recognition
- **Clustering**: For grouping similar behaviors

**Memory Management**:
```cpp
class BehaviorTracker {
private:
    std::unordered_map<uint32_t, IPBehavior> ip_behaviors;
    std::unordered_map<uint64_t, ConnectionState> connections;
    LRUCache<uint32_t, BaselineData> baselines;
    
    // Memory optimization
    uint32_t max_tracked_ips;
    uint32_t cleanup_interval;
    double memory_cleanup_threshold;
};
```

### 3. Statistics Engine

**Purpose**: Real-time statistical analysis and anomaly detection

**Key Algorithms**:

**Shannon Entropy Calculation**:
```
H(X) = -Σ P(xi) * log2(P(xi))
```
- Used for detecting traffic randomness
- Applied to source IPs, ports, and packet sizes
- Threshold-based anomaly detection

**EWMA Implementation**:
```
EWMA(t) = α * X(t) + (1-α) * EWMA(t-1)
```
- α = smoothing factor (0 < α < 1)
- Used for adaptive baseline learning
- Real-time trend analysis

**Z-Score Analysis**:
```
Z = (X - μ) / σ
```
- Standard deviation-based outlier detection
- Applied to packet rates and connection metrics
- Dynamic threshold adjustment

### 4. Attack Detector

**Purpose**: Multi-vector attack detection using combined analysis

**Detection Engines**:

**SYN Flood Detection**:
- Half-open connection tracking
- SYN/ACK ratio analysis
- Rate-based detection
- State table overflow detection

```cpp
bool detectSYNFlood(const IPStats& stats) {
    return (stats.half_open_connections > syn_flood_threshold) ||
           (stats.syn_rate > syn_rate_threshold) ||
           (stats.syn_ack_ratio < 0.1);
}
```

**HTTP Flood Detection**:
- Request rate analysis
- User-Agent pattern analysis
- Session behavior tracking
- Payload analysis

**Slowloris Detection**:
- Long-lived connection analysis
- Incomplete request detection
- Connection pool exhaustion detection

**UDP Flood Detection**:
- Packet rate analysis
- Fragmentation analysis
- Amplification attack detection

### 5. Firewall Controller

**Purpose**: Automated mitigation through firewall integration

**Supported Backends**:
- **nftables** (preferred): Modern netfilter framework
- **iptables** (legacy): Traditional Linux firewall
- **API Integration**: REST APIs for external firewalls

**Implementation**:
```cpp
class FirewallController {
public:
    virtual bool blockIP(const std::string& ip, uint32_t timeout) = 0;
    virtual bool unblockIP(const std::string& ip) = 0;
    virtual std::vector<std::string> getBlockedIPs() = 0;
    
protected:
    BlockingPolicy policy;
    ProgressiveBlocking progressive_blocking;
};
```

**Blocking Strategies**:
- **Immediate Blocking**: Instant IP blocking upon detection
- **Progressive Blocking**: Increasing block duration for repeat offenders
- **Whitelist Protection**: Never block whitelisted IPs/networks
- **Temporary Blocking**: Automatic unblocking after timeout

## Data Structures and Memory Management

### Core Data Structures

**IP Statistics Tracking**:
```cpp
struct IPStats {
    uint32_t ip_address;
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t connection_count;
    uint32_t half_open_connections;
    double entropy_score;
    time_t first_seen;
    time_t last_seen;
    AttackVector detected_attacks;
};
```

**Connection State Tracking**:
```cpp
struct ConnectionState {
    uint64_t flow_id;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    ConnectionPhase phase;
    time_t start_time;
    time_t last_activity;
    uint64_t packets_sent;
    uint64_t bytes_sent;
};
```

**Memory Pool Management**:
```cpp
class MemoryPool {
    void* allocate(size_t size);
    void deallocate(void* ptr);
    void cleanup_expired();
    
private:
    std::vector<MemoryBlock> blocks;
    uint32_t total_allocated;
    uint32_t cleanup_threshold;
};
```

### Performance Optimizations

**Hash Table Sizing**:
- Power-of-2 sizing for optimal performance
- Separate chaining for collision resolution
- Load factor monitoring and automatic resizing

**Memory Management**:
- Custom memory pools for frequent allocations
- LRU eviction for memory pressure handling
- Batch cleanup operations during low traffic

**Lock-Free Operations**:
- Atomic operations for counters
- RCU (Read-Copy-Update) for configuration updates
- Per-thread data structures to minimize contention

## Multi-Threading Architecture

### Thread Model

```
Main Thread (Snort)
│
├── Packet Processing Thread 1
│   ├── Traffic Analysis
│   ├── Behavior Tracking
│   └── Attack Detection
│
├── Packet Processing Thread 2
│   ├── Traffic Analysis
│   ├── Behavior Tracking
│   └── Attack Detection
│
├── Statistics Thread
│   ├── Metrics Calculation
│   ├── Baseline Updates
│   └── Performance Monitoring
│
├── Firewall Thread
│   ├── IP Blocking/Unblocking
│   ├── Rule Management
│   └── Status Monitoring
│
└── Cleanup Thread
    ├── Memory Cleanup
    ├── Expired Connection Removal
    └── Log Rotation
```

### Thread Synchronization

**Lock-Free Counters**:
```cpp
class AtomicCounter {
    std::atomic<uint64_t> value{0};
public:
    void increment() { value.fetch_add(1, std::memory_order_relaxed); }
    uint64_t get() const { return value.load(std::memory_order_acquire); }
};
```

**Thread-Safe Configuration**:
```cpp
class ConfigManager {
    std::shared_ptr<Config> config;
    std::mutex config_mutex;
    
public:
    void updateConfig(std::shared_ptr<Config> new_config) {
        std::lock_guard<std::mutex> lock(config_mutex);
        config = new_config;
    }
};
```

## Integration Architecture

### Snort 3 Integration

**Plugin Interface**:
```cpp
class DDoSInspector : public Inspector {
public:
    bool configure(const Config&) override;
    void eval(Packet*) override;
    void show(const Config&) const override;
    
private:
    TrafficAnalyzer analyzer;
    BehaviorTracker tracker;
    AttackDetector detector;
    FirewallController firewall;
};
```

**Event Handling**:
- Packet inspection callback
- Configuration reload handling
- Statistics export
- Alert generation

### External System Integration

**Monitoring Systems**:
- Prometheus metrics export
- SNMP integration
- Syslog forwarding
- REST API endpoints

**SIEM Integration**:
- CEF (Common Event Format) output
- JSON structured logging
- Real-time event streaming
- Historical data export

## Scalability and Performance

### Horizontal Scaling

**Multi-Instance Deployment**:
```
Load Balancer
│
├── DDoS Inspector Instance 1 (Interface eth0)
├── DDoS Inspector Instance 2 (Interface eth1)
└── DDoS Inspector Instance 3 (Interface eth2)
    │
    └── Shared State Management
        ├── Redis Cluster
        └── Distributed Blocking
```

**State Synchronization**:
- Distributed IP blocking across instances
- Shared attack intelligence
- Coordinated response actions

### Vertical Scaling

**CPU Optimization**:
- SIMD instructions for bulk operations
- Branch prediction optimization
- Cache-friendly data structures
- Minimal system calls

**Memory Optimization**:
- Memory-mapped files for large datasets
- Compression for historical data
- Efficient data structures (packed structs)
- Memory pool reuse

**I/O Optimization**:
- Asynchronous firewall operations
- Batched metric updates
- Zero-copy packet processing
- Ring buffer implementation

## Security Architecture

### Attack Surface Minimization

**Privilege Separation**:
- Snort runs with minimal privileges
- Firewall operations through dedicated service
- Configuration file validation
- Input sanitization

**Resource Protection**:
- Memory usage limits
- CPU usage monitoring
- File descriptor limits
- Rate limiting for operations

### Defense in Depth

**Self-Protection**:
- Protection against algorithmic complexity attacks
- Memory exhaustion protection
- Recursive detection prevention
- Configuration validation

**Audit and Logging**:
- All configuration changes logged
- Attack detection events recorded
- Performance metrics tracked
- Security events forwarded to SIEM

## Monitoring and Observability

### Metrics Architecture

**Real-time Metrics**:
```cpp
class MetricsCollector {
    std::map<std::string, AtomicCounter> counters;
    std::map<std::string, Gauge> gauges;
    std::map<std::string, Histogram> histograms;
    
public:
    void incrementCounter(const std::string& name);
    void setGauge(const std::string& name, double value);
    void recordHistogram(const std::string& name, double value);
};
```

**Metric Categories**:
- **Traffic Metrics**: Packet rates, byte rates, connection counts
- **Detection Metrics**: Attack counts, detection latency, accuracy
- **Performance Metrics**: CPU usage, memory usage, processing rates
- **System Metrics**: Uptime, configuration version, error rates

### Health Checks

**Internal Health Monitoring**:
- Thread health status
- Memory usage monitoring
- Processing queue depths
- Error rate tracking

**External Health Endpoints**:
- HTTP health check endpoint
- Prometheus metrics endpoint
- Status API for monitoring systems

## Configuration Management

### Configuration Architecture

**Hierarchical Configuration**:
```
Global Configuration
├── Detection Parameters
│   ├── Entropy Settings
│   ├── EWMA Parameters
│   └── Threshold Values
├── Performance Settings
│   ├── Thread Configuration
│   ├── Memory Limits
│   └── Batch Sizes
└── Integration Settings
    ├── Firewall Backend
    ├── Monitoring Endpoints
    └── Alert Destinations
```

**Dynamic Reconfiguration**:
- Hot reload without service restart
- Configuration validation before application
- Rollback capability for invalid configurations
- Configuration versioning and history

### Configuration Validation

**Schema Validation**:
```cpp
class ConfigValidator {
public:
    bool validate(const Config& config) const;
    std::vector<std::string> getErrors() const;
    
private:
    bool validateThresholds(const Config& config) const;
    bool validatePerformanceSettings(const Config& config) const;
    bool validateIntegrationSettings(const Config& config) const;
};
```

## Error Handling and Recovery

### Error Classification

**Recoverable Errors**:
- Temporary network failures
- Memory allocation failures
- Configuration parsing errors
- External service unavailability

**Non-Recoverable Errors**:
- Critical system failures
- Security violations
- Data corruption
- Plugin initialization failures

### Recovery Strategies

**Graceful Degradation**:
- Continue operation with reduced functionality
- Switch to backup systems
- Reduce resource usage
- Alert administrators

**Automatic Recovery**:
- Retry failed operations with exponential backoff
- Restart failed threads
- Clear corrupted data structures
- Reload configuration

## Future Architecture Considerations

### Machine Learning Integration

**Planned Enhancements**:
- Deep learning models for attack classification
- Anomaly detection using autoencoders
- Behavioral clustering with unsupervised learning
- Predictive analytics for proactive defense

**Architecture Implications**:
- GPU acceleration support
- Model versioning and deployment
- Training data pipeline
- Real-time inference optimization

### Cloud-Native Architecture

**Kubernetes Integration**:
- Containerized deployment
- Horizontal pod autoscaling
- Service mesh integration
- Cloud provider integration

**Microservices Evolution**:
- Detection service separation
- Mitigation service isolation
- Configuration service
- Monitoring service

---

## Related Documentation

- [Getting Started](../getting-started/) - Initial setup and installation
- [Configuration Guide](../configuration/) - Detailed configuration options
- [Deployment Guide](../deployment/) - Production deployment strategies
- [Development Guide](../development/) - Contributing and customization
- [Performance Tuning](../deployment/performance-tuning.md) - Optimization techniques

---

**Key Takeaways**:
1. Modular architecture enables easy customization and extension
2. Multi-threaded design provides high performance and scalability
3. Pluggable components allow integration with various systems
4. Comprehensive monitoring ensures operational visibility
5. Security-first design minimizes attack surface