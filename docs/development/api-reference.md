# API Reference

This document provides comprehensive API documentation for DDoS Inspector's components, configuration options, and extension points.

## Configuration API

### Core Configuration

```lua
-- Main configuration structure
ddos_inspector = {
    -- Detection Parameters
    entropy_threshold = 2.0,        -- Shannon entropy threshold (1.0-4.0)
    ewma_alpha = 0.1,              -- EWMA smoothing factor (0.01-0.5)
    baseline_alpha = 0.01,         -- Baseline adaptation rate (0.001-0.1)
    
    -- Attack Thresholds
    syn_flood_threshold = 500,      -- Half-open connections threshold
    syn_rate_threshold = 200,       -- SYN packets per 10s
    ack_flood_threshold = 40,       -- Orphan ACK packets per 10s
    http_flood_threshold = 200,     -- HTTP requests per minute
    slowloris_threshold = 200,      -- Long connections threshold
    udp_flood_threshold = 500,      -- UDP packets per second
    
    -- Behavioral Analysis
    connection_timeout = 300,       -- Connection tracking timeout (seconds)
    max_tracked_ips = 100000,      -- Maximum IPs to track
    max_tracked_connections = 50000, -- Maximum connections to track
    cleanup_interval = 60,          -- Cleanup interval (seconds)
    
    -- Blocking Configuration
    block_timeout = 600,           -- IP block duration (seconds)
    progressive_blocking = false,   -- Enable progressive blocking
    initial_block_time = 60,       -- Initial block duration
    max_block_time = 3600,         -- Maximum block duration
    
    -- Performance Settings
    allow_icmp = false,            -- Process ICMP packets
    batch_processing = true,       -- Enable batch processing
    batch_size = 100,             -- Packet batch size
    worker_threads = 1,           -- Number of worker threads
    
    -- Output Configuration
    metrics_file = "/tmp/ddos_inspector_stats",
    log_file = "/var/log/snort/ddos_inspector.log",
    alert_mode = "fast",          -- "fast", "full", or "json"
    log_level = "info",           -- "debug", "info", "warn", "error"
    
    -- Monitoring Integration
    metrics_enabled = true,        -- Enable metrics export
    metrics_format = "prometheus", -- "text" or "prometheus"
    metrics_port = 9090,          -- Metrics HTTP port
    
    -- Whitelisting
    whitelist_ips = {},           -- Array of whitelisted IP ranges
    whitelist_domains = {},       -- Array of whitelisted domains
    
    -- Advanced Features
    enable_entropy_analysis = true,
    enable_behavior_tracking = true,
    enable_connection_tracking = true,
    enable_payload_analysis = true,
    enable_geolocation = false,
    enable_reputation_checking = false
}
```

### Protocol-Specific Configuration

```lua
-- TCP-specific settings
tcp_config = {
    syn_timeout = 30,             -- SYN timeout (seconds)
    fin_timeout = 5,              -- FIN timeout (seconds)
    established_timeout = 3600,   -- Established connection timeout
    track_sequence_numbers = true, -- Enable sequence number tracking
    detect_tcp_hijacking = true   -- Enable TCP hijacking detection
}

-- HTTP-specific settings
http_config = {
    max_request_size = 8192,      -- Maximum HTTP request size
    max_header_count = 50,        -- Maximum HTTP headers
    user_agent_analysis = true,   -- Enable User-Agent analysis
    detect_slow_headers = true,   -- Detect slow header attacks
    detect_slow_body = true       -- Detect slow body attacks
}

-- UDP-specific settings
udp_config = {
    track_sessions = true,        -- Enable UDP session tracking
    session_timeout = 60,         -- UDP session timeout
    amplification_ratio = 10,     -- DNS amplification detection ratio
    detect_fragmentation = true   -- Detect fragmentation attacks
}
```

## C++ API Reference

### Core Classes

#### DDosInspector Class

Main plugin class that integrates with Snort 3:

```cpp
class DDosInspector {
public:
    // Constructor/Destructor
    DDosInspector(DDosInspectorConfig* config);
    ~DDosInspector();
    
    // Snort Integration
    void eval(Packet* packet) override;
    void show(const SnortConfig*) override;
    void reset_stats() override;
    
    // Configuration
    bool configure(SnortConfig*) override;
    void set_config(DDosInspectorConfig* config);
    DDosInspectorConfig* get_config() const;
    
    // Statistics
    PegCount* get_counts() const override;
    const PegInfo* get_pegs() const override;
    
private:
    DDosInspectorConfig* config_;
    StatsEngine* stats_engine_;
    BehaviorTracker* behavior_tracker_;
    FirewallAction* firewall_action_;
    std::unique_ptr<MetricsCollector> metrics_;
};
```

#### StatsEngine Class

Statistical analysis and anomaly detection:

```cpp
class StatsEngine {
public:
    // Constructor
    StatsEngine(double entropy_threshold = 2.0, double ewma_alpha = 0.1);
    
    // Statistical Analysis
    double calculate_ewma(double new_value, double old_ewma, double alpha);
    double calculate_shannon_entropy(const std::vector<uint8_t>& data);
    double calculate_baseline_ewma(double current_ewma, double baseline, double alpha);
    
    // Anomaly Detection
    bool detect_anomaly(const TrafficStats& current, const TrafficStats& baseline);
    double calculate_anomaly_score(double current, double baseline);
    AnomalyType classify_anomaly(const TrafficStats& stats);
    
    // Traffic Analysis
    void update_traffic_stats(const PacketData& packet);
    void update_protocol_stats(Protocol protocol, size_t packet_size);
    void update_port_stats(uint16_t port, size_t packet_count);
    
    // Baseline Management
    void learn_baseline(const TrafficStats& stats);
    void reset_baseline();
    TrafficStats get_baseline() const;
    
    // Configuration
    void set_entropy_threshold(double threshold);
    void set_ewma_alpha(double alpha);
    void set_baseline_alpha(double alpha);
    
    // Statistics Export
    std::map<std::string, double> get_statistics() const;
    void export_metrics(MetricsFormat format, std::ostream& output);
    
private:
    double entropy_threshold_;
    double ewma_alpha_;
    double baseline_alpha_;
    TrafficStats current_stats_;
    TrafficStats baseline_stats_;
    std::mutex stats_mutex_;
};
```

#### BehaviorTracker Class

Attack pattern recognition and behavioral analysis:

```cpp
class BehaviorTracker {
public:
    // Constructor
    BehaviorTracker(size_t max_tracked_ips = 100000);
    
    // IP Behavior Tracking
    void update_ip_behavior(const std::string& ip, const PacketData& packet);
    IPBehavior get_ip_behavior(const std::string& ip) const;
    void cleanup_expired_ips(std::chrono::seconds timeout);
    
    // Attack Classification
    AttackType classify_attack(const IPBehavior& behavior);
    double calculate_threat_score(const IPBehavior& behavior);
    AttackSeverity assess_severity(const IPBehavior& behavior);
    
    // Connection Tracking
    void track_connection(const ConnectionKey& key, const PacketData& packet);
    ConnectionState get_connection_state(const ConnectionKey& key) const;
    void cleanup_expired_connections();
    
    // Pattern Analysis
    bool detect_syn_flood(const IPBehavior& behavior);
    bool detect_ack_flood(const IPBehavior& behavior);
    bool detect_http_flood(const IPBehavior& behavior);
    bool detect_slowloris(const IPBehavior& behavior);
    bool detect_udp_flood(const IPBehavior& behavior);
    
    // Statistics
    size_t get_tracked_ip_count() const;
    size_t get_tracked_connection_count() const;
    std::map<AttackType, size_t> get_attack_counts() const;
    
    // Configuration
    void set_max_tracked_ips(size_t max_ips);
    void set_connection_timeout(std::chrono::seconds timeout);
    
private:
    size_t max_tracked_ips_;
    std::chrono::seconds connection_timeout_;
    std::unordered_map<std::string, IPBehavior> ip_behaviors_;
    std::unordered_map<ConnectionKey, ConnectionState> connections_;
    mutable std::shared_mutex behavior_mutex_;
    mutable std::shared_mutex connection_mutex_;
};
```

#### FirewallAction Class

Automated blocking and rate limiting:

```cpp
class FirewallAction {
public:
    // Constructor
    FirewallAction(FirewallType type = FirewallType::NFTABLES);
    
    // IP Blocking
    bool block_ip(const std::string& ip, std::chrono::seconds timeout);
    bool unblock_ip(const std::string& ip);
    bool is_ip_blocked(const std::string& ip) const;
    
    // Rate Limiting
    bool apply_rate_limit(const std::string& ip, size_t rate_limit);
    bool remove_rate_limit(const std::string& ip);
    
    // Bulk Operations
    bool block_ip_range(const std::string& cidr, std::chrono::seconds timeout);
    bool block_multiple_ips(const std::vector<std::string>& ips, std::chrono::seconds timeout);
    
    // Cleanup Operations
    void cleanup_expired_blocks();
    void cleanup_all_blocks();
    size_t get_blocked_ip_count() const;
    
    // Configuration
    void set_firewall_type(FirewallType type);
    void set_default_timeout(std::chrono::seconds timeout);
    void set_max_blocked_ips(size_t max_ips);
    
    // Status and Statistics
    std::vector<std::string> get_blocked_ips() const;
    std::map<std::string, std::chrono::system_clock::time_point> get_block_expiry_times() const;
    FirewallStats get_statistics() const;
    
private:
    FirewallType firewall_type_;
    std::chrono::seconds default_timeout_;
    size_t max_blocked_ips_;
    std::map<std::string, std::chrono::system_clock::time_point> blocked_ips_;
    mutable std::shared_mutex firewall_mutex_;
    
    // Implementation methods
    bool execute_nftables_command(const std::string& command);
    bool execute_iptables_command(const std::string& command);
    std::string generate_nftables_rule(const std::string& ip, bool block);
    std::string generate_iptables_rule(const std::string& ip, bool block);
};
```

### Data Structures

#### PacketData Structure

```cpp
struct PacketData {
    // Basic packet information
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    Protocol protocol;
    size_t packet_size;
    std::chrono::system_clock::time_point timestamp;
    
    // TCP-specific fields
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_flags;
    uint16_t tcp_window;
    
    // Payload information
    std::vector<uint8_t> payload;
    size_t payload_size;
    double payload_entropy;
    
    // Analysis results
    bool is_suspicious;
    double threat_score;
    AttackType detected_attack;
    
    // Helper methods
    bool is_tcp() const;
    bool is_udp() const;
    bool is_icmp() const;
    bool has_tcp_flag(uint8_t flag) const;
    std::string to_string() const;
};
```

#### IPBehavior Structure

```cpp
struct IPBehavior {
    // Connection statistics
    size_t total_connections;
    size_t half_open_connections;
    size_t established_connections;
    size_t failed_connections;
    
    // Traffic statistics
    size_t packets_sent;
    size_t bytes_sent;
    double packets_per_second;
    double bytes_per_second;
    
    // Protocol distribution
    size_t tcp_packets;
    size_t udp_packets;
    size_t icmp_packets;
    size_t other_packets;
    
    // Attack indicators
    size_t syn_count;
    size_t ack_count;
    size_t rst_count;
    size_t fin_count;
    
    // HTTP-specific
    size_t http_requests;
    size_t slow_connections;
    double avg_request_size;
    
    // Timing analysis
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    std::chrono::duration<double> session_duration;
    
    // Behavioral scores
    double anomaly_score;
    double threat_score;
    AttackType primary_attack_type;
    
    // Helper methods
    double get_connection_rate() const;
    double get_failure_rate() const;
    bool is_suspicious() const;
    std::string to_json() const;
};
```

### Enumerations

```cpp
// Attack types
enum class AttackType {
    NONE = 0,
    SYN_FLOOD,
    ACK_FLOOD,
    HTTP_FLOOD,
    SLOWLORIS,
    UDP_FLOOD,
    ICMP_FLOOD,
    VOLUMETRIC,
    MIXED
};

// Attack severity levels
enum class AttackSeverity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Network protocols
enum class Protocol {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    OTHER = 0
};

// Firewall types
enum class FirewallType {
    NFTABLES,
    IPTABLES,
    BOTH
};

// Anomaly types
enum class AnomalyType {
    NONE,
    TRAFFIC_SPIKE,
    ENTROPY_ANOMALY,
    BEHAVIORAL_ANOMALY,
    PROTOCOL_ANOMALY
};
```

## Metrics API

### Exported Metrics

```cpp
// Performance metrics
struct PerformanceMetrics {
    uint64_t packets_processed_total;
    uint64_t packets_per_second;
    double detection_latency_ms;
    uint64_t memory_usage_bytes;
    double cpu_usage_percent;
    uint64_t errors_total;
};

// Security metrics
struct SecurityMetrics {
    uint64_t attacks_detected_total;
    uint64_t ips_blocked_total;
    uint64_t false_positives;
    uint64_t false_negatives;
    std::map<AttackType, uint64_t> attacks_by_type;
    std::map<AttackSeverity, uint64_t> attacks_by_severity;
};

// System metrics
struct SystemMetrics {
    uint64_t connections_tracked;
    uint64_t ips_tracked;
    uint64_t entropy_calculations;
    uint64_t firewall_rules_active;
    uint64_t cleanup_operations;
    std::chrono::system_clock::time_point last_cleanup;
};
```

### Metrics Export Functions

```cpp
class MetricsCollector {
public:
    // Metric recording
    void record_packet_processed();
    void record_attack_detected(AttackType type, AttackSeverity severity);
    void record_ip_blocked(const std::string& ip);
    void record_detection_latency(double latency_ms);
    void record_error(const std::string& error_type);
    
    // Metric retrieval
    PerformanceMetrics get_performance_metrics() const;
    SecurityMetrics get_security_metrics() const;
    SystemMetrics get_system_metrics() const;
    
    // Export functions
    void export_prometheus_metrics(std::ostream& output);
    void export_json_metrics(std::ostream& output);
    void export_text_metrics(std::ostream& output);
    
    // Configuration
    void set_export_interval(std::chrono::seconds interval);
    void enable_histogram_metrics(bool enable);
    
private:
    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> attacks_detected_{0};
    std::map<AttackType, std::atomic<uint64_t>> attack_counters_;
    mutable std::mutex metrics_mutex_;
};
```

## Extension Points

### Custom Attack Detection

```cpp
// Interface for custom attack detectors
class CustomAttackDetector {
public:
    virtual ~CustomAttackDetector() = default;
    
    // Detection interface
    virtual bool detect_attack(const IPBehavior& behavior) = 0;
    virtual AttackType get_attack_type() const = 0;
    virtual std::string get_detector_name() const = 0;
    
    // Configuration
    virtual void configure(const std::map<std::string, std::string>& config) = 0;
    virtual std::map<std::string, std::string> get_configuration() const = 0;
    
    // Statistics
    virtual size_t get_detection_count() const = 0;
    virtual double get_accuracy() const = 0;
};

// Registration function
void register_custom_detector(std::unique_ptr<CustomAttackDetector> detector);
```

### Custom Mitigation Actions

```cpp
// Interface for custom mitigation actions
class CustomMitigationAction {
public:
    virtual ~CustomMitigationAction() = default;
    
    // Action interface
    virtual bool execute_action(const std::string& ip, AttackType attack) = 0;
    virtual bool undo_action(const std::string& ip) = 0;
    virtual std::string get_action_name() const = 0;
    
    // Status checking
    virtual bool is_action_active(const std::string& ip) const = 0;
    virtual std::chrono::system_clock::time_point get_action_expiry(const std::string& ip) const = 0;
    
    // Configuration
    virtual void configure(const std::map<std::string, std::string>& config) = 0;
};

// Registration function
void register_custom_action(std::unique_ptr<CustomMitigationAction> action);
```

## Error Handling

### Exception Classes

```cpp
// Base exception class
class DDosInspectorException : public std::exception {
public:
    explicit DDosInspectorException(const std::string& message);
    const char* what() const noexcept override;
    
private:
    std::string message_;
};

// Configuration errors
class ConfigurationException : public DDosInspectorException {
public:
    ConfigurationException(const std::string& parameter, const std::string& value);
};

// Runtime errors
class RuntimeException : public DDosInspectorException {
public:
    RuntimeException(const std::string& operation, const std::string& details);
};

// Firewall errors
class FirewallException : public DDosInspectorException {
public:
    FirewallException(const std::string& command, int exit_code);
};
```

### Error Codes

```cpp
enum class ErrorCode {
    SUCCESS = 0,
    CONFIGURATION_ERROR = 1,
    RUNTIME_ERROR = 2,
    FIREWALL_ERROR = 3,
    MEMORY_ERROR = 4,
    NETWORK_ERROR = 5,
    PERMISSION_ERROR = 6,
    UNKNOWN_ERROR = 99
};

// Error handling utilities
std::string error_code_to_string(ErrorCode code);
void log_error(ErrorCode code, const std::string& message);
```

## Callback Functions

### Event Callbacks

```cpp
// Callback function types
using AttackDetectedCallback = std::function<void(const std::string& ip, AttackType type, AttackSeverity severity)>;
using IPBlockedCallback = std::function<void(const std::string& ip, std::chrono::seconds timeout)>;
using ThresholdExceededCallback = std::function<void(const std::string& metric, double value, double threshold)>;

// Callback registration
class CallbackManager {
public:
    // Register callbacks
    void register_attack_detected_callback(AttackDetectedCallback callback);
    void register_ip_blocked_callback(IPBlockedCallback callback);
    void register_threshold_exceeded_callback(ThresholdExceededCallback callback);
    
    // Trigger callbacks
    void trigger_attack_detected(const std::string& ip, AttackType type, AttackSeverity severity);
    void trigger_ip_blocked(const std::string& ip, std::chrono::seconds timeout);
    void trigger_threshold_exceeded(const std::string& metric, double value, double threshold);
    
private:
    std::vector<AttackDetectedCallback> attack_callbacks_;
    std::vector<IPBlockedCallback> block_callbacks_;
    std::vector<ThresholdExceededCallback> threshold_callbacks_;
};
```

## Utility Functions

### Network Utilities

```cpp
namespace NetworkUtils {
    // IP address utilities
    bool is_valid_ipv4(const std::string& ip);
    bool is_valid_ipv6(const std::string& ip);
    bool is_private_ip(const std::string& ip);
    bool ip_in_range(const std::string& ip, const std::string& cidr);
    
    // Network analysis
    std::string get_network_address(const std::string& ip, int prefix_length);
    int calculate_prefix_length(const std::string& netmask);
    std::vector<std::string> expand_ip_range(const std::string& start_ip, const std::string& end_ip);
    
    // Protocol utilities
    std::string protocol_to_string(Protocol protocol);
    Protocol string_to_protocol(const std::string& protocol_str);
    bool is_well_known_port(uint16_t port);
    std::string port_to_service_name(uint16_t port);
}
```

### Time Utilities

```cpp
namespace TimeUtils {
    // Time formatting
    std::string format_timestamp(const std::chrono::system_clock::time_point& time);
    std::string format_duration(const std::chrono::duration<double>& duration);
    
    // Rate calculations
    double calculate_rate(uint64_t count, const std::chrono::duration<double>& duration);
    double calculate_average_rate(const std::vector<uint64_t>& counts, 
                                 const std::chrono::duration<double>& window);
    
    // Time window utilities
    bool is_within_time_window(const std::chrono::system_clock::time_point& time,
                              const std::chrono::duration<double>& window);
    std::chrono::system_clock::time_point get_window_start(const std::chrono::duration<double>& window);
}
```

---

**Next**: [Contributing Guide](contributing.md) →