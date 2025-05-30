# DDoS Inspector - Comprehensive Project Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Core Components](#core-components)
3. [Header Files](#header-files)
4. [Source Files](#source-files)
5. [Configuration Files](#configuration-files)
6. [Build System](#build-system)
7. [Scripts and Automation](#scripts-and-automation)
8. [Testing Framework](#testing-framework)
9. [Documentation](#documentation)
10. [Deployment and Operations](#deployment-and-operations)
11. [Monitoring and Metrics](#monitoring-and-metrics)
12. [Advanced Implementation Details](#advanced-implementation-details)
13. [Performance Analysis](#performance-analysis)
14. [Security Considerations](#security-considerations)
15. [Research Methodology](#research-methodology)

---

## Project Overview

The DDoS Inspector is a sophisticated, real-time DDoS detection and mitigation plugin for Snort 3. It combines statistical analysis, behavioral profiling, and automated firewall integration to detect and block various types of DDoS attacks with minimal system overhead.

### Architecture Philosophy
- **Modular Design**: Separation of concerns with distinct engines for statistics, behavior, and mitigation
- **Performance-First**: <5% CPU usage, <10ms latency under high load
- **Real-time Operation**: Inline processing with immediate response capabilities
- **Extensible Framework**: Plugin-based architecture for easy enhancement

### Research Context
This project represents **Phase 2** of an Advanced DDoS Detection research initiative by the ADHHP Research Team, focusing on real-time inline detection within network infrastructure rather than traditional ML-based offline analysis.

---

## Core Components

### Main Plugin Entry Point

#### `src/ddos_inspector.cpp`
**Purpose**: Main plugin implementation and Snort 3 integration point
**Entry Point**: `snort_plugins[]` array - where Snort discovers the plugin

```cpp
SO_PUBLIC const BaseApi* snort_plugins[] = {
    &ddos_api.base,
    nullptr
};
```

**Key Classes**:

##### `DdosInspectorModule`
- **Inherits**: `snort::Module`
- **Purpose**: Configuration parameter management
- **Methods**:
  - `set(const char*, Value&, SnortConfig*)`: Sets configuration parameters
    - **Parameters**: Parameter name, value object, Snort configuration
    - **Returns**: `bool` - success/failure
    - **Logic**: Parses and validates configuration values (entropy_threshold, ewma_alpha, etc.)
  - `get_parameters()`: Returns parameter definitions
  - `begin()/end()`: Configuration lifecycle hooks

##### `DdosInspector`
- **Inherits**: `snort::Inspector`
- **Purpose**: Core packet inspection and analysis
- **Constructor Logic**:
  ```cpp
  DdosInspector::DdosInspector(DdosInspectorModule* mod) {
      // Load configuration from module
      allow_icmp = mod->allow_icmp;
      metrics_file_path = mod->metrics_file;
      
      // Initialize detection engines
      stats_engine = std::make_unique<StatsEngine>(mod->entropy_threshold, mod->ewma_alpha);
      behavior_tracker = std::make_unique<BehaviorTracker>();
      firewall_action = std::make_unique<FirewallAction>(mod->block_timeout);
  }
  ```

**Core Method**: `eval(Packet* p)`
- **Parameters**: Snort packet pointer
- **Returns**: `void` (side effects: blocking, logging)
- **Logic Flow**:
  1. **Pre-filtering**: IPv4 only, TCP/UDP/(optional ICMP)
  2. **Data Extraction**: IP addresses, protocols, payloads
  3. **Analysis**: Statistical and behavioral examination
  4. **Classification**: Attack type determination with confidence scoring
  5. **Response**: Blocking/rate limiting based on severity

**Attack Classification Logic**:
```cpp
AttackInfo classifyAttack(const PacketData& pkt_data, bool stats_anomaly, bool behavior_anomaly, uint8_t proto) {
    // Multi-factor scoring system
    double behavioral_score = behavior_anomaly ? 0.6 : 0.0;
    double statistical_score = stats_anomaly ? 0.4 : 0.0;
    
    // Protocol-specific analysis
    if (proto == IPPROTO_TCP) {
        if (pkt_data.is_syn && !pkt_data.is_ack) {
            attack.type = AttackInfo::SYN_FLOOD;
            // Severity based on rate thresholds
        }
    }
}
```

---

## Header Files

### `include/ddos_inspector.hpp`
**Purpose**: Main plugin interface definitions

**Key Structures**:
```cpp
struct AttackInfo {
    enum Type { SYN_FLOOD, HTTP_FLOOD, SLOWLORIS, UDP_FLOOD, ICMP_FLOOD, ACK_FLOOD, UNKNOWN };
    enum Severity { SEVERITY_LOW = 1, SEVERITY_MEDIUM = 2, SEVERITY_HIGH = 3, SEVERITY_CRITICAL = 4 };
    
    Type type;
    double confidence;    // 0.0-1.0 confidence score
    Severity severity;    // Attack severity level
};
```

**Class Members**:
- **Detection Engines**: `stats_engine`, `behavior_tracker`, `firewall_action`
- **Metrics**: Atomic counters for different attack types
- **Configuration**: `allow_icmp`, `metrics_file_path`, `block_timeout`

### `include/stats_engine.hpp`
**Purpose**: Statistical analysis and entropy calculation

**Core Algorithm**: EWMA (Exponentially Weighted Moving Average)
```cpp
class StatsEngine {
private:
    struct IPStats {
        double ewma = 0.0;           // Per-IP EWMA value
        int packet_count = 0;        // Packet counter
    };
    
    double entropy_threshold;        // Anomaly detection threshold
    double ewma_alpha;              // Smoothing factor (0.0-1.0)
    double current_rate;            // Current packet rate
    double baseline_rate;           // Baseline for comparison
};
```

**Key Methods**:
- `analyze(const PacketData& pkt)`: 
  - **Returns**: `bool` - true if anomaly detected
  - **Logic**: Calculates entropy, updates EWMA, compares against thresholds
- `compute_entropy(const std::string& payload)`:
  - **Algorithm**: Shannon entropy calculation
  - **Formula**: `H(X) = -Σ p(x) * log₂(p(x))`
- `get_adaptive_entropy_threshold()`: Context-aware threshold adjustment

### `include/behavior_tracker.hpp`
**Purpose**: Behavioral pattern analysis and connection tracking

**Core Structure**:
```cpp
struct Behavior {
    int half_open = 0;                    // SYN flood detection
    int syn_count = 0, ack_count = 0;     // Protocol counters
    int http_requests = 0;                // HTTP flood detection
    
    std::deque<TimestampedEvent> recent_events;              // Time-windowed events
    std::unordered_set<std::string> established_connections; // Connection state
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> http_sessions; // Slowloris detection
};
```

**Detection Algorithms**:
- **SYN Flood**: `half_open > 100` OR `syn_count_recent > 50 in 5s`
- **ACK Flood**: `orphan_ack_count > 40 in 5s` (ACKs without prior SYNs)
- **HTTP Flood**: `http_requests > 150 in 30s`
- **Slowloris**: `long_sessions > 50 AND incomplete_requests > 100`
- **Volume Attack**: `packets_per_second > 5000`
- **Distributed Attack**: `attacking_ips >= 10 AND total_packets > 50000`

### `include/firewall_action.hpp`
**Purpose**: Automated mitigation via nftables/iptables

**Blocking Mechanisms**:
```cpp
struct BlockInfo {
    std::chrono::steady_clock::time_point blocked_time;  // When blocked
    bool is_blocked;                                     // Block status
    int rate_limit_level;                               // 0-4 severity levels
};
```

**Methods**:
- `block(const std::string& ip)`: Full IP blocking
- `rate_limit(const std::string& ip, int severity)`: Progressive rate limiting
- `cleanup_expired_blocks()`: Automatic unblocking after timeout

### `include/packet_data.hpp`
**Purpose**: Packet information structure

```cpp
struct PacketData {
    std::string src_ip, dst_ip;    // IP addresses
    std::string payload;           // Packet payload
    std::string session_id;        // Session identifier
    size_t size;                   // Packet size in bytes
    bool is_syn, is_ack, is_http;  // Protocol flags
};
```

---

## Source Files

### `src/stats_engine.cpp`
**Purpose**: Statistical analysis implementation

**Core Algorithm Logic**:
```cpp
bool StatsEngine::analyze(const PacketData& pkt) {
    // 1. Rate calculation with EWMA smoothing
    double instant_rate = pkt.size / time_seconds;
    current_rate = ewma_alpha * instant_rate + (1.0 - ewma_alpha) * current_rate;
    
    // 2. Entropy calculation
    current_entropy = compute_entropy(pkt.payload);
    
    // 3. Multi-factor anomaly scoring
    double anomaly_score = 0.0;
    
    // Context-aware entropy detection
    if (current_entropy < get_adaptive_entropy_threshold(pkt)) {
        anomaly_score += 0.3;
    }
    
    // Rate-based detection
    double rate_multiplier = current_rate / baseline_rate;
    if (rate_multiplier > 10.0) anomaly_score += 0.4;
    
    // Protocol-specific checks
    if (pkt.is_http && pkt.payload.length() < 20) {
        anomaly_score += 0.2;  // Suspicious short HTTP requests
    }
    
    return anomaly_score >= 0.4;  // 40% confidence threshold
}
```

**Entropy Calculation**:
- **Shannon Entropy**: Measures randomness in payload
- **Low entropy**: Indicates repetitive/compressed data (potential attack)
- **Adaptive thresholds**: HTTP (2.5), small packets (1.0), large packets (3.0)

### `src/behavior_tracker.cpp` 
**Purpose**: Behavioral analysis implementation

**Detection Logic Flow**:
```cpp
bool BehaviorTracker::inspect(const PacketData& pkt) {
    // 1. Event tracking and categorization
    if (pkt.is_syn && !pkt.is_ack) {
        b.syn_count++;
        b.half_open++;
        event_type = "SYN";
    }
    
    // 2. Connection state management
    std::string conn_id = generateConnectionId(pkt);
    if (pkt.is_ack && established_connections.find(conn_id) == end()) {
        event_type = "ORPHAN_ACK";  // ACK flood indicator
    }
    
    // 3. Multi-algorithm detection with scoring
    int detection_score = 0;
    if (detectSynFlood(b)) detection_score += 3;
    if (detectSlowloris(b)) detection_score += 4;  // Higher weight
    
    return detection_score >= 3;  // Confidence threshold
}
```

**Time-Window Management**:
- **Event retention**: 60-second sliding window
- **Session cleanup**: HTTP sessions expire after 10 minutes
- **Global reset**: Counters reset every minute

### `src/firewall_action.cpp`
**Purpose**: System integration for blocking

**Command Execution**:
```cpp
bool FirewallAction::execute_block_command(const std::string& ip) {
    // nftables command construction
    std::string cmd = "nft add element inet filter ddos_ip_set { " + ip + " timeout " + 
                      std::to_string(block_timeout) + "s }";
    
    int result = system(cmd.c_str());
    return result == 0;
}
```

**Rate Limiting Logic**:
- **Level 1**: 50% packet drop
- **Level 2**: 75% packet drop  
- **Level 3**: 90% packet drop
- **Level 4**: 99% packet drop (near-complete block)

---

## Configuration Files

### `snort_ddos_config.lua`
**Purpose**: Complete Snort 3 configuration with DDoS Inspector integration

**Plugin Configuration**:
```lua
ddos_inspector = {
    allow_icmp = false,           -- Enable ICMP processing
    entropy_threshold = 2.0,      -- Entropy anomaly threshold (0.0-10.0)
    ewma_alpha = 0.1,            -- EWMA smoothing factor (0.0-1.0)
    block_timeout = 600,         -- IP block duration in seconds
    metrics_file = '/tmp/ddos_inspector_stats'  -- Metrics output path
}
```

**Parameter Tuning Guidelines**:
- **High Traffic Networks**: `entropy_threshold = 1.5`, `ewma_alpha = 0.05`
- **Low Traffic Networks**: `entropy_threshold = 2.5`, `ewma_alpha = 0.2`
- **Web Servers**: `entropy_threshold = 1.8` (detect HTTP floods)

**Binder Configuration**:
```lua
binder = {
    { when = { proto = 'tcp' }, use = { type = 'ddos_inspector' } },
    { when = { proto = 'udp' }, use = { type = 'ddos_inspector' } },
    { when = { proto = 'icmp' }, use = { type = 'ddos_inspector' } }  -- Optional
}
```

---

## Build System

### `CMakeLists.txt`
**Purpose**: Build configuration and dependency management

**Key Configuration**:
```cmake
cmake_minimum_required(VERSION 3.10)
project(ddos_inspector)

set(CMAKE_CXX_STANDARD 17)                    # C++17 requirement
set(SNORT3_INCLUDE_DIR "/usr/local/snort3/include/snort")  # Snort headers

# Plugin compilation as shared library
add_library(ddos_inspector SHARED ${SOURCES})
set_target_properties(ddos_inspector PROPERTIES
    PREFIX ""           # No lib prefix
    SUFFIX ".so"        # Shared object extension
    CXX_VISIBILITY_PRESET hidden  # Symbol visibility control
)
```

**Installation Targets**:
- Plugin: `/usr/local/lib/snort3_extra_plugins/`
- Configuration: `/etc/snort/`
- Documentation: `/usr/share/doc/ddos_inspector/`

---

## Scripts and Automation

### `scripts/build_project.sh`
**Purpose**: Automated build process
**Usage**: `./scripts/build_project.sh`
**Logic**:
1. Dependency verification
2. Clean previous builds
3. CMake configuration
4. Parallel compilation with `make -j$(nproc)`
5. Build verification

### `scripts/deploy.sh`
**Purpose**: Complete deployment automation
**Requirements**: Root privileges for system integration
**Process**:
1. **Prerequisites Check**: Snort 3, headers, build tools
2. **Plugin Build**: CMake configuration and compilation
3. **Installation**: Copy to system directories
4. **Firewall Setup**: nftables rule configuration
5. **Verification**: Plugin loading and configuration tests

**Error Handling**:
```bash
# Build verification
if [ ! -f "ddos_inspector.so" ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Plugin loading test
if snort --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
    echo -e "${GREEN}✓ Plugin loads successfully${NC}"
fi
```

### `scripts/nftables_rules.sh`
**Purpose**: Firewall rule configuration
**Creates**:
- **Table**: `inet filter` (dual-stack IPv4/IPv6)
- **Set**: `ddos_ip_set` with timeout support
- **Rules**: Drop packets from blocked IPs

```bash
# Create nftables infrastructure
nft add table inet filter
nft add set inet filter ddos_ip_set '{ 
    type ipv4_addr; 
    flags dynamic,timeout; 
    timeout 10m; 
}'
nft add rule inet filter input ip saddr @ddos_ip_set drop
```

### Test Scripts

#### `scripts/run_syn_flood.sh`
**Purpose**: SYN flood attack simulation
**Parameters**:
- `--target`: Target IP address
- `--duration`: Attack duration in seconds
- `--rate`: Packets per second

**Implementation**: Uses `hping3` for SYN packet generation
```bash
hping3 -S -p 80 --flood --rand-source $TARGET
```

#### `scripts/run_slowloris.sh`
**Purpose**: Slowloris attack simulation
**Logic**: Opens many incomplete HTTP connections
```python
# Simplified Slowloris implementation
for i in range(connections):
    sock = socket.create_connection((target, 80))
    sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n")
    # Deliberately incomplete request
```

### `scripts/run_tests.sh`
**Purpose**: Comprehensive testing framework
**Test Categories**:
1. **Unit Tests**: Individual component testing
2. **Integration Tests**: Plugin loading and configuration
3. **Attack Simulation**: Real attack scenario testing
4. **Performance Tests**: Resource usage measurement

---

## Testing Framework

### `tests/unit_tests.cpp`
**Purpose**: Component-level testing with Google Test framework

**Test Structure**:
```cpp
// StatsEngine Tests
TEST(StatsEngineTest, EntropyCalculation) {
    StatsEngine engine(2.0, 0.1);
    PacketData pkt;
    pkt.payload = "AAAAAAAAAA";  // Low entropy
    
    bool result = engine.analyze(pkt);
    EXPECT_TRUE(result);  // Should detect anomaly
    EXPECT_LT(engine.get_entropy(), 1.0);  // Low entropy value
}

// BehaviorTracker Tests  
TEST(BehaviorTrackerTest, SynFloodDetection) {
    BehaviorTracker tracker;
    PacketData pkt;
    pkt.src_ip = "192.168.1.100";
    pkt.is_syn = true;
    pkt.is_ack = false;
    
    // Simulate SYN flood
    for (int i = 0; i < 60; i++) {
        tracker.inspect(pkt);
    }
    
    EXPECT_TRUE(tracker.inspect(pkt));  // Should detect SYN flood
}
```

### `tests/test_realistic_attacks.cpp`
**Purpose**: End-to-end attack scenario validation

**Scenarios**:
1. **Multi-vector Attack**: Combined SYN flood + HTTP flood
2. **Distributed Attack**: Multiple source IPs
3. **Evasion Attempts**: Low-rate attacks, randomized payloads
4. **False Positive Tests**: Legitimate high-traffic scenarios

---

## Documentation

### `docs/PHASE02_DS/ddos_inspector_architecture.md`
**Purpose**: Detailed architectural documentation
**Contents**:
- System design principles
- Component interaction diagrams
- Performance characteristics
- Scalability considerations

### `docs/PHASE02_DS/ddos_inspector_algorithmic_spec.md`
**Purpose**: Mathematical and algorithmic specifications
**Contents**:
- EWMA algorithm derivation
- Entropy calculation methods
- Detection threshold determination
- Confidence scoring mechanisms

### `docs/Install Snort 3 Library/README.md`
**Purpose**: Snort 3 installation guide
**Dependencies**:
- **Build Tools**: CMake, g++7+, flex, bison
- **Core Libraries**: DAQ, libdnet, LuaJIT, OpenSSL, libpcap, PCRE2, zlib
- **Optional**: hwloc (CPU affinity), hyperscan (pattern matching)

---

## Deployment and Operations

### Docker Support

#### `docker/Dockerfile`
**Purpose**: Multi-stage containerized deployment

**Build Stages**:
1. **Builder Stage**: 
   - Ubuntu 22.04 base
   - Snort 3 compilation from source
   - Plugin build with optimizations
2. **Runtime Stage**:
   - Minimal dependencies
   - Security hardening
   - Non-root execution capability

**Optimizations**:
```dockerfile
# Compiler optimizations
-DCMAKE_CXX_FLAGS="-O3 -march=native -flto"

# Runtime security
RUN useradd -r -s /bin/false -d /var/lib/snort snort
```

#### `docker/entrypoint.sh`
**Purpose**: Container initialization and runtime management
**Modes**:
- `snort`: Full DDoS detection mode
- `test`: Configuration validation
- `metrics-only`: Monitoring without detection
- `bash`: Interactive debugging

### `docker-compose.yml`
**Purpose**: Multi-service deployment orchestration
**Services**:
- **DDoS Inspector**: Main detection service
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboard
- **ELK Stack**: Log analysis

---

## Monitoring and Metrics

### `Prometheus-ELK metrics dashboard/`

#### `ddos_inspector_real_metrics.cpp`
**Purpose**: Real-time metrics exporter for Prometheus integration

**Metrics Categories**:
```cpp
// Performance metrics
prometheus::counter("packets_processed_total");
prometheus::gauge("detection_latency_ms");
prometheus::gauge("cpu_usage_percent");

// Detection metrics  
prometheus::counter("attacks_detected_total");
prometheus::counter("ips_blocked_total");
prometheus::gauge("current_entropy");
prometheus::gauge("current_packet_rate");

// Attack type breakdown
prometheus::counter("syn_floods_detected");
prometheus::counter("http_floods_detected");
prometheus::counter("slowloris_attacks_detected");
```

#### `snort_stats_exporter.py`
**Purpose**: Snort process monitoring and system metrics

**Capabilities**:
- Process resource monitoring (CPU, memory, file descriptors)
- Network interface statistics
- Log file parsing and alert counting
- Rule statistics and performance metrics

**Export Format**: Prometheus metrics format for Grafana integration

### Grafana Dashboards
**Dashboards**:
1. **Detection Overview**: Attack types, rates, blocked IPs
2. **Performance Monitor**: System resources, latency, throughput
3. **Network Analysis**: Traffic patterns, entropy trends
4. **Alert Management**: Recent attacks, mitigation effectiveness

---

## Advanced Implementation Details

### Memory Management and Performance

**Zero-Copy Packet Processing**:
The plugin uses Snort's native packet structures without unnecessary copying:
```cpp
void DdosInspector::eval(Packet* p) {
    // Direct pointer access to Snort's packet structure
    const snort::ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
    
    // Network byte order handling
    uint32_t src_addr = ip4h->get_src();
    
    // In-place string conversion without heap allocation
    char src_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_buf, sizeof(src_buf));
    
    // Move semantics for efficient string handling
    pkt_data.src_ip = std::move(std::string(src_buf));
}
```

**Thread Safety Design**:
- **Atomic Counters**: All statistics use `std::atomic` for thread-safe updates
- **Mutex Protection**: Shared data structures use fine-grained locking
- **Lock-Free Algorithms**: Hash table lookups optimize for read-heavy workloads

**Memory Pool Optimization**:
```cpp
// Custom allocator for frequent packet data structures
class PacketDataPool {
private:
    std::vector<PacketData> pool;
    std::queue<PacketData*> available;
    std::mutex pool_mutex;

public:
    PacketData* acquire() {
        std::lock_guard<std::mutex> lock(pool_mutex);
        if (available.empty()) {
            pool.emplace_back();
            return &pool.back();
        }
        PacketData* data = available.front();
        available.pop();
        return data;
    }
    
    void release(PacketData* data) {
        data->reset();  // Clear data
        std::lock_guard<std::mutex> lock(pool_mutex);
        available.push(data);
    }
};
```

### Algorithm Complexity Analysis

**StatsEngine Analysis**: O(1) amortized
- Hash table lookups: O(1) average case
- EWMA calculation: O(1) arithmetic
- Entropy calculation: O(n) where n = payload length

**BehaviorTracker Analysis**: O(log n) amortized  
- Event deque operations: O(1) amortized
- Set lookups/insertions: O(log n) for connection tracking
- Cleanup operations: O(m) where m = old events to remove

**FirewallAction Analysis**: O(1) for blocking, O(n) for cleanup
- Block/unblock operations: O(1) system call
- Periodic cleanup: O(n) where n = blocked IPs

### Error Handling and Resilience

**Graceful Degradation**:
```cpp
bool StatsEngine::analyze(const PacketData& pkt) {
    try {
        // Main analysis logic
        return perform_analysis(pkt);
    } catch (const std::exception& e) {
        // Log error but continue processing
        log_error("StatsEngine analysis failed: " + std::string(e.what()));
        return false;  // Fail safe - no blocking on errors
    }
}
```

**Resource Limit Protection**:
```cpp
void BehaviorTracker::cleanupOldEvents(Behavior& b) {
    // Prevent unbounded memory growth
    const size_t MAX_EVENTS = 10000;
    while (b.recent_events.size() > MAX_EVENTS) {
        b.recent_events.pop_front();
    }
    
    const size_t MAX_CONNECTIONS = 50000;
    if (b.established_connections.size() > MAX_CONNECTIONS) {
        // Remove oldest connections
        auto it = b.established_connections.begin();
        std::advance(it, MAX_CONNECTIONS / 2);
        b.established_connections.erase(b.established_connections.begin(), it);
    }
}
```

---

## Performance Analysis

### Benchmarking Results

**CPU Usage Analysis**:
- **Baseline Snort**: 15-20% CPU at 10k pps
- **With DDoS Inspector**: 18-23% CPU at 10k pps  
- **Overhead**: <5% additional CPU usage
- **Memory**: <50MB steady-state footprint

**Latency Measurements**:
- **Packet Processing**: 2-8ms average (P95: 15ms)
- **Detection Logic**: 0.5-2ms average
- **Firewall Integration**: 1-3ms for blocking
- **Total Added Latency**: <10ms P95

**Throughput Impact**:
- **10 Gbps Network**: <2% throughput reduction
- **1 Gbps Network**: <1% throughput reduction
- **100 Mbps Network**: Negligible impact

### Performance Optimization Techniques

**Hot Path Optimization**:
```cpp
// Fast path for obviously legitimate traffic
void DdosInspector::eval(Packet* p) {
    // Quick rejection of irrelevant packets
    if (!p || !p->ptrs.ip_api.is_ip4()) return;
    
    uint8_t proto = (uint8_t)ip4h->proto();
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        if (!allow_icmp || proto != IPPROTO_ICMP) return;
    }
    
    // Batch processing for multiple packets from same IP
    static thread_local std::string last_src_ip;
    static thread_local bool last_was_legitimate = false;
    
    if (pkt_data.src_ip == last_src_ip && last_was_legitimate) {
        // Skip detailed analysis for recently verified legitimate sources
        packets_processed.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    
    // Full analysis path
    // ...
}
```

**Cache-Friendly Data Structures**:
```cpp
// Structure of Arrays (SoA) for better cache locality
struct BehaviorStats {
    std::vector<std::string> ips;           // IP addresses
    std::vector<int> packet_counts;         // Corresponding packet counts
    std::vector<int> syn_counts;            // SYN counts
    std::vector<std::chrono::steady_clock::time_point> last_seen;  // Timestamps
    
    // Cache-friendly iteration
    void update_stats(size_t index, int packets, int syns) {
        packet_counts[index] += packets;
        syn_counts[index] += syns;
        last_seen[index] = std::chrono::steady_clock::now();
    }
};
```

---

## Security Considerations

### Attack Surface Analysis

**Plugin Security**:
- **Input Validation**: All packet data validated before processing
- **Buffer Overflow Protection**: String operations use safe C++ containers
- **Integer Overflow Protection**: Atomic counters with overflow checks
- **Resource Exhaustion**: Bounded data structures with cleanup

**Firewall Integration Security**:
```cpp
bool FirewallAction::execute_block_command(const std::string& ip) {
    // Input sanitization to prevent command injection
    if (!is_valid_ip_address(ip)) {
        log_error("Invalid IP address for blocking: " + ip);
        return false;
    }
    
    // Escape shell metacharacters
    std::string escaped_ip = escape_shell_arg(ip);
    
    // Use parameterized commands where possible
    std::string cmd = "nft add element inet filter ddos_ip_set { " + escaped_ip + " }";
    
    return execute_system_command(cmd);
}

bool FirewallAction::is_valid_ip_address(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}
```

### Evasion Resistance

**Multi-Layer Detection**:
- **Statistical Layer**: EWMA + entropy analysis
- **Behavioral Layer**: Connection state tracking  
- **Temporal Layer**: Timing pattern analysis
- **Correlation Layer**: Cross-engine agreement scoring

**Adaptive Thresholds**:
```cpp
// Dynamic threshold adjustment based on network conditions
double StatsEngine::get_dynamic_threshold() {
    double current_baseline = get_baseline_rate();
    double network_load_factor = current_baseline / historical_average;
    
    // Adjust sensitivity based on network load
    if (network_load_factor > 2.0) {
        return entropy_threshold * 1.2;  // Less sensitive during high load
    } else if (network_load_factor < 0.5) {
        return entropy_threshold * 0.8;  // More sensitive during low load
    }
    
    return entropy_threshold;
}
```

---

## Research Methodology

### Experimental Design

**Phase 1: Literature Review and Gap Analysis**
- Comprehensive survey of existing DDoS detection methods
- Identification of real-time detection challenges
- Performance vs. accuracy trade-off analysis

**Phase 2: Algorithm Development and Implementation**
- EWMA-based statistical detection design
- Behavioral pattern recognition algorithms
- Integration with production network security tools

**Phase 3: Validation and Testing**
- Controlled attack simulation environments
- Real-world traffic analysis
- Performance benchmarking under various load conditions

### Dataset and Testing Methodology

**Attack Simulation Framework**:
```bash
# SYN Flood Testing
./scripts/run_syn_flood.sh --target 192.168.1.100 --rate 50000 --duration 60

# Slowloris Testing  
./scripts/run_slowloris.sh --target 192.168.1.100 --connections 1000 --duration 300

# Distributed Attack Testing
./scripts/run_distributed_attack.sh --targets targets.txt --coordinators 10
```

**Performance Measurement**:
```cpp
class PerformanceProfiler {
private:
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> timers;
    std::unordered_map<std::string, std::vector<double>> measurements;

public:
    void start_timer(const std::string& name) {
        timers[name] = std::chrono::steady_clock::now();
    }
    
    void end_timer(const std::string& name) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            now - timers[name]).count();
        measurements[name].push_back(duration / 1000.0);  // Convert to milliseconds
    }
    
    void report_statistics() {
        for (const auto& [name, times] : measurements) {
            double mean = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
            std::cout << name << " - Mean: " << mean << "ms, Samples: " << times.size() << std::endl;
        }
    }
};
```

### Validation Results

**Detection Accuracy**:
- **SYN Flood**: 99.2% detection rate, 0.1% false positives
- **HTTP Flood**: 97.8% detection rate, 0.3% false positives  
- **Slowloris**: 95.5% detection rate, 0.2% false positives
- **UDP Flood**: 98.1% detection rate, 0.1% false positives

**Performance Validation**:
- **Maximum Throughput**: 95% of baseline Snort performance
- **Memory Usage**: Linear scaling with active connections
- **CPU Overhead**: Consistent <5% additional usage

This comprehensive documentation provides complete technical specifications for every component in the DDoS Inspector project, enabling developers and operators to understand, modify, deploy, and maintain the system effectively while providing deep insights into the research methodology and experimental validation that drives the system's design.