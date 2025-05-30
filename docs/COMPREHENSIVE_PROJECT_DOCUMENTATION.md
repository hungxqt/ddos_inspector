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

---

## Project Overview

The DDoS Inspector is a sophisticated, real-time DDoS detection and mitigation plugin for Snort 3. It combines statistical analysis, behavioral profiling, and automated firewall integration to detect and block various types of DDoS attacks with minimal system overhead.

### Architecture Philosophy
- **Modular Design**: Separation of concerns with distinct engines for statistics, behavior, and mitigation
- **Performance-First**: <5% CPU usage, <10ms latency under high load
- **Real-time Operation**: Inline processing with immediate response capabilities
- **Extensible Framework**: Plugin-based architecture for easy enhancement

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

## File Manifest Summary

### Core Implementation (8 files)
- `src/ddos_inspector.cpp` (370 lines): Main plugin logic
- `src/stats_engine.cpp` (165 lines): Statistical analysis
- `src/behavior_tracker.cpp` (280 lines): Behavioral detection
- `src/firewall_action.cpp` (120 lines): Mitigation actions
- `include/*.hpp` (4 files): Interface definitions

### Configuration & Build (3 files)
- `CMakeLists.txt`: Build system configuration
- `snort_ddos_config.lua`: Runtime configuration
- `docker-compose.yml`: Service orchestration

### Automation Scripts (8 files)
- Build, deployment, testing, and setup automation
- Attack simulation and validation tools

### Testing Suite (5 files)
- Unit tests, integration tests, realistic attack scenarios
- Performance and stress testing

### Documentation (15+ files)
- Architecture, algorithms, installation guides
- User manuals, troubleshooting, integration guides

### Monitoring & Operations (10+ files)
- Docker deployment, metrics collection
- Grafana dashboards, log analysis tools

**Total Lines of Code**: ~3,500 lines across core components
**Supported Platforms**: Linux (Ubuntu 20.04+, CentOS 8+)
**Dependencies**: Snort 3.1.0+, C++17, CMake 3.10+, nftables/iptables

This comprehensive documentation provides complete technical specifications for every component in the DDoS Inspector project, enabling developers and operators to understand, modify, deploy, and maintain the system effectively.