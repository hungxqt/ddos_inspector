# Testing Guide

This guide covers all aspects of testing DDoS Inspector, from unit tests to realistic attack simulations and performance validation.

## Test Overview

DDoS Inspector includes comprehensive testing at multiple levels:

- **Unit Tests**: Component-level testing (350+ test cases)
- **Integration Tests**: End-to-end functionality testing
- **Performance Tests**: Latency and throughput validation
- **Attack Simulations**: Realistic DDoS attack testing
- **Stress Tests**: Resource exhaustion and recovery testing

## Running Tests

### Quick Test Suite

```bash
# Run all tests
./scripts/run_tests.sh

# Run specific test categories
./scripts/run_tests.sh --unit        # Unit tests only
./scripts/run_tests.sh --integration # Integration tests only
./scripts/run_tests.sh --performance # Performance tests only
```

### Manual Test Execution

```bash
# Build and run unit tests
cd build
make test

# Run individual test executables
./unit_tests
./test_stats_engine
./test_behavior_tracker
./test_firewall_action
./test_realistic_attacks
```

## Unit Tests

### Statistical Engine Tests

Tests for the core detection algorithms:

```bash
# Test EWMA calculations
./test_stats_engine --gtest_filter="StatsEngine.EWMACalculation"

# Test entropy analysis
./test_stats_engine --gtest_filter="StatsEngine.EntropyAnalysis"

# Test anomaly detection
./test_stats_engine --gtest_filter="StatsEngine.AnomalyDetection"
```

**Key Test Cases**:
- EWMA convergence under different traffic patterns
- Shannon entropy calculation accuracy
- Baseline adaptation over time
- False positive rate validation

### Behavioral Tracker Tests

Tests for attack pattern recognition:

```bash
# Test SYN flood detection
./test_behavior_tracker --gtest_filter="BehaviorTracker.SynFloodDetection"

# Test HTTP flood detection
./test_behavior_tracker --gtest_filter="BehaviorTracker.HttpFloodDetection"

# Test slowloris detection
./test_behavior_tracker --gtest_filter="BehaviorTracker.SlowlorisDetection"
```

**Key Test Cases**:
- Attack pattern classification accuracy
- Behavioral scoring algorithms
- Time-window analysis
- Multi-attack correlation

### Firewall Action Tests

Tests for mitigation mechanisms:

```bash
# Test IP blocking
./test_firewall_action --gtest_filter="FirewallAction.IPBlocking"

# Test rate limiting
./test_firewall_action --gtest_filter="FirewallAction.RateLimiting"

# Test cleanup mechanisms
./test_firewall_action --gtest_filter="FirewallAction.CleanupExpired"
```

**Key Test Cases**:
- nftables integration functionality
- iptables fallback mechanisms
- Block expiration and cleanup
- Rate limiting effectiveness

## Integration Tests

### End-to-End Detection

Tests complete detection pipeline:

```bash
# Test complete SYN flood detection and blocking
./test_realistic_attacks --attack=syn_flood --duration=30

# Test HTTP flood detection
./test_realistic_attacks --attack=http_flood --duration=30

# Test slowloris detection
./test_realistic_attacks --attack=slowloris --duration=30
```

### Configuration Testing

Validate different configuration scenarios:

```bash
# Test high-sensitivity configuration
ENTROPY_THRESHOLD=1.5 ./test_realistic_attacks --attack=all

# Test low-sensitivity configuration
ENTROPY_THRESHOLD=3.0 ./test_realistic_attacks --attack=all

# Test performance-optimized configuration
MAX_TRACKED_IPS=10000 ./test_realistic_attacks --attack=volume
```

## Attack Simulations

### SYN Flood Simulation

Generate realistic SYN flood attacks:

```bash
# Basic SYN flood test
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30

# High-intensity SYN flood
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --rate 10000 --duration 60

# Distributed SYN flood (multiple source IPs)
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --sources 100 --duration 30
```

**Validation**:
```bash
# Check detection logs
grep "SYN_FLOOD" /var/log/snort/alert

# Verify IP blocking
sudo nft list set inet filter ddos_ip_set

# Monitor metrics
watch -n 1 'cat /var/log/ddos_inspector/metrics.log | grep syn_flood'
```

### HTTP Flood Simulation

Generate HTTP-based attacks:

```bash
# Slowloris attack simulation
sudo ./scripts/run_slowloris.sh --target 127.0.0.1 --connections 1000

# HTTP GET flood
sudo ./scripts/run_http_flood.sh --target 127.0.0.1 --rate 1000

# Mixed HTTP attack patterns
sudo ./scripts/run_mixed_http_attack.sh --target 127.0.0.1
```

**Validation**:
```bash
# Check HTTP flood detection
grep "HTTP_FLOOD" /var/log/snort/alert

# Check slowloris detection
grep "SLOWLORIS" /var/log/snort/alert

# Monitor connection states
ss -tuln | grep :80
```

### UDP Flood Simulation

Generate volumetric UDP attacks:

```bash
# Basic UDP flood
sudo ./scripts/run_udp_flood.sh --target 127.0.0.1 --port 53 --rate 5000

# Random port UDP flood
sudo ./scripts/run_udp_flood.sh --target 127.0.0.1 --random-ports --rate 10000

# DNS amplification simulation
sudo ./scripts/run_dns_amplification.sh --target 127.0.0.1
```

### Mixed Attack Scenarios

Simulate realistic multi-vector attacks:

```bash
# Combined SYN and HTTP flood
sudo ./scripts/run_mixed_attack.sh --target 127.0.0.1 --types syn,http

# Distributed multi-vector attack
sudo ./scripts/run_distributed_attack.sh --target 127.0.0.1 --vectors all

# Progressive attack intensity
sudo ./scripts/run_escalating_attack.sh --target 127.0.0.1
```

## Performance Testing

### Latency Testing

Measure detection latency:

```bash
# Measure packet processing latency
./build/test_performance --metric latency --duration 60

# Measure detection response time
./build/test_performance --metric detection_time --attack syn_flood
```

**Expected Results**:
- Packet processing: <1ms average, <5ms P99
- Detection latency: <10ms average, <50ms P99
- Blocking latency: <100ms average

### Throughput Testing

Measure packet processing capacity:

```bash
# Test maximum packet rate
./build/test_performance --metric throughput --packet_size 64

# Test with realistic traffic mix
./build/test_performance --metric throughput --traffic_mix realistic

# Test under attack conditions
./build/test_performance --metric throughput --under_attack
```

**Expected Results**:
- Clean traffic: >1M packets/second
- Under attack: >500K packets/second
- Memory usage: <100MB steady-state

### Resource Usage Testing

Monitor system resource consumption:

```bash
# Memory usage profiling
valgrind --tool=massif ./build/unit_tests

# CPU profiling
perf record -g ./build/test_performance --duration 60
perf report

# Network interface utilization
iftop -i eth0 -t -s 60
```

## Stress Testing

### Memory Exhaustion Testing

Test behavior under memory pressure:

```bash
# Test with limited memory
systemd-run --scope -p MemoryLimit=512M ./build/test_stress_memory

# Test IP tracking limits
./build/test_stress_memory --max_ips 1000000

# Test memory leak detection
valgrind --leak-check=full ./build/unit_tests
```

### CPU Overload Testing

Test performance under CPU stress:

```bash
# Test with CPU limits
systemd-run --scope -p CPUQuota=50% ./build/test_stress_cpu

# Test under high packet rates
./build/test_stress_cpu --packet_rate 10000000

# Test with concurrent attacks
./build/test_stress_cpu --concurrent_attacks 10
```

### Network Saturation Testing

Test behavior under network saturation:

```bash
# Test with interface saturation
./scripts/generate_background_traffic.sh --interface eth0 --rate 1gbps &
./build/test_performance --duration 300

# Test with packet loss
tc qdisc add dev eth0 root netem loss 10%
./build/test_performance --duration 60
tc qdisc del dev eth0 root
```

## Validation Testing

### False Positive Testing

Validate detection accuracy with legitimate traffic:

```bash
# Test with normal web traffic
./scripts/generate_normal_traffic.sh --duration 300 &
./build/test_false_positives --duration 300

# Test with encrypted traffic
./scripts/generate_tls_traffic.sh --duration 300 &
./build/test_false_positives --traffic_type encrypted

# Test with gaming traffic
./scripts/generate_gaming_traffic.sh --duration 300 &
./build/test_false_positives --traffic_type gaming
```

**Acceptance Criteria**:
- False positive rate: <0.1%
- Legitimate traffic blocking: <0.01%

### False Negative Testing

Ensure attacks are properly detected:

```bash
# Test with stealthy attacks
./scripts/run_stealthy_syn_flood.sh --target 127.0.0.1
./build/test_false_negatives --attack_type stealthy_syn

# Test with low-rate attacks
./scripts/run_low_rate_attack.sh --target 127.0.0.1 --rate 10
./build/test_false_negatives --attack_type low_rate

# Test with encrypted attacks
./scripts/run_encrypted_attack.sh --target 127.0.0.1
./build/test_false_negatives --attack_type encrypted
```

## Continuous Integration Testing

### Automated Test Pipeline

```yaml
# .github/workflows/test.yml
name: DDoS Inspector Tests
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: sudo apt-get install -y build-essential cmake libpcap-dev
      - name: Build
        run: |
          mkdir build && cd build
          cmake .. && make -j$(nproc)
      - name: Run unit tests
        run: cd build && make test

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Setup environment
        run: ./scripts/setup_test_environment.sh
      - name: Run integration tests
        run: ./scripts/run_integration_tests.sh

  performance-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Run performance tests
        run: ./scripts/run_performance_tests.sh
      - name: Upload performance results
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: performance_results.json
```

### Test Environment Setup

```bash
#!/bin/bash
# scripts/setup_test_environment.sh

# Install test dependencies
sudo apt-get update
sudo apt-get install -y nftables iptables netcat-openbsd hping3

# Setup test network namespace
sudo ip netns add ddos_test
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns ddos_test
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip netns exec ddos_test ip addr add 192.168.100.2/24 dev veth1
sudo ip link set veth0 up
sudo ip netns exec ddos_test ip link set veth1 up

# Setup firewall rules for testing
sudo nft add table inet test_filter
sudo nft add set inet test_filter ddos_ip_set { type ipv4_addr\; }
```

## Test Data and Benchmarks

### Baseline Performance Metrics

Record baseline performance for regression testing:

```json
{
  "performance_baseline": {
    "packet_processing_rate": 1200000,
    "detection_latency_avg_ms": 2.8,
    "detection_latency_p99_ms": 9.2,
    "memory_usage_mb": 42,
    "cpu_overhead_percent": 3.8,
    "false_positive_rate": 0.0008
  },
  "attack_detection_rates": {
    "syn_flood": 0.998,
    "ack_flood": 0.995,
    "http_flood": 0.992,
    "slowloris": 0.989,
    "udp_flood": 0.996,
    "volumetric": 0.994
  }
}
```

### Test Data Generation

```bash
# Generate test PCAP files
./scripts/generate_test_pcaps.sh --output ./test_data/

# Generate attack patterns
./scripts/generate_attack_patterns.sh --type all --output ./test_data/attacks/

# Generate normal traffic baselines
./scripts/generate_normal_traffic.sh --duration 3600 --output ./test_data/normal/
```

## Troubleshooting Test Issues

### Common Test Failures

```bash
# Check test environment
./scripts/validate_test_environment.sh

# Verify permissions
sudo -l | grep -E "(nft|iptables|tcpdump)"

# Check network interfaces
ip link show | grep -E "(eth0|veth)"

# Verify firewall rules
sudo nft list tables
sudo iptables -L
```

### Debug Test Execution

```bash
# Run tests with debug output
DDOS_DEBUG=1 ./build/unit_tests --gtest_verbose

# Enable detailed logging
LOG_LEVEL=debug ./build/test_realistic_attacks

# Monitor system during tests
htop &
iotop &
./build/test_performance
```

### Test Result Analysis

```bash
# Analyze test results
./scripts/analyze_test_results.sh --input test_results.xml

# Generate performance reports
./scripts/generate_performance_report.sh --baseline baseline.json --current results.json

# Compare with previous runs
./scripts/compare_test_runs.sh --previous previous_results/ --current current_results/
```

---

**Next**: [Monitoring Guide](monitoring.md) →