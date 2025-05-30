# Test Running Guide - DDoS Inspector

## Overview
This guide covers all aspects of running tests for the DDoS Inspector project, including unit tests, integration tests, performance tests, and specialized attack simulation tests.

## Test Structure

The project includes the following test files:
- `tests/unit_tests.cpp` - Basic unit tests for all components
- `tests/test_stats_engine.cpp` - Detailed StatsEngine testing
- `tests/test_behavior_tracker.cpp` - Comprehensive BehaviorTracker testing
- `tests/test_firewall_action.cpp` - FirewallAction functionality testing
- `tests/test_realistic_attacks.cpp` - Real-world attack simulation

## Quick Start

### Run All Tests
```bash
# Method 1: Using the test script (recommended)
./scripts/run_tests.sh

# Method 2: Using CMake/CTest directly
cd build && ctest --output-on-failure

# Method 3: Using make
cd build && make test
```

### Run Specific Test Suites
```bash
cd build

# Run individual test executables
./unit_tests                    # Basic unit tests
./test_stats_engine            # StatsEngine detailed tests
./test_behavior_tracker        # BehaviorTracker detailed tests
./test_firewall_action         # FirewallAction detailed tests
```

## Detailed Test Execution

### 1. Unit Tests (`unit_tests`)

**Purpose:** Basic functionality tests for all components

**Coverage:**
- StatsEngine initialization and basic operations
- BehaviorTracker SYN flood, HTTP flood detection
- FirewallAction IP blocking/unblocking
- Integration test scenarios

**Run Commands:**
```bash
# Run all unit tests
cd build && ./unit_tests

# Run with verbose output
cd build && ./unit_tests --gtest_output=verbose

# Run specific test cases
cd build && ./unit_tests --gtest_filter="StatsEngineTest.*"
cd build && ./unit_tests --gtest_filter="BehaviorTrackerTest.*"
cd build && ./unit_tests --gtest_filter="FirewallActionTest.*"
```

### 2. StatsEngine Tests (`test_stats_engine`)

**Purpose:** Comprehensive testing of statistical analysis and anomaly detection

**Test Coverage:**
- EWMA (Exponentially Weighted Moving Average) calculations
- Entropy calculation accuracy
- Different threshold behaviors
- Performance under load (1000+ packets)
- Edge case payload handling
- Multiple source IP tracking

**Run Commands:**
```bash
# Run all StatsEngine tests
cd build && ./test_stats_engine

# Run with detailed output
cd build && ./test_stats_engine --gtest_output=verbose

# Run specific tests
cd build && ./test_stats_engine --gtest_filter="*EWMA*"
cd build && ./test_stats_engine --gtest_filter="*Performance*"
```

### 3. BehaviorTracker Tests (`test_behavior_tracker`)

**Purpose:** Detailed testing of attack pattern detection algorithms

**Test Coverage:**
- **SYN Flood Detection:** Tests threshold of 100+ half-open connections and 50+ SYNs in 5 seconds
- **HTTP Flood Detection:** Tests threshold of 150+ HTTP requests
- **ACK Flood Detection:** Tests threshold of 40+ orphan ACKs
- **Slowloris Detection:** Tests incomplete HTTP requests and long sessions
- **Volume Attack Detection:** Tests 5000+ packets per second
- **Distributed Attack Detection:** Tests coordinated attacks from multiple IPs

**Run Commands:**
```bash
# Run all BehaviorTracker tests
cd build && ./test_behavior_tracker

# Run specific attack detection tests
cd build && ./test_behavior_tracker --gtest_filter="*SynFlood*"
cd build && ./test_behavior_tracker --gtest_filter="*HttpFlood*"
cd build && ./test_behavior_tracker --gtest_filter="*Slowloris*"
cd build && ./test_behavior_tracker --gtest_filter="*DistributedAttack*"
```

**Detection Thresholds Tested:**
- SYN Flood: 100+ half-open connections OR 50+ SYNs in 5 seconds
- HTTP Flood: 150+ HTTP requests
- ACK Flood: 40+ orphan ACKs
- Volume Attack: 5000+ packets per second
- Slowloris: 100+ incomplete requests AND 50+ long sessions

### 4. FirewallAction Tests (`test_firewall_action`)

**Purpose:** Testing IP blocking/unblocking functionality and timeout management

**Test Coverage:**
- Basic block/unblock functionality
- Duplicate blocking prevention
- Multiple IP management
- Timeout-based expiration (5-second and 5-minute timeouts tested)
- Concurrent access handling
- High volume blocking (1000+ IPs)
- Invalid IP handling
- IPv6 address support

**Run Commands:**
```bash
# Run all FirewallAction tests
cd build && ./test_firewall_action

# Run timeout-related tests
cd build && ./test_firewall_action --gtest_filter="*Timeout*"

# Run performance tests
cd build && ./test_firewall_action --gtest_filter="*HighVolume*"
cd build && ./test_firewall_action --gtest_filter="*Concurrent*"
```

## Advanced Test Execution

### Parallel Test Execution
```bash
# Run tests in parallel (faster execution)
cd build && ctest -j$(nproc)

# Run with maximum parallelism
cd build && ctest --parallel $(nproc)
```

### Verbose Output and Debugging
```bash
# Maximum verbosity
cd build && ctest --verbose --output-on-failure

# Debug specific test failures
cd build && ./unit_tests --gtest_output=xml:test_results.xml

# Run tests with memory checking (if valgrind is available)
cd build && valgrind --tool=memcheck ./unit_tests
```

### Performance Testing
```bash
# Test with timing information
cd build && time ./test_stats_engine
cd build && time ./test_behavior_tracker

# Run performance-specific tests
cd build && ./test_stats_engine --gtest_filter="*Performance*"
cd build && ./test_firewall_action --gtest_filter="*HighVolume*"
```

## Test Categories and Expected Results

### 1. Functional Tests
**Expected:** All basic functionality should pass
- Component initialization
- Basic operations (block/unblock, analyze packets)
- Normal traffic handling

### 2. Threshold Tests
**Expected:** Precise detection at configured thresholds
- SYN flood at exactly 101 half-open connections
- HTTP flood at exactly 151 requests
- ACK flood at exactly 41 orphan ACKs

### 3. Performance Tests
**Expected:** 
- Process 1000 packets in <100ms
- Handle 1000 IP blocks in <1 second
- Maintain accuracy under load

### 4. Integration Tests
**Expected:** Components work together correctly
- Stats engine detects anomalies → Behavior tracker confirms → Firewall blocks IP
- Multiple detection engines can trigger blocking
- Blocked IPs are properly managed

## Attack Simulation Tests

### Real Attack Testing Scripts
```bash
# Test SYN flood detection (requires sudo)
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 10

# Test Slowloris detection (requires sudo)
sudo ./scripts/run_slowloris.sh --target 127.0.0.1 --duration 10

# Monitor blocked IPs during tests
sudo nft list set inet filter ddos_ip_set
```

### Manual Attack Simulation
```bash
# Generate test traffic using hping3 (if available)
sudo hping3 -S -p 80 --flood 127.0.0.1

# Generate HTTP flood using curl
for i in {1..200}; do curl -s http://127.0.0.1/ > /dev/null & done
```

## Continuous Integration Testing

### Build and Test Script
```bash
#!/bin/bash
# Complete CI/CD test pipeline

echo "🧹 Cleaning previous build..."
rm -rf build/
mkdir build && cd build

echo "🔧 Configuring project..."
cmake .. -DCMAKE_BUILD_TYPE=Debug

echo "🏗️ Building project..."
make -j$(nproc)

echo "🧪 Running all tests..."
ctest --output-on-failure --parallel $(nproc)

echo "📊 Generating test report..."
ctest --output-junit test_results.xml

echo "✅ CI/CD pipeline completed successfully!"
```

## Troubleshooting Test Issues

### Common Test Failures

#### 1. Timing-Related Failures
**Symptoms:** Tests fail intermittently, especially timeout-based tests
```bash
# Solution: Run tests with longer timeouts
cd build && ./test_firewall_action --gtest_filter="*Timeout*" --gtest_repeat=5
```

#### 2. Permission Errors
**Symptoms:** Firewall tests fail with permission denied
```bash
# Solution: Ensure proper permissions or run in test mode
export TESTING=1
cd build && ./test_firewall_action
```

#### 3. Memory Issues
**Symptoms:** Tests crash or show memory errors
```bash
# Debug with valgrind
cd build && valgrind --leak-check=full ./unit_tests

# Or run with address sanitizer
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address"
make && ./unit_tests
```

#### 4. Build Issues
**Symptoms:** Tests don't compile or link
```bash
# Clean rebuild
rm -rf build && mkdir build && cd build
cmake .. && make -j$(nproc)

# Check for missing dependencies
ldd ./unit_tests
```

### Test Environment Setup
```bash
# Ensure test environment is clean
sudo pkill -f ddos_inspector
sudo nft flush set inet filter ddos_ip_set 2>/dev/null || true

# Set up test-specific environment variables
export TESTING=1
export GTEST_COLOR=1
export GTEST_OUTPUT=xml:test_results.xml
```

## Performance Benchmarks

### Expected Performance Metrics
- **Unit Tests:** Complete in <5 seconds
- **StatsEngine Tests:** Complete in <3 seconds
- **BehaviorTracker Tests:** Complete in <10 seconds
- **FirewallAction Tests:** Complete in <15 seconds (includes sleep timeouts)
- **Total Test Suite:** Complete in <30 seconds

### Performance Monitoring
```bash
# Monitor test execution time
cd build && time ctest

# Profile specific test performance
cd build && perf record ./test_stats_engine
perf report

# Memory usage monitoring
cd build && /usr/bin/time -v ./unit_tests
```

## Test Coverage Analysis

### Generating Coverage Reports
```bash
# Build with coverage flags
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage"
make

# Run tests
ctest

# Generate coverage report
gcov src/*.cpp
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

### Expected Coverage
- **StatsEngine:** >95% line coverage
- **BehaviorTracker:** >90% line coverage  
- **FirewallAction:** >85% line coverage
- **Overall Project:** >90% line coverage

## Integration with IDE

### VS Code Integration
```json
// .vscode/tasks.json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Run All Tests",
            "type": "shell",
            "command": "./scripts/run_tests.sh",
            "group": "test",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            }
        }
    ]
}
```

### CLion Integration
Tests are automatically discovered and can be run individually from the IDE test runner.

## Automated Testing

### Git Hooks Setup
```bash
# Pre-commit hook to run tests
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
echo "Running tests before commit..."
./scripts/run_tests.sh
if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi
EOF

chmod +x .git/hooks/pre-commit
```

### Continuous Integration
```yaml
# .github/workflows/test.yml
name: Run Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y cmake build-essential
      - name: Build and test
        run: |
          mkdir build && cd build
          cmake .. && make -j$(nproc)
          ctest --output-on-failure
```

## Best Practices

### 1. Before Committing Code
```bash
# Always run the full test suite
./scripts/run_tests.sh

# Run specific tests for modified components
cd build && ./test_behavior_tracker  # if you modified behavior_tracker.cpp
```

### 2. When Adding New Features
```bash
# Run existing tests to ensure no regression
./scripts/run_tests.sh

# Add appropriate tests for new functionality
# Run new tests to verify they work
cd build && ./unit_tests --gtest_filter="*YourNewTest*"
```

### 3. When Debugging Issues
```bash
# Run tests with maximum verbosity
cd build && ./unit_tests --gtest_output=verbose

# Use test filters to isolate problematic tests
cd build && ./test_behavior_tracker --gtest_filter="*SynFlood*"

# Run tests multiple times to catch intermittent issues
cd build && ./unit_tests --gtest_repeat=10
```

## Summary

The DDoS Inspector test suite provides comprehensive coverage of all components:
- **350+ individual test cases** across all test files
- **Multiple attack pattern simulations** with realistic thresholds
- **Performance and stress testing** capabilities
- **Integration testing** to verify component interaction
- **Automated CI/CD pipeline** support

Regular testing ensures the reliability and effectiveness of the DDoS detection and mitigation capabilities.