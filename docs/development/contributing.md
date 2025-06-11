# Contributing Guide

We welcome contributions to DDoS Inspector! This guide will help you get started with contributing to the project, whether you're fixing bugs, adding features, or improving documentation.

## Quick Start for Contributors

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/ddos_inspector.git
cd ddos_inspector

# Add upstream remote
git remote add upstream https://github.com/hung-qt/ddos_inspector.git
```

### 2. Set Up Development Environment

```bash
# Install development dependencies
sudo apt-get install -y build-essential cmake git libpcap-dev nftables
sudo apt-get install -y snort3 snort3-dev valgrind gdb

# Install testing tools
sudo apt-get install -y googletest libgtest-dev hping3 netcat-openbsd

# Build in debug mode
mkdir build-dev && cd build-dev
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTING=ON
make -j$(nproc)
```

### 3. Run Tests

```bash
# Run all tests to ensure everything works
./scripts/run_tests.sh

# Run specific test categories
make test                    # Unit tests
./test_realistic_attacks     # Integration tests
./scripts/run_syn_flood.sh   # Attack simulations
```

## Development Workflow

### Branch Strategy

We use a feature branch workflow:

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes and commit
git add .
git commit -m "Add feature: your feature description"

# Keep your branch updated
git fetch upstream
git rebase upstream/main

# Push your branch
git push origin feature/your-feature-name
```

### Commit Guidelines

Follow conventional commit format:

```bash
# Feature commits
git commit -m "feat: add new attack detection algorithm"
git commit -m "feat(api): add metrics export endpoint"

# Bug fixes
git commit -m "fix: resolve memory leak in behavior tracker"
git commit -m "fix(config): validate threshold parameters"

# Documentation
git commit -m "docs: update installation guide"
git commit -m "docs(api): add missing function documentation"

# Tests
git commit -m "test: add unit tests for stats engine"
git commit -m "test(integration): add slowloris detection test"

# Performance improvements
git commit -m "perf: optimize packet processing pipeline"

# Refactoring
git commit -m "refactor: extract firewall interface"
```

## Coding Standards

### C++ Style Guidelines

We follow Google C++ Style Guide with some modifications:

#### Naming Conventions

```cpp
// Classes: PascalCase
class StatsEngine;
class BehaviorTracker;

// Functions and variables: snake_case
void calculate_entropy();
int packet_count;
double detection_latency;

// Constants: UPPER_SNAKE_CASE
const int MAX_TRACKED_IPS = 100000;
const double DEFAULT_ENTROPY_THRESHOLD = 2.0;

// Private member variables: trailing underscore
class MyClass {
private:
    int member_variable_;
    std::string config_file_;
};

// Namespaces: lowercase
namespace network_utils {
namespace time_utils {
```

#### Code Formatting

```cpp
// Use clang-format with provided .clang-format file
clang-format -i src/*.cpp include/*.hpp

// Function declarations
bool detect_syn_flood(const IPBehavior& behavior,
                     double threshold,
                     std::chrono::seconds window);

// Class definitions
class StatsEngine {
public:
    // Public methods first
    explicit StatsEngine(double entropy_threshold = 2.0);
    ~StatsEngine() = default;
    
    // No copy/move if not needed
    StatsEngine(const StatsEngine&) = delete;
    StatsEngine& operator=(const StatsEngine&) = delete;
    
    // Main interface
    double calculate_entropy(const std::vector<uint8_t>& data);
    
private:
    // Private members
    double entropy_threshold_;
    mutable std::mutex stats_mutex_;
};
```

#### Error Handling

```cpp
// Use exceptions for error handling
class ConfigurationException : public std::exception {
public:
    explicit ConfigurationException(const std::string& message)
        : message_(message) {}
    
    const char* what() const noexcept override {
        return message_.c_str();
    }
    
private:
    std::string message_;
};

// Function error handling
bool parse_config(const std::string& config_file) {
    try {
        // Parse configuration
        return true;
    } catch (const ConfigurationException& e) {
        log_error("Configuration error: %s", e.what());
        return false;
    }
}
```

#### Memory Management

```cpp
// Use RAII and smart pointers
class ResourceManager {
public:
    ResourceManager() : data_(std::make_unique<Data>()) {}
    
    // Use smart pointers for dynamic allocation
    std::unique_ptr<Data> create_data() {
        return std::make_unique<Data>();
    }
    
    // Use containers instead of raw arrays
    std::vector<uint8_t> buffer_;
    std::array<int, 100> fixed_array_;
    
private:
    std::unique_ptr<Data> data_;
};
```

### Documentation Standards

#### Code Documentation

```cpp
/**
 * @brief Calculate Shannon entropy of data
 * 
 * Computes the Shannon entropy H(X) = -∑ P(xi) × log2(P(xi))
 * where P(xi) is the probability of byte value xi.
 * 
 * @param data Input data buffer
 * @return Entropy value (0.0 to 8.0 for byte data)
 * 
 * @throws std::invalid_argument if data is empty
 * 
 * @example
 * std::vector<uint8_t> packet_data = {0x41, 0x42, 0x43};
 * double entropy = calculate_shannon_entropy(packet_data);
 */
double calculate_shannon_entropy(const std::vector<uint8_t>& data);
```

#### Markdown Documentation

```markdown
# Use clear headings

## Section headers should be descriptive

### Use consistent formatting

- List items with proper indentation
- Code examples should be complete and runnable
- Include command outputs where helpful

```bash
# Commands should be copy-pastable
sudo apt-get install package-name
```

**Important notes** should be highlighted.
```

## Testing Guidelines

### Unit Tests

Write comprehensive unit tests for all new functionality:

```cpp
// tests/test_stats_engine.cpp
#include <gtest/gtest.h>
#include "stats_engine.hpp"

class StatsEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine_ = std::make_unique<StatsEngine>(2.0, 0.1);
    }
    
    std::unique_ptr<StatsEngine> engine_;
};

TEST_F(StatsEngineTest, CalculateEntropyEmptyData) {
    std::vector<uint8_t> empty_data;
    EXPECT_THROW(engine_->calculate_shannon_entropy(empty_data), 
                 std::invalid_argument);
}

TEST_F(StatsEngineTest, CalculateEntropyUniformData) {
    std::vector<uint8_t> uniform_data(256);
    std::iota(uniform_data.begin(), uniform_data.end(), 0);
    
    double entropy = engine_->calculate_shannon_entropy(uniform_data);
    EXPECT_NEAR(entropy, 8.0, 0.01);  // Perfect entropy for uniform distribution
}

TEST_F(StatsEngineTest, EWMACalculation) {
    double old_ewma = 100.0;
    double new_value = 150.0;
    double alpha = 0.1;
    
    double result = engine_->calculate_ewma(new_value, old_ewma, alpha);
    double expected = alpha * new_value + (1 - alpha) * old_ewma;
    
    EXPECT_DOUBLE_EQ(result, expected);
}
```

### Integration Tests

Test complete workflows:

```cpp
// tests/test_realistic_attacks.cpp
TEST(RealisticAttacksTest, SynFloodDetectionAndBlocking) {
    // Setup test environment
    auto config = create_test_config();
    DDosInspector inspector(config.get());
    
    // Simulate SYN flood attack
    for (int i = 0; i < 1000; ++i) {
        auto packet = create_syn_packet("192.168.1.100", "10.0.0.1", 80);
        inspector.eval(packet.get());
    }
    
    // Verify detection
    auto stats = inspector.get_statistics();
    EXPECT_GT(stats["syn_flood_detected"], 0);
    
    // Verify blocking
    EXPECT_TRUE(is_ip_blocked("192.168.1.100"));
}
```

### Performance Tests

Include performance benchmarks:

```cpp
// tests/benchmark_packet_processing.cpp
#include <benchmark/benchmark.h>

static void BM_PacketProcessing(benchmark::State& state) {
    auto config = create_performance_config();
    DDosInspector inspector(config.get());
    
    for (auto _ : state) {
        auto packet = create_test_packet();
        inspector.eval(packet.get());
    }
    
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_PacketProcessing);
```

## Feature Development

### Adding New Attack Detection

1. **Create detector class**:

```cpp
// include/custom_detector.hpp
class CustomAttackDetector : public AttackDetectorBase {
public:
    explicit CustomAttackDetector(const DetectorConfig& config);
    
    bool detect_attack(const IPBehavior& behavior) override;
    AttackType get_attack_type() const override { return AttackType::CUSTOM; }
    std::string get_detector_name() const override { return "custom_detector"; }
    
private:
    DetectorConfig config_;
};
```

2. **Implement detection logic**:

```cpp
// src/custom_detector.cpp
bool CustomAttackDetector::detect_attack(const IPBehavior& behavior) {
    // Implement your detection algorithm
    if (behavior.packets_per_second > config_.rate_threshold &&
        behavior.entropy_score < config_.entropy_threshold) {
        return true;
    }
    return false;
}
```

3. **Add configuration support**:

```lua
-- snort_ddos_config.lua
ddos_inspector = {
    -- ...existing config...
    
    custom_detector = {
        enabled = true,
        rate_threshold = 1000,
        entropy_threshold = 1.5
    }
}
```

4. **Write comprehensive tests**:

```cpp
TEST(CustomDetectorTest, DetectsAttackWithHighRateAndLowEntropy) {
    CustomAttackDetector detector(create_test_config());
    
    IPBehavior behavior;
    behavior.packets_per_second = 2000;  // Above threshold
    behavior.entropy_score = 1.0;        // Below threshold
    
    EXPECT_TRUE(detector.detect_attack(behavior));
}
```

### Adding New Mitigation Actions

1. **Implement action interface**:

```cpp
class CustomMitigationAction : public MitigationActionBase {
public:
    bool execute_action(const std::string& ip, AttackType attack) override;
    bool undo_action(const std::string& ip) override;
    std::string get_action_name() const override { return "custom_action"; }
};
```

2. **Register with system**:

```cpp
// In plugin initialization
register_mitigation_action(std::make_unique<CustomMitigationAction>());
```

## Pull Request Process

### Before Submitting

1. **Ensure all tests pass**:
```bash
./scripts/run_tests.sh
make test
valgrind --leak-check=full ./unit_tests
```

2. **Check code quality**:
```bash
# Format code
clang-format -i src/*.cpp include/*.hpp

# Static analysis
cppcheck --enable=all src/ include/

# Code coverage
gcov src/*.cpp
```

3. **Update documentation**:
```bash
# Update relevant docs
vim docs/api-reference.md
vim docs/configuration.md

# Test documentation examples
./scripts/test_documentation_examples.sh
```

### Pull Request Template

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Performance tests pass (if applicable)
- [ ] Manual testing completed

## Performance Impact
- [ ] No performance impact
- [ ] Performance improvement: X% faster
- [ ] Performance regression: X% slower (justified because...)

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
```

### Review Process

1. **Automated checks** must pass:
   - Build successfully
   - All tests pass
   - Code coverage maintained
   - No security vulnerabilities

2. **Code review** by maintainers:
   - Code quality and style
   - Test coverage
   - Documentation updates
   - Performance impact

3. **Approval and merge**:
   - At least one maintainer approval
   - All discussions r
   - Rebase and merge to main

## Development Environment Setup

### IDE Configuration

#### Visual Studio Code

```json
// .vscode/settings.json
{
    pp.default.configurationProvider": "ms-vscode.cmake-tools",
    "C_Cpp.default.cppStandard": "c++17",
    "C_Cpp.default.includePath": [
        "${workspaceFolder}/include",
        "/usr/include/snort3"
    ],
    "files.associations": {
        "*.hpp": "cpp",
        "*.lua": "lua"
    },
    "cmake.buildDirectory": "${workspaceFolder}/build-dev"
}
```

#### CLion

```cmake
# CMakeListsPrivate.txt for CLion
set(CMAKE_BUILD_TYPE Debug)
set(ENABLE_TESTING ON)
set(ENABLE_COVERAGE ON)
```

### Debug Configuration

```cpp
// Enable debug logging
#ifdef DEBUG
#define DEBUG_LOG(fmt, ...) \
    fprintf(stderr, "[DEBUG] %s:%d \n", __FILE__, __LINE__, ##__VA_ARGS__)
e
#define DEBUG_LOG(fmt, ...)
#endif

// Debug build flags
# In CMakeLists.txt
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(ddos_inspector PRIVATE 
        -g -O0 -DDEBUG 
        -fsanitize=address 
        -fsanitize=undefined
    )
    target_link_options(ddos_inspector PRIVATE 
        -fsanitize=address 
        -fsanitize=undefined
    )
endif()
```

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn and contribute
- Maintain professional communication

### Getting Help

- **GitHub Discussions**: For questions and general discussion
- **GitHub Issues**: For bug reports and feature requests
- **Email**: adhhp.research@fpt.edu.vn for sensitive issues

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Annual contributor highlights

## Release Process

### Version Numbering

We follow Semantic Versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Checklist

1. **Pre-release testing**:
```bash
./scripts/run_comprehensive_tests.sh
./scripts/test_deployment_scenarios.sh
./scripts/performance_regression_test.sh
```

2. **Documentation updates**:
```bash
# Update version numbers
sed -i 's/v1.2.0/v1.3.0/g' README.md docs/*.md

# Update changelog
vim CHANGELOG.md
```

3. **Create release**:
```bash
git tag -a v1.3.0 -m "Release version 1.3.0"
git push upstream v1.3.0
./scripts/create_release_package.sh v1.3.0
```

Thank you for contributing to DDoS Inspector! 🚀

---

For more information, see our [documentation](docs/) or reach out to the team.