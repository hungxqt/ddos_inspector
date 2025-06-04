# DDoS Inspector Environment Validation Guide

## Document Information
- **Version**: 2.0
- **Date**: June 3, 2025
- **Authors**: ADHHP Research Team
- **Status**: Production Ready

## Table of Contents
1. [Prerequisites Validation](#prerequisites-validation)
2. [System Requirements Check](#system-requirements-check)
3. [Dependency Verification](#dependency-verification)
4. [Build Environment Setup](#build-environment-setup)
5. [Runtime Environment Validation](#runtime-environment-validation)
6. [Performance Validation](#performance-validation)
7. [Security Validation](#security-validation)
8. [Troubleshooting Common Issues](#troubleshooting-common-issues)

## Prerequisites Validation

### Operating System Compatibility

**Supported Platforms**:
```bash
# Check OS version and compatibility
cat /etc/os-release

# Verified compatible systems:
# - Ubuntu 22.04 LTS / 24.04 LTS (recommended)
# - CentOS 8+ / RHEL 8+
# - Debian 11+ (Bullseye)
# - Fedora 35+
```

**Minimum System Requirements**:
```bash
#!/bin/bash
# System requirements validation script

echo "=== DDoS Inspector Environment Validation ==="

# Check CPU cores
CPU_CORES=$(nproc)
echo "CPU Cores: $CPU_CORES"
if [ $CPU_CORES -lt 2 ]; then
    echo "WARNING: Minimum 2 CPU cores recommended (found: $CPU_CORES)"
fi

# Check available memory
MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
echo "Available Memory: ${MEMORY_GB}GB"
if [ $MEMORY_GB -lt 4 ]; then
    echo "WARNING: Minimum 4GB RAM recommended (found: ${MEMORY_GB}GB)"
fi

# Check available disk space
DISK_SPACE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
echo "Available Disk Space: ${DISK_SPACE}GB"
if [ $DISK_SPACE -lt 10 ]; then
    echo "WARNING: Minimum 10GB free space recommended (found: ${DISK_SPACE}GB)"
fi

# Check network interfaces
INTERFACES=$(ip link show | grep -E "^[0-9]+:" | wc -l)
echo "Network Interfaces: $INTERFACES"
if [ $INTERFACES -lt 1 ]; then
    echo "ERROR: No network interfaces found"
    exit 1
fi

echo "=== Basic system requirements check completed ==="
```

### Kernel and Network Stack Requirements

```bash
# Check kernel version (minimum 4.15+ required for nftables)
KERNEL_VERSION=$(uname -r)
echo "Kernel Version: $KERNEL_VERSION"

# Verify required kernel modules
REQUIRED_MODULES=("nf_tables" "nfnetlink" "xt_limit" "ip_tables")
for module in "${REQUIRED_MODULES[@]}"; do
    if lsmod | grep -q "$module" || modinfo "$module" >/dev/null 2>&1; then
        echo "✓ Kernel module available: $module"
    else
        echo "✗ Missing kernel module: $module"
    fi
done

# Check network stack capabilities
if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
    CONNTRACK_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    echo "Connection tracking limit: $CONNTRACK_MAX"
    if [ $CONNTRACK_MAX -lt 65536 ]; then
        echo "WARNING: Low connection tracking limit. Consider increasing."
    fi
fi
```

## System Requirements Check

### Snort 3 Installation Validation

```bash
# Check Snort 3 installation
check_snort3() {
    echo "=== Snort 3 Validation ==="
    
    # Check if Snort 3 is installed
    if ! command -v snort &> /dev/null; then
        echo "ERROR: Snort 3 not found in PATH"
        echo "Please install Snort 3 using: sudo apt install snort3"
        return 1
    fi
    
    # Check Snort version (minimum 3.1.0.0)
    SNORT_VERSION=$(snort --version 2>&1 | grep -oP "Version \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
    echo "Snort Version: $SNORT_VERSION"
    
    # Validate minimum version
    MIN_VERSION="3.1.0.0"
    if [ "$(printf '%s\n' "$MIN_VERSION" "$SNORT_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
        echo "ERROR: Snort version $SNORT_VERSION is below minimum required $MIN_VERSION"
        return 1
    fi
    
    # Check Snort development headers
    SNORT_INCLUDE_DIRS=(
        "/usr/include/snort"
        "/usr/local/include/snort"
        "/usr/local/snort3/include/snort"
    )
    
    SNORT_HEADERS_FOUND=false
    for dir in "${SNORT_INCLUDE_DIRS[@]}"; do
        if [ -d "$dir" ] && [ -f "$dir/framework/inspector.h" ]; then
            echo "✓ Snort headers found: $dir"
            SNORT_HEADERS_FOUND=true
            export SNORT3_INCLUDE_DIR="$dir"
            break
        fi
    done
    
    if [ "$SNORT_HEADERS_FOUND" = false ]; then
        echo "ERROR: Snort development headers not found"
        echo "Install with: sudo apt install snort3-dev"
        return 1
    fi
    
    # Check plugin directory
    PLUGIN_DIRS=(
        "/usr/lib/snort3_extra_plugins"
        "/usr/local/lib/snort3_extra_plugins"
    )
    
    for dir in "${PLUGIN_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            echo "✓ Plugin directory found: $dir"
            export SNORT3_PLUGIN_DIR="$dir"
            break
        fi
    done
    
    echo "Snort 3 validation completed successfully"
    return 0
}
```

### Development Tools Validation

```bash
# Check build dependencies
check_build_dependencies() {
    echo "=== Build Dependencies Validation ==="
    
    REQUIRED_TOOLS=("cmake" "make" "g++" "pkg-config")
    MISSING_TOOLS=()
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            VERSION=$($tool --version 2>/dev/null | head -n1)
            echo "✓ $tool: $VERSION"
        else
            echo "✗ Missing: $tool"
            MISSING_TOOLS+=("$tool")
        fi
    done
    
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo "ERROR: Missing required build tools: ${MISSING_TOOLS[*]}"
        echo "Install with: sudo apt install build-essential cmake pkg-config"
        return 1
    fi
    
    # Check C++ compiler version (minimum GCC 7+ or Clang 5+)
    if command -v g++ &> /dev/null; then
        GCC_VERSION=$(g++ -dumpversion | cut -d. -f1)
        if [ "$GCC_VERSION" -lt 7 ]; then
            echo "WARNING: GCC version $GCC_VERSION may be too old (minimum 7 recommended)"
        else
            echo "✓ GCC version $GCC_VERSION is compatible"
        fi
    fi
    
    # Check CMake version (minimum 3.10+)
    CMAKE_VERSION=$(cmake --version | grep -oP "version \K[0-9]+\.[0-9]+")
    CMAKE_MAJOR=$(echo $CMAKE_VERSION | cut -d. -f1)
    CMAKE_MINOR=$(echo $CMAKE_VERSION | cut -d. -f2)
    
    if [ "$CMAKE_MAJOR" -lt 3 ] || [ "$CMAKE_MAJOR" -eq 3 -a "$CMAKE_MINOR" -lt 10 ]; then
        echo "ERROR: CMake version $CMAKE_VERSION is below minimum 3.10"
        return 1
    fi
    
    echo "Build dependencies validation completed"
    return 0
}
```

## Dependency Verification

### System Libraries Check

```bash
# Verify required system libraries
check_system_libraries() {
    echo "=== System Libraries Validation ==="
    
    REQUIRED_LIBS=(
        "libpcap-dev:libpcap"
        "nftables:nft"
        "iptables:iptables"
    )
    
    for lib_info in "${REQUIRED_LIBS[@]}"; do
        PACKAGE="${lib_info%%:*}"
        BINARY="${lib_info##*:}"
        
        if command -v "$BINARY" &> /dev/null; then
            echo "✓ $PACKAGE: Available"
        else
            echo "✗ $PACKAGE: Missing"
            echo "  Install with: sudo apt install $PACKAGE"
        fi
    done
    
    # Check library headers
    HEADER_CHECKS=(
        "/usr/include/pcap/pcap.h:libpcap-dev"
        "/usr/include/netinet/in.h:libc6-dev"
    )
    
    for header_info in "${HEADER_CHECKS[@]}"; do
        HEADER="${header_info%%:*}"
        PACKAGE="${header_info##*:}"
        
        if [ -f "$HEADER" ]; then
            echo "✓ Header available: $HEADER"
        else
            echo "✗ Missing header: $HEADER (package: $PACKAGE)"
        fi
    done
    
    echo "System libraries validation completed"
}
```

### Firewall System Validation

```bash
# Validate firewall system compatibility
check_firewall_system() {
    echo "=== Firewall System Validation ==="
    
    # Check nftables
    if command -v nft &> /dev/null; then
        echo "✓ nftables available"
        
        # Test nftables functionality
        if nft list tables &> /dev/null; then
            echo "✓ nftables functional"
        else
            echo "WARNING: nftables not functional (may need root privileges)"
        fi
    else
        echo "WARNING: nftables not available"
    fi
    
    # Check iptables as fallback
    if command -v iptables &> /dev/null; then
        echo "✓ iptables available as fallback"
    else
        echo "ERROR: Neither nftables nor iptables available"
        return 1
    fi
    
    # Check firewall permissions
    if [ "$EUID" -eq 0 ]; then
        echo "✓ Running as root - firewall modifications allowed"
    else
        echo "WARNING: Not running as root - firewall modifications will require sudo"
    fi
    
    echo "Firewall system validation completed"
}
```

## Build Environment Setup

### Automated Environment Setup Script

```bash
#!/bin/bash
# DDoS Inspector Environment Setup Script

setup_build_environment() {
    echo "=== Setting up DDoS Inspector Build Environment ==="
    
    # Update package lists
    echo "Updating package lists..."
    sudo apt update
    
    # Install build dependencies
    echo "Installing build dependencies..."
    sudo apt install -y \
        build-essential \
        cmake \
        pkg-config \
        libpcap-dev \
        nftables \
        iptables \
        git \
        curl \
        wget
    
    # Install Snort 3 if not present
    if ! command -v snort &> /dev/null; then
        echo "Installing Snort 3..."
        sudo apt install -y snort3 snort3-dev
        
        if ! command -v snort &> /dev/null; then
            echo "ERROR: Snort 3 installation failed"
            return 1
        fi
    fi
    
    # Create necessary directories
    echo "Creating directory structure..."
    sudo mkdir -p /usr/local/lib/snort3_extra_plugins
    sudo mkdir -p /var/log/snort
    sudo mkdir -p /etc/snort
    
    # Set permissions
    sudo chown -R $(whoami):$(whoami) /var/log/snort || true
    
    # Configure firewall
    echo "Setting up firewall infrastructure..."
    sudo nft add table inet filter 2>/dev/null || true
    sudo nft add set inet filter ddos_ip_set '{ 
        type ipv4_addr; 
        flags dynamic,timeout; 
        timeout 10m; 
    }' 2>/dev/null || true
    
    echo "Build environment setup completed successfully"
}
```

### Environment Variables Configuration

```bash
# Set up environment variables for DDoS Inspector
setup_environment_variables() {
    echo "=== Setting up Environment Variables ==="
    
    # Detect Snort installation paths
    SNORT_INCLUDE_PATHS=(
        "/usr/include/snort"
        "/usr/local/include/snort"
        "/usr/local/snort3/include/snort"
    )
    
    for path in "${SNORT_INCLUDE_PATHS[@]}"; do
        if [ -d "$path" ]; then
            export SNORT3_INCLUDE_DIR="$path"
            echo "SNORT3_INCLUDE_DIR=$path"
            break
        fi
    done
    
    # Set plugin directory
    PLUGIN_PATHS=(
        "/usr/lib/snort3_extra_plugins"
        "/usr/local/lib/snort3_extra_plugins"
    )
    
    for path in "${PLUGIN_PATHS[@]}"; do
        if [ -d "$path" ]; then
            export SNORT3_PLUGIN_DIR="$path"
            echo "SNORT3_PLUGIN_DIR=$path"
            break
        fi
    done
    
    # Create environment file for persistence
    cat > ~/.ddos_inspector_env << EOF
# DDoS Inspector Environment Variables
export SNORT3_INCLUDE_DIR="$SNORT3_INCLUDE_DIR"
export SNORT3_PLUGIN_DIR="$SNORT3_PLUGIN_DIR"
export PATH="\$PATH:/usr/local/bin"
EOF
    
    echo "Environment variables configured"
    echo "Source with: source ~/.ddos_inspector_env"
}
```

## Runtime Environment Validation

### Plugin Loading Validation

```bash
# Validate plugin loading and configuration
validate_plugin_loading() {
    echo "=== Plugin Loading Validation ==="
    
    # Check if plugin file exists
    PLUGIN_FILE="$SNORT3_PLUGIN_DIR/libddos_inspector.so"
    if [ -f "$PLUGIN_FILE" ]; then
        echo "✓ Plugin file found: $PLUGIN_FILE"
    else
        echo "ERROR: Plugin file not found: $PLUGIN_FILE"
        echo "Build the plugin first with: ./scripts/build_project.sh"
        return 1
    fi
    
    # Check plugin dependencies
    echo "Checking plugin dependencies..."
    if ldd "$PLUGIN_FILE" | grep -q "not found"; then
        echo "ERROR: Plugin has missing dependencies:"
        ldd "$PLUGIN_FILE" | grep "not found"
        return 1
    else
        echo "✓ Plugin dependencies satisfied"
    fi
    
    # Test plugin loading in Snort
    echo "Testing plugin loading in Snort..."
    if snort --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
        echo "✓ Plugin loads successfully in Snort"
    else
        echo "ERROR: Plugin failed to load in Snort"
        echo "Check Snort logs for details"
        return 1
    fi
    
    # Test configuration parsing
    echo "Testing configuration parsing..."
    CONFIG_TEST_FILE="/tmp/test_ddos_config.lua"
    cat > "$CONFIG_TEST_FILE" << 'EOF'
ddos_inspector = {
    allow_icmp = false,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = '/tmp/test_metrics'
}
EOF
    
    if snort -c "$CONFIG_TEST_FILE" -T 2>/dev/null; then
        echo "✓ Configuration parsing successful"
    else
        echo "ERROR: Configuration parsing failed"
        return 1
    fi
    
    rm -f "$CONFIG_TEST_FILE"
    echo "Plugin loading validation completed"
}
```

### Network Interface Validation

```bash
# Validate network interfaces for monitoring
validate_network_interfaces() {
    echo "=== Network Interface Validation ==="
    
    # List available interfaces
    echo "Available network interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
    
    # Check for promiscuous mode capability
    for interface in $(ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print $2}' | sed 's/@.*//'); do
        if [ "$interface" != "lo" ]; then
            echo "Testing interface: $interface"
            
            # Check if interface is up
            if ip link show "$interface" | grep -q "state UP"; then
                echo "  ✓ Interface $interface is UP"
            else
                echo "  ⚠ Interface $interface is DOWN"
            fi
            
            # Test promiscuous mode (requires root)
            if [ "$EUID" -eq 0 ]; then
                if ip link set "$interface" promisc on 2>/dev/null; then
                    echo "  ✓ Promiscuous mode supported on $interface"
                    ip link set "$interface" promisc off 2>/dev/null
                else
                    echo "  ⚠ Promiscuous mode not supported on $interface"
                fi
            else
                echo "  ⚠ Cannot test promiscuous mode (requires root)"
            fi
        fi
    done
    
    echo "Network interface validation completed"
}
```

## Performance Validation

### System Performance Benchmarking

```bash
# Benchmark system performance for DDoS Inspector
benchmark_system_performance() {
    echo "=== System Performance Benchmarking ==="
    
    # CPU performance test
    echo "CPU Performance Test (computing entropy for 10MB data)..."
    START_TIME=$(date +%s.%N)
    dd if=/dev/urandom bs=1M count=10 2>/dev/null | sha256sum > /dev/null
    END_TIME=$(date +%s.%N)
    CPU_TIME=$(echo "$END_TIME - $START_TIME" | bc)
    echo "CPU Test completed in: ${CPU_TIME}s"
    
    # Memory performance test
    echo "Memory Performance Test..."
    if command -v sysbench &> /dev/null; then
        sysbench memory --memory-block-size=1K --memory-total-size=100M run 2>/dev/null | grep "transferred"
    else
        echo "sysbench not available - install with: sudo apt install sysbench"
    fi
    
    # Network interface performance
    echo "Network Interface Performance:"
    for interface in $(ip route | grep default | awk '{print $5}' | head -1); do
        if [ -f "/sys/class/net/$interface/speed" ]; then
            SPEED=$(cat "/sys/class/net/$interface/speed")
            echo "  Interface $interface: ${SPEED}Mbps"
        fi
    done
    
    # Disk I/O performance (for logging)
    echo "Disk I/O Performance Test..."
    TEMP_FILE="/tmp/ddos_inspector_io_test"
    START_TIME=$(date +%s.%N)
    dd if=/dev/zero of="$TEMP_FILE" bs=1M count=100 2>/dev/null
    sync
    END_TIME=$(date +%s.%N)
    IO_TIME=$(echo "$END_TIME - $START_TIME" | bc)
    rm -f "$TEMP_FILE"
    echo "Disk I/O Test (100MB write): ${IO_TIME}s"
    
    echo "System performance benchmarking completed"
}
```

### Memory and Resource Validation

```bash
# Validate memory and resource limits
validate_system_resources() {
    echo "=== System Resource Validation ==="
    
    # Check memory limits
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    AVAILABLE_MEM=$(free -m | awk '/^Mem:/{print $7}')
    echo "Total Memory: ${TOTAL_MEM}MB"
    echo "Available Memory: ${AVAILABLE_MEM}MB"
    
    if [ $AVAILABLE_MEM -lt 1024 ]; then
        echo "WARNING: Low available memory (< 1GB)"
    fi
    
    # Check file descriptor limits
    ULIMIT_FILES=$(ulimit -n)
    echo "File descriptor limit: $ULIMIT_FILES"
    if [ $ULIMIT_FILES -lt 65536 ]; then
        echo "WARNING: Low file descriptor limit. Consider increasing with 'ulimit -n 65536'"
    fi
    
    # Check process limits
    ULIMIT_PROC=$(ulimit -u)
    echo "Process limit: $ULIMIT_PROC"
    
    # Check system load
    LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    echo "Current load average: $LOAD_AVG"
    
    echo "System resource validation completed"
}
```

## Security Validation

### Permission and Security Checks

```bash
# Validate security configuration and permissions
validate_security_configuration() {
    echo "=== Security Configuration Validation ==="
    
    # Check running user
    if [ "$EUID" -eq 0 ]; then
        echo "⚠ Running as root - consider running Snort as dedicated user"
    else
        echo "✓ Running as non-root user: $(whoami)"
    fi
    
    # Check firewall capabilities
    if [ "$EUID" -eq 0 ]; then
        echo "✓ Root privileges available for firewall management"
    else
        echo "⚠ Non-root user - firewall operations will require sudo"
        
        # Check sudo permissions for firewall commands
        if sudo -n nft list tables &>/dev/null; then
            echo "✓ Sudo permissions available for nftables"
        else
            echo "⚠ Sudo permissions may be required for nftables"
        fi
    fi
    
    # Check SELinux/AppArmor status
    if command -v getenforce &> /dev/null; then
        SELINUX_STATUS=$(getenforce)
        echo "SELinux status: $SELINUX_STATUS"
        if [ "$SELINUX_STATUS" = "Enforcing" ]; then
            echo "⚠ SELinux enforcing - may require policy adjustments"
        fi
    fi
    
    if command -v aa-status &> /dev/null; then
        echo "AppArmor profiles loaded: $(aa-status --enabled 2>/dev/null | wc -l)"
    fi
    
    # Check log directory permissions
    LOG_DIR="/var/log/snort"
    if [ -d "$LOG_DIR" ]; then
        LOG_PERMS=$(ls -ld "$LOG_DIR" | awk '{print $1, $3, $4}')
        echo "Log directory permissions: $LOG_PERMS"
    fi
    
    echo "Security configuration validation completed"
}
```

## Troubleshooting Common Issues

### Common Environment Issues and Solutions

```bash
# Troubleshooting guide for common issues
troubleshoot_common_issues() {
    echo "=== Common Issues Troubleshooting ==="
    
    # Issue 1: Snort headers not found
    if [ ! -d "$SNORT3_INCLUDE_DIR" ]; then
        echo "ISSUE: Snort headers not found"
        echo "SOLUTION: Install Snort development headers:"
        echo "  sudo apt install snort3-dev"
        echo ""
    fi
    
    # Issue 2: Plugin loading fails
    if ! snort --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
        echo "ISSUE: Plugin not loading in Snort"
        echo "SOLUTIONS:"
        echo "  1. Check plugin file exists: ls -la $SNORT3_PLUGIN_DIR/"
        echo "  2. Check plugin dependencies: ldd $SNORT3_PLUGIN_DIR/libddos_inspector.so"
        echo "  3. Rebuild plugin: ./scripts/build_project.sh"
        echo ""
    fi
    
    # Issue 3: Permission denied for firewall operations
    echo "ISSUE: Permission denied for firewall operations"
    echo "SOLUTIONS:"
    echo "  1. Run with sudo: sudo snort -c /etc/snort/snort.lua"
    echo "  2. Add user to appropriate groups"
    echo "  3. Configure sudo permissions for firewall commands"
    echo ""
    
    # Issue 4: High memory usage
    echo "ISSUE: High memory usage"
    echo "SOLUTIONS:"
    echo "  1. Reduce max_tracked_ips in configuration"
    echo "  2. Increase cleanup_interval frequency"
    echo "  3. Monitor with: watch -n 1 'ps aux | grep snort'"
    echo ""
    
    # Issue 5: Build failures
    echo "ISSUE: Build failures"
    echo "SOLUTIONS:"
    echo "  1. Check compiler version: g++ --version"
    echo "  2. Update CMake: sudo apt install cmake"
    echo "  3. Clean build: rm -rf build && mkdir build"
    echo "  4. Check build logs in build/CMakeConfigureLog.yaml"
    echo ""
    
    echo "For additional support, check:"
    echo "  - Project documentation: docs/"
    echo "  - GitHub issues: https://github.com/hung-qt/ddos_inspector/issues"
    echo "  - Build logs: build/CMakeConfigureLog.yaml"
}
```

### Environment Validation Summary Script

```bash
#!/bin/bash
# Complete environment validation script

main() {
    echo "=========================================="
    echo "DDoS Inspector Environment Validation"
    echo "=========================================="
    
    # Run all validation checks
    check_snort3 || exit 1
    check_build_dependencies || exit 1
    check_system_libraries || exit 1
    check_firewall_system || exit 1
    
    # Optional advanced checks
    if [ "$1" = "--full" ]; then
        benchmark_system_performance
        validate_system_resources
        validate_security_configuration
    fi
    
    echo "=========================================="
    echo "Environment validation completed successfully!"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo "1. Build the project: ./scripts/build_project.sh"
    echo "2. Deploy the plugin: sudo ./scripts/deploy.sh"
    echo "3. Run tests: ./scripts/run_tests.sh"
    echo ""
    echo "For full validation run: $0 --full"
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
```

This environment validation guide provides comprehensive checks for all aspects of the DDoS Inspector deployment environment, ensuring all dependencies, permissions, and system requirements are properly configured before installation and operation.

