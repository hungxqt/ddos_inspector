# Getting Started with DDoS Inspector

Welcome to DDoS Inspector! This comprehensive guide will take you from installation to your first successful attack detection in under 30 minutes.

## What You'll Accomplish

By following this guide, you will:
- Install DDoS Inspector on your system
- Configure it for your network environment
- Verify it's working with attack simulations
- Set up basic monitoring and alerting
- Understand how to move to production deployment

**Estimated Time**: 15-30 minutes depending on your chosen installation method

## Choose Your Path

Select the path that best fits your needs:

| Path | Best For | Time | Complexity |
|------|----------|------|------------|
| [Quick Start](#quick-start-path) | Testing & Evaluation | 5 min | Low |
| [Docker Path](#docker-deployment-path) | Development & Containers | 10 min | Medium |
| [Manual Path](#manual-installation-path) | Production & Customization | 20 min | High |

---

## Quick Start Path

**Perfect for**: First-time users, quick evaluation, testing environments

### Prerequisites Check

```bash
# Check your system meets minimum requirements
echo "=== System Information ==="
echo "OS: $(lsb_release -d | cut -f2)"
echo "CPU Cores: $(nproc)"
echo "Memory: $(free -h | grep ^Mem | awk '{print $2}')"
echo "Network Interfaces: $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ')"

# Verify you have sudo access
sudo echo "Sudo access confirmed"
```

**Minimum Requirements:**
- Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
- 2+ CPU cores, 4GB+ RAM
- Network interface with traffic
- Sudo/root access

### One-Command Installation

```bash
# Clone and auto-install DDoS Inspector
curl -sSL https://raw.githubusercontent.com/hung-qt/ddos_inspector/main/scripts/quick-install.sh | bash

# Alternative: Git clone method
git clone https://github.com/hung-qt/ddos_inspector.git
cd ddos_inspector
sudo ./scripts/deploy.sh --quick --interface eth0
```

**What the installer does:**
1. Checks system compatibility
2. Installs required dependencies (Snort 3, build tools)
3. Builds DDoS Inspector from source
4. Configures Snort integration
5. Sets up firewall rules (nftables/iptables)
6. Starts the service

### Verification

```bash
# 1. Verify plugin is loaded
sudo snort --show-plugins | grep ddos_inspector
# Expected output: "ddos_inspector: DDoS detection and mitigation plugin"

# 2. Check service status
sudo systemctl status snort-ddos
# Expected: Active (running)

# 3. Test configuration
sudo snort -c /etc/snort/snort_ddos_config.lua -T
# Expected: "Snort successfully validated the configuration"

# 4. Monitor live metrics
cat /var/log/ddos_inspector/ddos_inspector_stats
# Expected: Real-time statistics output
```

### Quick Test

```bash
# Run a safe SYN flood simulation against localhost
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --port 80 --duration 10

# Check for detection (wait 10-15 seconds)
grep "SYN_FLOOD" /var/log/snort/alert
grep "attacks_detected" /var/log/ddos_inspector/ddos_inspector_stats

# Success indicators:
# - Alert logged in /var/log/snort/alert
# - attacks_detected counter increased
# - IP 127.0.0.1 blocked (check with: sudo nft list set inet filter ddos_ip_set)
```

**Success!** If all checks pass, you have a working DDoS Inspector installation.

**Next Step**: [Set up monitoring](#basic-monitoring-setup) or jump to [Configuration Guide](../configuration/) for customization.

---

## Docker Deployment Path

**Perfect for**: Development, testing, containerized environments, quick demos

### Docker Prerequisites

```bash
# Install Docker and Docker Compose (if not already installed)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version && docker-compose --version
```

### Quick Docker Deployment

```bash
# Clone the repository
git clone https://github.com/hung-qt/ddos_inspector.git
cd ddos_inspector

# Set your network interface
export SNORT_INTERFACE=eth0  # Replace with your interface name

# Deploy with Docker Compose (includes monitoring stack)
docker-compose up -d

# Check status
docker-compose ps
```

### Docker Deployment Options

#### Option 1: Minimal Deployment
```bash
# Deploy only DDoS Inspector
sudo ./scripts/deploy_docker.sh --mode minimal --interface eth0

# What you get:
# - DDoS Inspector container
# - Basic configuration
# - Local metrics file
```

#### Option 2: Full Stack Deployment
```bash
# Deploy with full monitoring stack
sudo ./scripts/deploy_docker.sh --mode full --interface eth0

# What you get:
# - DDoS Inspector container
# - Prometheus metrics collection
# - Grafana dashboards
# - ELK stack for log analysis
# - Web interfaces for monitoring
```

#### Option 3: Custom Configuration
```bash
# Use custom configuration file
cp snort_ddos_config.lua my_custom_config.lua
# Edit my_custom_config.lua with your settings

# Deploy with custom config
docker run -d \
  --name ddos-inspector \
  --network host \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v $(pwd)/my_custom_config.lua:/etc/snort/snort_ddos_config.lua \
  -v /tmp:/tmp \
  hungqt/ddos-inspector:latest
```

### Docker Verification

```bash
# Check container status
docker ps | grep ddos

# View container logs
docker logs ddos-inspector

# Access container shell
docker exec -it ddos-inspector bash

# Inside container, verify plugin
snort --show-plugins | grep ddos_inspector

# Check metrics from host
cat /var/log/ddos_inspector/ddos_inspector_stats
```

### Access Monitoring Dashboards

After full stack deployment:

```bash
# Grafana Dashboard
echo "Grafana: http://localhost:3000"
echo "Login: admin / ddos_inspector_2025"

# Prometheus Metrics
echo "Prometheus: http://localhost:9090"

# Kibana Dashboard (if ELK enabled)
echo "Kibana: http://localhost:5601"

# Open dashboards
xdg-open http://localhost:3000 2>/dev/null || echo "Open browser to http://localhost:3000"
```

### Docker Attack Testing

```bash
# Test SYN flood detection
docker exec ddos-inspector ./scripts/run_syn_flood.sh --target host.docker.internal --duration 10

# Test HTTP flood detection
docker exec ddos-inspector ./scripts/run_slowloris.sh --target host.docker.internal --duration 10

# Check detection results
docker exec ddos-inspector cat /var/log/ddos_inspector/ddos_inspector_stats
```

**Next Step**: [Configure your deployment](../configuration/) or [set up advanced monitoring](../monitoring/).

---

## Manual Installation Path

**Perfect for**: Production environments, custom configurations, understanding internals

### Detailed Prerequisites

#### System Requirements Verification

```bash
# Comprehensive system check
echo "=== Detailed System Check ==="

# OS and Kernel
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"

# Hardware
echo "CPU: $(cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2 | xargs)"
echo "CPU Cores: $(nproc)"
echo "Memory Total: $(free -h | grep Mem | awk '{print $2}')"
echo "Memory Available: $(free -h | grep Mem | awk '{print $7}')"

# Network
echo "Network Interfaces:"
ip -o link show | awk -F': ' '{print "  " $2 " (" $3 ")"}'

# Storage
echo "Disk Space: $(df -h / | tail -1 | awk '{print $4}') available"

# Check if we meet requirements
CORES=$(nproc)
MEMORY_GB=$(free -g | grep Mem | awk '{print $2}')

if [ $CORES -ge 2 ] && [ $MEMORY_GB -ge 4 ]; then
    echo "System meets minimum requirements"
else
    echo "System does not meet minimum requirements"
    echo "   Need: 2+ cores, 4GB+ RAM"
    echo "   Have: $CORES cores, ${MEMORY_GB}GB RAM"
fi
```

#### Dependency Installation

**Ubuntu/Debian:**
```bash
# Update package list
sudo apt update

# Install build dependencies
sudo apt install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libpcap-dev \
    libdaq-dev \
    nftables \
    iptables \
    flex \
    bison \
    libssl-dev \
    zlib1g-dev

# Install Snort 3 dependencies
sudo apt install -y \
    libhwloc-dev \
    libluajit-5.1-dev \
    libdnet-dev \
    libnghttp2-dev \
    libpcre3-dev \
    uuid-dev

# Install optional monitoring dependencies
sudo apt install -y \
    htop \
    iotop \
    nethogs \
    tcpdump \
    wireshark-common
```

**CentOS/RHEL 8+:**
```bash
# Enable required repositories
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y epel-release

# Install dependencies
sudo dnf install -y \
    cmake \
    git \
    libpcap-devel \
    libdaq-devel \
    nftables \
    iptables \
    flex \
    bison \
    openssl-devel \
    zlib-devel

# Install Snort 3 dependencies
sudo dnf install -y \
    hwloc-devel \
    luajit-devel \
    libdnet-devel \
    libnghttp2-devel \
    pcre-devel \
    libuuid-devel
```

#### Snort 3 Installation

**Option 1: From Package (Ubuntu):**
```bash
# Add Snort repository
wget -qO - https://pkg.snort.org/ubuntu/snort.gpg.key | sudo apt-key add -
echo "deb https://pkg.snort.org/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/snort.list

# Install Snort 3
sudo apt update
sudo apt install -y snort3 snort3-dev

# Verify installation
snort --version
```

**Option 2: From Source (All Distributions):**
```bash
# Install libdaq from source
cd /tmp
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make -j$(nproc)
sudo make install

# Install Snort 3 from source
cd /tmp
git clone https://github.com/snort3/snort3.git
cd snort3
./configure_cmake.sh --prefix=/usr/local --enable-shell
cd build
make -j$(nproc)
sudo make install

# Update library path
sudo ldconfig

# Verify installation
/usr/local/bin/snort --version
```

### Build DDoS Inspector

```bash
# Clone the repository
git clone https://github.com/hung-qt/ddos_inspector.git
cd ddos_inspector

# Create and configure build directory
mkdir build && cd build

# Configure with CMake
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DENABLE_TESTING=ON

# Build the project
make -j$(nproc)

# Run tests to verify build
echo "Running unit tests..."
ctest --output-on-failure

# Install the plugin
sudo make install

# Verify installation
ls -la /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so
```

### System Configuration

#### Firewall Setup

**nftables Configuration:**
```bash
# Create nftables configuration
sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    set ddos_ip_set {
        type ipv4_addr
        size 65536
        timeout 10m
    }

    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @ddos_ip_set drop
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ip saddr @ddos_ip_set drop
    }
}
EOF

# Enable and start nftables
sudo systemctl enable nftables
sudo systemctl start nftables

# Verify configuration
sudo nft list tables
sudo nft list set inet filter ddos_ip_set
```

**iptables Configuration (alternative):**
```bash
# Create custom chain for DDoS blocking
sudo iptables -N ddos_chain
sudo iptables -A INPUT -j ddos_chain
sudo iptables -A FORWARD -j ddos_chain

# Save rules (method varies by distribution)
# Ubuntu/Debian:
sudo iptables-save > /etc/iptables/rules.v4
# CentOS/RHEL:
sudo iptables-save > /etc/sysconfig/iptables

# Install iptables-persistent (Ubuntu/Debian)
sudo apt install -y iptables-persistent
```

#### Snort Configuration

```bash
# Create Snort configuration directory
sudo mkdir -p /etc/snort
sudo mkdir -p /var/log/snort
sudo mkdir -p /usr/local/lib/snort_dynamicpreprocessor

# Copy DDoS Inspector configuration
sudo cp ../snort_ddos_config.lua /etc/snort/

# Create Snort user and group
sudo groupadd snort
sudo useradd -r -s /bin/false -M -c snort -g snort snort

# Set proper permissions
sudo chown -R snort:snort /var/log/snort
sudo chmod 755 /var/log/snort
```

#### Service Configuration

```bash
# Create systemd service file
sudo tee /etc/systemd/system/snort-ddos.service << 'EOF'
[Unit]
Description=Snort with DDoS Inspector
After=network.target nftables.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A alert_fast -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable snort-ddos
```

### Comprehensive Verification

#### Plugin Verification
```bash
# Verify plugin is installed and loadable
sudo snort --show-plugins | grep -A 5 ddos_inspector

# Test configuration file syntax
sudo snort -c /etc/snort/snort_ddos_config.lua -T

# Check for any configuration warnings
sudo snort -c /etc/snort/snort_ddos_config.lua -T 2>&1 | grep -i warning
```

#### Network Interface Testing
```bash
# Verify interface exists and is up
INTERFACE=eth0  # Replace with your interface
ip link show $INTERFACE

# Check if interface has traffic
sudo timeout 10 tcpdump -i $INTERFACE -c 5 2>/dev/null && echo "Interface has traffic" || echo "No traffic on interface"

# Test packet capture permissions
sudo timeout 5 snort -i $INTERFACE -c /etc/snort/snort_ddos_config.lua -A none -q 2>/dev/null && echo "Packet capture working" || echo "Packet capture failed"
```

#### Service Testing
```bash
# Start the service
sudo systemctl start snort-ddos

# Check service status
sudo systemctl status snort-ddos

# Monitor service logs
sudo journalctl -u snort-ddos -f --lines=20
```

#### Functionality Testing
```bash
# Test metrics file creation
timeout 30 bash -c 'while [ ! -f /var/log/ddos_inspector/ddos_inspector_stats ]; do sleep 1; done'
if [ -f /var/log/ddos_inspector/ddos_inspector_stats ]; then
    echo "Metrics file created"
    cat /var/log/ddos_inspector/ddos_inspector_stats
else
    echo "Metrics file not created"
fi

# Test firewall integration
sudo nft list set inet filter ddos_ip_set 2>/dev/null && echo "nftables integration working" || echo "nftables set not found"
```

---

## Basic Monitoring Setup

Regardless of your installation path, set up basic monitoring:

### Real-time Metrics Monitoring

```bash
# Create monitoring script
cat > ~/monitor_ddos.sh << 'EOF'
#!/bin/bash
# DDoS Inspector Real-time Monitor

while true; do
    clear
    echo "=== DDoS Inspector Live Monitor ==="
    echo "Time: $(date)"
    echo ""
    
    if [ -f /var/log/ddos_inspector/ddos_inspector_stats ]; then
        echo "--- Current Statistics ---"
        cat /var/log/ddos_inspector/ddos_inspector_stats | column -t
        echo ""
        
        # Extract key metrics
        PACKETS=$(grep "packets_processed_total" /var/log/ddos_inspector/ddos_inspector_stats | awk '{print $2}')
        ATTACKS=$(grep "attacks_detected_total" /var/log/ddos_inspector/ddos_inspector_stats | awk '{print $2}')
        BLOCKED=$(grep "ips_blocked_total" /var/log/ddos_inspector/ddos_inspector_stats | awk '{print $2}')
        
        echo "--- Key Metrics ---"
        echo "Packets Processed: ${PACKETS:-0}"
        echo "Attacks Detected: ${ATTACKS:-0}"
        echo "IPs Blocked: ${BLOCKED:-0}"
        echo ""
        
        # Show recent alerts
        echo "--- Recent Alerts (last 5) ---"
        if [ -f /var/log/snort/alert ]; then
            tail -5 /var/log/snort/alert | grep -E "(SYN_FLOOD|HTTP_FLOOD|SLOWLORIS|UDP_FLOOD)" || echo "No recent alerts"
        else
            echo "Alert log not found"
        fi
    else
        echo "Metrics file not found at /var/log/ddos_inspector/ddos_inspector_stats"
        echo "Check if DDoS Inspector is running"
    fi
    
    echo ""
    echo "Press Ctrl+C to exit"
    sleep 5
done
EOF

chmod +x ~/monitor_ddos.sh

# Run the monitor
~/monitor_ddos.sh
```

### Log Monitoring Setup

```bash
# Set up log rotation for Snort logs
sudo tee /etc/logrotate.d/snort-ddos << 'EOF'
/var/log/snort/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 644 snort snort
    postrotate
        /bin/kill -HUP `cat /var/run/snort.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
EOF

# Test log rotation configuration
sudo logrotate -d /etc/logrotate.d/snort-ddos
```

---

## Comprehensive Testing

Test your installation with safe, controlled attack simulations:

### SYN Flood Testing

```bash
# Basic SYN flood test
echo "Starting SYN flood test..."
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --port 80 --duration 15 --rate 100

# Wait for detection
sleep 10

# Check results
echo "=== SYN Flood Test Results ==="
echo "Alerts generated: $(grep -c "SYN_FLOOD" /var/log/snort/alert 2>/dev/null || echo "0")"

# Check if IP was blocked
if sudo nft list set inet filter ddos_ip_set 2>/dev/null | grep -q "127.0.0.1"; then
    echo "IP blocking working (nftables)"
elif sudo iptables -L ddos_chain 2>/dev/null | grep -q "127.0.0.1"; then
    echo "IP blocking working (iptables)"
else
    echo "IP blocking may not be working"
fi
```

### HTTP Flood Testing

```bash
# HTTP flood test (Slowloris-style)
echo "Starting HTTP flood test..."
sudo ./scripts/run_slowloris.sh --target 127.0.0.1 --port 80 --duration 15 --connections 50

# Wait for detection
sleep 10

# Check results
echo "=== HTTP Flood Test Results ==="
echo "Alerts generated: $(grep -c "HTTP_FLOOD\|SLOWLORIS" /var/log/snort/alert 2>/dev/null || echo "0")"

# Check attack statistics
grep "http_flood_detected\|slowloris_detected" /var/log/ddos_inspector/ddos_inspector_stats 2>/dev/null || echo "No HTTP flood statistics found"
```

---

## What's Next?

Congratulations! You now have a working DDoS Inspector installation. Choose your next step based on your goals:

### For Production Deployment
1. **[Configuration Guide](../configuration/)** - Optimize settings for your environment
2. **[Architecture Guide](../architecture/)** - Understand the system design
3. **[Deployment Guide](../deployment/)** - Production deployment options

### For Monitoring and Operations
1. **[Monitoring Guide](../monitoring/)** - Set up comprehensive monitoring
2. **[Troubleshooting Guide](../troubleshooting/)** - Solve common issues
3. **[Testing Guide](../testing/)** - Advanced testing procedures

### For Development and Customization
1. **[Development Guide](../development/)** - Contributing and customization
2. **[API Reference](../development/api-reference.md)** - Technical documentation
3. **[Architecture Guide](../architecture/)** - System internals

---

## Need Help?

If you encounter any issues during installation:

1. **First**: Check our [Troubleshooting Guide](../troubleshooting/) for common solutions
2. **Logs**: Examine system logs with `sudo journalctl -u snort-ddos -f`
3. **Community**: Ask questions in [GitHub Discussions](https://github.com/hung-qt/ddos_inspector/discussions)
4. **Issues**: Report bugs in [GitHub Issues](https://github.com/hung-qt/ddos_inspector/issues)
5. **Direct**: Email us at adhhp.research@fpt.edu.vn

---

**Welcome to the DDoS Inspector community!** You're now protecting your network with intelligent, automated DDoS detection and mitigation.

**Next Recommended Step**: [Configuration Guide](../configuration/) to optimize your setup.