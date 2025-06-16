# DDoS Inspector - Deployment & Management Scripts

This folder contains all the deployment, testing, and management scripts for the DDoS Inspector system.

## Available Scripts Overview

| Script | Purpose | Sudo Required | Key Features |
|--------|---------|---------------|--------------|
| `deploy.sh` | **Main deployment script** | Yes | System service, plugin installation |
| `deploy_docker.sh` | Container deployment | No | Full monitoring stack |
| `deploy_host.sh` | Host-based deployment | Yes | Native installation |
| `install_dependencies.sh` | System dependencies | **Yes** | Auto-detection, package management |
| `build_project.sh` | Project compilation | No | Debug/Release builds |
| `run_tests.sh` | Test suite runner | No | Unit, integration, performance tests |
| `run_syn_flood.sh` | SYN flood simulation | No | Attack testing |
| `run_slowloris.sh` | Slowloris simulation | No | HTTP attack testing |
| `nftables_rules.sh` | Firewall management | **Yes** | Dynamic IP blocking |
| `release.sh` | Release packaging | No | Binary distribution |
| `prepare_for_github.sh` | Repository cleanup | No | Submission preparation |
| `common_functions.sh` | Shared utilities | - | Helper functions |

## Primary Deployment Scripts

### `deploy.sh` - Main System Deployment (Recommended)

**The primary deployment script for production systems.**

```bash
# Standard deployment
sudo ./scripts/deploy.sh

# Service management
sudo ./scripts/deploy.sh --start
sudo ./scripts/deploy.sh --stop
sudo ./scripts/deploy.sh --restart
sudo ./scripts/deploy.sh --status
sudo ./scripts/deploy.sh --logs

# Testing and validation
sudo ./scripts/deploy.sh --test-config
sudo ./scripts/deploy.sh --enable
sudo ./scripts/deploy.sh --disable
```

**What it accomplishes:**
- [INSTALL] Builds and installs the DDoS Inspector plugin
- [CONFIG] Configures Snort 3 integration
- [SERVICE] Sets up systemd service (`snort-ddos-inspector`)
- [FIREWALL] Configures nftables firewall rules
- [LOGGING] Creates log directories and permissions
- [VALIDATE] Validates installation and configuration

**Output locations:**
- Plugin: `/usr/local/lib/snort/ddos_inspector.so`
- Config: `/etc/snort/snort_ddos_config.lua`
- Service: `/etc/systemd/system/snort-ddos-inspector.service`
- Logs: `/var/log/snort/`

### `deploy_docker.sh` - Container Deployment

**Deploys the complete monitoring stack with Docker.**

```bash
# Full monitoring stack (Prometheus + Grafana + ELK)
./scripts/deploy_docker.sh --mode full --interface eth0 --privileged

# Core DDoS detection only
./scripts/deploy_docker.sh --mode core --interface eth0 --privileged

# Monitoring dashboard only
./scripts/deploy_docker.sh --mode monitoring --dashboard

# Management commands
./scripts/deploy_docker.sh --stop
./scripts/deploy_docker.sh --down
./scripts/deploy_docker.sh --logs
./scripts/deploy_docker.sh --uninstall
```

**Deployment modes:**
- `full` - Complete stack (DDoS + Monitoring + ELK)
- `core` - DDoS detection only
- `monitoring` - Metrics and dashboards only

**Access points after deployment:**
- Grafana: `http://localhost:3000` (admin/ddos_inspector_2025)
- Prometheus: `http://localhost:9090`
- Kibana: `http://localhost:5601`
- AlertManager: `http://localhost:9093`

### `deploy_host.sh` - Native Host Deployment

**Direct host deployment without containers.**

```bash
# Basic host deployment
sudo ./scripts/deploy_host.sh

# Skip dependency checks
./scripts/deploy_host.sh --skip-deps

# Service mode
./scripts/deploy_host.sh --service
```

## Dependencies & Build Scripts

### `install_dependencies.sh` - System Dependencies Manager

**Installs all required system components automatically.**

```bash
# Install all dependencies (run as root)
sudo ./scripts/install_dependencies.sh

# Check what would be installed
./scripts/install_dependencies.sh --dry-run
```

**Dependencies installed:**
- **Snort 3** (3.1.0+) with development headers
- **Build tools**: GCC, CMake, pkg-config, autotools
- **Network tools**: nftables, hping3, tcpdump, netstat
- **Container tools**: Docker, Docker Compose
- **Development libraries**: libdaq, libdnet, libpcap, libpcre
- **System utilities**: systemd, logrotate

**Platform support:**
- Ubuntu 18.04+ / Debian 10+
- CentOS 8+ / RHEL 8+
- Fedora 32+

### `build_project.sh` - Project Compiler

**Compiles the DDoS Inspector from source code.**

```bash
# Standard release build
./scripts/build_project.sh

# Debug build with symbols
./scripts/build_project.sh --debug

# Clean build
./scripts/build_project.sh --clean

# Verbose compilation
./scripts/build_project.sh --verbose
```

**Build outputs:**
- `build/libddos_inspector.so` - Main plugin library
- `build/libddos_core.a` - Core static library
- `build/unit_tests` - Test executables
- `build/test_*` - Individual test programs

## Testing & Simulation Scripts

### `run_tests.sh` - Comprehensive Test Suite

**Runs the complete validation test suite (350+ test cases).**

```bash
# Run all tests
./scripts/run_tests.sh

# Specific test categories
./scripts/run_tests.sh --unit           # Unit tests only
./scripts/run_tests.sh --integration    # Integration tests
./scripts/run_tests.sh --performance    # Performance benchmarks
./scripts/run_tests.sh --realistic      # Real attack scenarios

# Test options
./scripts/run_tests.sh --verbose        # Detailed output
./scripts/run_tests.sh --parallel       # Parallel execution
./scripts/run_tests.sh --coverage       # Code coverage analysis
```

**Test components:**
- **Unit tests**: Core algorithm validation
- **Integration tests**: Snort plugin integration
- **Performance tests**: Latency and throughput
- **Attack simulation**: Real DDoS scenarios
- **Stress tests**: High load conditions

### `run_syn_flood.sh` - SYN Flood Attack Simulator

**Generates SYN flood attacks for testing detection algorithms.**

```bash
# Basic SYN flood test
./scripts/run_syn_flood.sh --target 192.168.1.100

# Custom attack parameters
./scripts/run_syn_flood.sh \
    --target 192.168.1.100 \
    --port 80 \
    --rate 1000 \
    --duration 60 \
    --source-randomization

# Localhost testing
./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30
```

**Parameters:**
- `--target <ip>` - Target IP address
- `--port <port>` - Target port (default: 80)
- `--rate <pps>` - Packets per second (default: flood rate)
- `--duration <sec>` - Attack duration (default: 30s)
- `--source-randomization` - Randomize source IPs
- `--interface <dev>` - Source interface

### `run_slowloris.sh` - Slowloris Attack Simulator

**Simulates slow HTTP (Slowloris) attacks for behavioral testing.**

```bash
# Basic Slowloris attack
./scripts/run_slowloris.sh --target 192.168.1.100

# Advanced configuration
./scripts/run_slowloris.sh \
    --target 192.168.1.100 \
    --port 80 \
    --connections 500 \
    --duration 120 \
    --slow-headers

# HTTPS testing
./scripts/run_slowloris.sh --target 192.168.1.100 --port 443 --ssl
```

**Parameters:**
- `--target <ip>` - Target web server
- `--port <port>` - Target port (default: 80)
- `--connections <num>` - Concurrent connections (default: 200)
- `--duration <sec>` - Attack duration (default: 60s)
- `--slow-headers` - Send partial HTTP headers
- `--ssl` - Use HTTPS connections

## System Management Scripts

### `nftables_rules.sh` - Firewall Rules Manager

**Manages dynamic nftables rules for IP blocking.**

```bash
# Setup firewall rules
sudo ./scripts/nftables_rules.sh --setup

# List blocked IPs
sudo ./scripts/nftables_rules.sh --list

# Remove specific IP
sudo ./scripts/nftables_rules.sh --remove-ip 192.168.1.100

# Clear all blocked IPs
sudo ./scripts/nftables_rules.sh --clear

# Backup/restore rules
sudo ./scripts/nftables_rules.sh --backup
sudo ./scripts/nftables_rules.sh --restore /path/to/backup
```

**Firewall capabilities:**
- Dynamic IP set management
- Automatic rule cleanup
- Backup and restore functionality
- IPv4/IPv6 dual-stack support
- Integration with DDoS Inspector plugin

### `release.sh` - Release Package Creator

**Creates distribution packages with binaries and documentation.**

```bash
# Create standard release
./scripts/release.sh

# Version-tagged release
./scripts/release.sh --version 2.0.0

# Include debug information
./scripts/release.sh --debug

# Create source distribution
./scripts/release.sh --source-only
```

**Release contents:**
- Compiled binaries (`libddos_inspector.so`)
- Configuration files
- Documentation
- Installation scripts
- Test suites

### `prepare_for_github.sh` - Repository Preparation

**Prepares repository for GitHub submission and distribution.**

```bash
# Standard preparation
./scripts/prepare_for_github.sh

# Include build artifacts
./scripts/prepare_for_github.sh --include-build

# Create archive
./scripts/prepare_for_github.sh --archive

# Validate repository
./scripts/prepare_for_github.sh --validate
```

## Complete Deployment Workflows

### Fresh Installation (Production)

```bash
# 1. Install system dependencies
sudo ./scripts/install_dependencies.sh

# 2. Deploy DDoS Inspector
sudo ./scripts/deploy.sh

# 3. Start the service
sudo ./scripts/deploy.sh --start

# 4. Verify installation
sudo ./scripts/deploy.sh --status
sudo snort --show-plugins | grep ddos_inspector

# 5. Test detection
./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30

# 6. Monitor results
watch -n 1 \'cat /var/log/ddos_inspector/ddos_inspector_stats\'
sudo nft list set inet filter ddos_ip_set
```

### Development Environment Setup

```bash
# 1. Install dependencies
sudo ./scripts/install_dependencies.sh

# 2. Build project
./scripts/build_project.sh --debug

# 3. Run test suite
./scripts/run_tests.sh --verbose

# 4. Deploy for testing
sudo ./scripts/deploy.sh

# 5. Run attack simulations
./scripts/run_syn_flood.sh --target 127.0.0.1
./scripts/run_slowloris.sh --target 127.0.0.1

# 6. Analyze results
tail -f /var/log/snort/alert
```

### Docker Monitoring Stack

```bash
# 1. Deploy full monitoring stack
./scripts/deploy_docker.sh --mode full --interface eth0 --privileged

# 2. Access dashboards
# Grafana: http://localhost:3000
# Prometheus: http://localhost:9090
# Kibana: http://localhost:5601

# 3. Test detection
./scripts/run_syn_flood.sh --target $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ddos_inspector)

# 4. View metrics
curl http://localhost:9091/metrics
docker logs -f ddos_inspector
```

## Monitoring & Diagnostics

### Real-time Monitoring

```bash
# Live statistics
watch -n 1 'cat /var/log/ddos_inspector/ddos_inspector_stats'

# Service status
sudo systemctl status snort-ddos-inspector

# Container status (if using Docker)
docker ps --filter name=ddos_
docker stats ddos_inspector

# Firewall status
sudo nft list set inet filter ddos_ip_set
```

### Log Analysis

```bash
# Snort alerts
tail -f /var/log/snort/alert

# System logs
journalctl -u snort-ddos-inspector -f

# Attack logs
tail -f /var/log/snort/ddos_attacks.log

# Performance logs
tail -f /var/log/snort/ddos_performance.log
```

### Performance Metrics

```bash
# Detection latency
grep "processing_time" /var/log/snort/ddos_performance.log

# Memory usage
ps aux | grep snort
cat /proc/$(pgrep snort)/status | grep VmRSS

# CPU usage
top -p $(pgrep snort)
```

## Troubleshooting Guide

### Common Issues

**1. Plugin not loading**
```bash
# Check plugin path
sudo snort --show-plugins | grep ddos_inspector

# Verify library dependencies
ldd /usr/local/lib/snort/ddos_inspector.so

# Test configuration
sudo snort -c /etc/snort/snort_ddos_config.lua -T
```

**2. Permission errors**
```bash
# Fix file permissions
sudo chown -R snort:snort /var/log/snort/
sudo chmod 755 /usr/local/lib/snort/ddos_inspector.so

# Fix nftables permissions
sudo usermod -a -G nftables snort
```

**3. Network interface issues**
```bash
# List available interfaces
ip link show

# Test interface
sudo tcpdump -i eth0 -c 10

# Manual interface specification
export SNORT_INTERFACE=your_interface
sudo ./scripts/deploy.sh
```

**4. Docker deployment issues**
```bash
# Check Docker daemon
sudo systemctl status docker

# Reset Docker environment
docker system prune -a
./scripts/deploy_docker.sh --down
./scripts/deploy_docker.sh --mode full --interface eth0 --privileged
```

### Debug Mode

```bash
# Enable debug logging
export DEBUG=1
sudo ./scripts/deploy.sh

# Verbose test execution
./scripts/run_tests.sh --verbose --debug

# Container debugging
docker exec -it ddos_inspector /bin/bash
```

## Related Documentation

- **[Main README](../README.md)** - Project overview and quick start
- **[Configuration Guide](../docs/Configuration%20guide/README.md)** - Detailed configuration options
- **[Docker Deployment Guide](../docs/Docker%20deployment%20guide/README.md)** - Container deployment
- **[Snort 3 Integration](../docs/Snort%203%20Integration%20guide/README.md)** - Plugin integration
- **[Test Running Guide](../docs/Test%20Running%20Guide/README.md)** - Testing procedures
- **[Design Specification](../docs/design_spec.md)** - Technical architecture

---

## Best Practices

### Security Considerations
- Always run with minimal required privileges
- Regularly update firewall rules and blocked IP lists
- Monitor for false positives in production
- Implement proper log rotation and retention

### Performance Optimization
- Tune detection thresholds for your environment
- Monitor system resource usage
- Use appropriate test parameters for your network capacity
- Regular performance validation with realistic traffic

### Operational Guidelines
- Test all deployments in staging environment first
- Implement proper backup and recovery procedures
- Monitor detection accuracy and adjust thresholds
- Keep documentation updated with environment-specific configurations

---

## Support & Troubleshooting

1. **Check logs first**: Most issues are logged with detailed error messages
2. **Verify prerequisites**: Ensure all dependencies are properly installed
3. **Test incrementally**: Use individual scripts to isolate issues
4. **Review configuration**: Check Snort and nftables configurations
5. **Consult documentation**: Reference the comprehensive docs in `/docs/`

For additional support, refer to the project documentation or open an issue on GitHub.

---

**Quick Start**: New to DDoS Inspector? Run `sudo ./scripts/deploy.sh` to get started!