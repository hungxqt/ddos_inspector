# 🐳 Docker Troubleshooting Guide - DDoS Inspector

## Overview
This guide addresses common Docker-related issues encountered when building and deploying the DDoS Inspector project, including build failures, network connectivity problems, and runtime issues.

## 🚨 Common Build Issues

### 1. Docker Connectivity/Proxy Issues

**Symptoms:**
```bash
Error response from daemon: failed to resolve reference "docker.io/library/ubuntu:24.04"
proxyconnect tcp: dial tcp: lookup http.docker.internal on 192.168.65.7:53: i/o timeout
```

**Root Cause:** Docker Desktop proxy configuration issues, especially in WSL2 environments.

**Solutions:**

#### Option A: Disable Docker Desktop Proxy (Recommended)
1. Open Docker Desktop on Windows
2. Go to Settings → Resources → Proxies
3. Disable "Manual proxy configuration" 
4. Click "Apply & Restart"

#### Option B: Add Docker Internal Hostnames
```bash
# Add Docker internal hostnames to /etc/hosts
sudo tee -a /etc/hosts << 'EOF'

# Docker Desktop internal hostnames
127.0.0.1       host.docker.internal
127.0.0.1       gateway.docker.internal
127.0.0.1       http.docker.internal
127.0.0.1       hubproxy.docker.internal
EOF
```

#### Option C: Use Alternative Base Images
```dockerfile
# In Dockerfile, try different Ubuntu sources
FROM ubuntu:22.04 AS builder
# OR use cached images
FROM local-ubuntu:24.04 AS builder
```

### 2. Multi-Stage Build Failures

**Symptoms:**
```bash
ERROR [builder 15/20] RUN wget https://github.com/snort3/snort3/archive/refs/tags/3.8.1.0.tar.gz
failed to solve: process "/bin/sh -c wget ..." did not complete successfully
```

**Solutions:**

#### Build with No Cache
```bash
# Force rebuild without cache
docker build --no-cache -t ddos_inspector:latest -f docker/Dockerfile .

# Build specific stage only
docker build --target builder -t ddos_inspector:builder -f docker/Dockerfile .
```

#### Use Build Arguments for Debugging
```bash
# Add debug flags to Dockerfile
docker build --build-arg DEBIAN_FRONTEND=noninteractive \
             --build-arg VERBOSE=1 \
             -t ddos_inspector:latest -f docker/Dockerfile .
```

### 3. Snort 3 Compilation Failures

**Symptoms:**
```bash
TCMalloc build failed, retrying without TCMalloc...
make: *** [Makefile:xxx] Error 2
```

**Solutions:**

#### Modify Dockerfile Build Strategy
```dockerfile
# Add fallback compilation without TCMalloc
RUN cd /tmp/snort3-3.8.1.0 \
    && rm -rf build \
    && ./configure_cmake.sh --prefix=/usr/local/snort3 \
        --enable-static-daq \
        --enable-large-pcap \
        --enable-debug-msgs \
        --with-daq-includes=/usr/local/include \
        --with-daq-libraries=/usr/local/lib \
    && cd build \
    && make -j$(nproc) \
    && make install
```

#### Check Available Resources
```bash
# Ensure sufficient resources for compilation
docker system df
docker system prune -f

# Build with limited parallelism
docker build --build-arg MAKEFLAGS="-j2" -t ddos_inspector:latest .
```

## 🌐 Network and Runtime Issues

### 4. Container Network Access Problems

**Symptoms:**
```bash
# Container can't access host network interfaces
ERROR: Interface eth0 not found
```

**Solutions:**

#### Host Network Mode (Recommended for Production)
```bash
# Deploy with host networking
./scripts/deploy_docker.sh --mode host --interface eth0 --privileged
```

#### Check Interface Availability
```bash
# List available interfaces inside container
docker exec ddos_inspector ip link show

# Verify host interfaces
ip link show

# Map specific interface
docker run --rm --network host ddos_inspector ip addr show eth0
```

### 5. Privileged Mode and Firewall Issues

**Symptoms:**
```bash
# Firewall operations fail
nft: Operation not permitted
```

**Solutions:**

#### Enable Privileged Mode
```bash
# Ensure privileged flag is set
docker run --privileged --network host ddos_inspector

# Check container capabilities
docker exec ddos_inspector capsh --print
```

#### Verify nftables Support
```bash
# Test nftables inside container
docker exec ddos_inspector nft list tables

# Install nftables if missing
docker exec ddos_inspector apt-get update && apt-get install -y nftables
```

### 6. Plugin Loading Failures

**Symptoms:**
```bash
# Snort can't find the plugin
snort: error while loading shared libraries: ddos_inspector.so: cannot open shared object file
```

**Solutions:**

#### Verify Plugin Installation
```bash
# Check plugin exists and has correct permissions
docker exec ddos_inspector ls -la /usr/local/lib/snort3_extra_plugins/ddos_inspector.so

# Check library dependencies
docker exec ddos_inspector ldd /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
```

#### Fix Library Path Issues
```bash
# Update library cache
docker exec ddos_inspector ldconfig

# Set library path explicitly
docker exec ddos_inspector env LD_LIBRARY_PATH=/usr/local/snort3/lib:/usr/local/lib snort --show-plugins
```

## 🔧 Configuration and Testing Issues

### 7. Configuration Validation Failures

**Symptoms:**
```bash
# Snort configuration test fails
FATAL: /etc/snort/snort_ddos_config.lua:xx: unknown parameter
```

**Solutions:**

#### Test Configuration Syntax
```bash
# Test Lua syntax
docker exec ddos_inspector lua -c /etc/snort/snort_ddos_config.lua

# Test Snort configuration
docker exec ddos_inspector snort -c /etc/snort/snort_ddos_config.lua -T
```

#### Debug Configuration Loading
```bash
# Run with verbose output
docker exec ddos_inspector snort -c /etc/snort/snort_ddos_config.lua -T --verbose

# Check plugin loading specifically
docker exec ddos_inspector snort --show-plugins | grep ddos_inspector
```

### 8. Health Check Failures

**Symptoms:**
```bash
# Container health checks failing
Health check failed: exit code 1
```

**Solutions:**

#### Debug Health Check
```bash
# Run health check command manually
docker exec ddos_inspector snort --version 2>&1 | grep -q "Version 3.8.1.0"
docker exec ddos_inspector test -f /tmp/ddos_inspector_stats
docker exec ddos_inspector test -f /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
```

#### Modify Health Check
```dockerfile
# Simplified health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD snort --version || exit 1
```

## 📊 Performance and Resource Issues

### 9. Memory and CPU Problems

**Symptoms:**
```bash
# Container OOM kills or slow performance
docker: Error response from daemon: OCI runtime create failed
```

**Solutions:**

#### Set Resource Limits
```bash
# Deploy with resource limits
docker run --memory=4g --cpus=2 ddos_inspector

# Monitor resource usage
docker stats --no-stream ddos_inspector
```

#### Optimize Build Process
```dockerfile
# Use smaller base images in multi-stage build
FROM ubuntu:24.04-slim AS builder

# Limit parallel compilation
RUN make -j2 && make install
```

### 10. Volume Mount Issues

**Symptoms:**
```bash
# Log files not accessible or permission denied
mkdir: cannot create directory '/var/log/snort': Permission denied
```

**Solutions:**

#### Fix Volume Permissions
```bash
# Create directories with correct permissions
sudo mkdir -p /var/log/snort
sudo chown 1000:1000 /var/log/snort

# Or use named volumes
docker volume create snort_logs
docker run -v snort_logs:/var/log/snort ddos_inspector
```

## 🛠️ Advanced Debugging Techniques

### Interactive Debugging

#### Enter Container for Debugging
```bash
# Enter running container
docker exec -it ddos_inspector bash

# Start container with shell override
docker run --rm -it --entrypoint bash ddos_inspector

# Run container in debug mode
docker run --rm -it ddos_inspector test
```

#### Build Stage Debugging
```bash
# Debug specific build stage
docker build --target builder --tag ddos_inspector:debug .
docker run --rm -it ddos_inspector:debug bash

# Copy files from failed container
docker cp ddos_inspector:/tmp/build.log ./debug_build.log
```

### Log Analysis

#### Container Logs
```bash
# View container logs with timestamps
docker logs -t --tail 100 ddos_inspector

# Follow logs in real-time
docker logs -f ddos_inspector

# Filter logs by level
docker logs ddos_inspector 2>&1 | grep -i error
```

#### System Logs
```bash
# Check Docker daemon logs
sudo journalctl -u docker.service --tail 50

# Monitor system resources
htop
iostat 1
```

## 🚀 Quick Fixes and Workarounds

### Emergency Recovery

#### Reset Docker Environment
```bash
# Stop all containers
docker stop $(docker ps -q)

# Remove all containers
docker rm $(docker ps -aq)

# Clean system
docker system prune -af
docker volume prune -f
```

#### Rebuild from Scratch
```bash
# Complete rebuild script
#!/bin/bash
set -e

echo "🧹 Cleaning Docker environment..."
docker stop ddos_inspector 2>/dev/null || true
docker rm ddos_inspector 2>/dev/null || true
docker rmi ddos_inspector:latest 2>/dev/null || true

echo "🔧 Building fresh image..."
docker build --no-cache -t ddos_inspector:latest -f docker/Dockerfile .

echo "🚀 Deploying container..."
./scripts/deploy_docker.sh --mode host --interface eth0 --privileged

echo "✅ Recovery complete!"
```

### Alternative Deployment Methods

#### Use Docker Compose for Complex Setups
```bash
# Deploy with monitoring stack
SNORT_INTERFACE=eth0 docker-compose up -d

# Scale services if needed
docker-compose up --scale ddos-inspector=2 -d
```

#### Fallback to Manual Installation
```bash
# If Docker continues to fail, use manual installation
sudo ./scripts/install_dependencies.sh
./scripts/build_project.sh
sudo ./scripts/deploy.sh
```

## 📋 Troubleshooting Checklist

Before deploying, verify:

- [ ] Docker daemon is running: `sudo systemctl status docker`
- [ ] Sufficient disk space: `df -h`
- [ ] Network connectivity: `ping 8.8.8.8`
- [ ] No proxy issues: `docker pull hello-world`
- [ ] Interface exists: `ip link show eth0`
- [ ] User has Docker permissions: `docker ps`
- [ ] nftables available: `which nft`
- [ ] Privileged mode allowed by security policy

## 📞 Getting Help

### Diagnostic Information Collection

When reporting issues, collect:

```bash
#!/bin/bash
echo "=== Docker Environment ==="
docker version
docker info
echo ""

echo "=== Container Status ==="
docker ps -a | grep ddos
echo ""

echo "=== Container Logs ==="
docker logs --tail 50 ddos_inspector
echo ""

echo "=== Image Information ==="
docker images | grep ddos_inspector
echo ""

echo "=== System Resources ==="
free -h
df -h
echo ""

echo "=== Network Interfaces ==="
ip link show
echo ""

echo "=== Docker Networks ==="
docker network ls
```

Save this diagnostic output when seeking help or reporting issues.

## 🔗 Related Documentation

- [Docker Deployment Guide](./README.md)
- [Build Troubleshooting](../Cmake%20build%20troubleshooting/README.md)
- [Snort 3 Integration Guide](../Snort%203%20Integration%20guide/README.md)
- [Configuration Guide](../Configuration%20guide/README.md)

---

**Last Updated:** June 2025  
**Version:** 1.0  
**Compatibility:** Docker Engine 20.10+, Docker Desktop 4.0+