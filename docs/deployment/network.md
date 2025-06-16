# DDoS Inspector Docker Deployment Guide

## Overview
This guide explains how to deploy and run the DDoS Inspector with configurable network interfaces using Docker and Docker Compose.

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Docker**: Version 24.0+ 
- **Docker Compose**: Version 2.0+
- **RAM**: Minimum 4GB, Recommended 8GB+
- **CPU**: 2+ cores recommended
- **Network**: Access to network interfaces for packet capture

### Required Permissions
- Root or sudo access for privileged container operations
- Network administration capabilities (NET_ADMIN, NET_RAW)

## Network Interface Configuration

The DDoS Inspector now supports flexible network interface configuration through multiple methods:

### Method 1: Environment Variables (Recommended)

#### Using docker-compose with .env file:
Create a `.env` file in your project root:
```bash
# Network interface configuration
NETWORK_INTERFACE=wlan0
```

Then run:
```bash
docker-compose up -d
```

#### Direct environment variable:
```bash
NETWORK_INTERFACE=enp0s3 docker-compose up -d
```

### Method 2: Docker Run Commands

#### Auto-detection (Default):
```bash
docker run --privileged --network host ddos_inspector:latest
```

#### Specific interface via environment:
```bash
docker run --privileged --network host \
  -e NETWORK_INTERFACE=wlan0 \
  ddos_inspector:latest
```

#### Specific interface via command arguments:
```bash
docker run --privileged --network host \
  ddos_inspector:latest -i wlan0 -A alert_fast
```

### Method 3: Docker Compose Override

Edit the `command` section in docker-compose.yml:
```yaml
services:
  ddos-inspector:
    # ... other configurations
    command: ["-i", "your_interface_name", "-A", "alert_fast"]
```

## Available Network Interface Options

| Interface Type | Example Names | Description |
|---------------|---------------|-------------|
| Ethernet | `eth0`, `enp0s3`, `ens33` | Wired network connections |
| Wireless | `wlan0`, `wlp2s0` | Wireless network connections |
| Virtual | `docker0`, `br-*` | Docker/bridge interfaces |
| Loopback | `lo` | Local loopback (not recommended) |
| Auto | `auto` | Auto-detect first available interface |

## Deployment Steps

### Step 1: Clone and Prepare
```bash
git clone <your-repo>
cd ddos-inspector
```

### Step 2: Check Available Interfaces
List your system's network interfaces:
```bash
ip link show
# or
ifconfig -a
```

### Step 3: Configure Interface
Choose one of the configuration methods above based on your needs.

### Step 4: Build and Deploy

#### Full Stack Deployment:
```bash
# Build the image
docker-compose build

# Deploy all services
docker-compose up -d

# Check status
docker-compose ps
```

#### DDoS Inspector Only:
```bash
# Build and run only the main service
docker-compose up -d ddos-inspector

# Follow logs
docker-compose logs -f ddos-inspector
```

## Configuration Examples

### Example 1: Home Network (WiFi)
```bash
# Check your WiFi interface
ip link show | grep wlan

# Set environment and run
NETWORK_INTERFACE=wlan0 docker-compose up -d
```

### Example 2: Server Environment (Ethernet)
```bash
# For typical server ethernet
NETWORK_INTERFACE=eth0 docker-compose up -d

# For Ubuntu server with predictable names
NETWORK_INTERFACE=enp0s3 docker-compose up -d
```

### Example 3: Virtual Machine
```bash
# Common VM interface patterns
NETWORK_INTERFACE=ens33 docker-compose up -d  # VMware
NETWORK_INTERFACE=enp0s8 docker-compose up -d  # VirtualBox
```

### Example 4: Auto-Detection
```bash
# Let the system choose the best interface
NETWORK_INTERFACE=auto docker-compose up -d
# or simply
docker-compose up -d
```

## Monitoring and Verification

### Check Container Status
```bash
# View all services
docker-compose ps

# Check DDoS Inspector logs
docker-compose logs -f ddos-inspector

# Check if interface is detected correctly
docker-compose logs ddos-inspector | grep "Using network interface"
```

### Access Web Interfaces
- **Grafana Dashboard**: http://localhost:3000 (admin/ddos_inspector_2025)
- **Prometheus Metrics**: http://localhost:9090
- **Kibana Logs**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200

### Validate Network Capture
```bash
# Check if Snort is capturing packets
docker exec ddos_inspector snort --version

# View real-time stats
docker exec ddos_inspector cat /var/log/ddos_inspector/ddos_inspector_stats
```

## Troubleshooting

### Interface Not Found
```bash
# Error: Interface 'wlan1' not found!
# Solution: Check available interfaces
docker exec ddos_inspector ip link show

# Or run with auto-detection
NETWORK_INTERFACE=auto docker-compose up -d
```

### Permission Issues
```bash
# Ensure privileged mode is enabled
docker-compose down
docker-compose up -d --force-recreate
```

### No Packet Capture
```bash
# Check if interface is UP
docker exec ddos_inspector ip link show <interface_name>

# Bring interface up if needed
docker exec ddos_inspector ip link set <interface_name> up
```

### Container Won't Start
```bash
# Check detailed logs
docker-compose logs ddos-inspector

# Restart with fresh build
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Advanced Configuration

### Custom Snort Arguments
Override the default command with additional Snort options:
```yaml
services:
  ddos-inspector:
    command: ["-i", "wlan0", "-A", "alert_fast", "-c", "/etc/snort/custom.lua"]
```

### Multiple Interface Monitoring
For monitoring multiple interfaces, run separate containers:
```bash
# Interface 1
NETWORK_INTERFACE=eth0 docker-compose -f docker-compose.yml -p ddos-eth0 up -d ddos-inspector

# Interface 2  
NETWORK_INTERFACE=wlan0 docker-compose -f docker-compose.yml -p ddos-wlan0 up -d ddos-inspector
```

### Performance Tuning
Adjust resource limits in docker-compose.yml:
```yaml
services:
  ddos-inspector:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.5'
```

## Security Considerations

1. **Privileged Mode**: Required for packet capture but increases security risk
2. **Host Network**: Necessary for interface access but reduces isolation
3. **Firewall Rules**: The container applies iptables/nftables rules automatically
4. **Log Access**: Ensure log directories have appropriate permissions

## Maintenance

### Update and Restart
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Cleanup
```bash
# Stop all services
docker-compose down

# Remove volumes (careful - deletes data!)
docker-compose down -v

# Clean up images
docker system prune -f
```

## Support

For issues or questions:
1. Check container logs: `docker-compose logs -f ddos-inspector`
2. Verify interface availability: `ip link show`
3. Ensure proper permissions and privileged mode
4. Review network configuration and firewall settings