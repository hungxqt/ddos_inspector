# 🏠 Host Network Monitoring Deployment Guide

## 🎯 Overview

This deployment mode allows your DDoS Inspector plugin to run inside Docker containers while monitoring your **host machine's network interface** (eth0) and integrating with the **host's firewall system**. This is the recommended approach for production environments.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HOST MACHINE                         │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────┐ │
│  │   eth0      │────│ Host Network │────│ nftables    │ │
│  │ (monitored) │    │   Stack      │    │ (firewall)  │ │
│  └─────────────┘    └──────────────┘    └─────────────┘ │
│         │                   │                   ▲       │
│         │                   │                   │       │
│    ┌────▼───────────────────▼───────────────────┼─────┐ │
│    │              DOCKER NETWORK                │     │ │
│    │                                            │     │ │
│    │  ┌─────────────────┐                       │     │ │
│    │  │ ddos-inspector  │───────────────────────┘     │ │
│    │  │ (network_mode:  │                             │ │
│    │  │     host)       │                             │ │
│    │  │ • Snort 3       │                             │ │
│    │  │ • DDoS Plugin   │                             │ │
│    │  │ • Packet Capture│                             │ │
│    │  └─────────────────┘                             │ │
│    │                                                  │ │
│    │  ┌─────────────┐  ┌─────────────┐                │ │
│    │  │ Prometheus  │  │   Grafana   │                │ │
│    │  │ (metrics)   │  │ (dashboard) │                │ │
│    │  └─────────────┘  └─────────────┘                │ │
│    └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Deployment

### 1. **Prepare Your Project**
```bash
# Copy your project to the host machine
scp -r ddos_inspector/ user@host-machine:~/
ssh user@host-machine
cd ~/ddos_inspector/
```

### 2. **Deploy with Host Integration**
```bash
# Run the automated host deployment script
sudo ./scripts/deploy_host.sh
```

This script will:
- ✅ Detect your host's network interface (eth0)
- ✅ Setup host-level nftables infrastructure
- ✅ Configure Docker containers with host network access
- ✅ Deploy the complete monitoring stack

### 3. **Verify Deployment**
```bash
# Check container status
docker ps

# Verify plugin is monitoring host interface
docker logs ddos_inspector | grep "Interface being monitored"

# Check host firewall setup
sudo nft list set inet filter ddos_ip_set

# Monitor real-time stats
watch cat ./data/metrics.log
```

## 🛡️ How Host Firewall Integration Works

### **Container to Host Communication**
- **Privileged Mode**: Container runs with `privileged: true`
- **Host Network**: Uses `network_mode: host` for direct network access
- **Shared Resources**: Mounts `/proc`, `/sys`, and firewall lock files

### **Firewall Operations**
```bash
# The plugin inside Docker can execute these commands on the HOST:
nft add element inet filter ddos_ip_set { 192.168.1.100 }  # Block IP
nft delete element inet filter ddos_ip_set { 192.168.1.100 }  # Unblock IP
nft list set inet filter ddos_ip_set  # List blocked IPs
```

### **Network Monitoring**
- Snort captures packets directly from host's eth0 interface
- No network namespace isolation - full host network visibility
- Real-time packet analysis with <10ms latency

## 🧪 Testing Your Deployment

### **Test 1: Generate Attack Traffic**
```bash
# From another machine, target your host's IP
hping3 -S -p 80 --flood <your-host-ip>

# Or use the built-in script
./scripts/run_syn_flood.sh --target <your-host-ip> --rate 1000 --duration 60
```

### **Test 2: Monitor Detection**
```bash
# Watch real-time stats
watch cat ./data/metrics.log

# Check detection logs
docker logs -f ddos_inspector | grep "SYN_FLOOD\|blocked"

# View blocked IPs on host firewall
sudo nft list set inet filter ddos_ip_set
```

### **Test 3: Verify Blocking**
```bash
# Try to connect from blocked IP (should fail)
telnet <your-host-ip> 80

# Check if packets are being dropped
sudo tcpdump -i eth0 host <blocked-ip>
```

## 📊 Monitoring Dashboard

Access your monitoring interfaces:
- **Grafana**: http://localhost:3000 (admin/ddos_inspector_2025)
- **Prometheus**: http://localhost:9090
- **Kibana**: http://localhost:5601

## 🔧 Configuration

### **Environment Variables**
```bash
# Set specific network interface
export NETWORK_INTERFACE=eth0

# Deploy with custom interface
NETWORK_INTERFACE=ens33 sudo ./scripts/deploy_host.sh
```

### **Custom Configuration**
Edit `snort_ddos_config.lua`:
```lua
ddos_inspector = {
    allow_icmp = true,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = "/app/data/metrics.log"
}
```

## 🚨 Troubleshooting

### **Issue: No Packets Being Captured**
```bash
# Check interface status
ip link show eth0

# Verify Snort is monitoring correct interface
docker logs ddos_inspector | grep "Interface being monitored"

# Test with tcpdump
sudo tcpdump -i eth0 -c 10
```

### **Issue: Firewall Commands Fail**
```bash
# Check nftables is installed on host
sudo nft --version

# Verify container has proper privileges
docker inspect ddos_inspector | grep -i privileged

# Check capability mounts
docker inspect ddos_inspector | grep -A 10 "CapAdd"
```

### **Issue: Stats File Not Updated**
```bash
# Check file permissions
ls -la ./data/metrics.log

# Verify container can write to data directory
docker exec ddos_inspector touch /app/data/test_write
```

## 🎯 Production Considerations

1. **Security**: The container runs in privileged mode with host network access
2. **Performance**: Direct host interface monitoring provides optimal performance
3. **Firewall**: Host-level nftables integration for immediate blocking
4. **Persistence**: Stats and logs are stored on host filesystem
5. **Monitoring**: Full observability stack with Grafana dashboards

## 📝 Manual Commands

```bash
# Start stack
sudo docker-compose up -d

# Stop stack
sudo docker-compose down

# View real-time logs
docker logs -f ddos_inspector

# Check blocked IPs
sudo nft list set inet filter ddos_ip_set

# Clear all blocked IPs
sudo nft flush set inet filter ddos_ip_set

# Restart just the DDoS inspector
docker restart ddos_inspector
```

Your DDoS Inspector is now protecting your host's network interface! 🛡️