# Deployment Guide

This comprehensive guide covers all aspects of deploying DDoS Inspector in production environments, from single-server installations to large-scale distributed deployments.

## Deployment Overview

DDoS Inspector supports multiple deployment patterns to meet different operational requirements, performance needs, and infrastructure constraints.

## Deployment Patterns

### Single Server Deployment
- **Best For**: Small to medium traffic loads, single points of ingress
- **Capacity**: Up to 1 Gbps traffic, 50k concurrent connections
- **Complexity**: Low
- **High Availability**: None

### High Availability Deployment
- **Best For**: Mission-critical applications requiring redundancy
- **Capacity**: Up to 5 Gbps traffic, 250k concurrent connections
- **Complexity**: Medium
- **High Availability**: Active-passive or active-active

### Distributed Deployment
- **Best For**: Large-scale environments, multiple data centers
- **Capacity**: 10+ Gbps traffic, millions of connections
- **Complexity**: High
- **High Availability**: Built-in redundancy

### Cloud-Native Deployment
- **Best For**: Container orchestration platforms, auto-scaling
- **Capacity**: Elastic scaling based on demand
- **Complexity**: Medium to High
- **High Availability**: Platform-managed

## Pre-Deployment Planning

### Capacity Planning

**Traffic Analysis Requirements**:
```bash
# Analyze current traffic patterns
echo "=== Traffic Analysis for Capacity Planning ==="

# Peak traffic rates
echo "Peak packet rate (pps):"
sar -n DEV 1 60 | grep eth0 | awk 'END {print $3 + $4 " packets/sec"}'

# Peak bandwidth utilization
echo "Peak bandwidth (Mbps):"
sar -n DEV 1 60 | grep eth0 | awk 'END {print ($5 + $6) * 8 / 1000000 " Mbps"}'

# Connection tracking requirements
echo "Active connections:"
ss -tuna | wc -l

# Memory requirements estimation
echo "Estimated memory needed:"
echo "Active connections * 150 bytes + Peak IPs * 200 bytes"
```

**Resource Requirements Matrix**:

| Traffic Load | CPU Cores | RAM | Storage | Network |
|--------------|-----------|-----|---------|---------|
| Light (<100 Mbps) | 2-4 | 4-8 GB | 50 GB | 1 Gbps |
| Medium (100 Mbps - 1 Gbps) | 4-8 | 8-16 GB | 100 GB | 1-10 Gbps |
| Heavy (1-5 Gbps) | 8-16 | 16-32 GB | 200 GB | 10+ Gbps |
| Enterprise (5+ Gbps) | 16+ | 32+ GB | 500+ GB | 40+ Gbps |

### Network Architecture Planning

**Single Server Architecture**:
```
Internet → Firewall → Router → DDoS Inspector Server → Internal Network
                                      │
                                   Blocking Rules Applied Here
```

**High Availability Architecture**:
```
Internet → Load Balancer → Primary DDoS Inspector → Internal Network
                      └──→ Secondary DDoS Inspector → Internal Network
                                      │
                              Shared State Storage (Redis/DB)
```

**Distributed Architecture**:
```
Internet → Geographic Load Balancer
              │
              ├─→ Data Center 1 → DDoS Inspector Cluster 1
              ├─→ Data Center 2 → DDoS Inspector Cluster 2
              └─→ Data Center 3 → DDoS Inspector Cluster 3
                                      │
                                Central Management & Analytics
```

## Single Server Deployment

### Production Server Setup

**System Hardening**:
```bash
# System security hardening for production
echo "=== Production System Hardening ==="

# Update system packages
sudo apt update && sudo apt upgrade -y

# Install security updates automatically
sudo apt install -y unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot "false";' | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades

# Configure firewall basics (before DDoS Inspector rules)
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon

# Configure log rotation
sudo tee /etc/logrotate.d/ddos-inspector << 'EOF'
/var/log/snort/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 644 snort snort
    postrotate
        /bin/kill -HUP $(cat /run/snort/snort.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
```

**Performance Optimization**:
```bash
# System performance tuning for DDoS Inspector
echo "=== Performance Optimization ==="

# Kernel network stack tuning
sudo tee -a /etc/sysctl.conf << 'EOF'
# Network performance tuning
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864
net.ipv4.tcp_rmem = 4096 65536 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_congestion_control = bbr

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# IP forwarding (if needed)
net.ipv4.ip_forward = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
EOF

# Apply settings
sudo sysctl -p

# Configure CPU governor for performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Optimize disk I/O scheduler for SSDs
echo noop | sudo tee /sys/block/sda/queue/scheduler
```

**Production Installation**:
```bash
# Production installation with monitoring
cd /opt
sudo git clone https://github.com/hung-qt/ddos_inspector.git
cd ddos_inspector

# Build with production optimizations
mkdir build && cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DENABLE_TESTING=OFF \
    -DENABLE_OPTIMIZATIONS=ON \
    -DENABLE_MONITORING=ON

make -j$(nproc)
sudo make install

# Install systemd service
sudo cp ../scripts/systemd/snort-ddos.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable snort-ddos
```

### Production Configuration

**Production-Optimized Configuration**:
```lua
-- Production DDoS Inspector Configuration
ddos_inspector = {
    -- Core detection parameters (tuned for production)
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    baseline_alpha = 0.01,
    
    -- Attack thresholds (conservative for production)
    syn_flood_threshold = 800,
    http_flood_threshold = 300,
    slowloris_threshold = 300,
    udp_flood_threshold = 600,
    
    -- Performance settings (optimized for production load)
    max_tracked_ips = 200000,
    max_tracked_connections = 100000,
    worker_threads = 6,
    batch_size = 200,
    cleanup_interval = 45,
    memory_cleanup_threshold = 0.75,
    
    -- Blocking configuration (production-safe)
    block_timeout = 900,                -- 15 minutes
    progressive_blocking = true,
    initial_block_time = 120,           -- 2 minutes
    max_block_time = 7200,              -- 2 hours
    block_multiplier = 2,
    
    -- Production whitelisting
    whitelist_ips = {
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "YOUR_OFFICE_NETWORK/24",       -- Replace with actual
        "YOUR_CDN_RANGES",              -- Replace with actual CDN ranges
    },
    
    -- Monitoring and alerting
    metrics_enabled = true,
    metrics_file = "/var/lib/ddos_inspector/metrics",
    log_level = "info",
    log_file = "/var/log/snort/ddos_inspector.log",
    
    -- Integration settings
    use_nftables = true,
    firewall_table = "inet filter",
    firewall_set = "ddos_ip_set",
    
    -- SIEM integration
    siem_enabled = true,
    siem_format = "cef",
    siem_server = "YOUR_SIEM_SERVER",
    siem_port = 514,
}
```

**Firewall Integration Setup**:
```bash
# Production nftables configuration
sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

# Flush existing rules
flush ruleset

# Main filtering table
table inet filter {
    # DDoS IP blocking set
    set ddos_ip_set {
        type ipv4_addr
        size 100000
        timeout 15m
        flags dynamic,timeout
    }
    
    # Whitelisted networks
    set whitelist_set {
        type ipv4_addr
        flags constant
        elements = {
            127.0.0.0/8,
            10.0.0.0/8,
            172.16.0.0/12,
            192.168.0.0/16
        }
    }
    
    # Rate limiting sets
    set syn_rate_limit {
        type ipv4_addr . inet_service
        size 10000
        timeout 10s
        flags dynamic
    }
    
    chain input {
        type filter hook input priority filter; policy accept;
        
        # Allow whitelisted IPs
        ip saddr @whitelist_set accept
        
        # Drop blocked IPs immediately
        ip saddr @ddos_ip_set counter drop
        
        # Allow established connections
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Rate limiting for new connections
        tcp flags syn limit rate 100/second burst 200 packets accept
        tcp flags syn counter drop
        
        # Log dropped packets (optional, disable in high traffic)
        # counter log prefix "nft-input-drop: " drop
    }
    
    chain forward {
        type filter hook forward priority filter; policy accept;
        
        # Allow whitelisted IPs
        ip saddr @whitelist_set accept
        
        # Drop blocked IPs
        ip saddr @ddos_ip_set counter drop
        
        # Allow established connections
        ct state established,related accept
    }
    
    chain output {
        type filter hook output priority filter; policy accept;
    }
}

# NAT table (if needed for forwarding)
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
    
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # Masquerade outgoing traffic (if acting as gateway)
        # ip saddr 192.168.1.0/24 oif eth0 masquerade
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

### Production Monitoring Setup

**Comprehensive Monitoring**:
```bash
# Install monitoring tools
sudo apt install -y prometheus-node-exporter grafana

# Configure Prometheus to scrape DDoS Inspector metrics
sudo tee -a /etc/prometheus/prometheus.yml << 'EOF'
  - job_name: 'ddos-inspector'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 5s
    metrics_path: '/metrics'
EOF

# Create monitoring dashboard
sudo mkdir -p /etc/grafana/provisioning/dashboards
sudo tee /etc/grafana/provisioning/dashboards/ddos-inspector.json << 'EOF'
{
  "dashboard": {
    "title": "DDoS Inspector - Production Dashboard",
    "panels": [
      {
        "title": "Attack Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(attacks_detected_total[5m])",
            "legendFormat": "Attacks/sec"
          }
        ]
      },
      {
        "title": "Blocked IPs",
        "type": "singlestat",
        "targets": [
          {
            "expr": "ips_blocked_total",
            "legendFormat": "Blocked IPs"
          }
        ]
      },
      {
        "title": "Packet Processing Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(packets_processed_total[5m])",
            "legendFormat": "Packets/sec"
          }
        ]
      }
    ]
  }
}
EOF

# Enable services
sudo systemctl enable prometheus
sudo systemctl enable grafana-server
sudo systemctl start prometheus
sudo systemctl start grafana-server
```

## High Availability Deployment

### Active-Passive HA Setup

**Master Node Configuration**:
```bash
# Master node setup with keepalived
sudo apt install -y keepalived

# Keepalived configuration for HA
sudo tee /etc/keepalived/keepalived.conf << 'EOF'
vrrp_script chk_ddos_inspector {
    script "/usr/local/bin/check_ddos_inspector.sh"
    interval 2
    weight -2
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 110
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass ddos_ha_2025
    }
    virtual_ipaddress {
        10.0.1.100/24
    }
    track_script {
        chk_ddos_inspector
    }
    notify_master "/usr/local/bin/ddos_master.sh"
    notify_backup "/usr/local/bin/ddos_backup.sh"
}
EOF

# Health check script
sudo tee /usr/local/bin/check_ddos_inspector.sh << 'EOF'
#!/bin/bash
# Check if DDoS Inspector is running and responsive
if systemctl is-active --quiet snort-ddos; then
    # Check if metrics file is being updated (within last 30 seconds)
    if [ -f /tmp/ddos_inspector_stats ]; then
        LAST_UPDATE=$(stat -c %Y /tmp/ddos_inspector_stats)
        CURRENT_TIME=$(date +%s)
        if [ $((CURRENT_TIME - LAST_UPDATE)) -lt 30 ]; then
            exit 0  # Healthy
        fi
    fi
fi
exit 1  # Unhealthy
EOF

chmod +x /usr/local/bin/check_ddos_inspector.sh

# Master/backup scripts
sudo tee /usr/local/bin/ddos_master.sh << 'EOF'
#!/bin/bash
echo "$(date): Becoming MASTER" >> /var/log/ddos_ha.log
# Start DDoS Inspector service
systemctl start snort-ddos
# Update routing if needed
# ip route add default via 10.0.1.1
EOF

sudo tee /usr/local/bin/ddos_backup.sh << 'EOF'
#!/bin/bash
echo "$(date): Becoming BACKUP" >> /var/log/ddos_ha.log
# Stop DDoS Inspector service to avoid conflicts
systemctl stop snort-ddos
EOF

chmod +x /usr/local/bin/ddos_master.sh /usr/local/bin/ddos_backup.sh
```

**Backup Node Configuration**:
```bash
# Same keepalived setup but with different priority
sudo sed -i 's/state MASTER/state BACKUP/' /etc/keepalived/keepalived.conf
sudo sed -i 's/priority 110/priority 100/' /etc/keepalived/keepalived.conf
```

### Active-Active HA Setup

**Load Balancer Configuration (HAProxy)**:
```bash
# Install HAProxy for load balancing
sudo apt install -y haproxy

# HAProxy configuration for DDoS Inspector cluster
sudo tee /etc/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    user haproxy
    group haproxy
    log 127.0.0.1:514 local0

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

# DDoS Inspector API endpoints
frontend ddos_api
    bind *:8080
    default_backend ddos_inspectors

backend ddos_inspectors
    balance roundrobin
    option tcp-check
    tcp-check connect port 8080
    server ddos1 10.0.1.10:8080 check
    server ddos2 10.0.1.11:8080 check
    server ddos3 10.0.1.12:8080 check

# Statistics page
frontend stats
    bind *:8404
    stats enable
    stats uri /
    stats refresh 10s
    stats admin if LOCALHOST

backend LOCALHOST
    server localhost 127.0.0.1:8404
EOF

sudo systemctl enable haproxy
sudo systemctl start haproxy
```

**Shared State Management (Redis)**:
```bash
# Install Redis for shared state
sudo apt install -y redis-server

# Configure Redis for HA
sudo tee -a /etc/redis/redis.conf << 'EOF'
# Clustering configuration
appendonly yes
appendfilename "appendonly.aof"
save 900 1
save 300 10
save 60 10000

# Network configuration
bind 0.0.0.0
protected-mode no
port 6379

# Memory optimization
maxmemory 2gb
maxmemory-policy allkeys-lru
EOF

# Start Redis
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

## Distributed Deployment

### Container Orchestration (Kubernetes)

**Namespace and ConfigMap**:
```yaml
# Create namespace
apiVersion: v1
kind: Namespace
metadata:
  name: ddos-inspector
---
# Configuration as ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: ddos-inspector-config
  namespace: ddos-inspector
data:
  snort_ddos_config.lua: |
    ddos_inspector = {
        entropy_threshold = 2.0,
        ewma_alpha = 0.1,
        syn_flood_threshold = 500,
        http_flood_threshold = 200,
        block_timeout = 600,
        max_tracked_ips = 100000,
        worker_threads = 4,
        metrics_enabled = true,
        log_level = "info"
    }
```

**DaemonSet Deployment**:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ddos-inspector
  namespace: ddos-inspector
spec:
  selector:
    matchLabels:
      app: ddos-inspector
  template:
    metadata:
      labels:
        app: ddos-inspector
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: ddos-inspector
        image: ddos-inspector:latest
        securityContext:
          privileged: true
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
        env:
        - name: INTERFACE
          value: "eth0"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: config
          mountPath: /etc/snort
        - name: logs
          mountPath: /var/log/snort
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: ddos-inspector-config
      - name: logs
        hostPath:
          path: /var/log/ddos-inspector
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      tolerations:
      - operator: Exists
```

**Service and Monitoring**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: ddos-inspector-metrics
  namespace: ddos-inspector
spec:
  selector:
    app: ddos-inspector
  ports:
  - name: metrics
    port: 8080
    targetPort: 8080
  - name: api
    port: 8081
    targetPort: 8081
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ddos-inspector
  namespace: ddos-inspector
spec:
  selector:
    matchLabels:
      app: ddos-inspector
  endpoints:
  - port: metrics
    interval: 15s
    path: /metrics
```

### Multi-Region Deployment

**Global Load Balancer Configuration**:
```bash
# Using CloudFlare as example global load balancer
curl -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/load_balancers" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "ddos-inspector-global.example.com",
    "fallback_pool": "backup-pool-id",
    "default_pools": ["primary-pool-id"],
    "description": "DDoS Inspector Global Load Balancer",
    "ttl": 30,
    "steering_policy": "geo",
    "session_affinity": "none",
    "region_pools": {
      "WNAM": ["us-west-pool-id"],
      "ENAM": ["us-east-pool-id"],
      "EU": ["europe-pool-id"],
      "APAC": ["asia-pool-id"]
    }
  }'
```

## Cloud Provider Deployments

### AWS Deployment

**CloudFormation Template**:
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'DDoS Inspector AWS Deployment'

Parameters:
  InstanceType:
    Type: String
    Default: c5.2xlarge
    Description: EC2 instance type for DDoS Inspector
  
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: VPC ID where DDoS Inspector will be deployed

Resources:
  DDoSInspectorSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for DDoS Inspector
      VpcId: !Ref VpcId
      SecurityGroupIngress:
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0

  DDoSInspectorRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy

  DDoSInspectorInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref DDoSInspectorRole

  DDoSInspectorLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: DDoSInspector
      LaunchTemplateData:
        InstanceType: !Ref InstanceType
        IamInstanceProfile:
          Arn: !GetAtt DDoSInspectorInstanceProfile.Arn
        SecurityGroupIds:
          - !Ref DDoSInspectorSecurityGroup
        UserData:
          Fn::Base64: !Sub |
            #!/bin/bash
            yum update -y
            yum install -y git cmake gcc-c++
            
            # Install DDoS Inspector
            cd /opt
            git clone https://github.com/hung-qt/ddos_inspector.git
            cd ddos_inspector
            ./scripts/deploy.sh --cloud aws --interface eth0
            
            # Configure CloudWatch monitoring
            yum install -y amazon-cloudwatch-agent
            cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
            {
              "metrics": {
                "namespace": "DDoSInspector",
                "metrics_collected": {
                  "procstat": [
                    {
                      "pattern": "snort",
                      "measurement": [
                        "cpu_usage",
                        "memory_rss"
                      ]
                    }
                  ]
                }
              },
              "logs": {
                "logs_collected": {
                  "files": {
                    "collect_list": [
                      {
                        "file_path": "/var/log/snort/alert",
                        "log_group_name": "ddos-inspector-alerts"
                      }
                    ]
                  }
                }
              }
            }
            EOF
            
            /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
              -a fetch-config -m ec2 -s \
              -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

  DDoSInspectorAutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      LaunchTemplate:
        LaunchTemplateId: !Ref DDoSInspectorLaunchTemplate
        Version: !GetAtt DDoSInspectorLaunchTemplate.LatestVersionNumber
      MinSize: 2
      MaxSize: 10
      DesiredCapacity: 2
      HealthCheckType: EC2
      HealthCheckGracePeriod: 300
```

### Azure Deployment

**ARM Template**:
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmSize": {
      "type": "string",
      "defaultValue": "Standard_D4s_v3",
      "metadata": {
        "description": "Size of the virtual machine"
      }
    }
  },
  "variables": {
    "vmName": "ddos-inspector-vm",
    "networkSecurityGroupName": "ddos-inspector-nsg",
    "virtualNetworkName": "ddos-inspector-vnet",
    "subnetName": "default"
  },
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "apiVersion": "2020-06-01",
      "name": "[variables('networkSecurityGroupName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "securityRules": [
          {
            "name": "SSH",
            "properties": {
              "priority": 1001,
              "protocol": "TCP",
              "access": "Allow",
              "direction": "Inbound",
              "sourceAddressPrefix": "*",
              "sourcePortRange": "*",
              "destinationAddressPrefix": "*",
              "destinationPortRange": "22"
            }
          }
        ]
      }
    },
    {
      "type": "Microsoft.Compute/virtualMachines",
      "apiVersion": "2020-06-01",
      "name": "[variables('vmName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "hardwareProfile": {
          "vmSize": "[parameters('vmSize')]"
        },
        "osProfile": {
          "computerName": "[variables('vmName')]",
          "adminUsername": "azureuser",
          "customData": "[base64(concat('#cloud-config\nruncmd:\n  - curl -fsSL https://raw.githubusercontent.com/hung-qt/ddos_inspector/main/scripts/deploy.sh | bash -s -- --cloud azure --interface eth0\n'))]"
        },
        "storageProfile": {
          "imageReference": {
            "publisher": "Canonical",
            "offer": "0001-com-ubuntu-server-focal",
            "sku": "20_04-lts-gen2",
            "version": "latest"
          }
        }
      }
    }
  ]
}
```

## Performance Monitoring and Optimization

### Production Performance Monitoring

**Real-time Performance Dashboard**:
```bash
# Create performance monitoring script
sudo tee /usr/local/bin/ddos_performance_monitor.sh << 'EOF'
#!/bin/bash
# DDoS Performance Monitor

LOG_FILE="/var/log/ddos_performance.log"
METRICS_FILE="/tmp/ddos_inspector_stats"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # System metrics
  _USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}')
    
    # Network metrics
    PACKET_RATE=$(sar -n DEV 1 1 | grep eth0 | tail -1 | awk '{print $3 + $4}')
    
    # DDoS Inspector metrics
    if [ -f "$METRICS_FILE" ]; then
        ATTACKS_DETECTED=$(grep "attacks_detected_total" "$METRICS_FILE" | awk '{print $2}' || echo "0")
        PACKETS_PROCESSED=$(grep "packets_processed_total" "$METRICS_FILE" | awk '{print $2}' || echo "0")
        IPS_BLOCKED=$(grep "ips_blocked_total" "$METRICS_FILE" | awk '{print $2}' || echo "0")
    else
        ATTACKS_DETECTED="0"
        PACKETS_PROCESSED="0"
        IPS_BLOCKED="0"
    fi
    
    # Log performance data
    echo "$TIMESTAMP,CPU:$CPU_USAGE%,Memory:$MEMORY_USAGE%,Load:$LOAD_AVG,PacketRate:$PACKET_RATE,Attacks:$ATTACKS_DETECTED,Processed:$PACKETS_PROCESSED,Blocked:$IPS_BLOCKED" >> "$LOG_FILE"
    
    sleep 60
done
EOF

chmod +x /usr/local/bin/ddos_performance_monitor.sh

# Create systemd service for performance monitoring
sudo tee /etc/systemd/system/ddos-performance-monitor.service << 'EOF'
[Unit]
Description=DDoS Inspector Performance Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ddos_performance_monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable ddos-performance-monitor
sudo systemctl start ddos-performance-monitor
```

### Capacity Management

**Auto-scaling Configuration**:
```bash
# Create auto-scaling script based on metrics
sudo tee /usr/local/bin/ddos_autoscale.sh << 'EOF'
#!/bin/bash
# DDoS Inspector Auto-scaling

METRICS_FILE="/tmp/ddos_inspector_stats"
CONFIG_FILE="/etc/snort/snort_ddos_config.lua"

# Get current metrics
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//' | sed 's/\..*//')
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%d", $3/$2 * 100}')

# Scale up conditions
if [ "$CPU_USAGE" -gt 80 ] || [ "$MEMORY_USAGE" -gt 85 ]; then
    echo "$(date): High resource usage detected, scaling up configuration"
    
    # Reduce tracking limits to free up resources
    sed -i 's/max_tracked_ips = [0-9]*/max_tracked_ips = 50000/' "$CONFIG_FILE"
    sed -i 's/cleanup_interval = [0-9]*/cleanup_interval = 30/' "$CONFIG_FILE"
    
    # Restart service to apply changes
    systemctl reload snort-ddos
    
# Scale down conditions
elif [ "$CPU_USAGE" -lt 30 ] && [ "$MEMORY_USAGE" -lt 40 ]; then
    echo "$(date): Low resource usage detected, scaling down configuration"
    
    # Increase tracking limits for better detection
    sed -i 's/max_tracked_ips = [0-9]*/max_tracked_ips = 200000/' "$CONFIG_FILE"
    sed -i 's/cleanup_interval = [0-9]*/cleanup_interval = 60/' "$CONFIG_FILE"
    
    # Restart service to apply changes
    systemctl reload snort-ddos
fi
EOF

chmod +x /usr/local/bin/ddos_autoscale.sh

# Add to crontab for periodic execution
echo "*/5 * * * * /usr/local/bin/ddos_autoscale.sh" | sudo crontab -
```

## Backup and Disaster Recovery

### Configuration Backup

**Automated Backup System**:
```bash
# Create backup script
sudo tee /usr/local/bin/ddos_backup.sh << 'EOF'
#!/bin/bash
# DDoS Inspector Backup Script

BACKUP_DIR="/var/backups/ddos-inspector"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="ddos_backup_$DATE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup archive
tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" \
    /etc/snort/snort_ddos_config.lua \
    /etc/nftables.conf \
    /etc/systemd/system/snort-ddos.service \
    /var/log/snort/ \
    /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "ddos_backup_*.tar.gz" -mtime +30 -delete

echo "$(date): Backup completed: $BACKUP_NAME.tar.gz"
EOF

chmod +x /usr/local/bin/ddos_backup.sh

# Schedule daily backups
echo "0 2 * * * /usr/local/bin/ddos_backup.sh" | sudo crontab -
```

### Disaster Recovery Procedures

**Recovery Playbook**:
```bash
# Create disaster recovery script
sudo tee /usr/local/bin/ddos_disaster_recovery.sh << 'EOF'
#!/bin/bash
# DDoS Inspector Disaster Recovery

BACKUP_DIR="/var/backups/ddos-inspector"
RECOVERY_LOG="/var/log/ddos_recovery.log"

echo "$(date): Starting DDoS Inspector disaster recovery" >> "$RECOVERY_LOG"

# Stop current services
systemctl stop snort-ddos
systemctl stop nftables

# Find latest backup
LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/ddos_backup_*.tar.gz | head -1)

if [ -n "$LATEST_BACKUP" ]; then
    echo "$(date): Restoring from backup: $LATEST_BACKUP" >> "$RECOVERY_LOG"
    
    # Extract backup
    cd /
    tar -xzf "$LATEST_BACKUP"
    
    # Restart services
    systemctl start nftables
    systemctl start snort-ddos
    
    # Verify services
    sleep 10
    if systemctl is-active --quiet snort-ddos; then
        echo "$(date): Recovery successful" >> "$RECOVERY_LOG"
        exit 0
    else
        echo "$(date): Recovery failed - service not starting" >> "$RECOVERY_LOG"
        exit 1
    fi
else
    echo "$(date): No backup found for recovery" >> "$RECOVERY_LOG"
    exit 1
fi
EOF

chmod +x /usr/local/bin/ddos_disaster_recovery.sh
```

## Related Documentation

- [Getting Started](../getting-started/) - Initial setup and installation
- [Configuration Guide](../configuration/) - Detailed configuration options
- [Architecture Guide](../architecture/) - System design and components
- [Monitoring Guide](../monitoring/) - Comprehensive monitoring setup
- [Troubleshooting](../troubleshooting/) - Common issues and solutions

---

**Quick Deployment Commands**:

```bash
# Single server production deployment
curl -fsSL https://raw.githubusercontent.com/hung-qt/ddos_inspector/main/scripts/deploy.sh | sudo bash -s -- --mode production --interface eth0

# High availability deployment
curl -fsSL https://raw.githubusercontent.com/hung-qt/ddos_inspector/main/scripts/deploy.sh | sudo bash -s -- --mode ha --interface eth0 --ha-partner 10.0.1.11

# Container deployment
docker run -d --name ddos-inspector --privileged --network host -v /etc/snort:/etc/snort ddos-inspector:latest
```

**Next Steps**: 
1. Set up monitoring with [Monitoring Guide](../monitoring/)
2. Configure alerts and notifications
3. Establish backup and recovery procedures
4. Plan capacity scaling strategies