# Monitoring & Metrics Guide

This guide covers comprehensive monitoring of DDoS Inspector, including metrics collection, alerting, and dashboard setup.

## Overview

DDoS Inspector provides extensive monitoring capabilities through multiple interfaces:

- **Real-time Metrics**: Live performance and security metrics
- **Prometheus Integration**: Time-series metrics collection
- **Grafana Dashboards**: Visual monitoring and alerting
- **ELK Stack Integration**: Log analysis and correlation
- **Custom Alerting**: Configurable alert rules

## Metrics Collection

### Built-in Metrics

DDoS Inspector exports metrics to `/tmp/ddos_inspector_stats` by default:

```bash
# View current metrics
cat /tmp/ddos_inspector_stats

# Monitor live updates
watch -n 1 'cat /tmp/ddos_inspector_stats'

# Parse specific metrics
grep "packets_processed" /tmp/ddos_inspector_stats
```

**Core Metrics**:
```
# Performance Metrics
packets_processed_total 1234567
packets_per_second 45678
detection_latency_ms 2.8
memory_usage_bytes 44040192
cpu_usage_percent 3.8

# Security Metrics
attacks_detected_total 42
ips_blocked_total 15
syn_flood_detected 12
http_flood_detected 8
slowloris_detected 3
false_positives 2

# System Metrics
connections_tracked 1024
entropy_calculations 98765
firewall_rules_active 15
cleanup_operations 567
```

### Prometheus Integration

#### Configuration

Configure Prometheus to scrape DDoS Inspector metrics:

```yaml
# prometheus.yml
global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'ddos-inspector'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
    metrics_path: '/metrics'
    
  - job_name: 'ddos-inspector-file'
    file_sd_configs:
      - files:
        - '/tmp/ddos_inspector_stats'
    scrape_interval: 5s
```

#### Metrics Exporter

Enable Prometheus format export:

```lua
-- In snort_ddos_config.lua
ddos_inspector = {
    -- ...existing config...
    
    -- Prometheus integration
    metrics_enabled = true,
    metrics_format = "prometheus",
    metrics_port = 9090,
    metrics_endpoint = "/metrics",
    
    -- Metric categories
    export_performance_metrics = true,
    export_security_metrics = true,
    export_system_metrics = true
}
```

#### Custom Metrics Exporter

Deploy the standalone metrics exporter:

```bash
# Start the metrics exporter service
cd prometheus-elk-metrics
python3 snort_stats_exporter.py --config config.yml

# Or run with Docker
docker run -d \
  --name ddos-metrics-exporter \
  -p 9091:9091 \
  -v /tmp/ddos_inspector_stats:/metrics/ddos_inspector_stats:ro \
  hungqt/ddos-metrics-exporter:latest
```

## Grafana Dashboards

### Dashboard Setup

Deploy pre-configured Grafana dashboards:

```bash
# Deploy Grafana with dashboards
cd prometheus-elk-metrics/grafana
docker-compose up -d grafana

# Access Grafana: http://localhost:3000
# Login: admin / ddos_inspector_2025
```

### Main Dashboard Panels

#### 1. Security Overview
```json
{
  "title": "DDoS Attacks Overview",
  "type": "stat",
  "targets": [
    {
      "expr": "rate(attacks_detected_total[5m])",
      "legendFormat": "Attacks/sec"
    }
  ]
}
```

#### 2. Performance Metrics
```json
{
  "title": "Detection Latency",
  "type": "graph",
  "targets": [
    {
      "expr": "detection_latency_ms",
      "legendFormat": "Avg Latency"
    },
    {
      "expr": "histogram_quantile(0.99, detection_latency_histogram)",
      "legendFormat": "P99 Latency"
    }
  ]
}
```

#### 3. Attack Types Distribution
```json
{
  "title": "Attack Types",
  "type": "piechart",
  "targets": [
    {
      "expr": "syn_flood_detected",
      "legendFormat": "SYN Flood"
    },
    {
      "expr": "http_flood_detected",
      "legendFormat": "HTTP Flood"
    },
    {
      "expr": "slowloris_detected",
      "legendFormat": "Slowloris"
    }
  ]
}
```

### Alert Rules

Configure Grafana alerts for critical events:

```yaml
# grafana/provisioning/alerting/rules.yml
groups:
  - name: ddos-inspector-alerts
    interval: 30s
    rules:
      - alert: HighAttackRate
        expr: rate(attacks_detected_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High DDoS attack rate detected"
          description: "Attack rate is {{ $value }} attacks/sec"
      
      - alert: SystemOverloaded
        expr: cpu_usage_percent > 80
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "DDoS Inspector system overloaded"
          description: "CPU usage is {{ $value }}%"
      
      - alert: HighMemoryUsage
        expr: memory_usage_bytes > 1073741824  # 1GB
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value | humanize }}B"
```

## ELK Stack Integration

### Logstash Configuration

Process DDoS Inspector logs with Logstash:

```ruby
# logstash/pipeline/ddos-inspector.conf
input {
  file {
    path => "/var/log/snort/alert"
    start_position => "beginning"
    tags => ["snort", "ddos"]
  }
  
  file {
    path => "/var/log/snort/ddos_inspector.log"
    start_position => "beginning"
    codec => json
    tags => ["ddos-inspector", "structured"]
  }
}

filter {
  if "ddos" in [tags] {
    grok {
      match => { 
        "message" => "%{TIMESTAMP_ISO8601:timestamp} \[%{DATA:priority}\] \[%{DATA:classification}\] %{DATA:description} \[Classification: %{DATA:class_type}\] \[Priority: %{NUMBER:priority_num}\] \{%{DATA:protocol}\} %{IPV4:src_ip}:%{NUMBER:src_port} -> %{IPV4:dest_ip}:%{NUMBER:dest_port}"
      }
    }
    
    if [classification] =~ /ddos_inspector/ {
      mutate {
        add_field => { "attack_type" => "unknown" }
      }
      
      if [description] =~ /SYN_FLOOD/ {
        mutate { replace => { "attack_type" => "syn_flood" } }
      }
      else if [description] =~ /HTTP_FLOOD/ {
        mutate { replace => { "attack_type" => "http_flood" } }
      }
      else if [description] =~ /SLOWLORIS/ {
        mutate { replace => { "attack_type" => "slowloris" } }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "ddos-inspector-%{+YYYY.MM.dd}"
  }
}
```

### Elasticsearch Index Template

Define index mapping for optimal search performance:

```json
{
  "index_patterns": ["ddos-inspector-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "src_ip": { "type": "ip" },
        "dest_ip": { "type": "ip" },
        "attack_type": { "type": "keyword" },
        "priority": { "type": "keyword" },
        "classification": { "type": "keyword" },
        "description": { "type": "text" },
        "src_port": { "type": "integer" },
        "dest_port": { "type": "integer" },
        "protocol": { "type": "keyword" }
      }
    },
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  }
}
```

### Kibana Dashboards

Import pre-built Kibana dashboards:

```bash
# Import dashboard configuration
curl -X POST "kibana:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  --form file=@kibana-dashboards.ndjson
```

**Key Visualizations**:
- Attack timeline and trends
- Geographic attack sources
- Port and protocol distribution
- Attack severity heatmap

## Custom Monitoring Scripts

### Real-time Monitoring Script

```bash
#!/bin/bash
# scripts/monitor_ddos.sh

METRICS_FILE="/tmp/ddos_inspector_stats"
LOG_FILE="/var/log/snort/alert"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "DDoS Inspector Real-time Monitor"
echo "================================"

while true; do
    clear
    echo -e "${GREEN}DDoS Inspector Status - $(date)${NC}"
    echo ""
    
    # Parse current metrics
    if [[ -f "$METRICS_FILE" ]]; then
        PACKETS_PROCESSED=$(grep "packets_processed_total" "$METRICS_FILE" | awk '{print $2}')
        ATTACKS_DETECTED=$(grep "attacks_detected_total" "$METRICS_FILE" | awk '{print $2}')
        IPS_BLOCKED=$(grep "ips_blocked_total" "$METRICS_FILE" | awk '{print $2}')
        CPU_USAGE=$(grep "cpu_usage_percent" "$METRICS_FILE" | awk '{print $2}')
        MEMORY_USAGE=$(grep "memory_usage_bytes" "$METRICS_FILE" | awk '{print $2}')
        
        echo -e "Packets Processed: ${GREEN}$PACKETS_PROCESSED${NC}"
        echo -e "Attacks Detected:  ${RED}$ATTACKS_DETECTED${NC}"
        echo -e "IPs Blocked:       ${YELLOW}$IPS_BLOCKED${NC}"
        echo -e "CPU Usage:         ${CPU_USAGE}%"
        echo -e "Memory Usage:      $(echo "scale=2; $MEMORY_USAGE/1024/1024" | bc) MB"
    else
        echo -e "${RED}Metrics file not found${NC}"
    fi
    
    echo ""
    echo "Recent Attacks:"
    echo "---------------"
    tail -5 "$LOG_FILE" | grep -E "(SYN_FLOOD|HTTP_FLOOD|SLOWLORIS)" | \
        while read line; do
            echo -e "${RED}$line${NC}"
        done
    
    echo ""
    echo "Active Blocked IPs:"
    echo "-------------------"
    sudo nft list set inet filter ddos_ip_set 2>/dev/null | grep elements | \
        sed 's/.*elements = { \(.*\) }.*/\1/' | tr ',' '\n' | head -10
    
    sleep 5
done
```

### Performance Monitoring

```bash
#!/bin/bash
# scripts/performance_monitor.sh

# Monitor system performance impact
echo "DDoS Inspector Performance Impact"
echo "================================="

# Get Snort process info
SNORT_PID=$(pgrep snort)
if [[ -n "$SNORT_PID" ]]; then
    echo "Snort Process ID: $SNORT_PID"
    
    # CPU usage
    CPU_USAGE=$(ps -p $SNORT_PID -o %cpu --no-headers)
    echo "CPU Usage: $CPU_USAGE%"
    
    # Memory usage
    MEMORY_KB=$(ps -p $SNORT_PID -o rss --no-headers)
    MEMORY_MB=$(echo "scale=2; $MEMORY_KB/1024" | bc)
    echo "Memory Usage: ${MEMORY_MB} MB"
    
    # File descriptors
    FD_COUNT=$(ls /proc/$SNORT_PID/fd 2>/dev/null | wc -l)
    echo "File Descriptors: $FD_COUNT"
    
    # Network connections
    CONN_COUNT=$(ss -p | grep -c "pid=$SNORT_PID")
    echo "Network Connections: $CONN_COUNT"
else
    echo "Snort process not running"
fi

# Network interface statistics
INTERFACE="eth0"  # Adjust as needed
echo ""
echo "Network Interface Statistics ($INTERFACE):"
echo "----------------------------------------"
cat /proc/net/dev | grep $INTERFACE | \
    awk '{printf "RX Packets: %s, TX Packets: %s\nRX Bytes: %s, TX Bytes: %s\n", $3, $11, $2, $10}'
```

## Alerting Configuration

### Email Alerts

Configure email notifications:

```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'ddos-inspector@yourdomain.com'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  email_configs:
  - to: 'security-team@yourdomain.com'
    subject: 'DDoS Inspector Alert: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      Severity: {{ .Labels.severity }}
      {{ end }}
```

### Slack Integration

Send alerts to Slack:

```yaml
receivers:
- name: 'slack-notifications'
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    channel: '#security-alerts'
    title: 'DDoS Inspector Alert'
    text: |
      {{ range .Alerts }}
      *Alert:* {{ .Annotations.summary }}
      *Description:* {{ .Annotations.description }}
      *Severity:* {{ .Labels.severity }}
      {{ end }}
```

### Custom Webhook Alerts

Send alerts to custom endpoints:

```python
#!/usr/bin/env python3
# scripts/custom_alerting.py

import requests
import json
import time
from datetime import datetime

def check_metrics():
    """Check current metrics and trigger alerts if needed"""
    try:
        with open('/tmp/ddos_inspector_stats', 'r') as f:
            metrics = {}
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    metrics[parts[0]] = float(parts[1])
        
        # Check attack rate
        if metrics.get('attacks_detected_total', 0) > 100:
            send_alert('high_attack_rate', {
                'message': 'High attack rate detected',
                'attack_count': metrics['attacks_detected_total'],
                'timestamp': datetime.now().isoformat()
            })
        
        # Check system load
        if metrics.get('cpu_usage_percent', 0) > 90:
            send_alert('high_cpu_usage', {
                'message': 'High CPU usage detected',
                'cpu_usage': metrics['cpu_usage_percent'],
                'timestamp': datetime.now().isoformat()
            })
            
    except Exception as e:
        print(f"Error checking metrics: {e}")

def send_alert(alert_type, data):
    """Send alert to webhook endpoint"""
    webhook_url = "https://your-webhook-endpoint.com/alerts"
    
    payload = {
        'alert_type': alert_type,
        'data': data,
        'source': 'ddos_inspector'
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print(f"Alert sent: {alert_type}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

if __name__ == "__main__":
    while True:
        check_metrics()
        time.sleep(30)  # Check every 30 seconds
```

## Performance Monitoring

### Key Performance Indicators (KPIs)

Monitor these critical metrics:

**Detection Performance**:
- Packet processing rate (packets/second)
- Detection latency (milliseconds)
- Memory usage (MB)
- CPU utilization (%)

**Security Effectiveness**:
- Attack detection rate (attacks/hour)
- False positive rate (FP/total detections)
- False negative rate (missed attacks)
- IP blocking effectiveness

**System Health**:
- Service uptime (%)
- Resource availability
- Error rates
- Recovery time

### Baseline Establishment

Establish performance baselines:

```bash
#!/bin/bash
# scripts/establish_baseline.sh

BASELINE_FILE="/etc/ddos-inspector/baseline.json"
METRICS_FILE="/tmp/ddos_inspector_stats"

echo "Establishing performance baseline..."

# Collect metrics over 24 hours
for i in {1..288}; do  # 288 * 5 minutes = 24 hours
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Parse current metrics
    packets_processed=$(grep "packets_processed_total" "$METRICS_FILE" | awk '{print $2}')
    detection_latency=$(grep "detection_latency_ms" "$METRICS_FILE" | awk '{print $2}')
    memory_usage=$(grep "memory_usage_bytes" "$METRICS_FILE" | awk '{print $2}')
    cpu_usage=$(grep "cpu_usage_percent" "$METRICS_FILE" | awk '{print $2}')
    
    # Store in baseline file
    echo "{\"timestamp\":\"$timestamp\",\"packets_processed\":$packets_processed,\"detection_latency\":$detection_latency,\"memory_usage\":$memory_usage,\"cpu_usage\":$cpu_usage}" >> "$BASELINE_FILE.tmp"
    
    sleep 300  # 5 minutes
done

# Calculate baseline averages
python3 << EOF
import json
import statistics

with open('$BASELINE_FILE.tmp', 'r') as f:
    data = [json.loads(line) for line in f]

baseline = {
    'packets_processed_avg': statistics.mean([d['packets_processed'] for d in data]),
    'detection_latency_avg': statistics.mean([d['detection_latency'] for d in data]),
    'memory_usage_avg': statistics.mean([d['memory_usage'] for d in data]),
    'cpu_usage_avg': statistics.mean([d['cpu_usage'] for d in data]),
    'packets_processed_p95': statistics.quantiles([d['packets_processed'] for d in data], n=20)[18],
    'detection_latency_p95': statistics.quantiles([d['detection_latency'] for d in data], n=20)[18],
    'established_at': '$(date -u +"%Y-%m-%dT%H:%M:%SZ")'
}

with open('$BASELINE_FILE', 'w') as f:
    json.dump(baseline, f, indent=2)
EOF

rm "$BASELINE_FILE.tmp"
echo "Baseline established: $BASELINE_FILE"
```

## Troubleshooting Monitoring Issues

### Common Monitoring Problems

```bash
# Check if metrics file is being updated
stat /tmp/ddos_inspector_stats

# Verify metrics export process
ps aux | grep -E "(prometheus|snort_stats_exporter)"

# Check Prometheus connectivity
curl -s http://localhost:9090/metrics | head -10

# Verify Grafana data source
curl -s http://admin:ddos_inspector_2025@localhost:3000/api/datasources
```

### Debug Metrics Collection

```bash
# Enable debug logging for metrics
export DDOS_DEBUG_METRICS=1
sudo systemctl restart snort-ddos

# Monitor metrics file updates
tail -f /tmp/ddos_inspector_stats

# Check for metrics parsing errors
journalctl -u snort-ddos | grep -i error
```

---

**Next**: [Troubleshooting Guide](troubleshooting.md) →