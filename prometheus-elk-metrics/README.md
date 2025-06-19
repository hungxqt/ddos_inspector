# 🛡️ DDoS Inspector Monitoring Dashboard

A comprehensive real-time monitoring solution for the DDoS Inspector Snort plugin, featuring Prometheus metrics collection, Grafana visualization, and ELK stack log analysis.

---

## 🌟 **What You Get**

- **📊 Real-time Attack Visualization**: Live DDoS attack detection and classification
- **⚡ Performance Monitoring**: Plugin performance, Snort health, and system metrics
- **📈 Historical Analysis**: Attack trends and pattern recognition
- **🚨 Smart Alerting**: Configurable thresholds and notifications
- **🔍 Log Forensics**: Detailed packet-level investigation capabilities

---

## 🏗️ **Architecture Overview**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  DDoS Inspector │───▶│   Prometheus    │───▶│     Grafana     │
│     Plugin      │    │   (Metrics)     │    │  (Dashboards)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                                              │
         ▼                                              │
┌─────────────────┐    ┌─────────────────┐              │
│   Snort Logs    │───▶│   ELK Stack     │              │
│   (Alerts)      │    │ (Log Analysis)  │              │
└─────────────────┘    └─────────────────┘              │
                                │                       │
                                ▼                       ▼
                       ┌─────────────────────────────────────┐
                       │        Web Interfaces               │
                       │ • Grafana: :3000                    │
                       │ • Kibana: :5601                     │
                       │ • Prometheus: :9090                 │
                       └─────────────────────────────────────┘
```

---

## 🚀 **Quick Start (5 Minutes)**

### **Prerequisites**
```bash
# Check if you have Docker
docker --version
docker-compose --version

# If not installed:
sudo apt update && sudo apt install docker.io docker-compose
```

### **1. Deploy the Complete Stack**
```bash
cd "Prometheus-ELK metrics dashboard"
chmod +x deploy.sh
./deploy.sh
```

### **2. Access Your Dashboards**
- **🎛️ Grafana**: http://localhost:3000 (admin/admin)
- **📄 Kibana**: http://localhost:5601
- **📊 Prometheus**: http://localhost:9090

### **3. Start Monitoring**
```bash
# Start metrics collection
./start_monitoring.sh

# Run your DDoS Inspector plugin
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0
```

---

## 📊 **Dashboard Components**

### **🎯 Grafana Dashboards**

#### **Main DDoS Dashboard**
- **Attack Overview**: Real-time attack counts by type (SYN, UDP, HTTP, Slowloris)
- **Traffic Analysis**: Packet rates, entropy scores, connection counts
- **Performance Metrics**: Detection latency, CPU usage, memory consumption
- **Firewall Status**: Active blocks, blocked IPs, auto-unblocks

#### **System Health Dashboard**
- **Snort Performance**: Processing rates, rule efficiency, resource usage
- **Plugin Health**: Component status, error rates, throughput
- **Network Overview**: Interface statistics, traffic patterns

### **📋 Key Metrics Monitored**

| Metric Category | Examples | Purpose |
|----------------|----------|---------|
| **Attack Detection** | `ddos_inspector_syn_floods_total` | Track attack frequency |
| **Traffic Analysis** | `ddos_inspector_entropy`, `packet_rate` | Identify anomalies |
| **Performance** | `detection_time_ms`, `cpu_usage_percent` | Monitor efficiency |
| **Security Status** | `blocked_ips_count`, `active_connections` | Security posture |

### **📈 Kibana Log Analysis**

#### **Real-time Alert Stream**
- Live DDoS attack alerts as they're detected
- Source IP analysis and geographic mapping
- Attack pattern timeline and correlation

#### **Forensic Investigation**
- Detailed packet inspection
- Attack signature analysis
- Historical attack patterns

---

## ⚙️ **Detailed Setup Guide**

### **Step 1: Install Dependencies**
```bash
# System packages
sudo apt update
sudo apt install -y docker.io docker-compose git curl

# Prometheus C++ library (for metrics exporter)
git clone https://github.com/jupp0r/prometheus-cpp.git
cd prometheus-cpp && mkdir _build && cd _build
cmake .. -DBUILD_SHARED_LIBS=ON
make -j$(nproc) && sudo make install
cd ../..
```

### **Step 2: Configure the Stack**

The dashboard comes pre-configured, but you can customize:

#### **Prometheus Configuration** (`prometheus/prometheus.yml`)
```yaml
global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'ddos_inspector'
    static_configs:
      - targets: ['host.docker.internal:9091']
    scrape_interval: 2s

  - job_name: 'snort_stats'
    static_configs:
      - targets: ['host.docker.internal:9092']
    scrape_interval: 5s

  - job_name: 'node_exporter'
    static_configs:
      - targets: ['host.docker.internal:9100']
```

#### **Docker Compose Services**
```yaml
# Services automatically configured:
# - Prometheus (metrics storage)
# - Grafana (visualization)
# - Elasticsearch (log storage)
# - Logstash (log processing)
# - Kibana (log visualization)
```

### **Step 3: Start Metrics Collection**

#### **Option A: Automated Start**
```bash
./start_monitoring.sh
```

#### **Option B: Manual Start**
```bash
# Start the stack
docker-compose up -d

# Start DDoS Inspector metrics exporter
g++ ddos_inspector_real_metrics.cpp -o exporter \
    -lpthread -lprometheus-cpp-pull -lprometheus-cpp-core -lmicrohttpd
./exporter &

# Start Snort stats exporter
python3 snort_stats_exporter.py &
```

### **Step 4: Configure Data Sources**

#### **Grafana Setup**
1. Open http://localhost:3000
2. Login: admin/admin (change password when prompted)
3. Go to **Configuration → Data Sources**
4. Add Prometheus: `http://prometheus:9090`
5. Import dashboard from `grafana/dashboards/`

#### **Kibana Setup**
1. Open http://localhost:5601
2. Go to **Stack Management → Index Patterns**
3. Create pattern: `snort-logs-*`
4. Set timestamp: `@timestamp`

---

## 🧪 **Testing & Validation**

### **Generate Test Traffic**
```bash
# Test SYN flood detection
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30

# Test Slowloris attack
sudo ./scripts/run_slowloris.sh --target 127.0.0.1 --duration 30

# Generate HTTP flood
for i in {1..100}; do
    curl -s http://localhost/test_page > /dev/null &
done
```

### **Verify Dashboard Updates**
1. **Grafana**: Watch attack counters increase in real-time
2. **Kibana**: See new alert entries appear
3. **Prometheus**: Query metrics directly
4. **System**: Check blocked IPs with `sudo nft list tables`

### **Sample Test Alerts**
Add to `logs/alert_fast.txt` for testing:
```
[**] [1:1000001:0] SYN Flood Detected [**] {TCP} 192.168.1.100:12345 -> 10.0.0.1:80
[**] [1:1000002:0] Slowloris Attack Detected [**] {HTTP} 192.168.1.101:54321 -> 10.0.0.1:443
[**] [1:1000003:0] UDP Flood Detected [**] {UDP} 192.168.1.102:53 -> 10.0.0.1:53
```

---

## 🎛️ **Dashboard Usage Guide**

### **Monitoring Active Attacks**
1. Open Grafana DDoS Dashboard
2. Check the **Attack Overview** panel for real-time counts
3. Monitor **Traffic Analysis** for anomaly patterns
4. Review **Blocked IPs** for mitigation status

### **Investigating Incidents**
1. Switch to Kibana for detailed logs
2. Filter by time range during the incident
3. Analyze source IPs and attack patterns
4. Cross-reference with Grafana performance metrics

### **Performance Tuning**
1. Monitor **Detection Latency** in Grafana
2. Check **CPU/Memory Usage** trends
3. Adjust plugin thresholds based on false positive rates
4. Review **Rule Efficiency** in Snort stats

---

## 🚨 **Alerting Configuration**

### **Grafana Alerts**
```yaml
# Example alert rules (configured in Grafana UI):
- alert: HighAttackRate
  expr: rate(ddos_inspector_packets_blocked_total[5m]) > 10
  for: 30s
  labels:
    severity: warning
  annotations:
    summary: "High DDoS attack rate detected"

- alert: PluginDown
  expr: up{job="ddos_inspector"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "DDoS Inspector plugin is down"
```

### **Notification Channels**
- Slack integration
- Email alerts
- PagerDuty escalation
- Webhook notifications

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **🔴 Metrics Not Appearing**
```bash
# Check metrics file
ls -la /var/log/ddos_inspector/metrics.log
cat /var/log/ddos_inspector/metrics.log

# Verify exporter
curl http://localhost:9091/metrics

# Check container logs
docker-compose logs ddos-metrics
```

#### **🔴 Dashboard Not Loading**
```bash
# Check service status
docker-compose ps

# Restart services
docker-compose restart grafana prometheus

# Check resources
docker stats
```

#### **🔴 No Log Data in Kibana**
```bash
# Check Elasticsearch
curl http://localhost:9200/_cluster/health

# Verify Logstash processing
docker-compose logs logstash

# Check log file permissions
ls -la logs/alert_fast.txt
```

### **Performance Optimization**

#### **For High Traffic Environments**
```yaml
# Adjust in docker-compose.yml
elasticsearch:
  environment:
    - ES_JAVA_OPTS=-Xms2g -Xmx2g  # Increase memory

prometheus:
  command:
    - '--storage.tsdb.retention.time=72h'  # Reduce retention
```

#### **Resource Monitoring**
```bash
# Monitor system resources
htop
iotop
docker stats

# Check disk usage
df -h
du -sh logs/
```

---

## 🔒 **Security & Production Deployment**

### **Authentication Setup**
```bash
# Enable Grafana authentication
# Edit grafana/grafana.ini:
[auth]
disable_login_form = false

[security]
admin_user = your_admin
admin_password = your_secure_password
```

### **TLS/SSL Configuration**
```yaml
# Add to docker-compose.yml for HTTPS
grafana:
  environment:
    - GF_SERVER_PROTOCOL=https
    - GF_SERVER_CERT_FILE=/etc/ssl/grafana.crt
    - GF_SERVER_CERT_KEY=/etc/ssl/grafana.key
```

### **Data Backup**
```bash
# Backup Grafana dashboards
curl -s "http://admin:admin@localhost:3000/api/search?type=dash-db" | \
jq -r '.[] | .uri' | xargs -I {} curl -s "http://admin:admin@localhost:3000/api/dashboards/{}" > backup.json

# Backup Elasticsearch data
docker exec elasticsearch elasticsearch-dump --input=http://localhost:9200 --output=/backup
```

---

## 📚 **Advanced Usage**

### **Custom Metrics**
Add to your DDoS Inspector plugin:
```cpp
// Custom metric example
void writeCustomMetric(const std::string& name, double value) {
    std::ofstream file("/var/log/ddos_inspector/metrics.log", std::ios::app);
    file << name << ":" << value << std::endl;
}
```

### **Dashboard Customization**
1. Export existing dashboard JSON
2. Modify panels and queries
3. Import customized version
4. Share with team via Git

### **API Integration**
```bash
# Query Prometheus API
curl 'http://localhost:9090/api/v1/query?query=ddos_inspector_packets_processed_total'

# Grafana API for automation
curl -H "Authorization: Bearer YOUR_API_KEY" \
     'http://localhost:3000/api/dashboards/home'
```

---

## 🆘 **Support & Resources**

### **Getting Help**
- 📖 **Documentation**: Check the main project README
- 🐛 **Issues**: GitHub issue tracker
- 💬 **Community**: Project discussions
- 📧 **Contact**: Technical support team

### **Useful Commands**
```bash
# Quick health check
./health_check.sh

# View all logs
docker-compose logs -f

# Reset everything
./reset_dashboard.sh

# Export metrics for analysis
curl -s http://localhost:9091/metrics > metrics_export.txt
```

---

## 📈 **What's Next?**

1. **Custom Alerts**: Set up your specific alert thresholds
2. **Team Dashboards**: Create role-specific views
3. **Integration**: Connect with your existing monitoring
4. **Automation**: Set up automated response workflows
5. **Scaling**: Configure for multi-node deployments

---

**🎉 Your DDoS Inspector monitoring is now ready! Visit http://localhost:3000 to start monitoring your network security in real-time.**



