# 🛡️ Full Observability System Setup and Testing Guide

This guide helps you deploy, run, and test a full observability setup for `ddos_inspector`, integrating Prometheus, Grafana, ELK (Elasticsearch, Logstash, Kibana), and metric exporters.

---

## 📁 Directory Structure

```
Prometheus-ELK metrics dashboard/
├── docker-compose.yml
├── prometheus/
│   └── prometheus.yml
├── logstash/
│   └── pipeline/
│       └── logstash.conf
├── logs/
│   └── alert_fast.txt      # Snort or simulated alerts
├── exporters/
│   └── ddos_inspector_real_metrics.cpp
│   └── snort_stats_exporter.py
```

---

## 🛠️ Step 1: Docker Compose Setup

Place this `docker-compose.yml` in your project root:

```yaml
version: '3.7'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    networks:
      - monitoring

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    networks:
      - logging

  logstash:
    image: docker.elastic.co/logstash/logstash:8.13.0
    container_name: logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logs:/var/log/snort
    depends_on:
      - elasticsearch
    networks:
      - logging

  kibana:
    image: docker.elastic.co/kibana/kibana:8.13.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - logging

volumes:
  esdata:

networks:
  logging:
  monitoring:
```

---

## 📊 Step 2: Prometheus Configuration

Create `prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: 'ddos_inspector'
    static_configs:
      - targets: ['host.docker.internal:9091']

  - job_name: 'snort_stats'
    static_configs:
      - targets: ['host.docker.internal:9092']
```

---

## 📄 Step 3: Logstash Parser

Create `logstash/pipeline/logstash.conf`:

```conf
input {
  file {
    path => "/var/log/snort/alert_fast.txt"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}
filter {
  grok {
    match => { "message" => "\[%{DATA:timestamp}\] \[%{DATA:signature}\] %{GREEDYDATA:alert_msg}" }
  }
}
output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "snort-logs"
  }
}
```

---

## 🚀 Step 4: Run Observability Stack

```bash
docker-compose up -d
```

---

## ⚙️ Step 5: Start Exporters

### 1. System Libraries
Run this to install required packages:
```bash
sudo apt update
sudo apt install -y g++ cmake libmicrohttpd-dev libcurl4-openssl-dev libssl-dev
```

### 2. prometheus-cpp Library
Build and install the C++ Prometheus client library:
```bash
git clone https://github.com/jupp0r/prometheus-cpp.git
cd prometheus-cpp
mkdir _build && cd _build
cmake .. -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
sudo make install
```

### Option A. Metrics Exporter (C++)

Compile:
```bash
g++ ddos_inspector_real_metrics.cpp -o exporter -lpthread -lprometheus-cpp-pull -lprometheus-cpp-core -lmicrohttpd
```
Run:
```bash
./exporter
```

### Option B. Snort Stats Exporter (Python)

```bash
python3 snort_stats_exporter.py
```

---

## 📈 Step 6: Grafana Dashboard

1. Open http://localhost:3000
2. Add Prometheus data source: `http://prometheus:9090`
3. Create dashboards with queries like:
   - `ddos_entropy_score`
   - `ddos_packet_rate`
   - `snort_decoder_pkts`

---

## 📄 Step 7: Kibana Log Dashboard

1. Open http://localhost:5601
2. Create index pattern: `snort-logs`
3. Go to Discover to inspect alerts.
4. Build:
   - Pie chart: `signature.keyword`
   - Line: alert count over time
   - Table: timestamp + alert_msg

---

## 🧪 Step 8: Test Data

Append to `logs/alert_fast.txt`:
```
[**] [1:1000001:0] SYN Flood Detected [**] {TCP} 192.168.1.10:443 -> 10.0.0.2:80
[**] [1:1000002:0] HTTP Flood Detected [**] {TCP} 192.168.1.12:443 -> 10.0.0.2:80
```

Verify:
- Metrics update in Grafana
- Logs appear in Kibana

---

# DDoS Inspector Real Metrics Dashboard

This dashboard provides comprehensive monitoring for the DDoS Inspector Snort plugin using real metrics integration with Prometheus and ELK stack.

## Architecture

The monitoring stack consists of:

### Metrics Collection (Prometheus Stack)
- **DDoS Inspector Metrics Exporter** (Port 9091): Reads real metrics from the DDoS Inspector plugin
- **Snort Statistics Exporter** (Port 9092): Monitors Snort process and log files
- **Node Exporter** (Port 9100): System-level metrics
- **Prometheus** (Port 9090): Metrics storage and querying
- **Grafana** (Port 3000): Metrics visualization and dashboards

### Log Analysis (ELK Stack)
- **Elasticsearch** (Port 9200): Log storage and indexing
- **Kibana** (Port 5601): Log visualization and analysis
- **Logstash** (Port 5044): Log processing and parsing

## Real Metrics Integration

### DDoS Inspector Plugin Integration

The dashboard reads real metrics from your DDoS Inspector plugin through:

1. **Metrics File**: `/tmp/ddos_inspector_stats` - Written by the plugin
2. **Log Files**: Snort alert and event logs
3. **Process Monitoring**: Live Snort process statistics

### Metrics Collected

#### DDoS Inspector Metrics
- `ddos_inspector_packets_processed_total`: Total packets processed
- `ddos_inspector_packets_blocked_total`: Total packets blocked
- `ddos_inspector_attack_detections_total{type="syn_flood"}`: SYN flood detections
- `ddos_inspector_attack_detections_total{type="slowloris"}`: Slowloris detections
- `ddos_inspector_attack_detections_total{type="udp_flood"}`: UDP flood detections
- `ddos_inspector_attack_detections_total{type="icmp_flood"}`: ICMP flood detections
- `ddos_inspector_current_stats{metric="entropy"}`: Current entropy value
- `ddos_inspector_current_stats{metric="rate"}`: Current packet rate
- `ddos_inspector_current_stats{metric="connections"}`: Active connections
- `ddos_inspector_current_stats{metric="blocked_ips"}`: Blocked IP count
- `ddos_inspector_detection_time_milliseconds`: Attack detection latency

#### Snort Process Metrics
- `snort_cpu_usage_percent`: Snort CPU usage
- `snort_memory_usage_bytes`: Snort memory consumption
- `snort_uptime_seconds`: Snort process uptime
- `snort_packets_analyzed_total`: Total packets analyzed
- `snort_alerts_generated_total`: Total alerts generated
- `snort_packet_processing_rate`: Packets per second
- `snort_active_rules_count`: Number of active rules

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- DDoS Inspector plugin compiled and ready
- Snort3 with your plugin configured

### 1. Deploy the Dashboard
```bash
cd "Prometheus-ELK metrics dashboard"
./deploy.sh
```

### 2. Access the Dashboards
- **Grafana**: http://localhost:3000 (admin/admin)
- **Kibana**: http://localhost:5601
- **Prometheus**: http://localhost:9090

### 3. Configure Data Sources

#### Grafana Configuration
1. Go to Configuration → Data Sources
2. Add Prometheus data source: `http://prometheus:9090`
3. Import the pre-built dashboards (coming in next update)

#### Kibana Configuration
1. Go to Stack Management → Index Patterns
2. Create index pattern: `snort-logs-*`
3. Set timestamp field: `@timestamp`

### 4. Start Your DDoS Inspector Plugin

Ensure your plugin writes metrics to `/tmp/ddos_inspector_stats` in the format:
```
packets_processed:12345
packets_blocked:67
syn_floods:3
slowloris_attacks:1
udp_floods:2
icmp_floods:0
connections:45
blocked_ips:12
entropy:1.85
rate:1024.5
detection_time:15
```

## Real-Time Monitoring Features

### Live Attack Detection
- Real-time visualization of DDoS attacks as they're detected
- Attack type breakdown and frequency analysis
- Geographic mapping of attack sources (if IP geolocation is enabled)

### Performance Monitoring
- Plugin performance metrics and resource usage
- Snort process health and statistics
- System-level monitoring (CPU, memory, network)

### Alerting
- Configurable alerts for attack thresholds
- Performance degradation warnings
- System resource alerts

## Advanced Configuration

### Custom Metrics
Add custom metrics to your DDoS Inspector plugin by writing to the metrics file:
```cpp
void write_custom_metric(const std::string& name, uint64_t value) {
    std::ofstream file("/tmp/ddos_inspector_stats", std::ios::app);
    file << name << ":" << value << std::endl;
}
```

### Log Processing
Customize Logstash configuration in `logstash/pipeline/snort.conf` to parse additional log formats.

### Retention Policies
- Prometheus: 200 hours of metrics retention
- Elasticsearch: Configure in docker-compose.yml for longer retention

## Troubleshooting

### Common Issues

1. **Metrics not appearing**
   - Check if `/tmp/ddos_inspector_stats` file exists and is readable
   - Verify DDoS Inspector plugin is writing metrics
   - Check metrics exporter logs: `docker-compose logs ddos-metrics`

2. **Snort stats not showing**
   - Ensure Snort is running and accessible
   - Check Snort log file permissions
   - Review snort-stats exporter logs: `docker-compose logs snort-stats`

3. **Services not starting**
   - Check system resources (especially memory for Elasticsearch)
   - Verify port availability
   - Review service logs: `docker-compose logs [service-name]`

### Debugging Commands
```bash
# View all service logs
docker-compose logs -f

# Check specific service
docker-compose logs -f ddos-metrics

# Check metrics endpoints
curl http://localhost:9091/metrics
curl http://localhost:9092/metrics

# Restart specific service
docker-compose restart ddos-metrics
```

## Development

### Building Custom Exporters
The metrics exporters are built from source:
- `ddos_inspector_real_metrics.cpp`: C++ exporter for DDoS Inspector metrics
- `snort_stats_exporter.py`: Python exporter for Snort statistics

### Extending Metrics
1. Add new metrics to the appropriate exporter
2. Rebuild the containers: `docker-compose build`
3. Update Grafana dashboards to display new metrics

## Production Deployment

For production use:
1. Configure proper authentication for all services
2. Set up TLS/SSL encryption
3. Configure backup and disaster recovery
4. Implement log rotation and cleanup policies
5. Set up monitoring for the monitoring stack itself

## Support

For issues related to:
- DDoS Inspector plugin: Check the main project documentation
- Metrics collection: Review exporter logs and metrics file format
- Dashboard configuration: Consult Grafana and Kibana documentation



