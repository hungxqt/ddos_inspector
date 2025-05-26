
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



