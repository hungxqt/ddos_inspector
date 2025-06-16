# Docker Deployment Guide

This guide covers deploying DDoS Inspector using Docker containers for different environments and use cases.

## Quick Start

### Single Command Deployment

```bash
# Deploy with host networking (recommended for production)
sudo ./scripts/deploy_docker.sh --mode host --interface eth0 --privileged

# Deploy with bridge networking (for development)
sudo ./scripts/deploy_docker.sh --mode bridge --interface eth0
```

### Docker Compose Deployment

```bash
# Set your network interface
export SNORT_INTERFACE=eth0

# Deploy full stack with monitoring
docker-compose up -d

# Deploy minimal stack (DDoS Inspector only)
docker-compose -f docker-compose.minimal.yml up -d
```

## Docker Images

### Pre-built Images

```bash
# Pull latest stable image
docker pull hungqt/ddos-inspector:latest

# Pull specific version
docker pull hungqt/ddos-inspector:v1.2.0

# Pull development image
docker pull hungqt/ddos-inspector:dev
```

### Building Custom Images

```bash
# Build production image
docker build -t ddos-inspector:custom -f docker/Dockerfile .

# Build with debug symbols
docker build --build-arg BUILD_TYPE=Debug -t ddos-inspector:debug .

# Build multi-architecture
docker buildx build --platform linux/amd64,linux/arm64 -t ddos-inspector:multi .
```

## Deployment Modes

### Production Deployment (Host Network)

Best for production environments requiring maximum performance:

```yaml
version: '3.8'
services:
  ddos-inspector:
    image: hungqt/ddos-inspector:latest
    container_name: ddos_inspector_prod
    network_mode: host
    privileged: true
    volumes:
      - ./snort_ddos_config.lua:/etc/snort/snort_ddos_config.lua:ro
      - /var/log/ddos_inspector/ddos_inspector_stats:/var/log/ddos_inspector/ddos_inspector_stats
      - /var/log/snort:/var/log/snort
    environment:
      - SNORT_INTERFACE=${SNORT_INTERFACE:-eth0}
      - LOG_LEVEL=info
      - METRICS_ENABLED=true
    restart: unless-stopped
```

### Development Deployment (Bridge Network)

Suitable for development and testing:

```yaml
version: '3.8'
services:
  ddos-inspector:
    image: hungqt/ddos-inspector:latest
    container_name: ddos_inspector_dev
    ports:
      - "9090:9090"  # Metrics port
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./snort_ddos_config.lua:/etc/snort/snort_ddos_config.lua:ro
      - ddos_logs:/var/log/snort
    environment:
      - SNORT_INTERFACE=eth0
      - LOG_LEVEL=debug
    restart: unless-stopped

volumes:
  ddos_logs:
```

## Complete Monitoring Stack

Deploy DDoS Inspector with full monitoring capabilities:

```yaml
version: '3.8'

services:
  ddos-inspector:
    image: hungqt/ddos-inspector:latest
    container_name: ddos_inspector
    network_mode: host
    privileged: true
    volumes:
      - ./snort_ddos_config.lua:/etc/snort/snort_ddos_config.lua:ro
      - /var/log/ddos_inspector/ddos_inspector_stats:/var/log/ddos_inspector/ddos_inspector_stats
      - ddos_logs:/var/log/snort
    environment:
      - SNORT_INTERFACE=${SNORT_INTERFACE:-eth0}
      - METRICS_ENABLED=true
    restart: unless-stopped
    depends_on:
      - prometheus

  prometheus:
    image: prom/prometheus:latest
    container_name: ddos_prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: ddos_grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./grafana/datasources:/etc/grafana/provisioning/datasources:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=ddos_inspector_2025
    restart: unless-stopped

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: ddos_elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    restart: unless-stopped

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    container_name: ddos_logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logsth/pipeline:ro
      - ddos_logs:/var/log/snort:ro
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch
    restart: unless-stopped

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: ddos_kibana
    ports:
     1:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    restart: unless-stopped

volumes:
  ddos_logs:
  prometheus_data:
  grafana_data:
  elasticsearch_data:
```

## Configuration Management

### Environment riables

Configure DDoS Inspector behavior using environment variables:

```bash
# Core settings
export SNORT_INTERFACE=eth0
export LOG_LEVEL=info
export METRICS_ENABLED=true

# Detection parameters
export ENTROPY_THRESHOLD=2.0
export EWMA_ALPHA=0.1
export BLOCK_TIMEOUT=600

# Performance tuning
export MAX_TRACKED_IPS=100000
export CLEANUP_INTERVAL=60

# Monitoring
export METRICS_FILE=/var/log/ddos_inspector/ddos_inspector_stats
export PROMETHEUS_PORT=9090
```

### Volume Mounts

Critical directories and files to mount:

```yaml
volumes:
  # Configuration files
  - ./snort_ddos_config.lua:/etc/snort/snort_ddos_config.lua:ro
  - ./nftables.conf:/etc/nftables.conf:ro
  
  # Data and logs
  - /var/log/ddos_inspector/ddos_inspector_stats:/var/log/ddos_inspector/ddos_inspector_stats
  - /var/log/snort:/var/log/snort
  - /var/lib/snort:/var/lib/snort
  
  # Optional: Custom rules
  - ./custom_rules:/etc/snort/rules:ro
```

## Security Considerations

### Container Security

```yaml
services:
  ddos-inspector:
    # Use specific version tags
    image: hungqt/ddos-inspector:v1.2.0
    
    # Minimal required capabilities
    cap_add:
      - NET_ADMIN
      - NET_RAW
    cap_drop:
      - ALL
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - apparmor:unconfined
    
    # Resource limits
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
        reservations:
          memory: 1G
          cpus: '1.0'
    
    # Read-only filesystem (where possible)
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
```

### Network Security

```yaml
# Create custom network for isolation
networks:
  ddos_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

services:
  ddos-inspector:
    networks:
      - ddos_network
    # Expose only necessary ports
    ports:
      - "127.0.0.1:9090:9090"  # Bind to localhost only
```

## Performance Optimization

### Resource Allocation

```yaml
services:
  ddos-inspector:
    # CPU pinning for consistent performance
    cpuset: "0,1"
    
    # Memory optimization
    mem_limit: 4g
    mem_reservation: 2g
    
    # Disable swap
    mem_swappiness: 0
    
    # High-performance settings
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
```

### Storage Optimization

```yaml
volumes:
  # Use tmpfs for high-frequency writes
  - type: tmpfs
    target: /var/log/ddos_inspector/ddos_inspector_stats
    tmpfs:
      size: 100M
  
  # Use bind mounts for logs with proper options
  - type: bind
    source: /var/log/snort
    target: /var/log/snort
    bind:
      propagation: rshared
```

## Multi-Node Deployment

### Docker Swarm

```yaml
version: '3.8'

services:
  ddos-inspector:
    image: hungqt/ddos-inspector:latest
    deploy:
      mode: global  # Deploy on all nodes
      placement:
        constraints:
          - node.role == worker
          - node.labels.network == edge
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
      restart_policy:
        condition: on-failure
        delay: 30s
        max_attempts: 3
        window: 120s
    networks:
      - ddos_network
    volumes:
      - /var/log/ddos_inspector/ddos_inspector_stats:/var/log/ddos_inspector/ddos_inspector_stats

networks:
  ddos_network:
    driver: overlay
    attachable: true
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ddos-inspector
  namespace: security
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
      containers:
      - name: ddos-inspector
        image: hungqt/ddos-inspector:latest
        securityContext:
          privileged: true
          capabilities:
            add: ["NET_ADMIN", "NET_RAW"]
        env:
        - name: SNORT_INTERFACE
          value: "eth0"
        - name: LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /etc/snort/snort_ddos_config.lua
          subPath: snort_ddos_config.lua
        - name: metrics
          mountPath: /var/log/ddos_inspector/ddos_inspector_stats
        resources:
          requests:
            memory: "1Gi"
            cpu: "1000m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
      volumes:
      - name: config
        configMap:
          name: ddos-inspector-config
      - name: metrics
        hostPath:
          path: /var/log/ddos_inspector/ddos_inspector_stats
          type: FileOrCreate
      nodeSelector:
        node-type: edge
      tolerations:
      - key: node-role.kubernetes.io/edge
        operator: Exists
        effect: NoSchedule
```

## Troubleshooting

### Common Issues

```bash
# Check container status
docker ps -a | grep ddos

# View container logs
docker logs ddos_inspector --tail=50 -f

# Execute commands in container
docker exec -it ddos_inspector bash

# Check network configuration
docker exec ddos_inspector ip addr show
docker exec ddos_inspector nft list tables

# Monitor resource usage
docker stats ddos_inspector
```

### Debug Mode

```yaml
services:
  ddos-inspector:
    image: hungqt/ddos-inspector:debug
    environment:
      - LOG_LEVEL=debug
      - SNORT_VERBOSE=true
    # Keep container running for debugging
    command: ["tail", "-f", "/dev/null"]
```

### Health Checks

```yaml
services:
  ddos-inspector:
    healthcheck:
      test: ["CMD", "/usr/local/bin/health_check.sh"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
```

## Maintenance

### Updates and Upgrades

```bash
# Pull latest image
docker pull hungqt/ddos-inspector:latest

# Graceful update
docker-compose down
docker-compose up -d

# Rolling update in Swarm
docker service update --image hungqt/ddos-inspector:latest ddos_inspector
```

### Backup and Recovery

```bash
# Backup configuration
docker cp ddos_inspector:/etc/snort/snort_ddos_config.lua ./backup/

# Backup logs and data
docker run --rm -v ddos_logs:/data -v $(pwd)/backup:/backup \
  alpine tar czf /backup/ddos_logs_$(date +%Y%m%d).tar.gz -C /data .

# Restore configuration
docker cp ./backup/snort_ddos_config.lua ddos_inspector:/etc/snort/
docker restart ddos_inspector
```

---

**Next**: [Configuration Guide](configuration.md) →