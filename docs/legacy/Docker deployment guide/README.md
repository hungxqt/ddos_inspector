# 🐳 Docker Deployment Guide for DDoS Inspector

Your DDoS Inspector plugin is fully containerized and can run in multiple Docker deployment scenarios. This guide covers all deployment options from simple containers to full production stacks.

## 🚀 **Quick Start - Docker Deployment**

### **Option 1: Simple Container Deployment**
```bash
# Build and run with basic configuration
sudo ./scripts/deploy_docker.sh --mode standard --interface eth0 --privileged

# Or with monitoring dashboard
sudo ./scripts/deploy_docker.sh --mode standard --interface eth0 --privileged --dashboard
```

### **Option 2: Complete Stack with Docker Compose**
```bash
# Start the full monitoring stack
SNORT_INTERFACE=eth0 docker-compose up -d

# Access dashboards
# Grafana: http://localhost:3000 (admin/ddos_inspector_2025)
# Kibana: http://localhost:5601
# Prometheus: http://localhost:9090
```

## 🏗️ **Docker Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host Network                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ DDoS Inspector  │  │   Prometheus    │  │   Grafana    │ │
│  │   Container     │  │   (Metrics)     │  │ (Dashboard)  │ │
│  │                 │  │                 │  │              │ │
│  │ • Snort 3       │  │ Port: 9090      │  │ Port: 3000   │ │
│  │ • Plugin        │  └─────────────────┘  └──────────────┘ │
│  │ • nftables      │                                        │
│  │ • Metrics       │  ┌─────────────────┐  ┌──────────────┐ │
│  │                 │  │  Elasticsearch  │  │    Kibana    │ │
│  │ Host Network    │  │    (Logs)       │  │ (Log Viewer) │ │
│  │ Privileged      │  │                 │  │              │ │
│  └─────────────────┘  │ Port: 9200      │  │ Port: 5601   │ │
│                       └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 📋 **Deployment Modes**

### **1. Standard Mode** (Recommended for testing)
```bash
./scripts/deploy_docker.sh --mode standard --interface eth0 --privileged
```
- ✅ Port mapping for metrics access
- ✅ Isolated networking
- ✅ Good for development/testing
- ⚠️ Limited network access

### **2. Host Networking Mode** (Recommended for production)
```bash
./scripts/deploy_docker.sh --mode host --interface eth0 --privileged
```
- ✅ Full network access
- ✅ Best performance
- ✅ Real network interface access
- ⚠️ Less isolation

### **3. Bridge Mode** (Custom networking)
```bash
./scripts/deploy_docker.sh --mode bridge --interface eth0 --privileged
```
- ✅ Custom network configuration
- ✅ Multiple container communication
- ✅ Network isolation

### **4. Monitor-Only Mode** (Metrics without detection)
```bash
./scripts/deploy_docker.sh --mode monitor --dashboard
```
- ✅ Just metrics and monitoring
- ✅ No network privileges needed
- ✅ Perfect for centralized monitoring

## 🔧 **Advanced Deployment Options**

### **Production Deployment with Docker Compose**

Create a production environment file `.env`:
```bash
# Network configuration
SNORT_INTERFACE=eth0
NETWORK_MODE=host

# Security
PRIVILEGED_MODE=true
CONTAINER_USER=root

# Monitoring
ENABLE_METRICS=true
GRAFANA_PASSWORD=your_secure_password_here
PROMETHEUS_RETENTION=7d

# Resource limits
ELASTICSEARCH_MEMORY=2g
GRAFANA_MEMORY=512m
PROMETHEUS_MEMORY=1g
```

Deploy with production settings:
```bash
docker-compose --env-file .env up -d
```

### **Multi-Interface Monitoring**
```bash
# Monitor multiple interfaces with separate containers
./scripts/deploy_docker.sh --mode host --interface eth0 --privileged &
./scripts/deploy_docker.sh --mode host --interface eth1 --privileged &

# Or use Docker Compose scaling
docker-compose up --scale ddos-inspector=2 -d
```

### **High Availability Deployment**
```yaml
# Add to docker-compose.yml for HA
deploy:
  replicas: 2
  restart_policy:
    condition: on-failure
    delay: 5s
    max_attempts: 3
  resources:
    limits:
      memory: 1G
      cpus: '0.5'
```

## 🧪 **Testing Your Docker Deployment**

### **1. Verify Container Health**
```bash
# Check container status
docker ps -f name=ddos_inspector

# View container logs
docker logs -f ddos_inspector

# Check health status
docker inspect ddos_inspector --format='{{.State.Health.Status}}'
```

### **2. Test Plugin Functionality**
```bash
# Enter container for testing
docker exec -it ddos_inspector bash

# Inside container - verify plugin
snort --show-plugins | grep ddos_inspector

# Test configuration
snort -c /etc/snort/snort_ddos_config.lua -T

# Check firewall rules
nft list set inet filter ddos_ip_set
```

### **3. Generate Test Traffic**
```bash
# From host - test SYN flood detection
docker exec ddos_inspector /app/scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30

# Monitor results
docker exec ddos_inspector tail -f /var/log/snort/alert
curl http://localhost:9091/metrics | grep ddos_inspector
```

## 📊 **Monitoring Your Docker Deployment**

### **Container Metrics**
```bash
# View container resource usage
docker stats ddos_inspector

# Monitor container health
watch 'docker inspect ddos_inspector --format="{{.State.Health.Status}}"'

# Check logs in real-time
docker logs -f --tail 50 ddos_inspector
```

### **DDoS Detection Metrics**
```bash
# Access Prometheus metrics
curl http://localhost:9091/metrics

# Check blocked IPs
docker exec ddos_inspector nft list set inet filter ddos_ip_set

# View detection statistics
docker exec ddos_inspector cat /var/log/ddos_inspector/ddos_inspector_stats
```

### **Dashboard Access**
- **Grafana**: http://localhost:3000
  - Username: `admin`
  - Password: `ddos_inspector_2025`
- **Kibana**: http://localhost:5601
- **Prometheus**: http://localhost:9090
- **AlertManager**: http://localhost:9093

## 🔒 **Security Considerations**

### **Container Security**
```bash
# Run with security profiles
docker run --security-opt seccomp=default \
           --security-opt apparmor=docker-default \
           --cap-add=NET_ADMIN \
           --cap-drop=ALL \
           ddos_inspector:latest
```

### **Network Security**
```yaml
# Docker Compose with security
services:
  ddos-inspector:
    security_opt:
      - seccomp:default
      - apparmor:docker-default
    cap_add:
      - NET_ADMIN
      - NET_RAW
    cap_drop:
      - ALL
```

### **Secrets Management**
```bash
# Use Docker secrets for sensitive data
echo "your_secure_password" | docker secret create grafana_password -

# Reference in docker-compose.yml
secrets:
  - grafana_password
```

## 🚀 **Production Deployment Checklist**

- [ ] Configure appropriate network mode (host for production)
- [ ] Set resource limits for containers
- [ ] Configure log rotation and retention
- [ ] Set up monitoring and alerting
- [ ] Configure backup for persistent data
- [ ] Test failover scenarios
- [ ] Set up SSL/TLS for web interfaces
- [ ] Configure firewall rules on host
- [ ] Set up centralized logging
- [ ] Configure auto-restart policies

## 🔧 **Troubleshooting**

### **Container Won't Start**
```bash
# Check Docker daemon
systemctl status docker

# Check container logs
docker logs ddos_inspector

# Verify image build
docker images | grep ddos_inspector

# Test without detached mode
docker run --rm -it ddos_inspector:latest bash
```

### **Network Issues**
```bash
# Check interface availability
docker exec ddos_inspector ip link show

# Verify privileged mode
docker inspect ddos_inspector | grep Privileged

# Test network connectivity
docker exec ddos_inspector ping 8.8.8.8
```

### **Performance Issues**
```bash
# Monitor resource usage
docker stats --no-stream

# Check system resources
free -h
df -h

# Optimize container resources
docker update --memory=2g --cpus=2 ddos_inspector
```

## 🎯 **Best Practices**

1. **Use Host Networking** for production deployments
2. **Enable Privileged Mode** for firewall functionality
3. **Mount Volumes** for logs and persistent data
4. **Set Resource Limits** to prevent resource exhaustion
5. **Use Health Checks** for container monitoring
6. **Configure Log Rotation** to manage disk space
7. **Regular Backups** of configuration and data
8. **Monitor Container Metrics** for performance
9. **Security Scanning** of container images
10. **Update Base Images** regularly for security

Your DDoS Inspector is now fully containerized and production-ready! 🎉