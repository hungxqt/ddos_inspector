#!/bin/bash

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=== DDoS Inspector Prometheus-ELK Dashboard Deployment ===${NC}"

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERROR] Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}[ERROR] Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

# Create logs directory
mkdir -p logs

# Stop any existing containers
echo -e "${YELLOW}[STOP] Stopping existing containers...${NC}"
docker-compose down

# Build custom images
echo -e "${BLUE}[BUILD] Building custom metrics exporters...${NC}"
docker-compose build ddos-metrics snort-stats

# Start the complete stack
echo -e "${GREEN}[START] Starting the monitoring stack...${NC}"
docker-compose up -d

# Wait for services to be ready
echo -e "${YELLOW}[WAIT] Waiting for services to start...${NC}"
sleep 30

# Check service health
echo -e "${CYAN}[CHECK] Checking service health...${NC}"

services=("elasticsearch:9200/_cluster/health" "kibana:5601/api/status" "prometheus:9090/-/healthy" "grafana:3000/api/health")

for service in "${services[@]}"; do
    IFS=':' read -r container port_path <<< "$service"
    echo -n "    Checking $container... "
    
    max_attempts=30
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "http://localhost:$port_path" > /dev/null 2>&1; then
            echo -e "${GREEN}Ready${NC}"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            echo -e "${RED}Failed to start${NC}"
        else
            sleep 2
            ((attempt++))
        fi
    done
done

# Check custom exporters
echo -n "    Checking DDoS metrics exporter... "
if curl -s -f "http://localhost:9091/metrics" > /dev/null 2>&1; then
    echo -e "${GREEN}Ready${NC}"
else
    echo -e "${RED}Not responding${NC}"
fi

echo -n "    Checking Snort stats exporter... "
if curl -s -f "http://localhost:9092/metrics" > /dev/null 2>&1; then
    echo -e "${GREEN}Ready${NC}"
else
    echo -e "${RED}Not responding${NC}"
fi

echo ""
echo -e "${CYAN}=== Dashboard URLs ===${NC}"
echo "    Grafana (Metrics): http://localhost:3000 (admin/admin)"
echo "    Kibana (Logs): http://localhost:5601"
echo "    Prometheus: http://localhost:9090"
echo "    DDoS Metrics: http://localhost:9091/metrics"
echo "    Snort Stats: http://localhost:9092/metrics"
echo ""

echo -e "${BLUE}=== Next Steps ===${NC}"
echo "    1. Configure Grafana data sources:"
echo "       - Add Prometheus: http://prometheus:9090"
echo "       - Import dashboards from grafana-dashboards/ directory"
echo ""
echo "    2. Configure Kibana:"
echo "       - Create index patterns: snort-logs-*"
echo "       - Import visualizations and dashboards"
echo ""
echo "    3. Start your DDoS Inspector plugin to generate real metrics"
echo ""

# Show container status
echo -e "${YELLOW}=== Container Status ===${NC}"
docker-compose ps

echo ""
echo -e "${GREEN}[SUCCESS] Dashboard deployment completed!${NC}"
echo "    Run 'docker-compose logs -f [service-name]' to view logs"
echo "    Run 'docker-compose down' to stop all services"