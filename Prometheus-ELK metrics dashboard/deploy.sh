#!/bin/bash

set -e

echo "=== DDoS Inspector Prometheus-ELK Dashboard Deployment ==="

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create logs directory
mkdir -p logs

# Stop any existing containers
echo "Stopping existing containers..."
docker-compose down

# Build custom images
echo "Building custom metrics exporters..."
docker-compose build ddos-metrics snort-stats

# Start the complete stack
echo "Starting the monitoring stack..."
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 30

# Check service health
echo "Checking service health..."

services=("elasticsearch:9200/_cluster/health" "kibana:5601/api/status" "prometheus:9090/-/healthy" "grafana:3000/api/health")

for service in "${services[@]}"; do
    IFS=':' read -r container port_path <<< "$service"
    echo -n "Checking $container... "
    
    max_attempts=30
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "http://localhost:$port_path" > /dev/null 2>&1; then
            echo "✓ Ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            echo "✗ Failed to start"
        else
            sleep 2
            ((attempt++))
        fi
    done
done

# Check custom exporters
echo -n "Checking DDoS metrics exporter... "
if curl -s -f "http://localhost:9091/metrics" > /dev/null 2>&1; then
    echo "✓ Ready"
else
    echo "✗ Not responding"
fi

echo -n "Checking Snort stats exporter... "
if curl -s -f "http://localhost:9092/metrics" > /dev/null 2>&1; then
    echo "✓ Ready"
else
    echo "✗ Not responding"
fi

echo ""
echo "=== Dashboard URLs ==="
echo "Grafana (Metrics): http://localhost:3000 (admin/admin)"
echo "Kibana (Logs): http://localhost:5601"
echo "Prometheus: http://localhost:9090"
echo "DDoS Metrics: http://localhost:9091/metrics"
echo "Snort Stats: http://localhost:9092/metrics"
echo ""

echo "=== Next Steps ==="
echo "1. Configure Grafana data sources:"
echo "   - Add Prometheus: http://prometheus:9090"
echo "   - Import dashboards from grafana-dashboards/ directory"
echo ""
echo "2. Configure Kibana:"
echo "   - Create index patterns: snort-logs-*"
echo "   - Import visualizations and dashboards"
echo ""
echo "3. Start your DDoS Inspector plugin to generate real metrics"
echo ""

# Show container status
echo "=== Container Status ==="
docker-compose ps

echo ""
echo "Dashboard deployment completed!"
echo "Run 'docker-compose logs -f [service-name]' to view logs"
echo "Run 'docker-compose down' to stop all services"