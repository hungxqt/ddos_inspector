#!/bin/bash

# Enhanced Docker Deployment Script for DDoS Inspector
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🐳 DDoS Inspector Docker Deployment${NC}"

# Configuration
IMAGE_NAME="ddos_inspector"
CONTAINER_NAME="ddos_inspector"
VERSION="latest"

# Parse command line arguments
DEPLOYMENT_MODE="standard"
INTERFACE="eth0"
PRIVILEGED="false"
DETACHED="true"
ENABLE_DASHBOARD="false"

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -m, --mode MODE          Deployment mode: standard|host|bridge|monitor"
    echo "  -i, --interface IFACE    Network interface (default: eth0)"
    echo "  -p, --privileged         Run with privileged mode (for firewall)"
    echo "  -f, --foreground         Run in foreground (not detached)"
    echo "  -d, --dashboard          Also start monitoring dashboard"
    echo "  -t, --test               Test mode - just validate configuration"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Deployment Modes:"
    echo "  standard    - Normal container with port mapping"
    echo "  host        - Host networking (full network access)"
    echo "  bridge      - Bridge networking with custom network"
    echo "  monitor     - Metrics and monitoring only"
    echo ""
    echo "Examples:"
    echo "  $0 --mode host --interface eth0 --privileged"
    echo "  $0 --mode monitor --dashboard"
    echo "  $0 --test"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -p|--privileged)
            PRIVILEGED="true"
            shift
            ;;
        -f|--foreground)
            DETACHED="false"
            shift
            ;;
        -d|--dashboard)
            ENABLE_DASHBOARD="true"
            shift
            ;;
        -t|--test)
            DEPLOYMENT_MODE="test"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Build image
echo -e "${BLUE}Building Docker image: ${IMAGE_NAME}:${VERSION}${NC}"
docker build -t "${IMAGE_NAME}:${VERSION}" -f docker/Dockerfile .

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Docker build failed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker image built successfully${NC}"

# Stop existing container if running
if docker ps -q -f name="${CONTAINER_NAME}" | grep -q .; then
    echo -e "${YELLOW}Stopping existing container...${NC}"
    docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

if docker ps -aq -f name="${CONTAINER_NAME}" | grep -q .; then
    echo -e "${YELLOW}Removing existing container...${NC}"
    docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

# Prepare Docker run options
DOCKER_OPTS=""
if [ "$DETACHED" = "true" ]; then
    DOCKER_OPTS="$DOCKER_OPTS -d"
fi

if [ "$PRIVILEGED" = "true" ]; then
    DOCKER_OPTS="$DOCKER_OPTS --privileged"
    echo -e "${YELLOW}⚠️  Running in privileged mode for firewall access${NC}"
fi

# Set environment variables
ENV_VARS="-e SNORT_INTERFACE=${INTERFACE}"

# Deploy based on mode
case $DEPLOYMENT_MODE in
    "standard")
        echo -e "${BLUE}🚀 Deploying in Standard Mode${NC}"
        docker run $DOCKER_OPTS \
            --name "${CONTAINER_NAME}" \
            --restart unless-stopped \
            -p 9091:9091 \
            -p 9092:9092 \
            -p 8080:8080 \
            $ENV_VARS \
            -v /var/log/snort:/var/log/snort \
            -v /tmp:/tmp \
            "${IMAGE_NAME}:${VERSION}" snort
        ;;
    
    "host")
        echo -e "${BLUE}🌐 Deploying in Host Networking Mode${NC}"
        docker run $DOCKER_OPTS \
            --name "${CONTAINER_NAME}" \
            --restart unless-stopped \
            --network host \
            $ENV_VARS \
            -v /var/log/snort:/var/log/snort \
            -v /tmp:/tmp \
            "${IMAGE_NAME}:${VERSION}" snort
        ;;
    
    "bridge")
        echo -e "${BLUE}🌉 Deploying in Bridge Mode${NC}"
        # Create custom network if it doesn't exist
        docker network create ddos_inspector_net 2>/dev/null || true
        
        docker run $DOCKER_OPTS \
            --name "${CONTAINER_NAME}" \
            --restart unless-stopped \
            --network ddos_inspector_net \
            -p 9091:9091 \
            -p 9092:9092 \
            -p 8080:8080 \
            $ENV_VARS \
            -v /var/log/snort:/var/log/snort \
            -v /tmp:/tmp \
            "${IMAGE_NAME}:${VERSION}" snort
        ;;
    
    "monitor")
        echo -e "${BLUE}📊 Deploying in Monitor Mode${NC}"
        docker run $DOCKER_OPTS \
            --name "${CONTAINER_NAME}" \
            --restart unless-stopped \
            -p 9091:9091 \
            -p 9092:9092 \
            $ENV_VARS \
            -v /tmp:/tmp \
            "${IMAGE_NAME}:${VERSION}" metrics-only
        ;;
    
    "test")
        echo -e "${BLUE}🧪 Running in Test Mode${NC}"
        docker run --rm \
            --name "${CONTAINER_NAME}_test" \
            "${IMAGE_NAME}:${VERSION}" test
        exit $?
        ;;
    
    *)
        echo -e "${RED}❌ Unknown deployment mode: ${DEPLOYMENT_MODE}${NC}"
        show_help
        exit 1
        ;;
esac

# Wait for container to start
if [ "$DETACHED" = "true" ] && [ "$DEPLOYMENT_MODE" != "test" ]; then
    echo -e "${BLUE}Waiting for container to start...${NC}"
    sleep 5
    
    if docker ps -q -f name="${CONTAINER_NAME}" | grep -q .; then
        echo -e "${GREEN}✅ Container started successfully${NC}"
        
        # Show container status
        echo -e "${BLUE}Container Status:${NC}"
        docker ps -f name="${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        # Show logs
        echo -e "${BLUE}Recent logs:${NC}"
        docker logs --tail 10 "${CONTAINER_NAME}"
        
    else
        echo -e "${RED}❌ Container failed to start${NC}"
        docker logs "${CONTAINER_NAME}" 2>/dev/null || true
        exit 1
    fi
fi

# Start monitoring dashboard if requested
if [ "$ENABLE_DASHBOARD" = "true" ]; then
    echo -e "${BLUE}🎛️ Starting monitoring dashboard...${NC}"
    cd "Prometheus-ELK metrics dashboard"
    docker-compose up -d
    cd ..
    
    echo -e "${GREEN}📊 Dashboard available at:${NC}"
    echo -e "  Grafana: http://localhost:3000 (admin/admin)"
    echo -e "  Kibana: http://localhost:5601"
    echo -e "  Prometheus: http://localhost:9090"
fi

echo -e "${GREEN}🎉 Deployment complete!${NC}"
echo -e "${BLUE}Useful commands:${NC}"
echo -e "  View logs: ${YELLOW}docker logs -f ${CONTAINER_NAME}${NC}"
echo -e "  Enter container: ${YELLOW}docker exec -it ${CONTAINER_NAME} bash${NC}"
echo -e "  Stop container: ${YELLOW}docker stop ${CONTAINER_NAME}${NC}"
echo -e "  View metrics: ${YELLOW}curl http://localhost:9091/metrics${NC}"
echo -e "  Check blocked IPs: ${YELLOW}docker exec ${CONTAINER_NAME} nft list set inet filter ddos_ip_set${NC}"
