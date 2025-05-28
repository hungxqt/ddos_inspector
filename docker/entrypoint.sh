#!/bin/bash

# DDoS Inspector Docker Entrypoint Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🛡️ Starting DDoS Inspector Container${NC}"

# Initialize nftables if running with privileges
if [ "$(id -u)" = "0" ]; then
    echo -e "${BLUE}Setting up firewall rules...${NC}"
    /app/scripts/nftables_rules.sh || echo -e "${YELLOW}Warning: Could not setup nftables (may need --privileged)${NC}"
fi

# Start metrics exporters in background if enabled
if [ "${ENABLE_METRICS:-true}" = "true" ]; then
    echo -e "${BLUE}Starting metrics exporters...${NC}"
    
    # Start Snort stats exporter
    python3 /app/snort_stats_exporter.py &
    
    # Compile and start DDoS Inspector metrics exporter
    if [ -f "/app/ddos_inspector_real_metrics.cpp" ]; then
        cd /app
        g++ -o metrics_exporter ddos_inspector_real_metrics.cpp \
            -lpthread -std=c++17 2>/dev/null || echo -e "${YELLOW}Warning: Could not compile metrics exporter${NC}"
        if [ -f "./metrics_exporter" ]; then
            ./metrics_exporter &
        fi
    fi
fi

# Wait for network interface to be available
if [ "${WAIT_FOR_INTERFACE:-true}" = "true" ] && [ "$1" = "snort" ]; then
    INTERFACE="${SNORT_INTERFACE:-eth0}"
    echo -e "${BLUE}Waiting for network interface: ${INTERFACE}${NC}"
    
    for i in {1..30}; do
        if ip link show "${INTERFACE}" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Interface ${INTERFACE} is available${NC}"
            break
        fi
        echo -e "${YELLOW}Waiting for interface ${INTERFACE}... (${i}/30)${NC}"
        sleep 2
    done
    
    if ! ip link show "${INTERFACE}" >/dev/null 2>&1; then
        echo -e "${RED}Error: Interface ${INTERFACE} not found${NC}"
        echo -e "${YELLOW}Available interfaces:${NC}"
        ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
        exit 1
    fi
fi

# Handle different run modes
case "$1" in
    "snort")
        echo -e "${GREEN}🔍 Starting Snort with DDoS Inspector${NC}"
        INTERFACE="${SNORT_INTERFACE:-eth0}"
        CONFIG="${SNORT_CONFIG:-/etc/snort/snort_ddos_config.lua}"
        
        echo -e "${BLUE}Configuration: ${CONFIG}${NC}"
        echo -e "${BLUE}Interface: ${INTERFACE}${NC}"
        
        # Test configuration first
        if ! snort -c "${CONFIG}" -T; then
            echo -e "${RED}❌ Configuration test failed${NC}"
            exit 1
        fi
        
        exec snort -c "${CONFIG}" -i "${INTERFACE}" -A alert_fast "${@:2}"
        ;;
    "test")
        echo -e "${GREEN}🧪 Running test mode${NC}"
        exec snort -c /etc/snort/snort_ddos_config.lua -T
        ;;
    "metrics-only")
        echo -e "${GREEN}📊 Running metrics-only mode${NC}"
        # Keep container running with just metrics exporters
        while true; do
            sleep 30
            [ -f /tmp/ddos_inspector_stats ] && echo "Metrics active: $(date)"
        done
        ;;
    "bash"|"sh")
        echo -e "${GREEN}💻 Starting interactive shell${NC}"
        exec /bin/bash
        ;;
    *)
        echo -e "${GREEN}🚀 Executing custom command: $*${NC}"
        exec "$@"
        ;;
esac