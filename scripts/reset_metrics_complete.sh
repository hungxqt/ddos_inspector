#!/bin/bash

# Enhanced DDoS Inspector Metrics Reset Script with Grafana Cache Clear
# This script completely resets metrics and forces Grafana to show fresh data

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[START] Starting comprehensive DDoS Inspector metrics reset...${NC}"
echo -e "${BLUE}[INFO] This will force Grafana to show fresh zero metrics${NC}"

# Function to force Grafana to refresh its cache
force_grafana_refresh() {
    echo -e "${BLUE}[GRAFANA] Forcing Grafana to refresh dashboard cache...${NC}"
    
    # Method 1: Restart Grafana to clear any cached data
    if docker ps --format '{{.Names}}' | grep -q '^ddos_grafana$'; then
        echo "    Restarting Grafana to clear cache..."
        docker restart ddos_grafana >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] Grafana restarted${NC}"
        
        # Wait for Grafana to come back online
        echo "    Waiting for Grafana to restart..."
        sleep 10
        
        # Check if Grafana is healthy
        for i in {1..15}; do
            if curl -s http://localhost:3000/api/health >/dev/null 2>&1; then
                echo -e "${GREEN}[SUCCESS] Grafana is healthy and ready${NC}"
                break
            fi
            if [ $i -eq 15 ]; then
                echo -e "${YELLOW}[WARNING] Grafana may still be starting up${NC}"
            fi
            sleep 2
        done
    fi
}

# Function to completely reset the monitoring pipeline
reset_monitoring_pipeline() {
    echo -e "${BLUE}[RESET] Resetting entire monitoring pipeline...${NC}"
    
    # Step 1: Pause DDoS Inspector
    if docker ps --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
        echo "    Pausing DDoS Inspector..."
        docker pause ddos_inspector >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] DDoS Inspector paused${NC}"
        ddos_was_running=true
    else
        ddos_was_running=false
    fi
    
    # Step 2: Reset stats file
    echo "    Resetting stats file..."
    local stats_file="/var/log/ddos_inspector/ddos_inspector_stats"
    local reset_content="packets_processed:0
packets_blocked:0
entropy:0
rate:0
connections:0
blocked_ips:0
syn_floods:0
slowloris_attacks:0
udp_floods:0
icmp_floods:0
detection_time:0"
    
    if echo "$reset_content" > "$stats_file" 2>/dev/null; then
        echo -e "${GREEN}[SUCCESS] Stats file reset to zero${NC}"
    else
        echo "$reset_content" | sudo tee "$stats_file" > /dev/null
        sudo chown "$(whoami):$(whoami)" "$stats_file"
        echo -e "${GREEN}[SUCCESS] Stats file reset to zero (with sudo)${NC}"
    fi
    
    # Step 3: Restart all metrics services in correct order
    echo "    Restarting metrics exporters..."
    docker restart ddos_metrics_exporter snort_stats_exporter >/dev/null 2>&1
    echo -e "${GREEN}[SUCCESS] Metrics exporters restarted${NC}"
    
    echo "    Restarting Prometheus..."
    docker restart ddos_prometheus >/dev/null 2>&1
    echo -e "${GREEN}[SUCCESS] Prometheus restarted${NC}"
    
    # Step 4: Force Grafana refresh
    force_grafana_refresh
    
    # Step 5: Resume DDoS Inspector
    if [ "$ddos_was_running" = "true" ]; then
        echo "    Resuming DDoS Inspector..."
        docker unpause ddos_inspector >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] DDoS Inspector resumed${NC}"
    fi
    
    # Step 6: Display current (empty) stats
    echo "    Current stats:"
    cat "/var/log/ddos_inspector/ddos_inspector_stats" | sed 's/^/      /'
    echo ""
    
    # Step 7: Wait for everything to stabilize
    echo "    Waiting for monitoring pipeline to stabilize..."
    sleep 15
}

# Function to verify the reset worked
verify_reset() {
    echo -e "${BLUE}[VERIFY] Verifying metrics reset...${NC}"
    
    # Check stats file
    echo -e "${CYAN}[STATS] Stats file contents:${NC}"
    cat "/var/log/ddos_inspector/ddos_inspector_stats" | sed 's/^/      /'
    
    # Check metrics exporter
    if curl -s http://localhost:9091/metrics | grep -q "ddos_inspector_syn_floods_total 0"; then
        echo -e "${GREEN}[SUCCESS] Metrics exporter serving zero values${NC}"
    else
        echo -e "${YELLOW}[WARNING] Metrics exporter may still be starting${NC}"
    fi
    
    # Check Prometheus
    sleep 5
    local prom_value=$(curl -s "http://localhost:9090/api/v1/query?query=ddos_inspector_syn_floods_total" | grep -o '"value":\[[^]]*\]' | grep -o '[0-9.]*' | tail -1 2>/dev/null || echo "not_ready")
    if [ "$prom_value" = "0" ]; then
        echo -e "${GREEN}[SUCCESS] Prometheus returning zero values${NC}"
    else
        echo -e "${YELLOW}[WARNING] Prometheus: $prom_value (may take a moment to update)${NC}"
    fi
}

# Main execution
echo ""
echo -e "${CYAN}[EXECUTE] Performing comprehensive metrics reset...${NC}"

reset_monitoring_pipeline
verify_reset

echo ""
echo -e "${GREEN}[COMPLETE] Comprehensive metrics reset completed!${NC}"
echo ""
echo -e "${CYAN}[SUMMARY] What was reset:${NC}"
echo -e "${GREEN}    [RESET] DDoS Inspector statistics → all zeros${NC}"
echo -e "${GREEN}    [RESET] Metrics exporters → restarted with fresh data${NC}"
echo -e "${GREEN}    [RESET] Prometheus → restarted with clean time series${NC}"
echo -e "${GREEN}    [RESET] Grafana → restarted to clear cache${NC}"
echo ""
echo -e "${BLUE}[PRESERVED] What was preserved:${NC}"
echo -e "${GREEN}    [PRESERVED] All Grafana dashboards and settings${NC}"
echo -e "${GREEN}    [PRESERVED] All Kibana configurations${NC}"
echo -e "${GREEN}    [PRESERVED] All service configurations${NC}"
echo ""
echo -e "${GREEN}[READY] Grafana dashboard should now show ZERO metrics!${NC}"
echo -e "${BLUE}[ACTION] Refresh your browser and check the dashboard in 30 seconds.${NC}"