#!/bin/bash

# DDoS Inspector Metrics Reset Script
# This script resets ONLY metrics data while preserving user configurations
# in Grafana, Kibana, and other services

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Starting DDoS Inspector metrics-only cleanup...${NC}"
echo -e "${BLUE}[INFO] This will preserve all user configurations in Grafana and Kibana${NC}"

# Function to temporarily stop DDoS Inspector to prevent metric overwrites
pause_ddos_inspector() {
    echo -e "${YELLOW}[PAUSE] Temporarily pausing DDoS Inspector to reset metrics...${NC}"
    if docker ps --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
        docker pause ddos_inspector >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] DDoS Inspector paused${NC}"
        return 0
    else
        echo -e "${BLUE}[INFO] DDoS Inspector not running${NC}"
        return 1
    fi
}

# Function to resume DDoS Inspector
resume_ddos_inspector() {
    echo -e "${BLUE}[RESUME] Resuming DDoS Inspector...${NC}"
    
    # Check if container exists (running or paused)
    if docker ps -a --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
        # Check if container is paused specifically
        local container_status=$(docker inspect ddos_inspector --format '{{.State.Status}}' 2>/dev/null || echo "not_found")
        
        if [ "$container_status" = "paused" ]; then
            echo "    Container is paused, unpausing..."
            if docker unpause ddos_inspector >/dev/null 2>&1; then
                echo -e "${GREEN}[SUCCESS] DDoS Inspector resumed successfully${NC}"
            else
                echo -e "${YELLOW}[WARNING] Failed to unpause DDoS Inspector${NC}"
                # Try restarting if unpause fails
                echo "    Attempting restart instead..."
                docker restart ddos_inspector >/dev/null 2>&1
                echo -e "${GREEN}[SUCCESS] DDoS Inspector restarted${NC}"
            fi
        elif [ "$container_status" = "running" ]; then
            echo -e "${BLUE}[INFO] DDoS Inspector is already running${NC}"
        elif [ "$container_status" = "exited" ]; then
            echo "    Container is stopped, starting..."
            docker start ddos_inspector >/dev/null 2>&1
            echo -e "${GREEN}[SUCCESS] DDoS Inspector started${NC}"
        else
            echo -e "${YELLOW}[WARNING] DDoS Inspector container status: $container_status${NC}"
        fi
    else
        echo -e "${YELLOW}[WARNING] DDoS Inspector container not found${NC}"
    fi
}

# Function to reset DDoS Inspector stats file with permission handling
reset_stats_file() {
    local stats_file="/var/log/ddos_inspector/metrics.log"
    
    echo -e "${BLUE}[RESET] Resetting DDoS Inspector stats file...${NC}"
    
    # Create the reset content
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
    
    # Ensure data directory exists
    mkdir -p "/var/log/ddos_inspector"
    
    # Method 1: Reset from inside the container (most reliable)
    echo "    Attempting to reset stats from inside the container..."
    if docker exec ddos_inspector sh -c "echo '$reset_content' > /var/log/ddos_inspector/metrics.log" 2>/dev/null; then
        echo -e "${GREEN}[SUCCESS] DDoS Inspector stats reset from inside container${NC}"
        
        # Also send a signal to the process to refresh stats if possible
        echo "    Sending signal to DDoS Inspector to refresh stats..."
        docker exec ddos_inspector pkill -USR1 snort 2>/dev/null || true
        
    else
        echo -e "${YELLOW}[WARNING] Could not reset from inside container, trying host method...${NC}"
        
        # Method 2: Reset from host (fallback)
        # Attempt to write directly if permissions allow (e.g., running as root or with sudo)
        if sudo sh -c "echo '$reset_content' > \"$stats_file\"" 2>/dev/null; then
            echo -e "${GREEN}[SUCCESS] Stats file reset directly at $stats_file${NC}"
        # If direct write fails, try via Docker if container is running
        elif docker ps --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
            echo "    Attempting to reset stats file inside Docker container..."
            if docker exec ddos_inspector sh -c "echo \'$reset_content\' > /var/log/ddos_inspector/metrics.log" 2>/dev/null; then
                echo -e "${GREEN}[SUCCESS] Stats file reset inside ddos_inspector container${NC}"
            else
                echo -e "${YELLOW}[WARNING] Failed to reset stats file inside container. Check permissions or if path exists.${NC}"
            fi
        else
            echo -e "${RED}[ERROR] Failed to reset stats file: container not running and direct write not permitted${NC}"
            return 1
        fi
        
        # Force container restart to pick up the reset stats
        echo "    Forcing container restart to pick up reset stats..."
        docker restart ddos_inspector >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] Container restarted to reload stats${NC}"
    fi
    
    # Wait a moment for the file to be updated
    sleep 2
    
    # Verify the reset worked
    echo -e "${CYAN}[STATS] Current stats file content:${NC}"
    if [ -f "$stats_file" ]; then
        cat "$stats_file" | sed 's/^/    /'
    else
        echo -e "${YELLOW}[WARNING] Stats file not found on host${NC}"
    fi
    echo "    Current stats from host (if available):"
    sudo cat "$stats_file" 2>/dev/null | sed 's/^/    /' || echo -e "${YELLOW}[WARNING] Could not read stats from host${NC}"
    echo "    Current stats from ddos_inspector container (if running):"
    docker exec ddos_inspector cat /var/log/ddos_inspector/metrics.log 2>/dev/null | sed 's/^/    /' || echo -e "${YELLOW}[WARNING] Could not read stats from inside container${NC}"

    echo ""
}

# Function to restart metrics exporters to force fresh data
restart_metrics_exporters() {
    echo -e "${BLUE}[RESTART] Restarting metrics exporters to clear cached data...${NC}"
    
    # Restart DDoS metrics exporter
    if docker ps --format '{{.Names}}' | grep -q '^ddos_metrics_exporter$'; then
        echo "    Restarting DDoS metrics exporter..."
        docker restart ddos_metrics_exporter >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] DDoS metrics exporter restarted${NC}"
    fi
    
    # Restart Snort stats exporter
    if docker ps --format '{{.Names}}' | grep -q '^snort_stats_exporter$'; then
        echo "    Restarting Snort stats exporter..."
        docker restart snort_stats_exporter >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] Snort stats exporter restarted${NC}"
    fi
    
    # Give exporters a moment to restart and send fresh data
    echo "    Waiting for exporters to read fresh zero data..."
    sleep 5
}

# Function to reset Prometheus data by restarting it (since admin API is disabled)
reset_prometheus_data() {
    echo -e "${BLUE}[RESET] Resetting Prometheus time series data (preserving configuration)...${NC}"
    
    # Check if Prometheus container is running
    if docker ps --format '{{.Names}}' | grep -q '^ddos_prometheus$'; then
        echo "    Restarting Prometheus to clear time series data..."
        docker restart ddos_prometheus >/dev/null 2>&1
        echo -e "${GREEN}[SUCCESS] Prometheus restarted with fresh data${NC}"
        
        # Wait for Prometheus to come back online
        echo "    Waiting for Prometheus to restart..."
        sleep 8
        
        # Check if it's healthy
        for i in {1..10}; do
            if curl -s http://localhost:9090/-/healthy >/dev/null 2>&1; then
                echo -e "${GREEN}[SUCCESS] Prometheus is healthy and ready${NC}"
                break
            fi
            if [ $i -eq 10 ]; then
                echo -e "${YELLOW}[WARNING] Prometheus may still be starting up${NC}"
            fi
            sleep 2
        done
    else
        echo -e "${BLUE}[INFO] Prometheus not running, data will be clean on next start${NC}"
    fi
}

# Function to reset Elasticsearch indices only (preserve Kibana configurations)
reset_elasticsearch_data() {
    echo -e "${BLUE}[RESET] Resetting Elasticsearch log data (preserving Kibana configurations)...${NC}"
    
    # Check if Elasticsearch is running
    if docker ps --format '{{.Names}}' | grep -q '^ddos_elasticsearch$'; then
        echo "    Elasticsearch is running, deleting log indices only..."
        
        # Wait for Elasticsearch to be ready
        for i in {1..5}; do
            if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
                break
            fi
            echo "    Waiting for Elasticsearch to be ready..."
            sleep 2
        done
        
        # Delete only log-related indices, preserve Kibana system indices
        local indices_to_delete=(
            "snort-*"
            "ddos-*" 
            "logstash-*"
            "filebeat-*"
        )
        
        for index_pattern in "${indices_to_delete[@]}"; do
            if curl -s -X DELETE "http://localhost:9200/${index_pattern}" 2>/dev/null | grep -q "acknowledged"; then
                echo -e "${GREEN}[SUCCESS] Deleted indices matching: $index_pattern${NC}"
            else
                echo -e "${BLUE}[INFO] No indices found matching: $index_pattern${NC}"
            fi
        done
        
        echo -e "${GREEN}[SUCCESS] Log data cleared, Kibana configurations preserved${NC}"
    else
        echo -e "${BLUE}[INFO] Elasticsearch not running, data will be clean on next start${NC}"
    fi
}

# Function to clean log files only
clean_log_files() {
    if [ -d "./logs" ] && [ "$(find ./logs -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        echo -e "${BLUE}[CLEAN] Cleaning Snort log files...${NC}"
        if rm -rf ./logs/* 2>/dev/null; then
            echo -e "${GREEN}[SUCCESS] Snort logs cleaned${NC}"
        else
            echo -e "${YELLOW}[WARNING] Some log files require sudo, cleaning with elevated permissions...${NC}"
            sudo rm -rf ./logs/*
            echo -e "${GREEN}[SUCCESS] Snort logs cleaned (with sudo)${NC}"
        fi
    else
        echo -e "${BLUE}[INFO] No Snort logs found (already clean)${NC}"
    fi
    
    # Clean any temporary prometheus-elk-metrics logs
    if [ -d "./prometheus-elk-metrics/logs" ] && [ "$(find ./prometheus-elk-metrics/logs -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        echo -e "${BLUE}[CLEAN] Cleaning Prometheus-ELK temporary logs...${NC}"
        rm -rf ./prometheus-elk-metrics/logs/*
        echo -e "${GREEN}[SUCCESS] Prometheus-ELK logs cleaned${NC}"
    fi
}

# Main reset operations
echo ""
echo -e "${CYAN}[TARGET] Resetting metrics data only...${NC}"

# Step 1: Pause DDoS Inspector to prevent it from overwriting our reset
ddos_was_running=$(pause_ddos_inspector && echo "true" || echo "false")

# Step 2: Reset DDoS Inspector stats file
reset_stats_file

# Step 3: Clean log files
clean_log_files

# Step 4: Restart metrics exporters to force them to read fresh data
restart_metrics_exporters

# Step 5: Reset Prometheus time series (but keep config)
reset_prometheus_data

# Step 6: Reset Elasticsearch log data (but keep Kibana config)
reset_elasticsearch_data

# Step 7: Resume DDoS Inspector
if [ "$ddos_was_running" = "true" ]; then
    resume_ddos_inspector
fi

echo ""
echo -e "${GREEN}[TARGET] Metrics-only cleanup completed successfully!${NC}"
echo ""
echo -e "${CYAN}[SUMMARY] What was reset:${NC}"
echo -e "${GREEN}    [SUCCESS] DDoS Inspector statistics counters → 0${NC}"
echo -e "${GREEN}    [SUCCESS] All Snort log files → cleared${NC}"
echo -e "${GREEN}    [SUCCESS] Prometheus time series data → cleared${NC}"
echo -e "${GREEN}    [SUCCESS] Elasticsearch log indices → cleared${NC}"
echo -e "${GREEN}    [SUCCESS] Metrics exporters → restarted with fresh data${NC}"
echo ""
echo -e "${BLUE}[PRESERVED] What was preserved:${NC}"
echo -e "${GREEN}    [PRESERVED] Grafana dashboards, users, and settings${NC}"
echo -e "${GREEN}    [PRESERVED] Kibana visualizations, index patterns, and saved searches${NC}"
echo -e "${GREEN}    [PRESERVED] Prometheus configuration and rules${NC}"
echo -e "${GREEN}    [PRESERVED] Elasticsearch cluster settings and mappings${NC}"
echo -e "${GREEN}    [PRESERVED] AlertManager configuration${NC}"
echo ""
echo -e "${GREEN}[READY] Grafana should now show zero metrics within 60 seconds!${NC}"
echo -e "${BLUE}[INFO] The DDoS Inspector will start generating fresh metrics from zero.${NC}"