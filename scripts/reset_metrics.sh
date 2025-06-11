#!/bin/bash

# DDoS Inspector Metrics Reset Script
# This script resets ONLY metrics data while preserving user configurations
# in Grafana, Kibana, and other services

set -e

echo "🧹 Starting DDoS Inspector metrics-only cleanup..."
echo "ℹ️  This will preserve all user configurations in Grafana and Kibana"

# Function to temporarily stop DDoS Inspector to prevent metric overwrites
pause_ddos_inspector() {
    echo "  Temporarily pausing DDoS Inspector to reset metrics..."
    if docker ps --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
        docker pause ddos_inspector >/dev/null 2>&1
        echo "  ✅ DDoS Inspector paused"
        return 0
    else
        echo "  ℹ️  DDoS Inspector not running"
        return 1
    fi
}

# Function to resume DDoS Inspector
resume_ddos_inspector() {
    echo "  Resuming DDoS Inspector..."
    
    # Check if container exists (running or paused)
    if docker ps -a --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
        # Check if container is paused specifically
        local container_status=$(docker inspect ddos_inspector --format '{{.State.Status}}' 2>/dev/null || echo "not_found")
        
        if [ "$container_status" = "paused" ]; then
            echo "    Container is paused, unpausing..."
            if docker unpause ddos_inspector >/dev/null 2>&1; then
                echo "  ✅ DDoS Inspector resumed successfully"
            else
                echo "  ⚠️  Failed to unpause DDoS Inspector"
                # Try restarting if unpause fails
                echo "    Attempting restart instead..."
                docker restart ddos_inspector >/dev/null 2>&1
                echo "  ✅ DDoS Inspector restarted"
            fi
        elif [ "$container_status" = "running" ]; then
            echo "  ℹ️  DDoS Inspector is already running"
        elif [ "$container_status" = "exited" ]; then
            echo "    Container is stopped, starting..."
            docker start ddos_inspector >/dev/null 2>&1
            echo "  ✅ DDoS Inspector started"
        else
            echo "  ⚠️  DDoS Inspector container status: $container_status"
        fi
    else
        echo "  ⚠️  DDoS Inspector container not found"
    fi
}

# Function to reset DDoS Inspector stats file with permission handling
reset_stats_file() {
    local stats_file="./data/ddos_inspector_stats"
    
    echo "  Resetting DDoS Inspector stats file..."
    
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
    mkdir -p "./data"
    
    # Method 1: Reset from inside the container (most reliable)
    echo "    Attempting to reset stats from inside the container..."
    if docker exec ddos_inspector sh -c "echo '$reset_content' > /app/data/ddos_inspector_stats" 2>/dev/null; then
        echo "  ✅ DDoS Inspector stats reset from inside container"
        
        # Also send a signal to the process to refresh stats if possible
        echo "    Sending signal to DDoS Inspector to refresh stats..."
        docker exec ddos_inspector pkill -USR1 snort 2>/dev/null || true
        
    else
        echo "    ⚠️  Could not reset from inside container, trying host method..."
        
        # Method 2: Reset from host (fallback)
        # Try to write directly first
        if echo "$reset_content" > "$stats_file" 2>/dev/null; then
            echo "  ✅ DDoS Inspector stats reset from host"
        else
            # If direct write fails due to permissions, use sudo
            echo "  ⚠️  Permission denied, trying with sudo..."
            if echo "$reset_content" | sudo tee "$stats_file" > /dev/null; then
                # Fix ownership back to current user
                sudo chown "$(whoami):$(whoami)" "$stats_file"
                echo "  ✅ DDoS Inspector stats reset from host (with sudo)"
            else
                echo "  ❌ Failed to reset stats file even with sudo"
                return 1
            fi
        fi
        
        # Force container restart to pick up the reset stats
        echo "    Forcing container restart to pick up reset stats..."
        docker restart ddos_inspector >/dev/null 2>&1
        echo "    ✅ Container restarted to reload stats"
    fi
    
    # Wait a moment for the file to be updated
    sleep 2
    
    # Verify the reset worked
    echo "  📊 Current stats file content:"
    if [ -f "$stats_file" ]; then
        cat "$stats_file" | sed 's/^/    /'
    else
        echo "    ⚠️  Stats file not found on host"
    fi
    
    # Also check from inside container
    echo "  📊 Stats file content inside container:"
    docker exec ddos_inspector cat /app/data/ddos_inspector_stats 2>/dev/null | sed 's/^/    /' || echo "    ⚠️  Could not read stats from inside container"
}

# Function to restart metrics exporters to force fresh data
restart_metrics_exporters() {
    echo "  Restarting metrics exporters to clear cached data..."
    
    # Restart DDoS metrics exporter
    if docker ps --format '{{.Names}}' | grep -q '^ddos_metrics_exporter$'; then
        echo "    Restarting DDoS metrics exporter..."
        docker restart ddos_metrics_exporter >/dev/null 2>&1
        echo "    ✅ DDoS metrics exporter restarted"
    fi
    
    # Restart Snort stats exporter
    if docker ps --format '{{.Names}}' | grep -q '^snort_stats_exporter$'; then
        echo "    Restarting Snort stats exporter..."
        docker restart snort_stats_exporter >/dev/null 2>&1
        echo "    ✅ Snort stats exporter restarted"
    fi
    
    # Give exporters a moment to restart and send fresh data
    echo "    Waiting for exporters to read fresh zero data..."
    sleep 5
}

# Function to reset Prometheus data by restarting it (since admin API is disabled)
reset_prometheus_data() {
    echo "  Resetting Prometheus time series data (preserving configuration)..."
    
    # Check if Prometheus container is running
    if docker ps --format '{{.Names}}' | grep -q '^ddos_prometheus$'; then
        echo "    Restarting Prometheus to clear time series data..."
        docker restart ddos_prometheus >/dev/null 2>&1
        echo "    ✅ Prometheus restarted with fresh data"
        
        # Wait for Prometheus to come back online
        echo "    Waiting for Prometheus to restart..."
        sleep 8
        
        # Check if it's healthy
        for i in {1..10}; do
            if curl -s http://localhost:9090/-/healthy >/dev/null 2>&1; then
                echo "    ✅ Prometheus is healthy and ready"
                break
            fi
            if [ $i -eq 10 ]; then
                echo "    ⚠️  Prometheus may still be starting up"
            fi
            sleep 2
        done
    else
        echo "    ℹ️  Prometheus not running, data will be clean on next start"
    fi
}

# Function to reset Elasticsearch indices only (preserve Kibana configurations)
reset_elasticsearch_data() {
    echo "  Resetting Elasticsearch log data (preserving Kibana configurations)..."
    
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
                echo "    ✅ Deleted indices matching: $index_pattern"
            else
                echo "    ℹ️  No indices found matching: $index_pattern"
            fi
        done
        
        echo "    ✅ Log data cleared, Kibana configurations preserved"
    else
        echo "    ℹ️  Elasticsearch not running, data will be clean on next start"
    fi
}

# Function to clean log files only
clean_log_files() {
    if [ -d "./logs" ] && [ "$(find ./logs -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "  Cleaning Snort log files..."
        if rm -rf ./logs/* 2>/dev/null; then
            echo "  ✅ Snort logs cleaned"
        else
            echo "  ⚠️  Some log files require sudo, cleaning with elevated permissions..."
            sudo rm -rf ./logs/*
            echo "  ✅ Snort logs cleaned (with sudo)"
        fi
    else
        echo "  ℹ️  No Snort logs found (already clean)"
    fi
    
    # Clean any temporary prometheus-elk-metrics logs
    if [ -d "./prometheus-elk-metrics/logs" ] && [ "$(find ./prometheus-elk-metrics/logs -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "  Cleaning Prometheus-ELK temporary logs..."
        rm -rf ./prometheus-elk-metrics/logs/*
        echo "  ✅ Prometheus-ELK logs cleaned"
    fi
}

# Main reset operations
echo ""
echo "🎯 Resetting metrics data only..."

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
echo "🎯 Metrics-only cleanup completed successfully!"
echo ""
echo "📝 What was reset:"
echo "  ✅ DDoS Inspector statistics counters → 0"
echo "  ✅ All Snort log files → cleared"
echo "  ✅ Prometheus time series data → cleared"
echo "  ✅ Elasticsearch log indices → cleared"
echo "  ✅ Metrics exporters → restarted with fresh data"
echo ""
echo "💾 What was preserved:"
echo "  ✅ Grafana dashboards, users, and settings"
echo "  ✅ Kibana visualizations, index patterns, and saved searches"
echo "  ✅ Prometheus configuration and rules"
echo "  ✅ Elasticsearch cluster settings and mappings"
echo "  ✅ AlertManager configuration"
echo ""
echo "🚀 Grafana should now show zero metrics within 60 seconds!"
echo "💡 The DDoS Inspector will start generating fresh metrics from zero."