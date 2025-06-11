#!/bin/bash

# Enhanced DDoS Inspector Metrics Reset Script with Grafana Cache Clear
# This script completely resets metrics and forces Grafana to show fresh data

set -e

echo "🧹 Starting comprehensive DDoS Inspector metrics reset..."
echo "ℹ️  This will force Grafana to show fresh zero metrics"

# Function to force Grafana to refresh its cache
force_grafana_refresh() {
    echo "  Forcing Grafana to refresh dashboard cache..."
    
    # Method 1: Restart Grafana to clear any cached data
    if docker ps --format '{{.Names}}' | grep -q '^ddos_grafana$'; then
        echo "    Restarting Grafana to clear cache..."
        docker restart ddos_grafana >/dev/null 2>&1
        echo "    ✅ Grafana restarted"
        
        # Wait for Grafana to come back online
        echo "    Waiting for Grafana to restart..."
        sleep 10
        
        # Check if Grafana is healthy
        for i in {1..15}; do
            if curl -s http://localhost:3000/api/health >/dev/null 2>&1; then
                echo "    ✅ Grafana is healthy and ready"
                break
            fi
            if [ $i -eq 15 ]; then
                echo "    ⚠️  Grafana may still be starting up"
            fi
            sleep 2
        done
    fi
}

# Function to completely reset the monitoring pipeline
reset_monitoring_pipeline() {
    echo "  Resetting entire monitoring pipeline..."
    
    # Step 1: Pause DDoS Inspector
    if docker ps --format '{{.Names}}' | grep -q '^ddos_inspector$'; then
        echo "    Pausing DDoS Inspector..."
        docker pause ddos_inspector >/dev/null 2>&1
        echo "    ✅ DDoS Inspector paused"
        ddos_was_running=true
    else
        ddos_was_running=false
    fi
    
    # Step 2: Reset stats file
    echo "    Resetting stats file..."
    local stats_file="./data/ddos_inspector_stats"
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
        echo "    ✅ Stats file reset to zero"
    else
        echo "$reset_content" | sudo tee "$stats_file" > /dev/null
        sudo chown "$(whoami):$(whoami)" "$stats_file"
        echo "    ✅ Stats file reset to zero (with sudo)"
    fi
    
    # Step 3: Restart all metrics services in correct order
    echo "    Restarting metrics exporters..."
    docker restart ddos_metrics_exporter snort_stats_exporter >/dev/null 2>&1
    echo "    ✅ Metrics exporters restarted"
    
    echo "    Restarting Prometheus..."
    docker restart ddos_prometheus >/dev/null 2>&1
    echo "    ✅ Prometheus restarted"
    
    # Step 4: Force Grafana refresh
    force_grafana_refresh
    
    # Step 5: Resume DDoS Inspector
    if [ "$ddos_was_running" = "true" ]; then
        echo "    Resuming DDoS Inspector..."
        docker unpause ddos_inspector >/dev/null 2>&1
        echo "    ✅ DDoS Inspector resumed"
    fi
    
    # Step 6: Wait for everything to stabilize
    echo "    Waiting for monitoring pipeline to stabilize..."
    sleep 15
}

# Function to verify the reset worked
verify_reset() {
    echo "  Verifying metrics reset..."
    
    # Check stats file
    echo "    📊 Stats file contents:"
    cat "./data/ddos_inspector_stats" | sed 's/^/      /'
    
    # Check metrics exporter
    if curl -s http://localhost:9091/metrics | grep -q "ddos_inspector_syn_floods_total 0"; then
        echo "    ✅ Metrics exporter serving zero values"
    else
        echo "    ⚠️  Metrics exporter may still be starting"
    fi
    
    # Check Prometheus
    sleep 5
    local prom_value=$(curl -s "http://localhost:9090/api/v1/query?query=ddos_inspector_syn_floods_total" | grep -o '"value":\[[^]]*\]' | grep -o '[0-9.]*' | tail -1 2>/dev/null || echo "not_ready")
    if [ "$prom_value" = "0" ]; then
        echo "    ✅ Prometheus returning zero values"
    else
        echo "    ⚠️  Prometheus: $prom_value (may take a moment to update)"
    fi
}

# Main execution
echo ""
echo "🎯 Performing comprehensive metrics reset..."

reset_monitoring_pipeline
verify_reset

echo ""
echo "🎯 Comprehensive metrics reset completed!"
echo ""
echo "📝 What was reset:"
echo "  ✅ DDoS Inspector statistics → all zeros"
echo "  ✅ Metrics exporters → restarted with fresh data"
echo "  ✅ Prometheus → restarted with clean time series"
echo "  ✅ Grafana → restarted to clear cache"
echo ""
echo "💾 What was preserved:"
echo "  ✅ All Grafana dashboards and settings"
echo "  ✅ All Kibana configurations"
echo "  ✅ All service configurations"
echo ""
echo "🚀 Grafana dashboard should now show ZERO metrics!"
echo "📱 Refresh your browser and check the dashboard in 30 seconds."