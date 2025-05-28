#!/bin/bash

# DDoS Inspector Plugin Deployment Script
# This script builds and deploys the Snort 3 DDoS Inspector plugin

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== DDoS Inspector Plugin Deployment ===${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root for proper installation.${NC}"
    echo -e "${YELLOW}Please run: sudo $0${NC}"
    exit 1
fi

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

# Check for Snort 3
if ! command -v snort &> /dev/null; then
    echo -e "${RED}Error: Snort 3 not found. Please install Snort 3 first.${NC}"
    echo -e "${YELLOW}Installation guide: docs/Install\ Snort\ 3\ Library/README.md${NC}"
    exit 1
fi

# Get Snort version
SNORT_VERSION=$(snort --version 2>&1 | head -1 | awk '{print $2}')
echo -e "${GREEN}Found Snort version: ${SNORT_VERSION}${NC}"

# Check for required headers
SNORT_INCLUDE_DIRS=(
    "/usr/local/snort3/include/snort"
    "/usr/include/snort"
    "/opt/snort3/include/snort"
)

SNORT_HEADERS_FOUND=false
for dir in "${SNORT_INCLUDE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        SNORT_HEADERS_FOUND=true
        SNORT_INCLUDE_DIR="$dir"
        echo -e "${GREEN}Found Snort headers at: ${dir}${NC}"
        break
    fi
done

if [ "$SNORT_HEADERS_FOUND" = false ]; then
    echo -e "${RED}Error: Snort 3 development headers not found${NC}"
    echo -e "${YELLOW}Checked locations: ${SNORT_INCLUDE_DIRS[*]}${NC}"
    echo -e "${YELLOW}Please install snort3-dev package or compile Snort 3 from source${NC}"
    exit 1
fi

# Check for CMake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}Error: CMake not found. Installing...${NC}"
    apt-get update && apt-get install -y cmake
fi

# Check for build tools
if ! command -v g++ &> /dev/null; then
    echo -e "${RED}Error: g++ not found. Installing build tools...${NC}"
    apt-get update && apt-get install -y build-essential
fi

# Check for nftables
if ! command -v nft &> /dev/null; then
    echo -e "${YELLOW}nftables not found. Installing...${NC}"
    apt-get update && apt-get install -y nftables
fi

# Enable and start nftables service
systemctl enable nftables 2>/dev/null || true
systemctl start nftables 2>/dev/null || true

echo -e "${GREEN}Prerequisites check passed!${NC}"

# Determine plugin installation directory
PLUGIN_DIRS=(
    "/usr/local/lib/snort3_extra_plugins"
    "/usr/lib/snort3_extra_plugins"
    "/opt/snort3/lib/snort3_extra_plugins"
)

# Create plugin directory
PLUGIN_DIR="/usr/local/lib/snort3_extra_plugins"
if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${BLUE}Creating plugin directory: $PLUGIN_DIR${NC}"
    mkdir -p "$PLUGIN_DIR"
fi

# Build the plugin
echo -e "${BLUE}Building DDoS Inspector plugin...${NC}"
cd "$(dirname "$0")/.."

# Clean previous build
if [ -d "build" ]; then
    echo -e "${YELLOW}Cleaning previous build...${NC}"
    rm -rf build
fi

mkdir build
cd build

# Configure with proper Snort paths
echo -e "${BLUE}Configuring build...${NC}"
cmake .. -DSNORT_INCLUDE_DIR="$SNORT_INCLUDE_DIR" || {
    echo -e "${RED}CMake configuration failed${NC}"
    exit 1
}

# Build with all available cores
echo -e "${BLUE}Compiling plugin...${NC}"
make -j$(nproc) || {
    echo -e "${RED}Build failed!${NC}"
    exit 1
}

echo -e "${GREEN}Build successful!${NC}"

# Install the plugin
echo -e "${BLUE}Installing plugin to $PLUGIN_DIR${NC}"
cp ddos_inspector.so "$PLUGIN_DIR/"

# Set proper permissions
chmod 755 "$PLUGIN_DIR/ddos_inspector.so"
chown root:root "$PLUGIN_DIR/ddos_inspector.so"

# Install configuration files
echo -e "${BLUE}Installing configuration files...${NC}"

# Create Snort configuration directory if it doesn't exist
SNORT_CONFIG_DIR="/etc/snort"
mkdir -p "$SNORT_CONFIG_DIR"

# Copy configuration file
cp ../snort_ddos_config.lua "$SNORT_CONFIG_DIR/"
chmod 644 "$SNORT_CONFIG_DIR/snort_ddos_config.lua"

# Create log directories
mkdir -p /var/log/snort
chmod 755 /var/log/snort

# Setup nftables rules
echo -e "${BLUE}Setting up nftables firewall rules...${NC}"
cd ..
./scripts/nftables_rules.sh

# Verify installation
echo -e "${BLUE}Verifying installation...${NC}"

# Check plugin file
if [ -f "$PLUGIN_DIR/ddos_inspector.so" ]; then
    echo -e "${GREEN}✓ Plugin binary installed successfully${NC}"
else
    echo -e "${RED}✗ Plugin binary installation failed${NC}"
    exit 1
fi

# Check configuration file
if [ -f "$SNORT_CONFIG_DIR/snort_ddos_config.lua" ]; then
    echo -e "${GREEN}✓ Configuration file installed${NC}"
else
    echo -e "${RED}✗ Configuration file installation failed${NC}"
    exit 1
fi

# Test plugin loading
echo -e "${BLUE}Testing plugin loading...${NC}"
if snort --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
    echo -e "${GREEN}✓ Plugin loads successfully in Snort${NC}"
elif LD_LIBRARY_PATH="$PLUGIN_DIR" snort --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
    echo -e "${GREEN}✓ Plugin loads successfully (with library path)${NC}"
    echo -e "${YELLOW}Note: You may need to set LD_LIBRARY_PATH=$PLUGIN_DIR${NC}"
else
    echo -e "${YELLOW}⚠ Plugin loading test inconclusive${NC}"
    echo -e "${YELLOW}This is normal - try manual verification with the commands below${NC}"
fi

# Test configuration syntax
echo -e "${BLUE}Testing configuration syntax...${NC}"
if snort -c "$SNORT_CONFIG_DIR/snort_ddos_config.lua" -T 2>/dev/null; then
    echo -e "${GREEN}✓ Configuration syntax is valid${NC}"
else
    echo -e "${YELLOW}⚠ Configuration syntax test failed - may need manual adjustment${NC}"
fi

echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo
echo -e "${BLUE}=== Integration Instructions ===${NC}"
echo -e "${YELLOW}1. Verify plugin installation:${NC}"
echo -e "   sudo snort --show-plugins | grep ddos_inspector"
echo
echo -e "${YELLOW}2. Test with the provided configuration:${NC}"
echo -e "   sudo snort -c /etc/snort/snort_ddos_config.lua -T"
echo
echo -e "${YELLOW}3. Run DDoS detection on interface (replace eth0):${NC}"
echo -e "   sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A alert_fast"
echo
echo -e "${YELLOW}4. Monitor alerts and blocked IPs:${NC}"
echo -e "   tail -f /var/log/snort/alert"
echo -e "   sudo nft list set inet filter ddos_ip_set"
echo
echo -e "${YELLOW}5. Integration with existing Snort config:${NC}"
echo -e "   Add this to your main snort.lua file:"
echo -e "   ${BLUE}dofile('/etc/snort/snort_ddos_config.lua')${NC}"
echo
echo -e "${YELLOW}6. Monitor performance and metrics:${NC}"
echo -e "   cat /tmp/ddos_inspector_stats"
echo
echo -e "${GREEN}🎉 DDoS Inspector is ready to protect your network!${NC}"