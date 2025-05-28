#!/bin/bash

# DDoS Inspector Plugin Deployment Script
# This script builds and deploys the Snort 3 DDoS Inspector plugin

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== DDoS Inspector Plugin Deployment ===${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Warning: Running as root. This is required for installation.${NC}"
fi

# Check prerequisites
echo -e "${GREEN}Checking prerequisites...${NC}"

# Check for Snort 3
if ! command -v snort &> /dev/null; then
    echo -e "${RED}Error: Snort 3 not found. Please install Snort 3 first.${NC}"
    exit 1
fi

# Check for required headers
if [ ! -d "/usr/local/snort3/include/snort" ]; then
    echo -e "${RED}Error: Snort 3 development headers not found at /usr/local/snort3/include/snort${NC}"
    echo -e "${YELLOW}Please install snort3-dev package or compile Snort 3 from source${NC}"
    exit 1
fi

# Check for CMake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}Error: CMake not found. Please install cmake.${NC}"
    exit 1
fi

# Check for nftables
if ! command -v nft &> /dev/null; then
    echo -e "${YELLOW}Warning: nftables not found. Installing...${NC}"
    apt-get update && apt-get install -y nftables
fi

echo -e "${GREEN}Prerequisites check passed!${NC}"

# Create plugin directory if it doesn't exist
PLUGIN_DIR="/usr/local/lib/snort3_extra_plugins"
if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${GREEN}Creating plugin directory: $PLUGIN_DIR${NC}"
    mkdir -p "$PLUGIN_DIR"
fi

# Build the plugin
echo -e "${GREEN}Building DDoS Inspector plugin...${NC}"
cd "$(dirname "$0")/.."

# Clean previous build
if [ -d "build" ]; then
    rm -rf build
fi

mkdir build
cd build

# Configure and build
cmake ..
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Install the plugin
echo -e "${GREEN}Installing plugin to $PLUGIN_DIR${NC}"
cp ddos_inspector.so "$PLUGIN_DIR/"

# Set proper permissions
chmod 755 "$PLUGIN_DIR/ddos_inspector.so"

# Setup nftables rules
echo -e "${GREEN}Setting up nftables rules...${NC}"
../scripts/nftables_rules.sh

# Verify installation
echo -e "${GREEN}Verifying installation...${NC}"
if [ -f "$PLUGIN_DIR/ddos_inspector.so" ]; then
    echo -e "${GREEN}✓ Plugin installed successfully${NC}"
else
    echo -e "${RED}✗ Plugin installation failed${NC}"
    exit 1
fi

# Test plugin loading
echo -e "${GREEN}Testing plugin loading...${NC}"
if snort --help 2>/dev/null | grep -q "ddos_inspector"; then
    echo -e "${GREEN}✓ Plugin can be loaded by Snort${NC}"
else
    echo -e "${YELLOW}! Plugin loading test inconclusive - manual verification needed${NC}"
fi

echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Add the plugin configuration to your snort.lua file"
echo -e "2. Copy the example configuration from snort_ddos_config.lua"
echo -e "3. Test with: sudo snort -c snort.lua --show-plugins | grep ddos_inspector"
echo -e "4. Run Snort with: sudo snort -c snort.lua -i <interface>"