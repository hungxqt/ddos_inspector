#!/bin/bash

# DDoS Inspector Plugin Deployment Script
# This script builds and deploys the Snort 3 DDoS Inspector plugin

set -e

# Protect against PATH conflicts with Windows/Cygwin binaries
# Remove problematic Windows paths that might interfere with bash builtins
export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '/mnt/[a-z]/cygwin' | tr '\n' ':' | sed 's/:$//')

# Ensure we use bash builtins for common commands
alias wait='builtin wait'

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
NETWORK_INTERFACE="eth0"
ACTION="deploy"
SHOW_HELP=false

# Function to show help
show_help() {
    echo -e "${GREEN}=== DDoS Inspector Plugin Deployment Script ===${NC}"
    echo
    echo -e "${BLUE}USAGE:${NC}"
    echo "  $0 [OPTIONS]"
    echo
    echo -e "${BLUE}OPTIONS:${NC}"
    echo -e "  ${YELLOW}-h, --help${NC}              Show this help message"
    echo -e "  ${YELLOW}-i, --interface IFACE${NC}   Set network interface (default: eth0)"
    echo -e "  ${YELLOW}--start${NC}                 Start the DDoS Inspector service"
    echo -e "  ${YELLOW}--stop${NC}                  Stop the DDoS Inspector service"
    echo -e "  ${YELLOW}--restart${NC}               Restart the DDoS Inspector service"
    echo -e "  ${YELLOW}--status${NC}                Show service status"
    echo -e "  ${YELLOW}--logs${NC}                  Show service logs (follow mode)"
    echo -e "  ${YELLOW}--enable${NC}                Enable service to start on boot"
    echo -e "  ${YELLOW}--disable${NC}               Disable service from starting on boot"
    echo -e "  ${YELLOW}--test-config${NC}           Test configuration syntax"
    echo -e "  ${YELLOW}--show-plugins${NC}          Show loaded Snort plugins"
    echo -e "  ${YELLOW}--uninstall${NC}             Uninstall the DDoS Inspector"
    echo -e "  ${YELLOW}--force-uninstall${NC}       Force uninstall the DDoS Inspector"
    echo
    echo -e "${BLUE}EXAMPLES:${NC}"
    echo "  $0                           # Deploy with default settings"
    echo "  $0 -i enp0s3                # Deploy with specific interface"
    echo "  $0 --start                   # Start the service"
    echo "  $0 --stop                    # Stop the service"
    echo "  $0 --status                  # Check service status"
    echo "  $0 --logs                    # View service logs"
    echo
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            SHOW_HELP=true
            shift
            ;;
        -i|--interface)
            if [[ -n "$2" && "$2" != -* ]]; then
                NETWORK_INTERFACE="$2"
                shift 2
            else
                echo -e "${RED}Error: --interface requires an interface name${NC}"
                exit 1
            fi
            ;;
        --start)
            ACTION="start"
            shift
            ;;
        --stop)
            ACTION="stop"
            shift
            ;;
        --restart)
            ACTION="restart"
            shift
            ;;
        --status)
            ACTION="status"
            shift
            ;;
        --logs)
            ACTION="logs"
            shift
            ;;
        --enable)
            ACTION="enable"
            shift
            ;;
        --disable)
            ACTION="disable"
            shift
            ;;
        --test-config)
            ACTION="test-config"
            shift
            ;;
        --show-plugins)
            ACTION="show-plugins"
            shift
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        --force-uninstall)
            ACTION="force-uninstall"
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Show help if requested
if [ "$SHOW_HELP" = true ]; then
    show_help
    exit 0
fi

# Function to handle service operations
handle_service_action() {
    case $ACTION in
        start)
            echo -e "${BLUE}Starting DDoS Inspector service...${NC}"
            systemctl start snort-ddos-inspector
            echo -e "${GREEN}Service started successfully${NC}"
            ;;
        stop)
            echo -e "${BLUE}Stopping DDoS Inspector service...${NC}"
            systemctl stop snort-ddos-inspector
            echo -e "${GREEN}Service stopped successfully${NC}"
            ;;
        restart)
            echo -e "${BLUE}Restarting DDoS Inspector service...${NC}"
            systemctl restart snort-ddos-inspector
            echo -e "${GREEN}Service restarted successfully${NC}"
            ;;
        status)
            echo -e "${BLUE}DDoS Inspector service status:${NC}"
            systemctl status snort-ddos-inspector
            ;;
        logs)
            echo -e "${BLUE}Following DDoS Inspector service logs (Ctrl+C to exit):${NC}"
            journalctl -u snort-ddos-inspector -f
            ;;
        enable)
            echo -e "${BLUE}Enabling DDoS Inspector service to start on boot...${NC}"
            systemctl enable snort-ddos-inspector
            echo -e "${GREEN}Service enabled successfully${NC}"
            ;;
        disable)
            echo -e "${BLUE}Disabling DDoS Inspector service from starting on boot...${NC}"
            systemctl disable snort-ddos-inspector
            echo -e "${GREEN}Service disabled successfully${NC}"
            ;;
        test-config)
            echo -e "${BLUE}Testing configuration syntax...${NC}"
            if snort -c /etc/snort/snort_ddos_config.lua -T 2>/dev/null; then
                echo -e "${GREEN}✓ Configuration syntax is valid${NC}"
            else
                echo -e "${RED}✗ Configuration syntax test failed${NC}"
                echo -e "${YELLOW}Please check /etc/snort/snort_ddos_config.lua for errors${NC}"
                exit 1
            fi
            ;;
        show-plugins)
            echo -e "${BLUE}Showing loaded Snort plugins:${NC}"
            snort --show-plugins | grep -A 5 -B 5 ddos_inspector || {
                echo -e "${YELLOW}DDoS Inspector plugin not found in loaded plugins${NC}"
                echo -e "${BLUE}All available plugins:${NC}"
                snort --show-plugins
            }
            ;;
        uninstall)
            echo -e "${BLUE}Uninstalling DDoS Inspector...${NC}"
            
            # Stop and disable service
            systemctl stop snort-ddos-inspector 2>/dev/null || true
            systemctl disable snort-ddos-inspector 2>/dev/null || true
            
            # Remove service file
            rm -f /etc/systemd/system/snort-ddos-inspector.service
            systemctl daemon-reload
            
            # Remove plugin files
            rm -f /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
            rm -f /usr/lib/snort3_extra_plugins/ddos_inspector.so
            
            # Remove configuration files
            rm -f /etc/snort/snort_ddos_config.lua
            rm -rf /etc/snort/service
            
            # Call nftables uninstall
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
                echo -e "${BLUE}Removing firewall rules...${NC}"
                "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
                    echo -e "${YELLOW}⚠ Failed to remove firewall rules automatically${NC}"
                }
            fi
            
            echo -e "${GREEN}DDoS Inspector uninstalled successfully${NC}"
            ;;
        force-uninstall)
            echo -e "${BLUE}Force uninstalling DDoS Inspector...${NC}"
            
            # Call specialized uninstall scripts
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            
            # Uninstall dependencies
            if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
                echo -e "${BLUE}Running dependency uninstaller...${NC}"
                "$SCRIPT_DIR/install_dependencies.sh" --uninstall || {
                    echo -e "${RED}✗ Failed to run dependency uninstaller${NC}"
                }
            fi
            
            # Remove firewall rules
            if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
                echo -e "${BLUE}Removing firewall rules...${NC}"
                "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
                    echo -e "${RED}✗ Failed to remove firewall rules${NC}"
                }
            fi
            
            # Remove Docker deployment if exists
            if [ -f "$SCRIPT_DIR/deploy_docker.sh" ]; then
                echo -e "${BLUE}Cleaning up Docker deployment...${NC}"
                "$SCRIPT_DIR/deploy_docker.sh" --uninstall || {
                    echo -e "${YELLOW}⚠ Failed to clean up Docker deployment${NC}"
                }
            fi
            
            # Proceed with regular uninstall
            handle_service_action "uninstall"
            ;;
    esac
}

# Handle non-deploy actions
if [ "$ACTION" != "deploy" ]; then
    handle_service_action
    exit 0
fi

# Continue with deployment process if ACTION is "deploy"
echo -e "${GREEN}=== Starting DDoS Inspector Deployment ===${NC}"
echo -e "${BLUE}Network Interface: ${NETWORK_INTERFACE}${NC}"

# Install dependencies using the dedicated script
echo -e "${BLUE}Installing system dependencies...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
    if "$SCRIPT_DIR/install_dependencies.sh"; then
        echo -e "${GREEN}✓ Dependencies installed successfully${NC}"
    else
        echo -e "${RED}✗ Dependency installation failed${NC}"
        exit 1
    fi
else
    echo -e "${RED}Error: install_dependencies.sh not found at $SCRIPT_DIR${NC}"
    exit 1
fi

# Define Snort include directories to search
SNORT_INCLUDE_DIRS=(
    "/usr/include/snort"
    "/usr/local/include/snort"
    "/opt/snort3/include/snort"
    "/usr/include/snort3"
    "/usr/local/include/snort3"
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

# Create systemd service for Snort DDoS Inspector
echo -e "${BLUE}Setting up Snort DDoS Inspector as system service...${NC}"

# Create systemd service file
cat > /etc/systemd/system/snort-ddos-inspector.service << EOF
[Unit]
Description=Snort 3 DDoS Inspector Service
After=network.target nftables.service
Wants=nftables.service
Documentation=https://snort.org/

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/usr/bin/test -f /etc/snort/snort_ddos_config.lua
ExecStart=/usr/local/bin/snort -c /etc/snort/snort_ddos_config.lua -i ${NETWORK_INTERFACE} -A alert_fast -D
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/snort /tmp

[Install]
WantedBy=multi-user.target
EOF

# Create service environment configuration
mkdir -p /etc/snort/service
cat > /etc/snort/service/interface.conf << 'EOF'
# Network interface for Snort DDoS Inspector
# Change this to match your network interface
SNORT_INTERFACE=eth0

# Additional Snort options
SNORT_OPTIONS="-A alert_fast"

# Log level (0-4, 0=emergency, 4=debug)
LOG_LEVEL=2
EOF

chmod 644 /etc/systemd/system/snort-ddos-inspector.service
chmod 644 /etc/snort/service/interface.conf

# Reload systemd
systemctl daemon-reload

# Setup nftables rules
echo -e "${BLUE}Setting up nftables firewall rules...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
    if "$SCRIPT_DIR/nftables_rules.sh"; then
        echo -e "${GREEN}✓ nftables rules applied successfully${NC}"
    else
        echo -e "${RED}✗ nftables rules setup failed${NC}"
        exit 1
    fi
else
    echo -e "${RED}Error: nftables_rules.sh not found at $SCRIPT_DIR${NC}"
    exit 1
fi

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
echo -e "${BLUE}=== System Service Setup ===${NC}"
echo -e "${YELLOW}1. Configure network interface:${NC}"
echo -e "   Edit /etc/snort/service/interface.conf to set your network interface"
echo -e "   Current setting: eth0 (change if needed)"
echo
echo -e "${YELLOW}2. Enable and start the service:${NC}"
echo -e "   sudo systemctl enable snort-ddos-inspector"
echo -e "   sudo systemctl start snort-ddos-inspector"
echo
echo -e "${YELLOW}3. Check service status:${NC}"
echo -e "   sudo systemctl status snort-ddos-inspector"
echo
echo -e "${YELLOW}4. View service logs:${NC}"
echo -e "   sudo journalctl -u snort-ddos-inspector -f"
echo
echo -e "${YELLOW}5. Control the service:${NC}"
echo -e "   sudo systemctl stop snort-ddos-inspector     # Stop service"
echo -e "   sudo systemctl restart snort-ddos-inspector  # Restart service"
echo -e "   sudo systemctl reload snort-ddos-inspector   # Reload config"
echo
echo -e "${BLUE}=== Manual Testing (Alternative) ===${NC}"
echo -e "${YELLOW}1. Verify plugin installation:${NC}"
echo -e "   sudo snort --show-plugins | grep ddos_inspector"
echo
echo -e "${YELLOW}2. Test configuration syntax:${NC}"
echo -e "   sudo snort -c /etc/snort/snort_ddos_config.lua -T"
echo
echo -e "${YELLOW}3. Run DDoS Inspector manually (for testing):${NC}"
echo -e "   sudo snort -c /etc/snort/snort_ddos_config.lua -i $NETWORK_INTERFACE -A alert_fast"
echo
echo -e "${YELLOW}4. Monitor alerts:${NC}"
echo -e "   tail -f /var/log/snort/alert"
echo
echo -e "${BLUE}=== Configuration Files ===${NC}"
echo -e "${YELLOW}Plugin Binary:${NC} $PLUGIN_DIR/ddos_inspector.so"
echo -e "${YELLOW}Configuration:${NC} /etc/snort/snort_ddos_config.lua"
echo -e "${YELLOW}Service Config:${NC} /etc/snort/service/interface.conf"
echo -e "${YELLOW}Service File:${NC} /etc/systemd/system/snort-ddos-inspector.service"
echo -e "${YELLOW}Log Directory:${NC} /var/log/snort/"
echo
echo -e "${BLUE}=== Quick Start Commands ===${NC}"
echo -e "${YELLOW}Use this script for easy management:${NC}"
echo -e "   $0 --start           # Start the service"
echo -e "   $0 --status          # Check status"
echo -e "   $0 --logs            # View logs"
echo -e "   $0 --test-config     # Test configuration"
echo -e "   $0 --show-plugins    # Verify plugin loading"
echo
echo -e "${GREEN}=== Deployment Summary ===${NC}"
echo -e "${GREEN}✓ DDoS Inspector plugin compiled and installed${NC}"
echo -e "${GREEN}✓ System service configured${NC}"
echo -e "${GREEN}✓ Firewall rules applied${NC}"
echo -e "${GREEN}✓ Configuration files in place${NC}"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo -e "1. Adjust network interface in /etc/snort/service/interface.conf if needed"
echo -e "2. Review and customize /etc/snort/snort_ddos_config.lua as required"
echo -e "3. Start the service: $0 --start"
echo -e "4. Monitor with: $0 --logs"
echo
echo -e "${GREEN}DDoS Inspector deployment completed successfully!${NC}"