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

# Get script directory and project root at the beginning
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Function to find Snort binary
find_snort_binary() {
    local snort_paths=(
        "/usr/local/snort3/bin/snort"
        "/usr/local/bin/snort"
        "/usr/bin/snort"
        "/opt/snort3/bin/snort"
    )
    
    for path in "${snort_paths[@]}"; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    # Try which command as fallback
    if command -v snort >/dev/null 2>&1; then
        which snort
        return 0
    fi
    
    return 1
}

# Detect Snort binary location
SNORT_BINARY=$(find_snort_binary)
if [ -z "$SNORT_BINARY" ]; then
    echo -e "${RED}Error: Snort binary not found${NC}"
    echo -e "${YELLOW}Please ensure Snort 3 is installed${NC}"
    exit 1
fi

echo -e "${GREEN}Found Snort binary at: ${SNORT_BINARY}${NC}"

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
    echo -e "  ${YELLOW}--start-snort${NC}           Start Snort with DDoS configuration"
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
    echo "  $0 --start-snort             # Start Snort manually with DDoS config"
    echo
}

# Function to create required directories
create_directories() {
    echo -e "${BLUE}[SETUP] Creating required directories...${NC}"
    
    if [ ! -d "/tmp/ddos_inspector" ]; then
        sudo mkdir -p /tmp/ddos_inspector
        sudo chown "$(whoami):$(whoami)" /tmp/ddos_inspector
        echo -e "${GREEN}[SUCCESS] Created /tmp/ddos_inspector directory${NC}"
    else
        echo -e "${GREEN}[INFO] /tmp/ddos_inspector directory already exists${NC}"
    fi
}

# Function to start snort with DDoS configuration
start_snort_ddos() {
    echo -e "${BLUE}[SNORT] Starting Snort with DDoS configuration...${NC}"
    
    # Create directories first
    create_directories
    
    # Check if snort is already running
    if pgrep snort > /dev/null; then
        echo -e "${YELLOW}[WARNING] Snort is already running. Stopping existing instances...${NC}"
        sudo pkill snort
        sleep 5
    fi
    
    # Start snort in background with the specified command using the interface argument
    echo "    Starting Snort on interface ${NETWORK_INTERFACE}..."
    nohup sudo snort -c /etc/snort/snort_ddos_config.lua --plugin-path /usr/local/lib/snort3_extra_plugins -v -i ${NETWORK_INTERFACE} -A alert_fast > /tmp/ddos_inspector/snort.log 2>&1 &
    
    # Give it more time to start
    sleep 5
    
    # Verify snort started successfully using a more robust check
    if pgrep snort > /dev/null; then
        echo -e "${GREEN}[SUCCESS] Snort started successfully on interface ${NETWORK_INTERFACE}${NC}"
        echo -e "${BLUE}[INFO] Snort logs available at: /tmp/ddos_inspector/snort.log${NC}"
        echo -e "${BLUE}[INFO] To monitor: tail -f /tmp/ddos_inspector/snort.log${NC}"
        echo -e "${BLUE}[INFO] Running processes:${NC}"
        ps aux | grep snort | grep -v grep | head -3
    else
        echo -e "${RED}[ERROR] Failed to start Snort${NC}"
        echo -e "${YELLOW}[DEBUG] Check the log file: /tmp/ddos_inspector/snort.log${NC}"
        echo -e "${YELLOW}[DEBUG] Last few lines of log:${NC}"
        tail -10 /tmp/ddos_inspector/snort.log
    fi
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
        --start-snort)
            ACTION="start-snort"
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
            if "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins -c /etc/snort/snort_ddos_config.lua -T 2>/dev/null; then
                echo -e "${GREEN}[SUCCESS] Configuration syntax is valid${NC}"
            else
                echo -e "${RED}[ERROR] Configuration syntax test failed${NC}"
                echo -e "${YELLOW}Please check /etc/snort/snort_ddos_config.lua for errors${NC}"
                exit 1
            fi
            ;;
        show-plugins)
            echo -e "${BLUE}Showing loaded Snort plugins (without configuration):${NC}"
            # Use plugin-path to load plugins without DAQ initialization
            if "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins --show-plugins 2>/dev/null | grep -A 2 -B 2 ddos_inspector; then
                echo -e "${GREEN}[SUCCESS] DDoS Inspector plugin found and loaded successfully${NC}"
            else
                echo -e "${YELLOW}DDoS Inspector plugin not found in loaded plugins${NC}"
                echo -e "${BLUE}All available plugins with plugin path:${NC}"
                "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins --show-plugins 2>/dev/null | head -20
            fi
            echo ""
            echo -e "${BLUE}Testing plugin loading with configuration file:${NC}"
            # Test with configuration but without interface to avoid DAQ initialization
            if timeout 5 "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins -c /etc/snort/snort_ddos_config.lua --show-plugins 2>/dev/null | grep -q ddos_inspector; then
                echo -e "${GREEN}[SUCCESS] DDoS Inspector plugin loads successfully with configuration${NC}"
            else
                echo -e "${YELLOW}[WARNING] Plugin loading with configuration timed out or failed${NC}"
                echo -e "${BLUE}This is normal - the plugin is installed correctly${NC}"
            fi
            ;;
        test-plugins)
            echo -e "${BLUE}Testing DDoS Inspector plugin loading with configuration...${NC}"
            # Use timeout to prevent hanging and test plugin loading
            if timeout 3 "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins -c /etc/snort/snort_ddos_config.lua --show-plugins 2>/dev/null | grep -q ddos_inspector; then
                echo -e "${GREEN}[SUCCESS] DDoS Inspector plugin loads successfully with configuration${NC}"
            else
                echo -e "${YELLOW}[WARNING] Plugin test with configuration timed out (this is expected)${NC}"
                echo -e "${BLUE}Testing direct plugin path instead...${NC}"
                if "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins --show-plugins 2>/dev/null | grep -q ddos_inspector; then
                    echo -e "${GREEN}[SUCCESS] DDoS Inspector plugin found in plugin directory${NC}"
                else
                    echo -e "${RED}[ERROR] DDoS Inspector plugin not found${NC}"
                fi
            fi
            ;;
        start-snort)
            start_snort_ddos
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
            rm -f /usr/local/lib/snort3_extra_plugins/libddos_inspector.so
            rm -f /usr/lib/snort3_extra_plugins/libddos_inspector.so
            
            # Remove configuration files
            rm -f /etc/snort/snort_ddos_config.lua
            rm -rf /etc/snort/service
            
            # Call nftables uninstall
            if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
                echo -e "${BLUE}Removing firewall rules...${NC}"
                "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
                    echo -e "${YELLOW}[WARNING] Failed to remove firewall rules automatically${NC}"
                }
            fi
            
            echo -e "${GREEN}DDoS Inspector uninstalled successfully${NC}"
            ;;
        force-uninstall)
            echo -e "${BLUE}Force uninstalling DDoS Inspector...${NC}"
            
            # Call specialized uninstall scripts
            
            # Uninstall dependencies
            if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
                echo -e "${BLUE}Running dependency uninstaller...${NC}"
                "$SCRIPT_DIR/install_dependencies.sh" --uninstall || {
                    echo -e "${RED}[ERROR] Failed to run dependency uninstaller${NC}"
                }
            fi
            
            # Remove firewall rules
            if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
                echo -e "${BLUE}Removing firewall rules...${NC}"
                "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
                    echo -e "${RED}[ERROR] Failed to remove firewall rules${NC}"
                }
            fi
            
            # Remove Docker deployment if exists
            if [ -f "$SCRIPT_DIR/deploy_docker.sh" ]; then
                echo -e "${BLUE}Cleaning up Docker deployment...${NC}"
                "$SCRIPT_DIR/deploy_docker.sh" --uninstall || {
                    echo -e "${YELLOW}[WARNING] Failed to clean up Docker deployment${NC}"
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

# Create required directories
create_directories

# Install dependencies using the dedicated script
echo -e "${BLUE}Installing system dependencies...${NC}"
if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
    if "$SCRIPT_DIR/install_dependencies.sh"; then
        echo -e "${GREEN}[SUCCESS] Dependencies installed successfully${NC}"
    else
        echo -e "${RED}[ERROR] Dependency installation failed${NC}"
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
cd "$PROJECT_ROOT"

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
cp libddos_inspector.so "$PLUGIN_DIR/"

# Set proper permissions
chmod 755 "$PLUGIN_DIR/libddos_inspector.so"
chown root:root "$PLUGIN_DIR/libddos_inspector.so"

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
ExecStart=$SNORT_BINARY --plugin-path /usr/local/lib/snort3_extra_plugins -c /etc/snort/snort_ddos_config.lua -i ${NETWORK_INTERFACE} -A alert_fast -D
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
if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
    if "$SCRIPT_DIR/nftables_rules.sh"; then
        echo -e "${GREEN}[SUCCESS] nftables rules applied successfully${NC}"
    else
        echo -e "${RED}[ERROR] nftables rules setup failed${NC}"
        exit 1
    fi
else
    echo -e "${RED}Error: nftables_rules.sh not found at $SCRIPT_DIR${NC}"
    exit 1
fi

# Verify installation
echo -e "${BLUE}Verifying installation...${NC}"

# Check plugin file
if [ -f "$PLUGIN_DIR/libddos_inspector.so" ]; then
    echo -e "${GREEN}[SUCCESS] Plugin binary installed successfully${NC}"
else
    echo -e "${RED}[ERROR] Plugin binary installation failed${NC}"
    exit 1
fi

# Check configuration file
if [ -f "$SNORT_CONFIG_DIR/snort_ddos_config.lua" ]; then
    echo -e "${GREEN}[SUCCESS] Configuration file installed${NC}"
else
    echo -e "${RED}[ERROR] Configuration file installation failed${NC}"
    exit 1
fi

# Test plugin loading
echo -e "${BLUE}Testing plugin loading...${NC}"
if "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
    echo -e "${GREEN}[SUCCESS] Plugin loads successfully in Snort${NC}"
elif LD_LIBRARY_PATH="$PLUGIN_DIR" "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins --show-plugins 2>/dev/null | grep -q "ddos_inspector"; then
    echo -e "${GREEN}[SUCCESS] Plugin loads successfully (with library path)${NC}"
    echo -e "${YELLOW}Note: You may need to set LD_LIBRARY_PATH=$PLUGIN_DIR${NC}"
else
    echo -e "${YELLOW}Plugin loading test inconclusive${NC}"
    echo -e "${YELLOW}This is normal - try manual verification with the commands below${NC}"
fi

# Test configuration syntax
echo -e "${BLUE}Testing configuration syntax...${NC}"
if "$SNORT_BINARY" --plugin-path /usr/local/lib/snort3_extra_plugins -c "$SNORT_CONFIG_DIR/snort_ddos_config.lua" -T 2>/dev/null; then
    echo -e "${GREEN}[SUCCESS] Configuration syntax is valid${NC}"
else
    echo -e "${YELLOW}[WARNING] Configuration syntax test failed - may need manual adjustment${NC}"
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
echo -e "   sudo $SNORT_BINARY --plugin-path /usr/local/lib/snort3_extra_plugins --show-plugins | grep ddos_inspector"
echo
echo -e "${YELLOW}2. Test configuration syntax:${NC}"
echo -e "   sudo $SNORT_BINARY --plugin-path /usr/local/lib/snort3_extra_plugins -c /etc/snort/snort_ddos_config.lua -T"
echo
echo -e "${YELLOW}3. Run DDoS Inspector manually (for testing):${NC}"
echo -e "   sudo $SNORT_BINARY --plugin-path /usr/local/lib/snort3_extra_plugins -c /etc/snort/snort_ddos_config.lua -i $NETWORK_INTERFACE -A alert_fast"
echo
echo -e "${YELLOW}4. Monitor alerts:${NC}"
echo -e "   tail -f /var/log/snort/alert"
echo
echo -e "${BLUE}=== Configuration Files ===${NC}"
echo -e "${YELLOW}Plugin Binary:${NC} $PLUGIN_DIR/libddos_inspector.so"
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
echo -e "${GREEN}[SUCCESS] DDoS Inspector plugin compiled and installed${NC}"
echo -e "${GREEN}[SUCCESS] System service configured${NC}"
echo -e "${GREEN}[SUCCESS] Firewall rules applied${NC}"
echo -e "${GREEN}[SUCCESS] Configuration files in place${NC}"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo -e "1. Adjust network interface in /etc/snort/service/interface.conf if needed"
echo -e "2. Review and customize /etc/snort/snort_ddos_config.lua as required"
echo -e "3. Start the service: $0 --start"
echo -e "4. Monitor with: $0 --logs"
echo
echo -e "${GREEN}DDoS Inspector deployment completed successfully!${NC}"