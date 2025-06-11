#!/bin/bash
set -e

# DDoS Inspector Container Entrypoint Script
echo "DDoS Inspector Entrypoint"

# Set default values
export NETWORK_INTERFACE="${NETWORK_INTERFACE:-eth0}"
export PLUGIN_PATH="${PLUGIN_PATH:-/usr/local/lib/snort3_extra_plugins}"
export CONFIG_FILE="${CONFIG_FILE:-/etc/snort/snort_ddos_config.lua}"

# Colors for better output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to detect available network interface
detect_interface() {
    local interface
    
    # Check if NETWORK_INTERFACE is set and interface exists
    if [ -n "$NETWORK_INTERFACE" ] && [ "$NETWORK_INTERFACE" != "auto" ] && ip link show "$NETWORK_INTERFACE" &>/dev/null; then
        interface="$NETWORK_INTERFACE"
    # Otherwise try common interfaces
    elif ip link show eth0 &>/dev/null; then
        interface="eth0"
    elif ip link show ens33 &>/dev/null; then
        interface="ens33"
    elif ip link show enp0s3 &>/dev/null; then
        interface="enp0s3"
    else
        # Fallback: get first available interface (excluding lo)
        interface=$(ip link show | grep -E '^[0-9]+:' | grep -v 'lo:' | head -1 | cut -d: -f2 | xargs)
        if [ -z "$interface" ]; then
            echo "Error: No suitable network interface found"
            exit 1
        fi
    fi
    
    echo "$interface"
}

# Use a more reliable initialization flag that doesn't persist between container recreations
# Store in /var/run which is typically tmpfs and gets cleared on container restart
INIT_FLAG="/var/run/ddos_inspector_initialized"

# Always perform initialization on container start
echo "Initializing container..."

# Create necessary directories
mkdir -p /var/log/snort
mkdir -p /var/run

# Set permissions
chown -R snort:snort /var/log/snort

# Setup nftables infrastructure for DDoS protection
echo -e "${BLUE}Setting up firewall infrastructure...${NC}"

# Create nftables table and set for IP blocking (auto-creates if missing)
nft add table inet filter 2>/dev/null || true
nft add set inet filter ddos_ip_set "{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }" 2>/dev/null || true
nft add rule inet filter input ip saddr @ddos_ip_set drop 2>/dev/null || true

# Verify setup
if nft list set inet filter ddos_ip_set >/dev/null 2>&1; then
    echo -e "${GREEN}Firewall infrastructure ready for DDoS protection${NC}"
else
    echo -e "${YELLOW}Warning: Could not set up nftables (may need --privileged flag)${NC}"
fi

# Mark as initialized for this container session
touch "$INIT_FLAG"

# Note: Internal Snort stats exporter disabled to avoid port conflicts
# Using dedicated external snort-stats-exporter container instead
echo "Skipping internal Snort stats exporter (using dedicated external container)"

# Detect network interface
DETECTED_INTERFACE=$(detect_interface)
export NETWORK_INTERFACE="$DETECTED_INTERFACE"

echo "Starting Snort with DDoS Inspector..."
echo "Plugin path: $PLUGIN_PATH"
echo "Config file: $CONFIG_FILE"
echo -e "${BLUE}NETWORK MONITORING ACTIVE${NC}"
echo -e "${GREEN}Interface being monitored: $NETWORK_INTERFACE${NC}"
echo -e "${YELLOW}DDoS protection enabled on: $NETWORK_INTERFACE${NC}"

# Show available plugins for debugging
echo "Available plugins:"
ls -la "$PLUGIN_PATH"

# Build Snort command with proper arguments - avoid duplicates
if [ $# -eq 0 ]; then
    # No arguments provided - use defaults
    echo "Using default Snort configuration"
    exec snort -c "$CONFIG_FILE" --plugin-path "$PLUGIN_PATH" -v -i "$NETWORK_INTERFACE" -A alert_fast
else
    # Arguments provided - rebuild command carefully to avoid duplicates
    echo "Processing custom arguments: $*"
    
    # Initialize arrays to track what we've already added
    declare -A seen_args
    SNORT_ARGS=()
    
    # Always add config file first
    SNORT_ARGS+=("-c" "$CONFIG_FILE")
    seen_args["-c"]=1
    
    # Always add plugin path
    SNORT_ARGS+=("--plugin-path" "$PLUGIN_PATH")
    seen_args["--plugin-path"]=1
    
    # Always add interface
    SNORT_ARGS+=("-i" "$NETWORK_INTERFACE")
    seen_args["-i"]=1
    
    # Parse and process remaining arguments, skipping duplicates
    while [ $# -gt 0 ]; do
        case "$1" in
            -c|--config)
                # Skip - already added
                if [ -n "$2" ] && [[ "$2" != -* ]]; then
                    shift 2
                else
                    shift 1
                fi
                ;;
            --plugin-path)
                # Skip - already added
                if [ -n "$2" ] && [[ "$2" != -* ]]; then
                    shift 2
                else
                    shift 1
                fi
                ;;
            -i|--intf)
                # Skip - already added with detected interface
                if [ -n "$2" ] && [[ "$2" != -* ]]; then
                    shift 2
                else
                    shift 1
                fi
                ;;
            -A)
                # Only add if not already present
                if [ -z "${seen_args["-A"]}" ]; then
                    if [ -n "$2" ] && [[ "$2" != -* ]]; then
                        SNORT_ARGS+=("-A" "$2")
                        seen_args["-A"]=1
                        shift 2
                    else
                        SNORT_ARGS+=("-A" "alert_fast")
                        seen_args["-A"]=1
                        shift 1
                    fi
                else
                    # Skip duplicate
                    if [ -n "$2" ] && [[ "$2" != -* ]]; then
                        shift 2
                    else
                        shift 1
                    fi
                fi
                ;;
            -q|-v|-D)
                # Single argument flags - only add if not already present
                if [ -z "${seen_args["$1"]}" ]; then
                    SNORT_ARGS+=("$1")
                    seen_args["$1"]=1
                fi
                shift 1
                ;;
            *)
                # Other arguments - add if not already present
                if [ -z "${seen_args["$1"]}" ]; then
                    SNORT_ARGS+=("$1")
                    seen_args["$1"]=1
                fi
                shift 1
                ;;
        esac
    done
    
    echo "Final Snort command: snort ${SNORT_ARGS[*]}"
    exec snort "${SNORT_ARGS[@]}"
fi
