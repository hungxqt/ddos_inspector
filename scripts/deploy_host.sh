#!/bin/bash
# DDoS Inspector - Host Deployment Script
# This script sets up host-level firewall and delegates Docker operations to deploy_docker.sh

set -e

# Get script directory and source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source common functions library
source "$SCRIPT_DIR/common_functions.sh"

echo -e "[DEPLOY] DDoS Inspector - Host Deployment"
echo "===================================="

# Parse command line arguments
SERVICE_MODE=false
SKIP_DEPS=false
SPECIFIED_INTERFACE=""
DOCKER_MODE="full"
INTERACTIVE_MODE=false
ACTION="deploy"

while [[ $# -gt 0 ]]; do
    case $1 in
        -interface)
            if [ -n "$2" ] && [[ $2 != -* ]]; then
                SPECIFIED_INTERFACE="$2"
                shift 2
            else
                print_error "-interface requires an interface name"
                print_info "Usage: $0 -interface <interface_name>"
                print_info "Example: $0 -interface eth0"
                exit 1
            fi
            ;;
        --service)
            SERVICE_MODE=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --docker-mode)
            DOCKER_MODE="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Interface Selection:"
            echo "  -interface <name>     Specify network interface to protect"
            echo "  --interactive         Interactive interface selection"
            echo "  (no -interface)       Auto-detect interface"
            echo ""
            echo "Options:"
            echo "  --service             Run in service mode (for systemd)"
            echo "  --skip-deps           Skip dependency check and installation"
            echo "  --docker-mode MODE    Docker deployment mode (full|core|monitoring)"
            echo "  --uninstall           Uninstall DDoS Inspector completely"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                            # Auto-detect interface, full Docker stack"
            echo "  $0 -interface eth0            # Use eth0 interface"
            echo "  $0 --interactive              # Interactive interface selection"
            echo "  $0 --docker-mode core         # Deploy only core DDoS service"
            echo "  $0 --uninstall                # Uninstall everything"
            echo ""
            echo "Note: This script now delegates Docker operations to deploy_docker.sh"
            echo "      for better consolidation and reduced code duplication."
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            print_info "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Check sudo permissions early
if [ "$SKIP_SUDO_CHECK" != "true" ]; then
    check_sudo_permissions
fi

# Change to project root directory
cd "$PROJECT_ROOT"

# Handle uninstall action
if [ "$ACTION" = "uninstall" ]; then
    print_info "DDoS Inspector - Complete Host Uninstallation"
    echo "=================================================="
    echo ""
    print_warning "This will completely remove DDoS Inspector from your host!"
    echo "   The following will be removed:"
    echo "   • All Docker containers and images"
    echo "   • Host firewall rules (nftables)"
    echo "   • System dependencies (Docker, nftables, build tools)"
    echo "   • All configuration files and data"
    echo ""
    
    read -p "Are you sure you want to continue? (type 'UNINSTALL' to confirm): " -r
    if [ "$REPLY" != "UNINSTALL" ]; then
        print_error "Uninstall cancelled"
        exit 1
    fi
    
    echo ""
    print_info "Starting complete uninstallation..."
    
    # Step 1: Remove Docker deployment
    print_info "Removing Docker deployment..."
    if [ -f "$SCRIPT_DIR/deploy_docker.sh" ]; then
        sudo "$SCRIPT_DIR/deploy_docker.sh" --uninstall || {
            print_warning "Failed to cleanly remove Docker deployment"
        }
    fi
    
    # Step 2: Remove firewall rules
    print_info "Removing firewall rules..."
    if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
        sudo "$SCRIPT_DIR/nftables_rules.sh" --uninstall || {
            print_warning "Failed to cleanly remove firewall rules"
        }
    fi
    
    # Step 3: Remove dependencies (this is comprehensive)
    print_info "Removing system dependencies..."
    if [ -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
        sudo "$SCRIPT_DIR/install_dependencies.sh" --uninstall || {
            print_warning "Failed to cleanly remove dependencies"
        }
    fi
    
    # Step 4: Clean up any remaining project files
    print_info "Cleaning up project files..."
    
    # Remove logs and data directories
    sudo rm -rf "$PROJECT_ROOT/logs" 2>/dev/null || true
    sudo rm -rf "$PROJECT_ROOT/data" 2>/dev/null || true
    
    # Remove any systemd service files
    sudo systemctl stop ddos-inspector 2>/dev/null || true
    sudo systemctl disable ddos-inspector 2>/dev/null || true
    sudo rm -f /etc/systemd/system/ddos-inspector.service 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true
    
    echo ""
    print_success "Complete uninstallation finished!"
    echo ""
    echo -e "${CYAN}[SUMMARY] Removed Components:${NC}"
    echo -e "${GREEN}    [REMOVED] Docker containers and images${NC}"
    echo -e "${GREEN}    [REMOVED] Firewall rules and nftables configuration${NC}"
    echo -e "${GREEN}    [REMOVED] System dependencies (Docker, build tools, etc.)${NC}"
    echo -e "${GREEN}    [REMOVED] Project data and logs${NC}"
    echo -e "${GREEN}    [REMOVED] System service configurations${NC}"
    echo ""
    print_info "You may want to reboot your system to ensure all changes take effect."
    print_info "To reinstall DDoS Inspector, simply run: $0"
    exit 0
fi

# Function to install dependencies (host-specific wrapper)
install_dependencies() {
    print_info "Missing dependencies detected. Installing..."
    echo ""
    
    if [ ! -f "$SCRIPT_DIR/install_dependencies.sh" ]; then
        print_error "install_dependencies.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        print_info "Administrator privileges required for dependency installation."
        print_info "Re-running with sudo..."
        sudo "$SCRIPT_DIR/install_dependencies.sh"
        
        echo ""
        print_success "Dependencies installed. Please logout and login again for Docker group membership."
        print_info "Then re-run this script: $0"
        exit 0
    else
        "$SCRIPT_DIR/install_dependencies.sh"
    fi
}

# Check basic dependencies unless skipped
if [ "$SKIP_DEPS" = false ]; then
    print_info "Checking basic system dependencies..."
    
    if ! check_basic_dependencies; then
        print_warning "Some basic dependencies are missing."
        
        if [ "$SERVICE_MODE" = true ]; then
            print_error "Cannot install dependencies in service mode. Please run manually first."
            exit 1
        fi
        
        read -p "Would you like to install missing dependencies automatically? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_dependencies
        else
            print_error "Cannot proceed without required dependencies."
            print_info "Run: sudo $SCRIPT_DIR/install_dependencies.sh"
            exit 1
        fi
    else
        print_success "Basic dependencies are satisfied"
    fi
fi

# Determine network interface to use
if [ -n "$SPECIFIED_INTERFACE" ]; then
    print_info "Using specified interface: $SPECIFIED_INTERFACE"
    if ! validate_interface "$SPECIFIED_INTERFACE"; then
        print_error "Specified interface '$SPECIFIED_INTERFACE' is not valid"
        print_info "Available interfaces:"
        list_network_interfaces >/dev/null
        exit 1
    fi
    HOST_INTERFACE="$SPECIFIED_INTERFACE"
elif [ "$SERVICE_MODE" = true ]; then
    # Service mode - auto-detect without user interaction
    print_info "Service mode: Auto-detecting network interface..."
    HOST_INTERFACE=$(detect_host_interface)
    print_success "Auto-detected interface: $HOST_INTERFACE"
else
    # Default interactive behavior
    if ! list_network_interfaces >/dev/null 2>&1; then
        print_error "Failed to list network interfaces"
        print_info "Falling back to auto-detection..."
        HOST_INTERFACE=$(detect_host_interface)
        print_success "Auto-detected interface: $HOST_INTERFACE"
    else
        # Show interfaces and handle direct selection
        list_network_interfaces
        echo "Interface Selection Options:"
        echo "   • Enter interface number (1, 2, 3, etc.) to select directly"
        echo "   • Enter interface name (eth0, docker0, etc.) to select directly"  
        echo "   • Press Enter for interactive mode"
        echo "   • Enter 'a' for auto-detect"
        read -p "   Your choice: " -r choice
        
        # Get available interfaces for number-based selection
        readarray -t available_interfaces < <(get_available_interfaces)
        
        if [ -z "$choice" ]; then
            # Empty input - interactive mode
            echo ""
            print_info "Starting interactive interface selection..."
            if ! HOST_INTERFACE=$(interactive_interface_selection); then
                print_error "Interactive selection failed"
                print_info "Falling back to auto-detection..."
                HOST_INTERFACE=$(detect_host_interface)
                print_success "Auto-detected interface: $HOST_INTERFACE"
            fi
        elif [[ "$choice" =~ ^[Aa]$ ]]; then
            # Auto-detect mode
            echo ""
            print_info "Auto-detecting network interface..."
            HOST_INTERFACE=$(detect_host_interface)
            print_success "Auto-detected interface: $HOST_INTERFACE"
        elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            # Number selection - select interface directly
            if [ "$choice" -ge 1 ] && [ "$choice" -le ${#available_interfaces[@]} ]; then
                HOST_INTERFACE="${available_interfaces[$((choice-1))]}"
                print_success "Selected interface #$choice: $HOST_INTERFACE"
            else
                print_error "Invalid selection. Please choose 1-${#available_interfaces[@]}"
                print_info "Falling back to auto-detection..."
                HOST_INTERFACE=$(detect_host_interface)
                print_success "Auto-detected interface: $HOST_INTERFACE"
            fi
        else
            # Interface name selection - validate and use directly
            if validate_interface "$choice" >/dev/null 2>&1; then
                HOST_INTERFACE="$choice"
                print_success "Selected interface: $HOST_INTERFACE"
            else
                print_error "Invalid interface name: $choice"
                print_info "Falling back to auto-detection..."
                HOST_INTERFACE=$(detect_host_interface)
                print_success "Auto-detected interface: $HOST_INTERFACE"
            fi
        fi
    fi
fi

print_info "Selected network interface: $HOST_INTERFACE"

# Verify interface is up
if ! ip link show "$HOST_INTERFACE" | grep -q "state UP"; then
    print_warning "Interface $HOST_INTERFACE is not in UP state"
    print_info "Attempting to bring it up..."
    
    sudo ip link set "$HOST_INTERFACE" up || print_warning "Could not bring interface up automatically"
fi

print_info "Setting up host firewall infrastructure..."

# Use the comprehensive nftables rules script
if [ -f "$SCRIPT_DIR/nftables_rules.sh" ]; then
    print_info "Configuring firewall rules using nftables_rules.sh..."
    
    # Setup DDoS protection infrastructure
    if ! sudo "$SCRIPT_DIR/nftables_rules.sh" setup; then
        print_error "Failed to setup firewall infrastructure"
        exit 1
    fi
    
    # Verify the setup was successful
    if ! sudo "$SCRIPT_DIR/nftables_rules.sh" verify; then
        print_error "Firewall verification failed"
        exit 1
    fi
    
    print_success "Host firewall infrastructure ready"
else
    print_error "nftables_rules.sh not found at $SCRIPT_DIR/nftables_rules.sh"
    print_info "Falling back to basic firewall setup..."
    
    # Fallback to basic setup if script is missing
    sudo nft add table inet filter 2>/dev/null || true
    sudo nft add set inet filter ddos_ip_set "{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }" 2>/dev/null || true
    
    # Check if the input chain exists, if not create it
    if ! sudo nft list chain inet filter input >/dev/null 2>&1; then
        sudo nft add chain inet filter input "{ type filter hook input priority 0; }"
    fi
    
    # Add the actual blocking rule
    if ! sudo nft list rule inet filter input | grep -q "ip saddr @ddos_ip_set drop"; then
        sudo nft add rule inet filter input ip saddr @ddos_ip_set drop
    fi
    
    print_success "Basic firewall setup completed"
fi

echo ""
print_info "Delegating Docker deployment to deploy_docker.sh..."

# Prepare arguments for deploy_docker.sh
DOCKER_ARGS=("--mode" "$DOCKER_MODE")

# Pass the selected interface to deploy_docker.sh
DOCKER_ARGS+=("--interface" "$HOST_INTERFACE")

if [ "$SERVICE_MODE" = "true" ]; then
    DOCKER_ARGS+=("--service")
fi

# Always skip deps in deploy_docker.sh since we handled them here
DOCKER_ARGS+=("--skip-deps")

if [ "$ACTION" = "uninstall" ]; then
    DOCKER_ARGS+=("--uninstall")
fi

print_info "Calling: $SCRIPT_DIR/deploy_docker.sh ${DOCKER_ARGS[*]}"

# Call deploy_docker.sh with appropriate arguments
if ! "$SCRIPT_DIR/deploy_docker.sh" "${DOCKER_ARGS[@]}"; then
    print_error "Docker deployment failed"
    exit 1
fi

echo ""
print_success "Host deployment completed successfully!"
echo ""
echo "[CONFIG] Host-specific management:"
echo "    Firewall rules: sudo $SCRIPT_DIR/nftables_rules.sh --help"
echo "    List blocked IPs: sudo $SCRIPT_DIR/nftables_rules.sh --list"
echo ""
echo "[DOCKER] Docker management:"
echo "    Use: $SCRIPT_DIR/deploy_docker.sh --help"
echo "    Stop: $SCRIPT_DIR/deploy_docker.sh --stop"
echo "    Logs: $SCRIPT_DIR/deploy_docker.sh --logs"

if [ "$SERVICE_MODE" = false ]; then
    echo ""
    print_info "To enable auto-start on boot:"
    echo "    sudo systemctl enable ddos-inspector"
    echo "    sudo systemctl start ddos-inspector"
fi