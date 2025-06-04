#!/bin/bash
# Common Functions Library for DDoS Inspector Scripts
# Source this file to use shared functionality across scripts

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print utility functions
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC}  $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${BLUE}🔍${NC} $1"
}

print_success() {
    echo -e "${GREEN}🎉${NC} $1"
}

# Privilege checking
check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This operation requires root privileges"
        print_info "Usage: sudo $0 [OPTIONS]"
        exit 1
    fi
}

check_sudo_permissions() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    
    if ! command -v sudo &> /dev/null; then
        print_error "This script requires sudo privileges, but sudo is not installed"
        print_info "Please run as root or install sudo"
        exit 1
    fi
    
    if sudo -n true 2>/dev/null; then
        print_info "Sudo access confirmed (passwordless)"
        return 0
    fi
    
    if ! sudo -v; then
        print_error "Failed to obtain sudo privileges"
        exit 1
    fi
    
    print_info "Sudo access confirmed"
    return 0
}

# Network interface management
validate_interface() {
    local interface="$1"
    
    if [ -z "$interface" ]; then
        print_error "Interface name cannot be empty"
        return 1
    fi
    
    if ! ip link show "$interface" &>/dev/null; then
        print_error "Interface '$interface' does not exist"
        return 1
    fi
    
    if [ "$interface" = "lo" ]; then
        print_error "Cannot use loopback interface"
        return 1
    fi
    
    return 0
}

get_available_interfaces() {
    local interfaces=()
    
    while IFS= read -r interface; do
        if [ -n "$interface" ] && [ "$interface" != "lo" ]; then
            if ip link show "$interface" &>/dev/null; then
                interfaces+=("$interface")
            fi
        fi
    done < <(ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print $2}' | awk '{print $1}')
    
    printf '%s\n' "${interfaces[@]}"
}

list_network_interfaces() {
    print_info "Available Network Interfaces:"
    echo "================================="
    
    local counter=1
    
    while IFS= read -r interface; do
        if [ -n "$interface" ]; then
            status=$(ip link show "$interface" 2>/dev/null | grep -o "state [A-Z]*" | awk '{print $2}' || echo "UNKNOWN")
            ip_addr=$(ip addr show "$interface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1 || echo "No IP")
            
            printf "   %2d. %-15s - Status: %-8s - IP: %s\n" "$counter" "$interface" "$status" "$ip_addr"
            ((counter++))
        fi
    done < <(get_available_interfaces)
    
    if [ $counter -eq 1 ]; then
        print_error "No valid network interfaces found (excluding loopback)"
        return 1
    fi
    
    echo ""
    return 0
}

detect_host_interface() {
    local interface
    
    # Try common interface names
    if ip link show eth0 &>/dev/null && [ "eth0" != "lo" ]; then
        interface="eth0"
    elif ip link show ens33 &>/dev/null; then
        interface="ens33"
    elif ip link show enp0s3 &>/dev/null; then
        interface="enp0s3"
    else
        # Get first non-loopback interface
        interface=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -z "$interface" ] || [ "$interface" = "lo" ]; then
            print_error "Could not detect suitable network interface"
            return 1
        fi
    fi
    
    echo "$interface"
}

interactive_interface_selection() {
    readarray -t available_interfaces < <(get_available_interfaces)
    
    if [ ${#available_interfaces[@]} -eq 0 ]; then
        print_error "No interfaces available for selection"
        return 1
    fi
    
    if [ ${#available_interfaces[@]} -eq 1 ]; then
        print_info "Only one interface available: ${available_interfaces[0]}"
        read -p "   Use this interface? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            print_error "Selection cancelled by user"
            return 1
        fi
        echo "${available_interfaces[0]}"
        return 0
    fi
    
    while true; do
        print_info "Please select a network interface:"
        read -p "   Enter interface number (1-${#available_interfaces[@]}) or interface name: " selection
        
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            if [ "$selection" -ge 1 ] && [ "$selection" -le ${#available_interfaces[@]} ]; then
                echo "${available_interfaces[$((selection-1))]}"
                return 0
            else
                print_error "Invalid selection. Please choose 1-${#available_interfaces[@]}"
                continue
            fi
        else
            if validate_interface "$selection" >/dev/null 2>&1; then
                echo "$selection"
                return 0
            else
                print_error "Invalid interface name. Please try again."
                continue
            fi
        fi
    done
}

# Dependency checking
check_basic_dependencies() {
    local missing_deps=()
    
    if ! command -v ip &> /dev/null; then
        missing_deps+=("iproute2")
    fi
    
    if ! command -v nft &> /dev/null; then
        missing_deps+=("nftables")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing basic dependencies: ${missing_deps[*]}"
        return 1
    fi
    return 0
}

# Docker checking
check_docker_availability() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        return 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        return 1
    fi
    
    # Check Docker Compose (v2 or v1)
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        print_error "Docker Compose is not installed"
        return 1
    fi
    
    return 0
}

# Common error handler
handle_error() {
    local exit_code=$1
    local line_no=$2
    print_error "Script failed at line $line_no with exit code $exit_code"
    exit $exit_code
}

# Set up error trapping
set -e
trap 'handle_error $? $LINENO' ERR