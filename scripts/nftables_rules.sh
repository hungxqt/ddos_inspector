#!/bin/bash
# DDoS Inspector - nftables Firewall Rules Management Script
# This script manages all firewall-related operations for DDoS Inspector

set -e

# Get script directory and source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions library
source "$SCRIPT_DIR/common_functions.sh"

# Default configuration
DEFAULT_TIMEOUT="10m"
DDOS_TABLE="inet filter"
DDOS_SET="ddos_ip_set"
BACKUP_DIR="/tmp/nftables_backups"

# Function to check if nftables is available
check_nftables_availability() {
    if ! command -v nft >/dev/null 2>&1; then
        print_error "nftables not available on this system"
        print_info "Install with: apt-get install nftables"
        exit 1
    fi
}

# Function to create backup directory
ensure_backup_directory() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        print_status "Created backup directory: $BACKUP_DIR"
    fi
}

# Function to backup current nftables ruleset
backup_current_rules() {
    local backup_file="$BACKUP_DIR/nftables_backup_$(date +%Y%m%d_%H%M%S).conf"
    
    ensure_backup_directory
    
    if nft list ruleset > "$backup_file" 2>/dev/null; then
        echo "$backup_file"
    else
        echo ""
    fi
}

# Function to setup DDoS protection infrastructure
setup_ddos_infrastructure() {
    local timeout="${1:-$DEFAULT_TIMEOUT}"
    
    print_info "Setting up DDoS protection infrastructure..."
    
    # Create main filter table if it doesn't exist
    nft add table inet filter 2>/dev/null || true
    
    # Create DDoS IP set with timeout support
    if ! nft list set inet filter "$DDOS_SET" >/dev/null 2>&1; then
        nft add set inet filter "$DDOS_SET" "{ type ipv4_addr; flags dynamic,timeout; timeout $timeout; }"
        print_status "Created DDoS IP set: inet filter $DDOS_SET"
    else
        print_status "DDoS IP set already exists: inet filter $DDOS_SET"
    fi
    
    # Create input chain if it doesn't exist
    if ! nft list chain inet filter input >/dev/null 2>&1; then
        nft add chain inet filter input "{ type filter hook input priority 0; }"
        print_status "Created input chain: inet filter input"
    else
        print_status "Input chain already exists: inet filter input"
    fi
    
    # Add DDoS blocking rule if not present
    if ! nft list chain inet filter input | grep -q "ip saddr @$DDOS_SET drop"; then
        nft add rule inet filter input ip saddr @"$DDOS_SET" drop
        print_status "Added DDoS blocking rule: drop packets from @$DDOS_SET"
    else
        print_status "DDoS blocking rule already exists"
    fi
}

# Function to setup container-specific rules (legacy support)
setup_container_rules() {
    print_info "Setting up container-specific DDoS rules..."
    
    # Create DDoS Inspector table for container-specific rules
    if ! nft list table inet ddos_inspector >/dev/null 2>&1; then
        nft add table inet ddos_inspector
        nft add chain inet ddos_inspector dynamic_blocking "{ type filter hook input priority -50; }"
        print_status "Created dynamic blocking chain"
    else
        print_status "DDoS Inspector container table already exists"
    fi
}

# Function to verify firewall setup
verify_firewall_setup() {
    local errors=0
    
    print_info "Verifying firewall setup..."
    
    # Check if main table exists
    if ! nft list table inet filter >/dev/null 2>&1; then
        print_error "Main filter table does not exist"
        ((errors++))
    fi
    
    # Check if DDoS set exists
    if ! nft list set inet filter "$DDOS_SET" >/dev/null 2>&1; then
        print_error "DDoS IP set does not exist"
        ((errors++))
    fi
    
    # Check if input chain exists
    if ! nft list chain inet filter input >/dev/null 2>&1; then
        print_error "Input chain does not exist"
        ((errors++))
    fi
    
    # Check if blocking rule exists
    if ! nft list chain inet filter input | grep -q "ip saddr @$DDOS_SET drop"; then
        print_error "DDoS blocking rule does not exist"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        print_status "Firewall setup verification passed"
        return 0
    else
        print_error "Firewall setup verification failed with $errors errors"
        return 1
    fi
}

# Function to add IP to DDoS set
block_ip() {
    local ip="$1"
    local timeout="${2:-$DEFAULT_TIMEOUT}"
    
    if [ -z "$ip" ]; then
        print_error "IP address required for blocking"
        return 1
    fi
    
    # Validate IP format
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Invalid IP format: $ip"
        return 1
    fi
    
    # Add IP to the set
    if nft add element inet filter "$DDOS_SET" "{ $ip timeout $timeout }" 2>/dev/null; then
        print_status "Blocked IP: $ip (timeout: $timeout)"
        return 0
    else
        print_warning "Failed to block IP or IP already blocked: $ip"
        return 1
    fi
}

# Function to remove IP from DDoS set
unblock_ip() {
    local ip="$1"
    
    if [ -z "$ip" ]; then
        print_error "IP address required for unblocking"
        return 1
    fi
    
    # Remove IP from the set
    if nft delete element inet filter "$DDOS_SET" "{ $ip }" 2>/dev/null; then
        print_status "Unblocked IP: $ip"
        return 0
    else
        print_warning "IP not found in blocked set or already expired: $ip"
        return 1
    fi
}

# Function to list all blocked IPs
list_blocked_ips() {
    print_info "Currently blocked IPs:"
    echo "======================="
    
    if nft list set inet filter "$DDOS_SET" 2>/dev/null | grep -q "elements = {"; then
        nft list set inet filter "$DDOS_SET" | grep -A 100 "elements = {" | grep -v "elements = {" | grep -v "^}" | sed 's/^\s*//' | while read -r line; do
            if [ -n "$line" ]; then
                echo "  🚫 $line"
            fi
        done
    else
        print_info "No IPs currently blocked"
    fi
    
    echo ""
}

# Function to show current ruleset
show_rules() {
    print_info "Current DDoS Inspector ruleset:"
    echo "==============================="
    
    # Show main filter table
    if nft list table inet filter >/dev/null 2>&1; then
        print_info "Main filter table:"
        nft list table inet filter | grep -A 20 -B 5 ddos_ip_set || print_warning "No DDoS rules found in filter table"
    fi
    
    # Show container-specific table if it exists
    if nft list table inet ddos_inspector >/dev/null 2>&1; then
        print_info "DDoS Inspector container table:"
        nft list table inet ddos_inspector 2>/dev/null || print_warning "Could not list ddos_inspector table"
    fi
    
    echo ""
}

# Function to remove all DDoS rules
remove_ddos_rules() {
    print_info "Removing DDoS Inspector rules..."
    
    # Remove main DDoS infrastructure
    if nft list set inet filter "$DDOS_SET" >/dev/null 2>&1; then
        # First remove rules that reference the set
        nft delete rule inet filter input ip saddr @"$DDOS_SET" drop 2>/dev/null || true
        # Then remove the set
        nft delete set inet filter "$DDOS_SET" 2>/dev/null || true
        print_status "Removed main DDoS IP set and rules"
    fi
    
    # Remove container-specific table
    if nft list table inet ddos_inspector >/dev/null 2>&1; then
        nft delete table inet ddos_inspector 2>/dev/null || true
        print_status "Removed container DDoS Inspector table"
    fi
    
    print_status "DDoS Inspector rules removed"
}

# Function to reset and rebuild rules
reset_rules() {
    local timeout="${1:-$DEFAULT_TIMEOUT}"
    
    print_info "Resetting and rebuilding DDoS rules..."
    
    # Backup current rules
    backup_file=$(backup_current_rules)
    if [ -n "$backup_file" ]; then
        print_status "Current rules backed up to: $backup_file"
    fi
    
    # Remove existing rules
    remove_ddos_rules
    
    # Setup fresh rules
    setup_ddos_infrastructure "$timeout"
    
    print_status "DDoS rules reset and rebuilt"
}

# Function to show usage information
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  setup [timeout]       Setup DDoS protection infrastructure"
    echo "  setup-container       Setup container-specific rules"
    echo "  verify               Verify firewall setup"
    echo "  show                 Show current rules and blocked IPs"
    echo "  list                 List currently blocked IPs"
    echo "  block IP [timeout]   Block an IP address"
    echo "  unblock IP           Unblock an IP address"
    echo "  remove               Remove all DDoS rules"
    echo "  reset [timeout]      Reset and rebuild all rules"
    echo "  backup               Backup current ruleset"
    echo "  uninstall            Uninstall all DDoS rules"
    echo ""
    echo "Options:"
    echo "  --timeout DURATION   Default timeout (e.g., 10m, 1h, 24h)"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup                    # Setup with default 10m timeout"
    echo "  $0 setup 30m                # Setup with 30 minute timeout"
    echo "  $0 block 192.168.1.100      # Block IP with default timeout"
    echo "  $0 block 192.168.1.100 1h   # Block IP for 1 hour"
    echo "  $0 unblock 192.168.1.100    # Unblock IP"
    echo "  $0 list                     # Show blocked IPs"
    echo "  $0 reset                    # Reset all rules"
}

# Main execution logic
main() {
    local command="$1"
    local ip="$2"
    local timeout="$3"
    
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --timeout)
                DEFAULT_TIMEOUT="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            --*)
                shift
                ;;
            *)
                # If no command is set yet, this is the command
                if [ -z "$command" ]; then
                    command="$1"
                fi
                shift
                ;;
        esac
    done
    
    # If no command specified, default to setup
    if [ -z "$command" ]; then
        command="setup"
    fi
    
    # Header
    echo "🛡️  DDoS Inspector - nftables Rules Management"
    echo "=============================================="
    
    # Check prerequisites for most commands
    if [ "$command" != "backup" ] && [ "$command" != "show" ] && [ "$command" != "list" ]; then
        check_root_privileges
    fi
    
    check_nftables_availability
    
    # Execute command
    case $command in
        setup)
            setup_ddos_infrastructure "$timeout"
            verify_firewall_setup
            ;;
        setup-container)
            check_root_privileges
            setup_container_rules
            ;;
        verify)
            verify_firewall_setup
            ;;
        show)
            show_rules
            list_blocked_ips
            ;;
        list)
            list_blocked_ips
            ;;
        block)
            check_root_privileges
            # Ensure infrastructure exists before blocking
            setup_ddos_infrastructure "$timeout" >/dev/null 2>&1
            block_ip "$ip" "$timeout"
            ;;
        unblock)
            check_root_privileges
            unblock_ip "$ip"
            ;;
        remove)
            check_root_privileges
            read -p "Are you sure you want to remove all DDoS Inspector rules? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                backup_current_rules >/dev/null
                remove_ddos_rules
            else
                print_info "Operation cancelled"
            fi
            ;;
        uninstall)
            check_root_privileges
            read -p "Are you sure you want to uninstall DDoS Inspector completely? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                backup_current_rules >/dev/null
                remove_ddos_rules
                print_status "DDoS Inspector uninstalled successfully"
            else
                print_info "Operation cancelled"
            fi
            ;;
        reset)
            check_root_privileges
            reset_rules "$timeout"
            ;;
        backup)
            backup_file=$(backup_current_rules)
            if [ -n "$backup_file" ]; then
                print_status "Ruleset backed up to: $backup_file"
            else
                print_error "Failed to backup ruleset"
                exit 1
            fi
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
