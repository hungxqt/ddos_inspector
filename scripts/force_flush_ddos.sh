#!/bin/bash

echo "=== FORCE DDoS Inspector Firewall Cleanup Script ==="
echo "This script aggressively removes ALL DDoS-related firewall rules"
echo "Date: $(date)"
echo ""

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "ERROR: This script must be run as root!"
        echo "Please run with sudo"
        exit 1
    fi
}

# Function to completely recreate the input chain (nuclear option)
recreate_input_chain() {
    echo "=== NUCLEAR OPTION: Recreating input chain ==="
    echo "WARNING: This will remove ALL rules from the inet filter input chain!"
    echo "Press Enter to continue or Ctrl+C to cancel..."
    read -r
    
    # Delete the entire input chain
    echo "Deleting input chain..."
    nft delete chain inet filter input 2>/dev/null && echo "✓ Input chain deleted" || echo "✗ Failed to delete input chain"
    
    # Recreate the input chain with default policy
    echo "Recreating input chain..."
    nft add chain inet filter input '{ type filter hook input priority filter; policy accept; }' 2>/dev/null && echo "✓ Input chain recreated" || echo "✗ Failed to recreate input chain"
    
    echo ""
}

# Function to selectively remove all DDoS rules
selective_cleanup() {
    echo "=== Selective DDoS Rule Cleanup ==="
    
    # First, flush the ddos_ip_set
    echo "Flushing ddos_ip_set..."
    nft flush set inet filter ddos_ip_set 2>/dev/null && echo "✓ DDoS IP set flushed" || echo "✗ Failed to flush DDoS IP set"
    
    # Get all rule handles from input chain and remove any that match DDoS patterns
    echo "Analyzing input chain rules..."
    
    # Create a temporary file to store rules to delete
    temp_file="/tmp/ddos_rules_to_delete.txt"
    
    # Get all rules with handles
    nft -a list chain inet filter input 2>/dev/null > "$temp_file"
    
    # Extract handles for rules that match DDoS patterns
    grep -E "(ddos|limit rate|@ddos_ip_set)" "$temp_file" | grep -o 'handle [0-9]*' | while read -r handle_line; do
        if [ ! -z "$handle_line" ]; then
            handle=$(echo $handle_line | cut -d' ' -f2)
            echo "Deleting DDoS-related rule with handle: $handle"
            nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted rule $handle" || echo "✗ Failed to delete rule $handle"
        fi
    done
    
    # Also look for specific IP rules that might be DDoS-related
    echo "Looking for specific IP rules..."
    grep -E "ip saddr [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$temp_file" | grep -o 'handle [0-9]*' | while read -r handle_line; do
        if [ ! -z "$handle_line" ]; then
            handle=$(echo $handle_line | cut -d' ' -f2)
            # Get the IP from the rule for logging
            ip=$(grep "handle $handle" "$temp_file" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
            echo "Deleting rule for IP $ip (handle: $handle)"
            nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted rule $handle for $ip" || echo "✗ Failed to delete rule $handle"
        fi
    done
    
    # Clean up temp file
    rm -f "$temp_file"
    
    echo ""
}

# Function to show current state
show_current_state() {
    echo "=== Current State ==="
    echo ""
    echo "DDoS IP Set:"
    nft list set inet filter ddos_ip_set 2>/dev/null || echo "ddos_ip_set not found"
    echo ""
    echo "Input Chain Rules:"
    nft list chain inet filter input 2>/dev/null || echo "input chain not found"
    echo ""
}

# Main execution
main() {
    check_root
    
    echo "Current firewall state:"
    show_current_state
    
    echo "Choose cleanup method:"
    echo "1) Selective cleanup (recommended) - removes only DDoS-related rules"
    echo "2) Nuclear option - completely recreates the input chain (removes ALL rules)"
    echo "3) Exit"
    echo ""
    
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1)
            selective_cleanup
            ;;
        2)
            recreate_input_chain
            ;;
        3)
            echo "Exiting without changes"
            exit 0
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
    
    echo "=== Final State ==="
    show_current_state
    
    echo "=== Cleanup Complete ==="
    echo "DDoS Inspector firewall rules have been cleaned up."
    echo ""
}

# Run the script
main
