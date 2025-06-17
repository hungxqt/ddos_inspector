#!/bin/bash

echo "=== DDoS Inspector Firewall Cleanup Script ==="
echo "This script will remove all firewall rules created by the DDoS Inspector plugin"
echo "Date: $(date)"
echo ""

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "WARNING: This script should be run as root for full cleanup"
        echo "Some operations may fail without root privileges"
        echo ""
    fi
}

# Function to show what will be cleaned
show_current_state() {
    echo "=== Current DDoS Inspector Rules ==="
    echo ""
    
    echo "1. DDoS IP Set contents:"
    echo "------------------------"
    nft list set inet filter ddos_ip_set 2>/dev/null || echo "ddos_ip_set not found"
    
    echo ""
    echo "2. Rate limiting rules:"
    echo "-----------------------"
    nft list ruleset | grep "ddos-rate-limit" || echo "No rate limiting rules found"
    
    echo ""
    echo "3. Drop rules for DDoS IPs:"
    echo "----------------------------"
    nft list ruleset | grep "ddos_ip_set drop" || echo "No drop rules found"
    
    echo ""
}

# Function to clean up DDoS IP set
cleanup_ddos_set() {
    echo "=== Cleaning up DDoS IP Set ==="
    
    # Clear all elements from the set
    echo "Flushing ddos_ip_set..."
    nft flush set inet filter ddos_ip_set 2>/dev/null && echo "✓ DDoS IP set flushed" || echo "✗ Failed to flush DDoS IP set (may not exist)"
    
    # Optionally delete the entire set (uncomment if you want to remove it completely)
    # echo "Deleting ddos_ip_set..."
    # nft delete set inet filter ddos_ip_set 2>/dev/null && echo "✓ DDoS IP set deleted" || echo "✗ Failed to delete DDoS IP set"
    
    echo ""
}

# Function to clean up specific IP rules (including duplicates)
cleanup_specific_ip_rules() {
    echo "=== Cleaning up Specific IP Rules ==="
    
    # Find all rules for specific IPs that are likely DDoS-related
    # Look for patterns like "ip saddr 192.168.x.x" in the input chain
    echo "Finding all rules for specific IP addresses..."
    
    # Get rules with handles for easier deletion
    nft -a list chain inet filter input 2>/dev/null | grep -E "ip saddr [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | while read -r line; do
        # Extract handle from the line
        handle=$(echo "$line" | grep -o 'handle [0-9]*' | cut -d' ' -f2)
        ip=$(echo "$line" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        
        if [ ! -z "$handle" ] && [ ! -z "$ip" ]; then
            echo "Removing rule for IP $ip (handle: $handle)"
            nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted rule $handle for $ip" || echo "✗ Failed to delete rule $handle"
        fi
    done
    
    echo ""
}

# Function to clean up rate limiting rules
cleanup_rate_limit_rules() {
    echo "=== Cleaning up Rate Limiting Rules ==="
    
    # Get all rule handles that contain ddos-rate-limit comments
    echo "Finding rate limiting rules with comments..."
    nft -a list chain inet filter input 2>/dev/null | grep "ddos-rate-limit" | while read -r line; do
        handle=$(echo "$line" | grep -o 'handle [0-9]*' | cut -d' ' -f2)
        if [ ! -z "$handle" ]; then
            echo "Deleting commented rate limit rule with handle: $handle"
            nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted rule $handle" || echo "✗ Failed to delete rule $handle"
        fi
    done
    
    # Clean up any remaining rate limit rules by pattern
    echo "Cleaning up any remaining rate limit rules..."
    for rate in "10/second" "5/second" "2/second" "1/second"; do
        nft -a list chain inet filter input 2>/dev/null | grep "limit rate $rate" | while read -r line; do
            handle=$(echo "$line" | grep -o 'handle [0-9]*' | cut -d' ' -f2)
            if [ ! -z "$handle" ]; then
                echo "Removing rate limit rule ($rate) with handle: $handle"
                nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted rule $handle" || echo "✗ Failed to delete rule $handle"
            fi
        done
    done
    
    echo ""
}

# Function to clean up drop rules
cleanup_drop_rules() {
    echo "=== Cleaning up Drop Rules ==="
    
    # Find and remove drop rules that reference ddos_ip_set
    echo "Finding drop rules for ddos_ip_set..."
    nft -a list chain inet filter input 2>/dev/null | grep "ddos_ip_set drop" | while read -r line; do
        handle=$(echo "$line" | grep -o 'handle [0-9]*' | cut -d' ' -f2)
        if [ ! -z "$handle" ]; then
            echo "Deleting drop rule with handle: $handle"
            nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted drop rule $handle" || echo "✗ Failed to delete drop rule $handle"
        fi
    done
    
    # Also look for any standalone drop rules that might be DDoS-related
    echo "Finding other potential DDoS drop rules..."
    nft -a list chain inet filter input 2>/dev/null | grep -E "ip saddr.*drop" | while read -r line; do
        handle=$(echo "$line" | grep -o 'handle [0-9]*' | cut -d' ' -f2)
        ip=$(echo "$line" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        if [ ! -z "$handle" ] && [ ! -z "$ip" ]; then
            echo "Deleting drop rule for IP $ip with handle: $handle"
            nft delete rule inet filter input handle $handle 2>/dev/null && echo "✓ Deleted drop rule $handle for $ip" || echo "✗ Failed to delete drop rule $handle"
        fi
    done
    
    echo ""
}

# Function to show final state
show_final_state() {
    echo "=== Final State After Cleanup ==="
    echo ""
    
    echo "1. DDoS IP Set (should be empty or not exist):"
    echo "----------------------------------------------"
    nft list set inet filter ddos_ip_set 2>/dev/null || echo "ddos_ip_set not found (cleaned up)"
    
    echo ""
    echo "2. Rate limiting rules (should be none):"
    echo "----------------------------------------"
    nft list ruleset | grep "ddos-rate-limit" || echo "No rate limiting rules found (cleaned up)"
    
    echo ""
    echo "3. Drop rules (should be none):"
    echo "-------------------------------"
    nft list ruleset | grep "ddos_ip_set drop" || echo "No drop rules found (cleaned up)"
    
    echo ""
}

# Main execution
main() {
    check_root
    
    echo "This will clean up ALL DDoS Inspector firewall rules!"
    echo "Press Enter to continue or Ctrl+C to cancel..."
    read -r
    
    show_current_state
    
    cleanup_ddos_set
    cleanup_specific_ip_rules
    cleanup_rate_limit_rules
    cleanup_drop_rules
    
    show_final_state
    
    echo "=== Cleanup Complete ==="
    echo "All DDoS Inspector firewall rules have been removed."
    echo "The plugin will recreate necessary rules when it next detects threats."
    echo ""
}

# Run the script
main
