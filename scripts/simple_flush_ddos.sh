#!/bin/bash

echo "=== Simple DDoS Firewall Cleanup ==="
echo "Date: $(date)"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root!"
    echo "Please run with sudo"
    exit 1
fi

echo "Current input chain rules:"
echo "========================="
nft list chain inet filter input 2>/dev/null || echo "No input chain found"
echo ""

echo "Current ddos_ip_set contents:"
echo "============================"
nft list set inet filter ddos_ip_set 2>/dev/null || echo "No ddos_ip_set found"
echo ""

echo "Cleanup options:"
echo "1) Flush entire input chain (removes ALL rules from input chain)"
echo "2) Flush ddos_ip_set only (keeps rules, clears IP set)"
echo "3) Both (flush input chain AND ddos_ip_set)"
echo "4) Exit"
echo ""

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo "Flushing input chain..."
        nft flush chain inet filter input && echo "✓ Input chain flushed successfully" || echo "✗ Failed to flush input chain"
        ;;
    2)
        echo "Flushing ddos_ip_set..."
        nft flush set inet filter ddos_ip_set && echo "✓ DDoS IP set flushed successfully" || echo "✗ Failed to flush ddos_ip_set"
        ;;
    3)
        echo "Flushing input chain..."
        nft flush chain inet filter input && echo "✓ Input chain flushed successfully" || echo "✗ Failed to flush input chain"
        echo "Flushing ddos_ip_set..."
        nft flush set inet filter ddos_ip_set && echo "✓ DDoS IP set flushed successfully" || echo "✗ Failed to flush ddos_ip_set"
        ;;
    4)
        echo "Exiting without changes"
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "=== Final State ==="
echo "Input chain after cleanup:"
nft list chain inet filter input 2>/dev/null || echo "No input chain found"
echo ""
echo "ddos_ip_set after cleanup:"
nft list set inet filter ddos_ip_set 2>/dev/null || echo "No ddos_ip_set found"
echo ""
echo "Cleanup complete!"
