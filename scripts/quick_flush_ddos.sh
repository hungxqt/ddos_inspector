#!/bin/bash

echo "=== Quick DDoS Inspector Firewall Flush ==="
echo "Performing aggressive cleanup of all DDoS Inspector rules..."
echo ""

# Quick and dirty cleanup - flush everything related to DDoS Inspector
echo "1. Flushing DDoS IP set..."
nft flush set inet filter ddos_ip_set 2>/dev/null && echo "✓ Flushed" || echo "✗ Failed or not found"

echo "2. Removing all rate limiting rules with ddos-rate-limit comments..."
nft list ruleset | grep "ddos-rate-limit" | grep -o 'handle [0-9]*' | cut -d' ' -f2 | while read handle; do
    [ ! -z "$handle" ] && nft delete rule inet filter input handle $handle 2>/dev/null
done && echo "✓ Rate limit rules removed"

echo "3. Removing drop rules for ddos_ip_set..."
nft list ruleset | grep "ddos_ip_set drop" | grep -o 'handle [0-9]*' | cut -d' ' -f2 | while read handle; do
    [ ! -z "$handle" ] && nft delete rule inet filter input handle $handle 2>/dev/null
done && echo "✓ Drop rules removed"

echo "4. Cleaning up any remaining limit rate rules (aggressive)..."
nft list ruleset | grep "limit rate.*second" | grep -o 'handle [0-9]*' | cut -d' ' -f2 | while read handle; do
    [ ! -z "$handle" ] && nft delete rule inet filter input handle $handle 2>/dev/null
done && echo "✓ All rate limit rules removed"

echo ""
echo "=== Quick Flush Complete ==="
echo "All DDoS Inspector firewall rules should now be removed."
echo ""
echo "To verify cleanup:"
echo "  nft list set inet filter ddos_ip_set"
echo "  nft list ruleset | grep -E 'ddos|limit rate'"
echo ""
