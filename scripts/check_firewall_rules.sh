#!/bin/bash

echo "=== DDoS Inspector Firewall Rules Check ==="
echo "Date: $(date)"
echo ""

echo "1. DDoS IP Set contents (blocked IPs - should have no duplicates):"
echo "------------------------------------------------------------------"
echo "Expected: Clean list of IPs with timeout values"
nft list set inet filter ddos_ip_set 2>/dev/null || echo "ddos_ip_set not found"

echo ""
echo "2. Rate limiting rules (separate from blocked IPs):"
echo "--------------------------------------------------"
echo "Expected: Individual rules with 'ddos-rate-limit-<IP>' comments"
nft list ruleset | grep -C 1 "ddos-rate-limit" || echo "No rate limiting rules found"

echo ""
echo "3. All input chain rules with handles:"
echo "------------------------------------"
nft list chain inet filter input -a 2>/dev/null || echo "Input chain not found"

echo ""
echo "4. Drop rules for blocked IPs:"
echo "-----------------------------"
echo "Expected: One rule that drops traffic from @ddos_ip_set"
nft list ruleset | grep "ddos_ip_set drop" || echo "No drop rules found"

echo ""
echo "=== Analysis ==="
echo "✓ Blocked IPs: Should be in ddos_ip_set (no duplicates)"
echo "✓ Rate-limited IPs: Should be separate rules with comments"
echo "✓ Both types should be cleaned up when expired"
echo ""
echo "If you see duplicates or rules not being cleaned up,"
echo "the recent fixes should resolve these issues."
echo "=== End of Firewall Rules Check ==="
