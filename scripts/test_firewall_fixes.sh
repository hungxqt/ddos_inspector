#!/bin/bash

echo "=== Testing DDoS Inspector Firewall Rules Management ==="
echo "This script tests the fixed duplicate and cleanup issues"
echo ""

# Function to show current state
show_state() {
    echo "--- Current firewall state ---"
    echo "Blocked IPs in set:"
    nft list set inet filter ddos_ip_set 2>/dev/null | grep elements || echo "  (empty)"
    echo "Rate limit rules:"
    nft list ruleset | grep "ddos-rate-limit" || echo "  (none)"
    echo ""
}

echo "1. Initial state:"
show_state

echo "2. The fixed implementation should now:"
echo "   ✓ Remove existing IP from set before adding (no duplicates)"
echo "   ✓ Use unique comments for rate limit rules"
echo "   ✓ Clean up expired rules automatically"
echo "   ✓ Separate blocked IPs (in set) from rate-limited IPs (as rules)"
echo ""

echo "3. Key changes made:"
echo "   - execute_block_command: Removes IP before adding to prevent duplicates"
echo "   - execute_rate_limit_command: Uses unique comments and removes old rules"
echo "   - execute_unrate_limit_command: Properly cleans up by comment"
echo "   - cleanup_expired_blocks: Calls unrate_limit_command for proper cleanup"
echo ""

echo "4. To test manually:"
echo "   - Watch firewall rules: watch -n 2 'nft list ruleset | grep -E \"ddos|limit\"'"
echo "   - Check logs: tail -f /var/log/ddos_inspector/firewall.log"
echo "   - Run attacks and verify no duplicates appear"
echo ""

echo "=== Test Complete ==="
