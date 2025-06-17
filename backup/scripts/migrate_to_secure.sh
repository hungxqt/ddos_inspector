#!/bin/bash

# DDoS Inspector Security Migration Script
# This script safely migrates from the old implementation to the secure version

echo "=== DDoS Inspector Security Migration ==="
echo "This will replace the current FirewallAction with the secure implementation"
echo "Date: $(date)"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root for proper capability setup"
    echo "Please run with sudo"
    exit 1
fi

echo "Step 1: Installing required dependencies..."
apt-get update
apt-get install -y libcap-dev libcap2-bin

echo "Step 2: Backing up current implementation..."
cp src/firewall_action.cpp src/firewall_action_backup.cpp
echo "✓ Backup created at src/firewall_action_backup.cpp"

echo "Step 3: Migrating to secure implementation..."
cp src/firewall_action_secure.cpp src/firewall_action.cpp
echo "✓ Secure implementation activated"

echo "Step 4: Setting up proper log directory permissions..."
mkdir -p /var/log/ddos_inspector
chmod 750 /var/log/ddos_inspector
chown root:adm /var/log/ddos_inspector
echo "✓ Log directory secured"

echo "Step 5: Setting up log rotation..."
cat > /etc/logrotate.d/ddos_inspector << 'EOF'
/var/log/ddos_inspector/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        # Signal the application to reopen log files if needed
        /bin/true
    endscript
}
EOF
echo "✓ Log rotation configured"

echo "Step 6: Testing compilation..."
cd /home/hungqt/res
rm -rf build && mkdir build && cd build
if cmake .. && make; then
    echo "✓ Compilation successful"
else
    echo "✗ Compilation failed - reverting changes"
    cd ..
    cp src/firewall_action_backup.cpp src/firewall_action.cpp
    exit 1
fi

echo "Step 7: Running security tests..."
cd /home/hungqt/res/build
if ./test_firewall_action; then
    echo "✓ Security tests passed"
else
    echo "⚠ Some tests failed - check test output"
fi

echo ""
echo "=== Migration Complete ==="
echo "The DDoS Inspector now uses the secure implementation with:"
echo "• Shell injection protection"
echo "• Worker queue system (no thread flooding)"
echo "• Privilege dropping (CAP_NET_ADMIN only)"
echo "• Thread-safe operations"
echo "• IPv6 support"
echo "• Async logging"
echo ""
echo "Security features:"
echo "• Input validation with regex patterns"
echo "• Safe command execution (no shell injection)"
echo "• Bounded resource usage"
echo "• Comprehensive error logging"
echo ""
echo "Monitor logs at: /var/log/ddos_inspector/firewall.log"
echo "Backup of old implementation: src/firewall_action_backup.cpp"
echo ""

# Create a simple verification script
cat > verify_security.sh << 'EOF'
#!/bin/bash
echo "=== DDoS Inspector Security Verification ==="

# Check for capabilities
echo "1. Checking capabilities support:"
if which getcap >/dev/null 2>&1; then
    echo "✓ Capabilities tools available"
else
    echo "✗ Missing capabilities tools (install libcap2-bin)"
fi

# Check log directory
echo "2. Checking log directory security:"
if [ -d "/var/log/ddos_inspector" ]; then
    perms=$(stat -c "%a" /var/log/ddos_inspector)
    if [ "$perms" = "750" ]; then
        echo "✓ Log directory has secure permissions ($perms)"
    else
        echo "⚠ Log directory permissions: $perms (should be 750)"
    fi
else
    echo "✗ Log directory not found"
fi

# Check for nftables
echo "3. Checking nftables availability:"
if which nft >/dev/null 2>&1; then
    echo "✓ nftables available"
else
    echo "✗ nftables not found (install nftables package)"
fi

# Check build
echo "4. Checking build status:"
if [ -f "build/libddos_inspector.so" ]; then
    echo "✓ DDoS Inspector library built successfully"
else
    echo "✗ Library not found - run build first"
fi

echo ""
echo "Verification complete."
EOF

chmod +x verify_security.sh
echo "Created verification script: verify_security.sh"
echo "Run ./verify_security.sh to check security status anytime"
