# Troubleshooting Guide

This guide covers common issues, diagnostic procedures, and solutions for DDoS Inspector deployment and operation.

## Quick Diagnostics

### System Health Check

```bash
# Run comprehensive health check
./scripts/health_check.sh

# Check service status
sudo systemctl status snort-ddos

# Verify plugin loading
sudo snort --show-plugins | grep ddos_inspector

# Test configuration
sudo snort -c /etc/snort/snort_ddos_config.lua -T
```

### Common Issue Checklist

- [ ] Snort 3 properly installed and configured
- [ ] DDoS Inspector plugin loaded successfully
- [ ] Network interface accessible and configured
- [ ] Firewall rules (nftables/iptables) working
- [ ] Sufficient system resources available
- [ ] Metrics file writable and updating

## Installation Issues

### Plugin Not Loading

**Symptoms**:
- Plugin not listed in `snort --show-plugins`
- Error: "can't load library"
- Snort fails to start

**Diagnosis**:
```bash
# Check plugin file exists and permissions
ls -la /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so

# Verify library dependencies
ldd /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so

# Check for missing symbols
nm -D /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so | grep -E "(ddos_inspector|snort)"

# Test manual loading
sudo snort --plugin-path /usr/local/lib/snort_dynamicpreprocessor --show-plugins
```

**Solutions**:
```bash
# Rebuild plugin with correct flags
cd build
make clean && cmake .. -DCMAKE_BUILD_TYPE=Release && make

# Fix permissions
sudo chmod 755 /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so
sudo chown root:root /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so

# Update library cache
sudo ldconfig

# Install missing dependencies
sudo apt-get install libpcap-dev libdaq-dev
```

### Configuration Errors

**Symptoms**:
- Snort configuration test fails
- Invalid parameter errors
- Lua syntax errors

**Diagnosis**:
```bash
# Test configuration syntax
sudo snort -c /etc/snort/snort_ddos_config.lua -T -v

# Check Lua syntax
lua -c /etc/snort/snort_ddos_config.lua

# Validate parameter ranges
grep -E "(threshold|alpha|timeout)" /etc/snort/snort_ddos_config.lua
```

**Solutions**:
```bash
# Reset to default configuration
sudo cp snort_ddos_config.lua.default /etc/snort/snort_ddos_config.lua

# Fix common parameter issues
sed -i 's/entropy_threshold = 0.5/entropy_threshold = 2.0/' /etc/snort/snort_ddos_config.lua
sed -i 's/ewma_alpha = 1.5/ewma_alpha = 0.1/' /etc/snort/snort_ddos_config.lua

# Validate configuration format
./scripts/validate_config.sh /etc/snort/snort_ddos_config.lua
```

## Runtime Issues

### High CPU Usage

**Symptoms**:
- CPU usage >90%
- System slowdown
- Packet drops

**Diagnosis**:
```bash
# Monitor CPU usage by process
top -p $(pgrep snort)

# Check packet processing rate
cat /var/log/ddos_inspector/ddos_inspector_stats | grep packets_per_second

# Profile CPU usage
sudo perf top -p $(pgrep snort)

# Check for infinite loops
strace -p $(pgrep snort) -c -f
```

**Solutions**:
```bash
# Optimize configuration for performance
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Performance optimization
ddos_inspector.allow_icmp = false
ddos_inspector.max_tracked_ips = 50000
ddos_inspector.cleanup_interval = 120
EOF

# Restart with optimized settings
sudo systemctl restart snort-ddos

# Consider hardware upgrade if persistent
```

### Memory Leaks

**Symptoms**:
- Memory usage continuously increasing
- Out of memory errors
- System swapping

**Diagnosis**:
```bash
# Monitor memory usage over time
while true; do
    echo "$(date): $(ps -p $(pgrep snort) -o rss --no-headers) KB"
    sleep 60
done

# Check for memory leaks
valgrind --leak-check=full --show-leak-kinds=all snort -c /etc/snort/snort_ddos_config.lua -i eth0

# Monitor system memory
watch -n 5 'free -h && echo "Snort RSS: $(ps -p $(pgrep snort) -o rss --no-headers) KB"'
```

**Solutions**:
```bash
# Reduce memory usage
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Memory optimization
ddos_inspector.max_tracked_ips = 10000
ddos_inspector.cleanup_interval = 30
ddos_inspector.connection_timeout = 60
EOF

# Enable periodic cleanup
echo "0 */2 * * * root systemctl restart snort-ddos" >> /etc/crontab

# Monitor and alert on memory usage
./scripts/memory_monitor.sh &
```

### Network Interface Issues

**Symptoms**:
- No packets being processed
- Interface errors
- Permission denied errors

**Diagnosis**:
```bash
# Check interface status
ip link show eth0

# Verify interface has traffic
sudo tcpdump -i eth0 -c 10

# Check interface permissions
ls -la /sys/class/net/eth0/

# Test packet capture
sudo snort -i eth0 -c /etc/snort/snort.conf -A console
```

**Solutions**:
```bash
# Fix interface permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which snort)

# Enable promiscuous mode
sudo ip link set eth0 promisc on

# Check for interface conflicts
sudo netstat -i
sudo ss -tuln | grep :eth0

# Restart network service
sudo systemctl restart networking
```

## Detection Issues

### False Positives

**Symptoms**:
- Legitimate traffic being blocked
- High false positive rate
- User complaints about connectivity

**Diagnosis**:
```bash
# Analyze blocked IPs
sudo nft list set inet filter ddos_ip_set

# Check detection patterns
grep -E "(SYN_FLOOD|HTTP_FLOOD)" /var/log/snort/alert | tail -20

# Monitor entropy calculations
grep "entropy" /var/log/ddos_inspector/ddos_inspector_stats

# Analyze traffic patterns
./scripts/analyze_traffic_patterns.sh
```

**Solutions**:
```bash
# Adjust sensitivity
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Reduce false positives
ddos_inspector.entropy_threshold = 2.5
ddos_inspector.ewma_alpha = 0.05
ddos_inspector.syn_flood_threshold = 1000
ddos_inspector.http_flood_threshold = 500
EOF

# Add whitelist for known good IPs
cat >> /etc/snort/snort_ddos_config.lua << EOF
ddos_inspector.whitelist_ips = {
    "192.168.1.0/24",
    "10.0.0.0/8",
    "trusted.domain.com"
}
EOF

# Implement progressive blocking
cat >> /etc/snort/snort_ddos_config.lua << EOF
ddos_inspector.progressive_blocking = true
ddos_inspector.initial_block_time = 60
ddos_inspector.max_block_time = 3600
EOF
```

### False Negatives

**Symptoms**:
- Known attacks not being detected
- No alerts during obvious attacks
- Continued service degradation

**Diagnosis**:
```bash
# Test with known attack patterns
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30

# Check detection thresholds
grep -E "(threshold|rate)" /etc/snort/snort_ddos_config.lua

# Monitor baseline learning
cat /var/log/ddos_inspector/ddos_inspector_stats | grep baseline

# Analyze missed attacks
./scripts/analyze_missed_attacks.sh /var/log/traffic.log
```

**Solutions**:
```bash
# Increase sensitivity
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Increase detection sensitivity
ddos_inspector.entropy_threshold = 1.8
ddos_inspector.ewma_alpha = 0.15
ddos_inspector.syn_flood_threshold = 200
ddos_inspector.http_flood_threshold = 100
EOF

# Enable all detection features
cat >> /etc/snort/snort_ddos_config.lua << EOF
ddos_inspector.enable_entropy_analysis = true
ddos_inspector.enable_behavior_tracking = true
ddos_inspector.enable_connection_tracking = true
ddos_inspector.enable_payload_analysis = true
EOF

# Reduce baseline adaptation time
cat >> /etc/snort/snort_ddos_config.lua << EOF
ddos_inspector.baseline_alpha = 0.02
ddos_inspector.baseline_window = 300
EOF
```

## Firewall Integration Issues

### nftables Problems

**Symptoms**:
- IPs not being blocked
- nftables rule errors
- Permission denied errors

**Diagnosis**:
```bash
# Check nftables status
sudo systemctl status nftables

# Verify table and set exist
sudo nft list tables
sudo nft list set inet filter ddos_ip_set

# Check rule syntax
sudo nft -c -f /etc/nftables.conf

# Test manual IP addition
sudo nft add element inet filter ddos_ip_set { 192.168.1.100 }
```

**Solutions**:
```bash
# Create required nftables structures
sudo nft add table inet filter
sudo nft add set inet filter ddos_ip_set { type ipv4_addr\; }
sudo nft add rule inet filter input ip saddr @ddos_ip_set drop

# Fix permissions
sudo usermod -a -G nftables snort
sudo chmod g+rw /var/run/nftables.sock

# Restart nftables service
sudo systemctl restart nftables
sudo systemctl enable nftables
```

### iptables Problems

**Symptoms**:
- iptables commands failing
- Chain doesn't exist errors
- Rules not applying

**Diagnosis**:
```bash
# Check iptables status
sudo iptables -L -n -v

# Verify custom chain exists
sudo iptables -L ddos_chain

# Check for conflicting rules
sudo iptables -L INPUT -n --line-numbers

# Test manual rule addition
sudo iptables -A ddos_chain -s 192.168.1.100 -j DROP
```

**Solutions**:
```bash
# Create required iptables chain
sudo iptables -N ddos_chain
sudo iptables -A INPUT -j ddos_chain

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4

# Install iptables-persistent
sudo apt-get install iptables-persistent
sudo systemctl enable netfilter-persistent
```

## Performance Issues

### High Latency

**Symptoms**:
- Detection latency >100ms
- Slow response to attacks
- Performance degradation

**Diagnosis**:
```bash
# Measure detection latency
./build/test_performance --metric latency --duration 60

# Check packet queue sizes
cat /proc/net/softnet_stat

# Monitor system load
uptime && iostat 1 5

# Check for CPU throttling
dmesg | grep -i throttl
```

**Solutions**:
```bash
# Optimize system for performance
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
sudo sysctl -p

# Use CPU affinity
echo 'SNORT_OPTS="--cpu-affinity 0,1"' >> /etc/default/snort

# Enable high-performance mode
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Performance optimization
ddos_inspector.batch_processing = true
ddos_inspector.batch_size = 200
ddos_inspector.worker_threads = 2
EOF
```

### Packet Drops

**Symptoms**:
- Packets being dropped
- Incomplete traffic analysis
- Missed attacks

**Diagnosis**:
```bash
# Check interface statistics
cat /proc/net/dev | grep eth0

# Monitor packet drops
watch -n 1 'cat /proc/net/dev | grep eth0'

# Check Snort statistics
sudo snort -i eth0 -c /etc/snort/snort_ddos_config.lua -A console --show-plugins

# Analyze system performance
sar -n DEV 1 10
```

**Solutions**:
```bash
# Increase buffer sizes
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Buffer optimization
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = {
        {
            name = 'pcap',
            variables = {
                buffer_size = 67108864,  -- 64MB
                snaplen = 1518
            }
        }
    }
}
EOF

# Optimize network interface
sudo ethtool -G eth0 rx 4096 tx 4096
sudo ethtool -K eth0 gro on gso on tso on

# Use DPDK for high performance (if available)
./scripts/setup_dpdk.sh
```

## Log Analysis Issues

### Missing Logs

**Symptoms**:
- No alert logs generated
- Empty log files
- Missing attack records

**Diagnosis**:
```bash
# Check log file permissions
ls -la /var/log/snort/

# Verify log directory exists
sudo mkdir -p /var/log/snort
sudo chown snort:snort /var/log/snort

# Test log writing
sudo -u snort touch /var/log/snort/test.log

# Check syslog configuration
grep snort /etc/rsyslog.conf
```

**Solutions**:
```bash
# Fix log permissions
sudo chown -R snort:snort /var/log/snort
sudo chmod 755 /var/log/snort
sudo chmod 644 /var/log/snort/*.log

# Configure log rotation
cat > /etc/logrotate.d/snort-ddos << EOF
/var/log/snort/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 644 snort snort
    postrotate
        /bin/kill -HUP \`cat /var/run/snort.pid 2>/dev/null\` 2>/dev/null || true
    endscript
}
EOF

# Restart logging service
sudo systemctl restart rsyslog
```

### Log Parsing Errors

**Symptoms**:
- Garbled log entries
- ELK parsing failures
- Missing structured data

**Diagnosis**:
```bash
# Check log format
tail -20 /var/log/snort/alert

# Test log parsing
./scripts/test_log_parsing.sh /var/log/snort/alert

# Validate JSON logs
jq . /var/log/snort/ddos_inspector.json
```

**Solutions**:
```bash
# Fix log format configuration
cat >> /etc/snort/snort_ddos_config.lua << EOF
-- Log format configuration
ddos_inspector.log_format = "json"
ddos_inspector.alert_mode = "full"
ddos_inspector.include_packet_data = true
EOF

# Update Logstash configuration
sudo systemctl restart logstash

# Clear corrupted log files
sudo truncate -s 0 /var/log/snort/alert
sudo systemctl restart snort-ddos
```

## Advanced Debugging

### Enable Debug Mode

```bash
# Enable comprehensive debugging
export DDOS_DEBUG=1
export SNORT_VERBOSE=1

# Debug specific components
export DDOS_DEBUG_STATS=1
export DDOS_DEBUG_BEHAVIOR=1
export DDOS_DEBUG_FIREWALL=1

# Start with debug logging
sudo DDOS_DEBUG=1 snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A console
```

### Memory Debugging

```bash
# Run with AddressSanitizer
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1
sudo -E snort -c /etc/snort/snort_ddos_config.lua -i eth0

# Use Valgrind for memory analysis
sudo valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
    snort -c /etc/snort/snort_ddos_config.lua -r test.pcap

# Monitor memory usage patterns
sudo pmap -x $(pgrep snort) | grep -E "(total|ddos)"
```

### Performance Profiling

```bash
# CPU profiling with perf
sudo perf record -g -p $(pgrep snort) -- sleep 60
sudo perf report --no-children

# System call tracing
sudo strace -c -p $(pgrep snort) -f -e trace=network

# I/O profiling
sudo iotop -p $(pgrep snort) -a -o -d 5
```

## Recovery Procedures

### Service Recovery

```bash
# Graceful service restart
sudo systemctl stop snort-ddos
sleep 10
sudo systemctl start snort-ddos

# Emergency stop and cleanup
sudo pkill -9 snort
sudo rm -f /var/run/snort.pid
sudo systemctl start snort-ddos

# Reset firewall rules
sudo nft flush set inet filter ddos_ip_set
sudo iptables -F ddos_chain
```

### Data Recovery

```bash
# Backup current state
sudo cp /var/log/ddos_inspector/ddos_inspector_stats /var/log/ddos_inspector/ddos_inspector_stats.backup
sudo tar -czf /tmp/snort-logs-$(date +%Y%m%d).tar.gz /var/log/snort/

# Reset statistics
sudo rm -f /var/log/ddos_inspector/ddos_inspector_stats
sudo systemctl restart snort-ddos

# Restore from backup if needed
sudo cp /var/log/ddos_inspector/ddos_inspector_stats.backup /var/log/ddos_inspector/ddos_inspector_stats
```

### System Recovery

```bash
# Check system integrity
sudo fsck -f /dev/sda1

# Clear system caches
sudo sync
sudo echo 3 > /proc/sys/vm/drop_caches

# Restart critical services
sudo systemctl restart networking
sudo systemctl restart nftables
sudo systemctl restart snort-ddos
```

## Getting Help

### Collect Diagnostic Information

```bash
#!/bin/bash
# scripts/collect_diagnostics.sh

DIAG_DIR="/tmp/ddos_diagnostics_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DIAG_DIR"

# System information
uname -a > "$DIAG_DIR/system_info.txt"
lscpu > "$DIAG_DIR/cpu_info.txt"
free -h > "$DIAG_DIR/memory_info.txt"

# Service status
systemctl status snort-ddos > "$DIAG_DIR/service_status.txt"
ps aux | grep snort > "$DIAG_DIR/process_info.txt"

# Configuration files
cp /etc/snort/snort_ddos_config.lua "$DIAG_DIR/"
cp /etc/nftables.conf "$DIAG_DIR/" 2>/dev/null

# Logs
tail -1000 /var/log/snort/alert > "$DIAG_DIR/recent_alerts.log"
journalctl -u snort-ddos --no-pager > "$DIAG_DIR/service_logs.txt"

# Metrics
cp /var/log/ddos_inspector/ddos_inspector_stats "$DIAG_DIR/" 2>/dev/null

# Network information
ip addr show > "$DIAG_DIR/network_config.txt"
sudo nft list tables > "$DIAG_DIR/nftables_config.txt" 2>/dev/null

# Create archive
tar -czf "${DIAG_DIR}.tar.gz" -C /tmp "$(basename "$DIAG_DIR")"
echo "Diagnostics collected: ${DIAG_DIR}.tar.gz"
```

### Support Channels

- **GitHub Issues**: [Report bugs and issues](https://github.com/hung-qt/ddos_inspector/issues)
- **GitHub Discussions**: [Community support](https://github.com/hung-qt/ddos_inspector/discussions)
- **Email Support**: adhhp.research@fpt.edu.vn
- **Documentation**: Check all guides in the [docs/](.) directory

---

**Next**: [Contributing Guide](contributing.md) →