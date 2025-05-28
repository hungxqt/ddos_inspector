# 🔌 Snort 3 Plugin Integration Guide

This guide provides step-by-step instructions for integrating the DDoS Inspector plugin with Snort 3.

## 🚀 **Quick Integration (Automated)**

```bash
# 1. Build and deploy the plugin
sudo ./scripts/deploy.sh

# 2. Verify installation
sudo snort --show-plugins | grep ddos_inspector

# 3. Test configuration
sudo snort -c /etc/snort/snort_ddos_config.lua -T

# 4. Start monitoring (replace eth0 with your interface)
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A alert_fast
```

## 📋 **Manual Integration Steps**

### **Step 1: Build the Plugin**

```bash
# Clean and build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Verify build
ls -la ddos_inspector.so
```

### **Step 2: Install Plugin Binary**

```bash
# Create plugin directory
sudo mkdir -p /usr/local/lib/snort3_extra_plugins

# Install plugin
sudo cp build/ddos_inspector.so /usr/local/lib/snort3_extra_plugins/
sudo chmod 755 /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
```

### **Step 3: Configure Snort**

#### **Option A: Standalone Configuration**
```bash
# Use the provided complete configuration
sudo cp snort_ddos_config.lua /etc/snort/
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0
```

#### **Option B: Integrate with Existing Configuration**
Add to your existing `snort.lua`:

```lua
-- Load DDoS Inspector plugin configuration
dofile('/etc/snort/snort_ddos_config.lua')

-- Add to your existing binder configuration
binder =
{
    -- Your existing bindings...
    
    -- DDoS Inspector bindings
    {
        when = { proto = 'tcp' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'udp' },
        use = { type = 'ddos_inspector' }
    }
}
```

### **Step 4: Setup Firewall Integration**

```bash
# Setup nftables rules for IP blocking
sudo ./scripts/nftables_rules.sh

# Verify nftables setup
sudo nft list tables
sudo nft list set inet filter ddos_ip_set
```

### **Step 5: Create Log Directories**

```bash
# Create Snort log directory
sudo mkdir -p /var/log/snort
sudo chmod 755 /var/log/snort

# Create metrics directory
sudo mkdir -p /tmp
sudo chmod 1777 /tmp  # Ensure temp directory has correct permissions
```

## 🧪 **Testing Integration**

### **Verify Plugin Loading**

```bash
# Check if plugin is recognized
sudo snort --show-plugins | grep ddos_inspector

# Test configuration syntax
sudo snort -c /etc/snort/snort_ddos_config.lua -T

# Show detailed plugin info
sudo snort --help | grep -A 10 -B 5 ddos_inspector
```

### **Test DDoS Detection**

```bash
# Terminal 1: Start Snort with DDoS Inspector
sudo snort -c /etc/snort/snort_ddos_config.lua -i lo -A alert_fast

# Terminal 2: Generate test traffic
sudo ./scripts/run_syn_flood.sh --target 127.0.0.1 --duration 30

# Terminal 3: Monitor results
tail -f /var/log/snort/alert
sudo nft list set inet filter ddos_ip_set
cat /tmp/ddos_inspector_stats
```

## ⚙️ **Configuration Options**

### **Plugin Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow_icmp` | boolean | false | Enable ICMP flood detection |
| `entropy_threshold` | float | 2.0 | Entropy threshold for anomaly detection |
| `ewma_alpha` | float | 0.1 | EWMA smoothing factor (0.0-1.0) |
| `block_timeout` | integer | 600 | IP block duration in seconds |
| `metrics_file` | string | "/tmp/ddos_inspector_stats" | Metrics output file path |

### **Environment-Specific Tuning**

#### **High Traffic Networks (>10Gbps)**
```lua
ddos_inspector = 
{
    entropy_threshold = 1.5,  -- More sensitive
    ewma_alpha = 0.05,        -- Less reactive
    block_timeout = 300,      -- Shorter blocks
    allow_icmp = false
}
```

#### **Low Traffic Networks (<1Gbps)**
```lua
ddos_inspector = 
{
    entropy_threshold = 2.5,  -- Less sensitive
    ewma_alpha = 0.2,         -- More reactive
    block_timeout = 900,      -- Longer blocks
    allow_icmp = true
}
```

#### **Web Servers**
```lua
ddos_inspector = 
{
    entropy_threshold = 1.8,  -- Detect HTTP floods
    ewma_alpha = 0.1,
    block_timeout = 600,
    allow_icmp = false
}
```

## 🔧 **Advanced Integration**

### **Multiple Interface Monitoring**

```bash
# Method 1: Multiple Snort instances
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 &
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth1 &

# Method 2: Bond interfaces
sudo snort -c /etc/snort/snort_ddos_config.lua -i "eth0 eth1"
```

### **Integration with SIEM Systems**

```bash
# Forward logs to syslog
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 \
    --alert-before-pass --treat-drop-as-alert \
    -A alert_syslog
```

### **Custom Metrics Integration**

```cpp
// Add custom metrics to your plugin
void writeCustomMetric(const std::string& name, double value) {
    std::ofstream file("/tmp/ddos_inspector_stats", std::ios::app);
    file << name << ":" << value << std::endl;
}
```

## 📊 **Monitoring Integration**

### **Real-time Metrics**

```bash
# Monitor plugin metrics
watch -n 1 cat /tmp/ddos_inspector_stats

# Monitor blocked IPs
watch -n 5 'sudo nft list set inet filter ddos_ip_set'

# Monitor Snort performance
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 --show-stats
```

### **Log Analysis**

```bash
# Real-time alert monitoring
tail -f /var/log/snort/alert

# Parse alerts for DDoS events
grep -i "ddos\|flood\|slowloris" /var/log/snort/alert

# Count attacks by type
awk -F'[' '/DDoS/ {print $2}' /var/log/snort/alert | sort | uniq -c
```

## 🔍 **Troubleshooting**

### **Plugin Not Loading**

```bash
# Check plugin exists
ls -la /usr/local/lib/snort3_extra_plugins/ddos_inspector.so

# Check permissions
sudo chmod 755 /usr/local/lib/snort3_extra_plugins/ddos_inspector.so

# Check Snort plugin paths
sudo snort --help | grep -i plugin

# Try with explicit library path
LD_LIBRARY_PATH=/usr/local/lib/snort3_extra_plugins snort --show-plugins
```

### **Configuration Errors**

```bash
# Test configuration syntax
sudo snort -c /etc/snort/snort_ddos_config.lua -T

# Validate Lua syntax
lua -l /etc/snort/snort_ddos_config.lua

# Check for missing dependencies
ldd /usr/local/lib/snort3_extra_plugins/ddos_inspector.so
```

### **Firewall Issues**

```bash
# Check nftables status
sudo systemctl status nftables

# Reload nftables rules
sudo ./scripts/nftables_rules.sh

# Manual nftables setup
sudo nft add table inet filter
sudo nft add set inet filter ddos_ip_set '{ type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
```

### **Performance Issues**

```bash
# Monitor CPU usage
top -p $(pidof snort)

# Check memory usage
ps aux | grep snort

# Enable performance profiling
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 --show-perf-stats
```

## 🎯 **Production Deployment**

### **Systemd Service Setup**

```bash
# Create systemd service
sudo tee /etc/systemd/system/snort-ddos.service << 'EOF'
[Unit]
Description=Snort 3 with DDoS Inspector
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/snort -c /etc/snort/snort_ddos_config.lua -i eth0 -D
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable snort-ddos
sudo systemctl start snort-ddos
```

### **Log Rotation**

```bash
# Setup log rotation
sudo tee /etc/logrotate.d/snort-ddos << 'EOF'
/var/log/snort/alert {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload snort-ddos
    endscript
}
EOF
```

### **Monitoring Setup**

```bash
# Start Prometheus metrics dashboard
cd "Prometheus-ELK metrics dashboard"
docker-compose up -d

# Access dashboards
# Grafana: http://localhost:3000
# Kibana: http://localhost:5601
```

## ✅ **Verification Checklist**

- [ ] Plugin compiles without errors
- [ ] Plugin loads in Snort (`snort --show-plugins | grep ddos_inspector`)
- [ ] Configuration syntax is valid (`snort -c config.lua -T`)
- [ ] Firewall rules are active (`sudo nft list tables`)
- [ ] Log directory exists and is writable
- [ ] Metrics file is created (`/tmp/ddos_inspector_stats`)
- [ ] Test attacks are detected and blocked
- [ ] Performance impact is acceptable (<5% CPU)

## 🎉 **Success Indicators**

When properly integrated, you should see:

1. **Plugin loads successfully**: `snort --show-plugins | grep ddos_inspector`
2. **Metrics are generated**: `cat /tmp/ddos_inspector_stats`
3. **Attacks are detected**: Alerts in `/var/log/snort/alert`
4. **IPs are blocked**: `sudo nft list set inet filter ddos_ip_set`
5. **Performance is maintained**: Normal Snort operation with <5% overhead

Your DDoS Inspector is now fully integrated with Snort 3 and ready for production use!