# Configuration Guide

This section covers all aspects of configuring DDoS Inspector for your environment and requirements.

## Configuration Topics

### **Basic Configuration**
- Core detection parameters
- Attack thresholds
- Basic blocking settings
- Essential security settings

### **Advanced Configuration**
- Performance tuning
- Custom detection algorithms
- Integration settings
- Enterprise features

### **Monitoring Configuration**
- Metrics collection
- Alert thresholds
- Dashboard setup
- Log configuration

## Quick Configuration

### Minimal Setup
```lua
ddos_inspector = {
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = "/tmp/ddos_inspector_stats"
}
```

### Production Setup
```lua
ddos_inspector = {
    -- Detection settings
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    baseline_alpha = 0.01,
    
    -- Attack thresholds
    syn_flood_threshold = 500,
    http_flood_threshold = 200,
    
    -- Blocking configuration
    block_timeout = 600,
    progressive_blocking = true,
    
    -- Performance settings
    max_tracked_ips = 100000,
    cleanup_interval = 60,
    
    -- Monitoring
    metrics_enabled = true,
    log_level = "info"
}
```

## Configuration Categories

| Category | Description | Priority |
|----------|-------------|----------|
| **Detection** | Anomaly detection parameters | High |
| **Thresholds** | Attack detection limits | High |
| **Blocking** | Mitigation settings | Medium |
| **Performance** | System optimization | Medium |
| **Monitoring** | Observability settings | Low |

## Configuration Files

- **Primary**: `snort_ddos_config.lua` - Main configuration
- **Firewall**: `nftables.conf` - Firewall rules
- **Service**: `/etc/systemd/system/snort-ddos.service` - Service config

## Configuration Workflow

```
Default Config -> Basic Tuning -> Test & Validate -> Performance Check
     ^                                                      |
     |                                                      v
Production Deploy <- Monitor & Tune <- Adjust Parameters <--+
```

## Core Detection Parameters

### Shannon Entropy Configuration

The entropy threshold is crucial for detecting traffic anomalies:

```lua
-- Entropy Analysis Configuration
entropy_threshold = 2.0,              -- Shannon entropy threshold (1.0-4.0)
entropy_window_size = 1000,           -- Packets per entropy calculation
entropy_update_interval = 5,          -- Seconds between entropy updates
```

**Recommended Values by Environment:**

| Environment | Threshold | Rationale |
|-------------|-----------|-----------|
| High Traffic | 1.8-2.2 | More sensitive detection |
| Medium Traffic | 2.0-2.5 | Balanced detection |
| Low Traffic | 2.5-3.0 | Reduce false positives |

### EWMA (Exponentially Weighted Moving Average) Settings

EWMA controls how quickly the system adapts to traffic changes:

```lua
-- EWMA Configuration
ewma_alpha = 0.1,                     -- Adaptation rate (0.01-0.5)
baseline_alpha = 0.01,                -- Baseline learning rate (0.001-0.1)
ewma_window_size = 100,               -- Packets per EWMA calculation
```

**Tuning Guidelines:**
- **High Alpha (0.3-0.5)**: Fast adaptation, good for dynamic environments
- **Medium Alpha (0.1-0.3)**: Balanced adaptation, good for most cases
- **Low Alpha (0.01-0.1)**: Slow adaptation, good for stable environments

### Behavioral Tracking Configuration

Controls how the system tracks and analyzes connection behavior:

```lua
-- Behavioral Analysis Settings
connection_timeout = 300,             -- Connection tracking timeout (seconds)
max_tracked_ips = 100000,            -- Maximum IPs to track simultaneously  
max_tracked_connections = 50000,      -- Maximum connections to track
cleanup_interval = 60,               -- Cleanup interval (seconds)
behavior_analysis_window = 60,       -- Analysis window (seconds)
```

## Attack Detection Thresholds

### SYN Flood Detection

```lua
-- SYN Flood Configuration
syn_flood_threshold = 500,            -- Half-open connections per IP
syn_rate_threshold = 200,             -- SYN packets per 10s window
syn_timeout = 60,                     -- SYN connection timeout (seconds)
syn_retries_threshold = 3,            -- Maximum SYN retries
```

**Environment-Specific Tuning:**

```lua
-- High Traffic Web Server
syn_flood_threshold = 1000,
syn_rate_threshold = 500,

-- Medium Traffic Application Server  
syn_flood_threshold = 500,
syn_rate_threshold = 200,

-- Low Traffic Internal Server
syn_flood_threshold = 100,
syn_rate_threshold = 50,
```

### HTTP Flood Detection

```lua
-- HTTP Flood Configuration
http_flood_threshold = 200,           -- HTTP requests per minute per IP
http_rate_window = 60,               -- Time window for rate calculation (seconds)
http_burst_threshold = 50,           -- Burst requests threshold
http_connection_limit = 100,         -- Max concurrent connections per IP
```

**HTTP-Specific Settings:**

```lua
-- Web Application Protection
http_methods = {"GET", "POST", "PUT", "DELETE"},
http_user_agent_check = true,
http_referrer_check = false,
http_cookie_analysis = true,

-- API Endpoint Protection
api_rate_limit = 1000,               -- API calls per minute
api_burst_limit = 100,               -- Burst API calls
api_key_tracking = true,
```

### Slowloris Attack Detection

```lua
-- Slowloris Configuration
slowloris_threshold = 200,           -- Long connections threshold
slowloris_timeout = 600,             -- Long connection timeout (seconds)
slowloris_header_timeout = 10,       -- Header completion timeout
slowloris_body_timeout = 30,         -- Body completion timeout
```

### UDP Flood Detection

```lua
-- UDP Flood Configuration
udp_flood_threshold = 500,           -- UDP packets per second per IP
udp_rate_window = 10,               -- Time window (seconds)
udp_packet_size_threshold = 1400,   -- Large packet threshold
udp_fragmentation_check = true,     -- Check for fragmented packets
```

## Blocking Configuration

### Basic Blocking Settings

```lua
-- IP Blocking Configuration
block_timeout = 600,                 -- IP block duration (10 minutes)
block_action = "drop",              -- "drop", "reject", or "log"
use_nftables = true,                -- Use nftables (preferred over iptables)
firewall_table = "inet filter",     -- nftables table
firewall_set = "ddos_ip_set",       -- nftables set name
```

### Progressive Blocking

Progressive blocking increases block duration for repeat offenders:

```lua
-- Progressive Blocking Configuration
progressive_blocking = true,         -- Enable progressive blocking
initial_block_time = 60,            -- Initial block duration (1 minute)
max_block_time = 3600,              -- Maximum block duration (1 hour)
block_multiplier = 2,               -- Multiplier for each offense
max_offenses = 5,                   -- Maximum tracked offenses
```

**Progressive Blocking Example:**
- 1st offense: 60 seconds
- 2nd offense: 120 seconds  
- 3rd offense: 240 seconds
- 4th offense: 480 seconds
- 5th offense: 960 seconds
- 6th+ offense: 3600 seconds (max)

### Whitelist Configuration

```lua
-- Network Whitelisting
whitelist_ips = {
    "127.0.0.0/8",                  -- Localhost
    "10.0.0.0/8",                   -- Private Class A
    "172.16.0.0/12",                -- Private Class B  
    "192.168.0.0/16",               -- Private Class C
    "203.0.113.0/24",               -- Your trusted network
},

whitelist_countries = {              -- GeoIP whitelisting (if enabled)
    "US", "CA", "GB", "AU"
},
```

## Performance Optimization

### Memory Management

```lua
-- Memory Configuration
max_tracked_ips = 100000,           -- Maximum IPs in memory
max_tracked_connections = 50000,    -- Maximum connections in memory  
memory_cleanup_threshold = 0.8,     -- Cleanup when 80% full
hash_table_size = 65536,            -- Hash table size (power of 2)
```

**Memory Usage Estimation:**
- Each tracked IP: ~200 bytes
- Each connection: ~150 bytes
- 100k IPs + 50k connections = ~27MB memory usage

### CPU Optimization

```lua
-- CPU Performance Settings
worker_threads = 4,                 -- Number of worker threads (1-8)
batch_processing = true,            -- Enable batch packet processing
batch_size = 100,                  -- Packets per batch (50-500)
allow_icmp = false,                -- Disable ICMP processing for performance
```

**Thread Configuration Guidelines:**
- **Single Core**: worker_threads = 1
- **Dual Core**: worker_threads = 2  
- **Quad Core**: worker_threads = 4
- **8+ Cores**: worker_threads = 6-8

### Network Interface Optimization

```lua
-- DAQ Configuration for Performance
daq = {
    modules = {
        {
            name = 'pcap',
            variables = {
                buffer_size = 67108864,     -- 64MB buffer
                snaplen = 1518,             -- Standard Ethernet MTU
                immediate_mode = false,     -- Batch mode for better performance
                promisc = true,             -- Promiscuous mode
            }
        }
    }
}
```

## Environment-Specific Configurations

### High Traffic Web Server

```lua
-- Configuration for high-traffic web servers (>1Gbps)
ddos_inspector = {
    -- Detection tuned for high volume
    entropy_threshold = 1.8,
    ewma_alpha = 0.15,
    
    -- Higher thresholds for legitimate traffic
    syn_flood_threshold = 1000,
    http_flood_threshold = 500,
    slowloris_threshold = 500,
    
    -- Aggressive performance settings
    max_tracked_ips = 200000,
    worker_threads = 6,
    batch_size = 200,
    
    -- Fast cleanup for memory efficiency
    cleanup_interval = 30,
    
    -- Shorter blocks to avoid blocking legitimate users
    block_timeout = 300,           -- 5 minutes
    progressive_blocking = true,
}
```

### Medium Traffic Application Server

```lua
-- Configuration for medium-traffic application servers
ddos_inspector = {
    -- Balanced detection parameters
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    
    -- Standard thresholds
    syn_flood_threshold = 500,
    http_flood_threshold = 200,
    slowloris_threshold = 200,
    
    -- Moderate performance settings
    max_tracked_ips = 100000,
    worker_threads = 4,
    batch_size = 100,
    
    -- Standard cleanup
    cleanup_interval = 60,
    
    -- Standard blocking
    block_timeout = 600,           -- 10 minutes
    progressive_blocking = true,
}
```

### Internal Network Server

```lua
-- Configuration for internal/low-traffic servers
ddos_inspector = {
    -- Sensitive detection for low traffic
    entropy_threshold = 2.5,
    ewma_alpha = 0.05,
    
    -- Lower thresholds for internal networks
    syn_flood_threshold = 100,
    http_flood_threshold = 50,
    slowloris_threshold = 50,
    
    -- Conservative resource usage
    max_tracked_ips = 10000,
    worker_threads = 2,
    batch_size = 50,
    
    -- Less frequent cleanup
    cleanup_interval = 120,
    
    -- Longer blocks for internal security
    block_timeout = 1800,          -- 30 minutes
    progressive_blocking = true,
}
```

## Monitoring and Logging Configuration

### Metrics Configuration

```lua
-- Metrics Export Configuration
metrics_enabled = true,             -- Enable metrics collection
metrics_file = "/tmp/ddos_inspector_stats",
metrics_format = "prometheus",      -- "text" or "prometheus"
metrics_update_interval = 5,       -- Seconds between updates
metrics_retention = 86400,         -- Metrics retention (24 hours)
```

### Logging Configuration

```lua
-- Logging Configuration
log_file = "/var/log/snort/ddos_inspector.log",
log_level = "info",                -- "debug", "info", "warn", "error"
log_rotation = true,               -- Enable log rotation
log_max_size = "100M",            -- Maximum log file size
log_max_files = 10,               -- Number of rotated files to keep
```

**Log Levels Explained:**
- **debug**: Very verbose, includes packet-level details
- **info**: Standard operational information  
- **warn**: Warning conditions and potential issues
- **error**: Error conditions requiring attention

### Alert Configuration

```lua
-- Alert Configuration
alert_mode = "fast",               -- "fast", "full", or "json"
alert_file = "/var/log/snort/alert",
alert_syslog = true,              -- Send alerts to syslog
alert_threshold = 1,              -- Minimum severity to alert
```

## Integration Settings

### SIEM Integration

```lua
-- SIEM Integration Settings
siem_enabled = true,
siem_format = "cef",              -- Common Event Format
siem_server = "192.168.1.100",
siem_port = 514,
siem_protocol = "udp",           -- "udp" or "tcp"
```

### API Configuration

```lua
-- REST API Configuration  
api_enabled = true,
api_bind_address = "127.0.0.1",
api_port = 8080,
api_ssl = false,                 -- Enable HTTPS
api_auth = "token",              -- "none", "basic", or "token"
api_token = "your-secure-token-here",
```

### Webhook Notifications

```lua
-- Webhook Configuration
webhook_enabled = true,
webhook_url = "https://your-webhook-endpoint.com/ddos-alerts",
webhook_timeout = 10,            -- Seconds
webhook_retry_count = 3,
webhook_events = {              -- Events to send webhooks for
    "attack_detected",
    "ip_blocked", 
    "threshold_exceeded"
},
```

## Testing Your Configuration

### Configuration Validation

```bash
# Test configuration syntax
sudo snort -c /etc/snort/snort_ddos_config.lua -T

# Test with verbose output to see all settings
sudo snort -c /etc/snort/snort_ddos_config.lua -T -v

# Test specific interface
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 -T
```

### Performance Testing

```bash
# Test with sample traffic
sudo snort -c /etc/snort/snort_ddos_config.lua -r sample_traffic.pcap

# Monitor resource usage during testing
htop &
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A none -q
```

### Configuration Benchmarking

```bash
# Create benchmark script
cat > benchmark_config.sh << 'EOF'
#!/bin/bash
echo "=== Configuration Benchmark ==="

# Test startup time
echo "Testing startup time..."
time sudo snort -c /etc/snort/snort_ddos_config.lua -T > /dev/null 2>&1

# Test memory usage
echo "Testing memory usage..."
sudo snort -c /etc/snort/snort_ddos_config.lua -i eth0 -A none -q -D
sleep 10
MEMORY=$(ps aux | grep snort | grep -v grep | awk '{print $6}')
echo "Memory usage: ${MEMORY}KB"
sudo pkill snort

# Test packet processing rate
echo "Testing packet processing rate..."
# Add your specific packet rate tests here
EOF

chmod +x benchmark_config.sh
./benchmark_config.sh
```

## Troubleshooting Configuration Issues

### Common Configuration Problems

**Issue**: Plugin not loading
```bash
# Check plugin path
ls -la /usr/local/lib/snort_dynamicpreprocessor/libddos_inspector.so

# Check Snort configuration
sudo snort --show-plugins | grep ddos
```

**Issue**: High memory usage
```lua
-- Reduce memory footprint
max_tracked_ips = 50000,        -- Reduce from 100000
max_tracked_connections = 25000, -- Reduce from 50000
cleanup_interval = 30,          -- More frequent cleanup
```

**Issue**: High CPU usage
```lua
-- Optimize for CPU performance
worker_threads = 2,             -- Reduce threads
batch_size = 50,               -- Smaller batches
allow_icmp = false,            -- Disable ICMP processing
```

**Issue**: Too many false positives
```lua
-- Reduce sensitivity
entropy_threshold = 2.5,        -- Increase threshold
syn_flood_threshold = 1000,     -- Increase threshold
ewma_alpha = 0.05,             -- Slower adaptation
```

### Configuration Validation Checklist

- [ ] Syntax validation passes (`snort -T`)
- [ ] Plugin loads successfully
- [ ] Network interface specified correctly
- [ ] Firewall integration configured
- [ ] Log files writable by snort user
- [ ] Metrics file location accessible
- [ ] Performance parameters appropriate for hardware
- [ ] Thresholds appropriate for traffic patterns
- [ ] Whitelist includes necessary networks
- [ ] Service configuration correct

## Related Documentation

- [Getting Started](../getting-started/) - Initial setup and installation
- [Deployment Guide](../deployment/) - Environment-specific deployment
- [Monitoring Guide](../monitoring/) - Setting up comprehensive monitoring
- [Troubleshooting](../troubleshooting/) - Solving configuration issues
- [Testing Guide](../testing/) - Validating your configuration
- [Architecture Guide](../architecture/) - Understanding system design

---

**Quick Start**: Copy the production setup above and adjust thresholds for your environment.

**Next Steps**: 
1. Test your configuration with [Testing Guide](../testing/)
2. Set up monitoring with [Monitoring Guide](../monitoring/)
3. Deploy to production with [Deployment Guide](../deployment/)