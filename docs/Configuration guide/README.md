# DDoS Inspector Configuration Guide

This comprehensive guide covers all configuration aspects of the DDoS Inspector framework, from basic setup to advanced tuning for production environments.

## Table of Contents

1. [Basic Configuration](#basic-configuration)
2. [Production Configuration](#production-configuration)
3. [Environment-Specific Tuning](#environment-specific-tuning)
4. [Snort Integration](#snort-integration)
5. [Advanced Parameters](#advanced-parameters)
6. [Performance Tuning](#performance-tuning)
7. [Monitoring Configuration](#monitoring-configuration)
8. [Security Configuration](#security-configuration)
9. [Troubleshooting](#troubleshooting)

## Basic Configuration

### Default Configuration File

Create the main configuration file at `/etc/snort/ddos_inspector.lua`:

```lua
-- DDoS Inspector Basic Configuration
-- File: /etc/snort/ddos_inspector.lua

ddos_inspector = {
    -- Statistical Analysis Parameters
    entropy_threshold = 2.0,        -- Shannon entropy threshold (0.0-8.0)
    ewma_alpha = 0.1,               -- EWMA smoothing factor (0.01-0.5)
    
    -- Behavioral Analysis Parameters
    syn_flood_threshold = 100,       -- Half-open connections limit
    http_flood_threshold = 150,      -- HTTP requests per 30s window
    slowloris_timeout = 300,         -- Long-lived session threshold (seconds)
    
    -- Mitigation Parameters
    block_timeout = 600,             -- IP blocking duration (seconds)
    rate_limit_levels = 4,           -- Progressive rate limiting stages
    
    -- Protocol Configuration
    allow_icmp = false,              -- ICMP flood detection
    enable_ipv6 = true,              -- IPv6 support
    
    -- Performance Tuning
    max_tracked_ips = 100000,        -- Memory usage control
    cleanup_interval = 60,           -- Periodic cleanup (seconds)
    
    -- Logging and Metrics
    metrics_file = "/var/log/snort/ddos_metrics.log",
    enable_prometheus = true,
    log_level = "INFO"               -- DEBUG, INFO, WARN, ERROR
}
```

### Configuration Validation

```bash
# Validate configuration syntax
snort -c /etc/snort/snort.lua --lua-path /etc/snort/?.lua -T

# Test plugin loading
snort --show-plugins | grep ddos_inspector
```

## Production Configuration

### High-Performance Production Setup

```lua
-- Production Configuration for High-Traffic Environments
-- File: /etc/snort/ddos_inspector_production.lua

ddos_inspector = {
    -- Statistical Analysis - Optimized for production
    entropy_threshold = 2.2,         -- Slightly higher to reduce false positives
    ewma_alpha = 0.08,              -- More stable for production traffic
    pattern_analysis = true,         -- Enable advanced pattern detection
    
    -- Behavioral Analysis - Production thresholds
    syn_flood_threshold = 200,       -- Higher threshold for web servers
    http_flood_threshold = 300,      -- Accommodate burst traffic
    slowloris_timeout = 180,         -- Shorter timeout for resource conservation
    ack_flood_threshold = 250,       -- ACK flood detection
    udp_flood_threshold = 500,       -- UDP amplification detection
    
    -- Advanced Mitigation
    block_timeout = 900,             -- 15-minute blocking
    progressive_blocking = true,     -- Escalating block durations
    rate_limit_levels = 6,          -- More granular rate limiting
    whitelist_file = "/etc/snort/whitelist.txt",
    
    -- Protocol Configuration
    allow_icmp = false,
    enable_ipv6 = true,
    enable_fragment_reassembly = true,
    deep_packet_inspection = true,
    
    -- Performance Optimization
    max_tracked_ips = 500000,        -- Large-scale deployment
    cleanup_interval = 30,           -- More frequent cleanup
    hash_table_size = 1048576,      -- Optimized hash table size
    memory_pool_size = "256MB",      -- Pre-allocated memory pool
    
    -- Enhanced Logging
    metrics_file = "/var/log/snort/ddos_metrics.log",
    attack_log_file = "/var/log/snort/ddos_attacks.log",
    blocked_ips_file = "/var/log/snort/blocked_ips.log",
    enable_prometheus = true,
    prometheus_port = 9090,
    log_level = "INFO",
    detailed_metrics = true,
    
    -- Security Features
    enable_reputation = true,
    reputation_file = "/etc/snort/ip_reputation.txt",
    enable_geoblocking = false,
    allowed_countries = {"US", "CA", "GB"},
    
    -- Alerting Configuration
    enable_syslog = true,
    syslog_facility = "LOG_DAEMON",
    email_alerts = false,
    snmp_traps = true,
    snmp_community = "ddos_monitor"
}
```

## Environment-Specific Tuning

### High-Traffic Web Servers

```lua
-- Configuration for high-traffic web servers (e-commerce, CDN edge)
ddos_inspector = {
    -- More sensitive to HTTP-specific attacks
    entropy_threshold = 1.5,         -- Lower threshold for HTTP content
    ewma_alpha = 0.05,              -- Very stable baseline for high volume
    
    -- Web server specific thresholds
    syn_flood_threshold = 300,       -- Higher for legitimate web traffic
    http_flood_threshold = 500,      -- Accommodate high web traffic
    slowloris_timeout = 120,         -- Aggressive slowloris detection
    http_incomplete_threshold = 50,   -- Incomplete HTTP request detection
    
    -- Quick response for web services
    block_timeout = 300,             -- Shorter blocks to reduce false positive impact
    rate_limit_levels = 8,          -- Granular rate limiting
    
    -- Web-specific features
    enable_http_analysis = true,
    http_methods_whitelist = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"},
    max_http_header_size = 8192,
    max_url_length = 2048,
    
    -- Performance for high throughput
    max_tracked_ips = 1000000,
    cleanup_interval = 15,          -- Frequent cleanup for dynamic traffic
    
    log_level = "WARN"              -- Reduce logging overhead
}
```

### Enterprise Edge Networks

```lua
-- Configuration for enterprise edge/perimeter networks
ddos_inspector = {
    -- Conservative settings for mixed traffic
    entropy_threshold = 2.8,         -- Higher threshold for diverse protocols
    ewma_alpha = 0.12,              -- More reactive to enterprise patterns
    
    -- Enterprise network thresholds
    syn_flood_threshold = 150,
    http_flood_threshold = 200,
    slowloris_timeout = 300,
    
    -- Longer blocking for enterprise security
    block_timeout = 1800,           -- 30-minute blocking
    rate_limit_levels = 4,
    
    -- Enterprise features
    enable_ipv6 = true,             -- Full IPv6 support
    enable_geoblocking = true,      -- Geographic restrictions
    allowed_countries = {"US", "CA", "GB", "DE", "FR"},
    
    -- Active Directory integration
    enable_ad_integration = false,   -- Placeholder for future feature
    domain_whitelist = {"company.com", "subsidiary.com"},
    
    -- Comprehensive logging for compliance
    max_tracked_ips = 200000,
    detailed_metrics = true,
    enable_syslog = true,
    log_level = "INFO"
}
```

### IoT/Smart City Networks

```lua
-- Configuration for IoT and smart city infrastructure
ddos_inspector = {
    -- IoT-specific tuning
    entropy_threshold = 3.2,         -- IoT data can be structured/repetitive
    ewma_alpha = 0.15,              -- Adaptive to IoT traffic patterns
    
    -- Lower thresholds for resource-constrained networks
    syn_flood_threshold = 50,
    http_flood_threshold = 75,
    udp_flood_threshold = 200,      -- Common in IoT protocols
    
    -- IoT-specific protocols
    enable_mqtt_analysis = true,     -- Placeholder for MQTT support
    enable_coap_analysis = true,     -- Placeholder for CoAP support
    
    -- Resource conservation
    block_timeout = 1200,           -- 20-minute blocking
    max_tracked_ips = 50000,        -- Smaller scale
    cleanup_interval = 120,         -- Less frequent cleanup
    
    -- IoT security features
    enable_device_profiling = true,  -- Placeholder for device behavior
    unknown_device_threshold = 10,   -- New device detection
    
    log_level = "WARN"
}
```

## Snort Integration

### Main Snort Configuration

Update your main `/etc/snort/snort.lua` configuration:

```lua
-- Main Snort 3 Configuration
-- File: /etc/snort/snort.lua

-- Load DDoS Inspector plugin
require("ddos_inspector")

-- Network configuration
HOME_NET = "192.168.1.0/24"
EXTERNAL_NET = "!$HOME_NET"

-- Include other necessary modules
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = { 'pcap' }
}

-- Inspection policy binding
binder = {
    {
        when = { proto = 'tcp', ports = '80 443 8080 8443' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'udp', ports = '53 123 161 514' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'icmp' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'tcp', ports = 'any' },
        use = { type = 'ddos_inspector' }
    }
}

-- Stream configuration for TCP state tracking
stream_tcp = {
    policy = 'linux',
    session_timeout = 30,
    max_window = 0,
    overlap_limit = 10,
    max_queued_bytes = 1048576,
    max_queued_segs = 2621,
    small_segments = {
        count = 0,
        maximum_size = 0,
    },
    ignore_any_rules = false,
}

-- Detection engine configuration
detection = {
    search_method = 'ac_bnfa',
    search_optimize = true,
    max_queue_events = 5,
    enable_hardened_mode = true,
}

-- Output configuration
output = {
    { 
        name = 'unified2',
        file = '/var/log/snort/snort.log'
    },
    {
        name = 'alert_fast',
        file = '/var/log/snort/alerts.txt'
    }
}

-- Memory profiling
memory = {
    cap = 512 * 1024 * 1024,  -- 512MB memory cap
}

-- Performance profiling
profiler = {
    max = true,
    sort = 'total_time'
}
```

### Policy-Based Configuration

Create specific policies for different network segments:

```lua
-- File: /etc/snort/policies/dmz_policy.lua
-- DMZ Network Policy

inspection_policy = {
    networks = "192.168.100.0/24",  -- DMZ network
    
    ddos_inspector = {
        entropy_threshold = 1.8,     -- More sensitive for DMZ
        syn_flood_threshold = 75,
        http_flood_threshold = 100,
        block_timeout = 1800,        -- Longer blocking in DMZ
        
        enable_advanced_logging = true,
        alert_priority = "HIGH"
    }
}
```

```lua
-- File: /etc/snort/policies/internal_policy.lua
-- Internal Network Policy

inspection_policy = {
    networks = "10.0.0.0/8",        -- Internal corporate network
    
    ddos_inspector = {
        entropy_threshold = 3.0,     -- Less sensitive for internal traffic
        syn_flood_threshold = 200,
        http_flood_threshold = 300,
        block_timeout = 600,         -- Shorter blocking for internal users
        
        enable_whitelist = true,
        whitelist_subnets = {"10.1.0.0/24", "10.2.0.0/24"},  -- Management subnets
        alert_priority = "MEDIUM"
    }
}
```

## Advanced Parameters

### Statistical Engine Advanced Configuration

```lua
ddos_inspector = {
    -- Advanced statistical parameters
    statistical_engine = {
        -- EWMA Configuration
        ewma_fast_alpha = 0.1,       -- Fast-adapting EWMA
        ewma_slow_alpha = 0.01,      -- Slow baseline EWMA
        ewma_convergence_factor = 0.95, -- Convergence threshold
        
        -- Entropy Analysis
        entropy_window_size = 1024,   -- Sliding window size for entropy
        entropy_min_payload = 32,     -- Minimum payload size for entropy calc
        entropy_adaptive_threshold = true,
        entropy_protocol_specific = {
            http = 2.5,
            https = 7.0,
            dns = 4.0,
            ssh = 7.5
        },
        
        -- Pattern Detection
        pattern_min_length = 4,       -- Minimum pattern length
        pattern_max_repetition = 0.25, -- Maximum pattern repetition ratio
        pattern_sliding_window = true,
        
        -- Variance Analysis
        enable_variance_analysis = true,
        variance_window_size = 100,   -- Number of packets for variance calc
        variance_threshold = 2.0,     -- Standard deviation threshold
        
        -- Seasonal Analysis
        enable_seasonal_analysis = false, -- Requires historical data
        seasonal_period = 86400,      -- 24-hour period
        seasonal_threshold = 1.5      -- Seasonal deviation threshold
    }
}
```

### Behavioral Engine Advanced Configuration

```lua
ddos_inspector = {
    -- Advanced behavioral parameters
    behavioral_engine = {
        -- Connection State Tracking
        connection_timeout = 300,     -- Connection state timeout
        max_half_open_per_ip = 100,   -- Half-open connections per IP
        syn_ack_ratio_threshold = 0.1, -- SYN/ACK ratio for flood detection
        
        -- HTTP Behavior Analysis
        http_session_timeout = 600,   -- HTTP session timeout
        max_http_requests_per_session = 1000,
        http_method_whitelist = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"},
        http_uri_max_length = 8192,
        http_header_max_count = 50,
        
        -- Application Layer Analysis
        slowloris_detection = {
            enabled = true,
            min_connections = 50,     -- Minimum connections to trigger
            connection_timeout = 300, -- Long-lived connection threshold
            incomplete_request_ratio = 0.8 -- Ratio of incomplete requests
        },
        
        -- DNS Behavior Analysis
        dns_analysis = {
            enabled = true,
            max_queries_per_second = 100,
            suspicious_query_types = {"ANY", "TXT"},
            max_subdomain_depth = 10,
            enable_dga_detection = false -- Domain Generation Algorithm detection
        },
        
        -- Temporal Analysis
        time_window_analysis = {
            enabled = true,
            short_window = 5,         -- 5-second window
            medium_window = 30,       -- 30-second window
            long_window = 300,        -- 5-minute window
            burst_detection_factor = 5.0 -- Factor for burst detection
        }
    }
}
```

## Performance Tuning

### Memory Optimization

```lua
ddos_inspector = {
    -- Memory management configuration
    memory_management = {
        -- Hash table optimization
        ip_hash_table_size = 1048576,    -- 2^20 entries
        connection_hash_table_size = 524288, -- 2^19 entries
        
        -- Memory pools
        enable_memory_pools = true,
        packet_pool_size = 10000,        -- Pre-allocated packet structures
        connection_pool_size = 50000,    -- Pre-allocated connection structures
        
        -- Garbage collection
        gc_interval = 60,                -- Garbage collection interval
        gc_threshold = 0.8,              -- Memory usage threshold for GC
        
        -- Bounded data structures
        max_events_per_ip = 10000,       -- Maximum events stored per IP
        max_connections_per_ip = 5000,   -- Maximum connections tracked per IP
        
        -- Memory limits
        max_memory_usage = "1GB",        -- Maximum memory usage
        memory_pressure_threshold = 0.9, -- Threshold for memory pressure
        
        -- LRU eviction policies
        enable_lru_eviction = true,
        lru_cleanup_batch_size = 1000    -- Number of entries to clean per batch
    }
}
```

### CPU Optimization

```lua
ddos_inspector = {
    -- CPU optimization configuration
    cpu_optimization = {
        -- Threading configuration
        enable_multithreading = true,
        worker_threads = 4,              -- Number of worker threads
        thread_affinity = true,          -- CPU affinity for threads
        
        -- Processing optimization
        enable_fast_path = true,         -- Fast path for legitimate traffic
        fast_path_cache_size = 10000,    -- Cache size for fast path
        fast_path_timeout = 300,         -- Cache timeout in seconds
        
        -- Batch processing
        enable_batch_processing = true,
        batch_size = 100,                -- Number of packets per batch
        
        -- SIMD optimization
        enable_simd = true,              -- Use SIMD instructions where possible
        
        -- Load balancing
        enable_load_balancing = true,
        load_balance_algorithm = "round_robin", -- round_robin, least_loaded
        
        -- Performance monitoring
        enable_performance_counters = true,
        performance_log_interval = 300   -- Performance log interval in seconds
    }
}
```

## Monitoring Configuration

### Prometheus Integration

```lua
ddos_inspector = {
    -- Prometheus metrics configuration
    prometheus = {
        enabled = true,
        port = 9090,
        interface = "0.0.0.0",
        metrics_path = "/metrics",
        
        -- Metric collection intervals
        collection_interval = 10,        -- Seconds between metric collections
        
        -- Custom metrics
        custom_metrics = {
            -- Attack metrics
            "ddos_attacks_detected_total",
            "ddos_attacks_blocked_total",
            "ddos_false_positives_total",
            
            -- Performance metrics
            "ddos_processing_latency_seconds",
            "ddos_memory_usage_bytes",
            "ddos_cpu_usage_percent",
            
            -- Traffic metrics
            "ddos_packets_processed_total",
            "ddos_bytes_processed_total",
            "ddos_connections_tracked_total"
        },
        
        -- Metric labels
        default_labels = {
            instance = "ddos-inspector-01",
            environment = "production",
            datacenter = "dc1"
        }
    }
}
```

### Logging Configuration

```lua
ddos_inspector = {
    -- Comprehensive logging configuration
    logging = {
        -- Log levels: DEBUG, INFO, WARN, ERROR, CRITICAL
        global_log_level = "INFO",
        
        -- Component-specific log levels
        component_log_levels = {
            stats_engine = "INFO",
            behavior_tracker = "INFO",
            firewall_action = "WARN",
            correlation_engine = "INFO"
        },
        
        -- Log destinations
        log_destinations = {
            {
                type = "file",
                path = "/var/log/snort/ddos_inspector.log",
                level = "INFO",
                rotation = {
                    enabled = true,
                    max_size = "100MB",
                    max_files = 10
                }
            },
            {
                type = "syslog",
                facility = "LOG_DAEMON",
                level = "WARN"
            },
            {
                type = "json",
                path = "/var/log/snort/ddos_inspector.json",
                level = "INFO",
                structured_logging = true
            }
        },
        
        -- Attack-specific logging
        attack_logging = {
            enabled = true,
            log_file = "/var/log/snort/ddos_attacks.log",
            include_packet_data = false,    -- For privacy compliance
            include_payload_hash = true,    -- Hash instead of full payload
            max_attack_log_size = "1GB"
        },
        
        -- Performance logging
        performance_logging = {
            enabled = true,
            log_file = "/var/log/snort/ddos_performance.log",
            log_interval = 60,              -- Seconds
            include_memory_stats = true,
            include_cpu_stats = true
        }
    }
}
```

## Security Configuration

### Access Control and Authentication

```lua
ddos_inspector = {
    -- Security configuration
    security = {
        -- Access control
        enable_access_control = true,
        admin_users = {"admin", "security_team"},
        readonly_users = {"monitor", "analyst"},
        
        -- API security (for management interface)
        api_security = {
            enabled = true,
            require_authentication = true,
            api_key_file = "/etc/snort/ddos_inspector_api.key",
            session_timeout = 3600,        -- 1 hour
            max_concurrent_sessions = 10
        },
        
        -- Configuration security
        config_security = {
            require_signed_configs = false, -- Require digitally signed configs
            config_checksum_validation = true,
            backup_configs = true,
            backup_directory = "/etc/snort/backups"
        },
        
        -- Network security
        network_security = {
            bind_interfaces = ["eth0"],     -- Limit to specific interfaces
            allow_remote_management = false,
            management_networks = ["192.168.1.0/24"], -- Management network access
            
            -- TLS configuration for secure communication
            enable_tls = false,
            tls_cert_file = "/etc/ssl/certs/ddos_inspector.crt",
            tls_key_file = "/etc/ssl/private/ddos_inspector.key",
            tls_ca_file = "/etc/ssl/certs/ca.crt"
        }
    }
}
```

### Compliance and Privacy

```lua
ddos_inspector = {
    -- Compliance and privacy configuration
    compliance = {
        -- GDPR compliance
        gdpr = {
            enabled = false,
            data_retention_days = 30,      -- Data retention period
            anonymize_ip_addresses = true, -- Anonymize last octet
            enable_data_export = true,     -- Allow data export requests
            enable_data_deletion = true    -- Allow data deletion requests
        },
        
        -- Audit logging
        audit_logging = {
            enabled = true,
            audit_log_file = "/var/log/snort/ddos_audit.log",
            log_configuration_changes = true,
            log_admin_actions = true,
            log_blocked_actions = true
        },
        
        -- Data protection
        data_protection = {
            encrypt_logs = false,          -- Encrypt log files
            hash_sensitive_data = true,    -- Hash instead of store sensitive data
            enable_data_classification = true, -- Classify data sensitivity
            
            -- PII handling
            mask_ip_addresses = false,     -- Mask IP addresses in logs
            mask_payload_data = true,      -- Mask payload data
            retention_policy = "30_days"   -- Data retention policy
        }
    }
}
```

## Troubleshooting

### Debug Configuration

```lua
-- Debug configuration for troubleshooting
-- File: /etc/snort/ddos_inspector_debug.lua

ddos_inspector = {
    -- Enable debug mode
    debug_mode = true,
    
    -- Verbose logging
    log_level = "DEBUG",
    
    -- Debug-specific settings
    debug_settings = {
        log_packet_details = true,      -- Log detailed packet information
        log_decision_process = true,    -- Log detection decision process
        log_performance_metrics = true, -- Log performance metrics
        log_memory_usage = true,        -- Log memory usage details
        
        -- Packet capture for analysis
        enable_packet_capture = true,
        capture_file = "/tmp/ddos_debug.pcap",
        capture_filter = "src host 192.168.1.100", -- Capture specific traffic
        max_capture_size = "100MB",
        
        -- State dumping
        enable_state_dumps = true,
        state_dump_interval = 300,      -- Dump state every 5 minutes
        state_dump_directory = "/tmp/ddos_state_dumps"
    },
    
    -- Reduced thresholds for testing
    entropy_threshold = 1.0,
    syn_flood_threshold = 10,
    http_flood_threshold = 20,
    
    -- Shorter timeouts for faster testing
    block_timeout = 60,
    cleanup_interval = 10
}
```

### Common Issues and Solutions

#### 1. High False Positive Rate

```lua
-- Configuration to reduce false positives
ddos_inspector = {
    entropy_threshold = 2.5,         -- Increase threshold
    ewma_alpha = 0.05,              -- More stable baseline
    syn_flood_threshold = 200,       -- Higher threshold
    
    -- Enable whitelist
    enable_whitelist = true,
    whitelist_file = "/etc/snort/whitelist.txt",
    
    -- Adaptive thresholds
    enable_adaptive_thresholds = true,
    learning_period = 86400,         -- 24-hour learning period
}
```

#### 2. High Memory Usage

```lua
-- Configuration to reduce memory usage
ddos_inspector = {
    max_tracked_ips = 50000,         -- Reduce tracked IPs
    cleanup_interval = 30,           -- More frequent cleanup
    
    -- Aggressive eviction
    enable_lru_eviction = true,
    memory_pressure_threshold = 0.7, -- Earlier eviction
    
    -- Disable expensive features
    enable_advanced_logging = false,
    detailed_metrics = false
}
```

#### 3. High CPU Usage

```lua
-- Configuration to reduce CPU usage
ddos_inspector = {
    enable_fast_path = true,         -- Enable fast path optimization
    fast_path_cache_size = 50000,    -- Larger cache
    
    -- Reduce analysis frequency
    entropy_analysis_interval = 10,  -- Analyze every 10th packet
    
    -- Disable expensive features
    pattern_analysis = false,
    deep_packet_inspection = false,
    
    -- Optimize for speed
    hash_table_size = 65536,         -- Smaller hash table
    enable_batch_processing = true
}
```

### Configuration Validation Script

```bash
#!/bin/bash
# File: /usr/local/bin/validate_ddos_config.sh

echo "Validating DDoS Inspector Configuration..."

# Check if configuration file exists
CONFIG_FILE="/etc/snort/ddos_inspector.lua"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Validate Lua syntax
lua -c "$CONFIG_FILE"
if [ $? -ne 0 ]; then
    echo "ERROR: Configuration file has syntax errors"
    exit 1
fi

# Validate Snort configuration
snort -c /etc/snort/snort.lua --lua-path /etc/snort/?.lua -T
if [ $? -ne 0 ]; then
    echo "ERROR: Snort configuration validation failed"
    exit 1
fi

# Check plugin loading
snort --show-plugins | grep -q ddos_inspector
if [ $? -ne 0 ]; then
    echo "ERROR: DDoS Inspector plugin not loaded"
    exit 1
fi

# Validate log directories
LOG_DIR="/var/log/snort"
if [ ! -d "$LOG_DIR" ]; then
    echo "WARNING: Log directory does not exist: $LOG_DIR"
    echo "Creating log directory..."
    sudo mkdir -p "$LOG_DIR"
    sudo chown snort:snort "$LOG_DIR"
fi

# Check firewall rules
nft list tables | grep -q ddos_inspector
if [ $? -ne 0 ]; then
    echo "WARNING: nftables rules not configured"
    echo "Run: sudo /path/to/scripts/nftables_rules.sh"
fi

echo "Configuration validation completed successfully!"
```

---

## Quick Reference

### Essential Commands

```bash
# Start Snort with DDoS Inspector
sudo snort -c /etc/snort/snort.lua -i eth0 -D

# Test configuration
sudo snort -c /etc/snort/snort.lua -T

# View real-time metrics
tail -f /var/log/snort/ddos_metrics.log

# Check blocked IPs
sudo nft list set inet ddos_inspector blocked_ips

# Unblock an IP manually
sudo nft delete element inet ddos_inspector blocked_ips { 192.168.1.100 }
```

### Configuration File Locations

- Main config: `/etc/snort/ddos_inspector.lua`
- Snort config: `/etc/snort/snort.lua`
- Whitelist: `/etc/snort/whitelist.txt`
- Logs: `/var/log/snort/`
- Metrics: `/var/log/snort/ddos_metrics.log`

For additional support and advanced configuration options, refer to the [comprehensive project documentation](./COMPREHENSIVE_PROJECT_DOCUMENTATION.md).