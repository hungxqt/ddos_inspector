HOME_NET = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EXTERNAL_NET = "!192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

-- Plugin path - correct path to installed plugin
plugin_path = "/usr/local/lib/snort3_extra_plugins"

include '/usr/local/snort3/etc/snort/snort_defaults.lua'

-- Configure your DDoS inspector with enhanced settings
ddos_inspector = {
    allow_icmp = true,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = "/tmp/ddos_inspector/ddos_inspector_stats",
    -- Enhanced configuration options
    config_profile = "web_server",  -- Options: default, strict, permissive, web_server, game_server
    protected_networks = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,2001:db8::/32",  -- Added IPv6
    log_level = "info",  -- Options: debug, info, warning, error
    enable_amplification_detection = true,  -- Enable amplification attack detection
    enable_adaptive_thresholds = true,      -- Enable adaptive threshold management
    enable_ipv6 = true,                     -- Enable IPv6 support
    enable_fragmentation_detection = true,  -- Enable fragment flood detection
    max_tracked_ips = 10000,               -- Memory management limit
    tarpit_enabled = true,                 -- Enable tarpit for slow down attacks
    tcp_reset_enabled = true               -- Enable TCP reset for malicious connections
}

-- Add DAQ configuration to use afpacket instead of pcap
daq = {
    modules = { 
        {
            name = 'afpacket'
        }
    }
}

-- Add your DDoS inspector to the default inspection policy
inspection_policy = 
{
    inspectors = 
    {
        { ddos_inspector = {} }
    }
}

-- Simple binder that uses the default configuration (no custom binding needed)
binder = {
    {
        when = {},
        use = {}
    }
}