-- Complete Snort 3 configuration for ddos_inspector plugin
-- This file provides a full working configuration

-- Network configuration
HOME_NET = 'any'
EXTERNAL_NET = '!$HOME_NET'

-- Define rule and log paths
RULE_PATH = '/usr/local/etc/rules'
BUILTIN_RULE_PATH = '/usr/local/etc/rules'
PLUGIN_RULE_PATH = '/usr/local/etc/so_rules'

-- Logging configuration
alert_fast = 
{
    file = '/var/log/snort/alert',
    packet = false,
    limit = 10
}

-- Load the DDoS Inspector plugin
ddos_inspector = 
{
    allow_icmp = false,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = '/tmp/ddos_inspector_stats'
}

-- IPS configuration
ips = 
{
    mode = 'inline',
    variables = default_variables
}

-- Detection engine configuration
detection = 
{
    search_method = 'ac_bnfa',
    split_any_any = true,
    max_queue_events = 5
}

-- Include the ddos_inspector in your detection pipeline
binder =
{
    {
        when = { proto = 'tcp' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'udp' },
        use = { type = 'ddos_inspector' }
    },
    {
        when = { proto = 'icmp' },
        use = { type = 'ddos_inspector' }
    }
}

-- Stream configuration for TCP analysis
stream_tcp = 
{
    policy = 'linux',
    timeout = 180,
    overlap_limit = 10,
    max_window = 0,
    require_3whs = false,
    use_static_footprint_sizes = true
}

stream_udp = 
{
    timeout = 180
}

-- Packet capture configuration
daq = 
{
    module_dirs = { '/usr/local/lib/daq' },
    modules = 
    {
        {
            name = 'pcap',
            mode = 'passive'
        }
    }
}

-- Performance profiling (optional)
profiler = 
{
    modules = true,
    memory = true,
    rules = true
}