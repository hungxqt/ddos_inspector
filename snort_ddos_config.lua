HOME_NET = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EXTERNAL_NET = "!192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

-- Plugin path - correct path to installed plugin
plugin_path = "/usr/local/lib/snort3_extra_plugins"

-- Function to load environment variables from .env file
local function load_env_file(filename)
    filename = filename or ".env"
    local env_vars = {}
    
    local file = io.open(filename, "r")
    if not file then
        return env_vars  -- Return empty table if file doesn't exist
    end
    
    for line in file:lines() do
        -- Skip comments and empty lines
        line = line:match("^%s*(.-)%s*$")  -- Trim whitespace
        if line ~= "" and not line:match("^#") then
            -- Parse KEY=VALUE format
            local key, value = line:match("^([%w_]+)%s*=%s*(.*)$")
            if key and value then
                -- Remove quotes if present
                value = value:match('^"(.*)"$') or value:match("^'(.*)'$") or value
                env_vars[key] = value
            end
        end
    end
    
    file:close()
    return env_vars
end

-- Load environment variables from .env file
local env_vars = load_env_file()

-- Helper function to get environment variable with fallback
local function get_env(key, default)
    return os.getenv(key) or env_vars[key] or default
end

include '/usr/local/snort3/etc/snort/snort_defaults.lua'

-- Configure your DDoS inspector with enhanced settings
ddos_inspector = {
    allow_icmp = true,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    
    -- NEW: Enable environment variable support (reads from .env file automatically)
    use_env_files = true,
    
    -- File paths - these will be read from environment variables or .env file
    -- Priority: Environment variables > .env file > default values
    metrics_file = get_env("DDOS_METRICS_FILE", "/var/log/ddos_inspector/metrics.log"),
    blocked_ips_file = get_env("DDOS_BLOCKED_IPS_FILE", "/var/log/ddos_inspector/blocked_ips.log"),
    rate_limited_ips_file = get_env("DDOS_RATE_LIMITED_IPS_FILE", "/var/log/ddos_inspector/rate_limited_ips.log"),
    
    -- Enhanced configuration options
    config_profile = "web_server",          -- Options: default, strict, permissive, web_server, game_server
    protected_networks = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,2001:db8::/32",  -- Added IPv6
    log_level = "info",                     -- Options: debug, info, warning, error
    enable_amplification_detection = true,  -- Enable amplification attack detection
    enable_adaptive_thresholds = true,      -- Enable adaptive threshold management
    enable_ipv6 = true,                     -- Enable IPv6 support
    enable_fragmentation_detection = true,  -- Enable fragment flood detection
    max_tracked_ips = 10000,                -- Memory management limit
    tarpit_enabled = true,                  -- Enable tarpit for slow down attacks
    tcp_reset_enabled = true                -- Enable TCP reset for malicious connections
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