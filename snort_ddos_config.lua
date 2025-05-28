-- Example Snort 3 configuration for ddos_inspector plugin
-- Add this to your snort.lua configuration file

-- Load the plugin
ddos_inspector = 
{
    allow_icmp = false,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600
}

-- Add to your inspector list
local_nets = '192.168.1.0/24'

ips = 
{
    rules = [[
        include $RULE_PATH/snort3-community-rules/snort3-community.rules
    ]],
    
    variables = default_variables,
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
    }
}