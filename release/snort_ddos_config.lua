HOME_NET = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EXTERNAL_NET = "!192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

-- Plugin path - works for both local and Docker environments
plugin_path = "/home/hungqt/res/release:/usr/local/lib/snort3_extra_plugins"

include '/usr/local/snort3/etc/snort/snort_defaults.lua'

-- Configure your DDoS inspector
ddos_inspector = {
    allow_icmp = true,
    entropy_threshold = 2.0,
    ewma_alpha = 0.1,
    block_timeout = 600,
    metrics_file = "/app/data/ddos_inspector_stats"
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