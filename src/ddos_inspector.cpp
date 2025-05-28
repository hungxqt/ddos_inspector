#include "ddos_inspector.hpp"
#include "stats_engine.hpp"
#include "behavior_tracker.hpp"
#include "firewall_action.hpp"
#include "packet_data.hpp"

#include <framework/snort_api.h>
#include <main/snort_config.h>
#include <protocols/ip.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace snort;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter ddos_params[] =
{
    { "allow_icmp", Parameter::PT_BOOL, nullptr, "false",
      "allow ICMP packets to be processed" },

    { "entropy_threshold", Parameter::PT_REAL, "0.0:10.0", "2.0",
      "entropy threshold for anomaly detection" },

    { "ewma_alpha", Parameter::PT_REAL, "0.0:1.0", "0.1",
      "EWMA smoothing factor" },

    { "block_timeout", Parameter::PT_INT, "1:3600", "600",
      "IP block timeout in seconds" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define DDOS_NAME "ddos_inspector"
#define DDOS_HELP "statistical and behavioral DDoS detection plugin"

DdosInspectorModule::DdosInspectorModule() : Module(DDOS_NAME, DDOS_HELP, ddos_params)
{
}

const Parameter* DdosInspectorModule::get_parameters() const
{
    return ddos_params;
}

bool DdosInspectorModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if (v.is("allow_icmp"))
        allow_icmp = v.get_bool();
    else if (v.is("entropy_threshold"))
        entropy_threshold = v.get_real();
    else if (v.is("ewma_alpha"))
        ewma_alpha = v.get_real();
    else if (v.is("block_timeout"))
        block_timeout = v.get_uint32();
    else
        return false;

    return true;
}

bool DdosInspectorModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool DdosInspectorModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

DdosInspector::DdosInspector(DdosInspectorModule* mod)
{
    allow_icmp = mod->allow_icmp;
    
    // Initialize components with configuration
    stats_engine = std::make_unique<StatsEngine>(mod->entropy_threshold, mod->ewma_alpha);
    behavior_tracker = std::make_unique<BehaviorTracker>();
    firewall_action = std::make_unique<FirewallAction>(mod->block_timeout);
}

DdosInspector::~DdosInspector() = default;

void DdosInspector::eval(Packet* p)
{
    if (!p || !p->ptrs.ip_api.is_ip())
        return;

    // Pre-filter: Only handle IPv4 for now
    if (!p->ptrs.ip_api.is_ip4())
        return;

    // Get IP header and protocol
    const snort::ip::IP4Hdr* ip4h = p->ptrs.ip_api.get_ip4h();
    uint8_t proto = (uint8_t)ip4h->proto();
    
    // Only handle TCP/UDP (and optionally ICMP)
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && 
        !(allow_icmp && proto == IPPROTO_ICMP))
        return;

    packets_processed++;

    // Extract packet information
    PacketData pkt_data;
    
    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];
    uint32_t src_addr = ip4h->get_src();
    uint32_t dst_addr = ip4h->get_dst();
    inet_ntop(AF_INET, &src_addr, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &dst_addr, dst_buf, sizeof(dst_buf));
    
    pkt_data.src_ip = src_buf;
    pkt_data.dst_ip = dst_buf;
    pkt_data.size = ip4h->len();
    pkt_data.is_syn = false;
    pkt_data.is_ack = false;
    pkt_data.is_http = false;

    // Extract TCP flags if TCP packet
    if (proto == IPPROTO_TCP && p->ptrs.tcph)
    {
        pkt_data.is_syn = (p->ptrs.tcph->th_flags & TH_SYN) != 0;
        pkt_data.is_ack = (p->ptrs.tcph->th_flags & TH_ACK) != 0;
    }

    // Extract payload if available
    if (p->data && p->dsize > 0)
    {
        pkt_data.payload = std::string(reinterpret_cast<const char*>(p->data), p->dsize);
        // Simple HTTP detection
        if (pkt_data.payload.find("HTTP/") != std::string::npos ||
            pkt_data.payload.find("GET ") == 0 ||
            pkt_data.payload.find("POST ") == 0)
        {
            pkt_data.is_http = true;
        }
    }

    // Analyze packet
    bool stats_anomaly = stats_engine->analyze(pkt_data);
    bool behavior_anomaly = behavior_tracker->inspect(pkt_data);

    // Take action if anomaly detected
    if (stats_anomaly || behavior_anomaly)
    {
        firewall_action->block(pkt_data.src_ip);
        packets_blocked++;
    }
}

void DdosInspector::show_stats(std::ostream& os)
{
    os << "DDoS Inspector Statistics:\n";
    os << "  Packets processed: " << packets_processed.load() << "\n";
    os << "  Packets blocked: " << packets_blocked.load() << "\n";
    if (stats_engine)
    {
        os << "  Current EWMA: " << stats_engine->get_current_rate() << "\n";
        os << "  Current Entropy: " << stats_engine->get_entropy() << "\n";
    }
    if (firewall_action)
    {
        os << "  Blocked IPs count: " << firewall_action->get_blocked_count() << "\n";
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new DdosInspectorModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* ddos_ctor(Module* m)
{
    DdosInspectorModule* mod = static_cast<DdosInspectorModule*>(m);
    return new DdosInspector(mod);
}

static void ddos_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi ddos_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DDOS_NAME,
        DDOS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ddos_ctor,
    ddos_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ddos_api.base,
    nullptr
};

