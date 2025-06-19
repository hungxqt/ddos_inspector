#ifndef PACKET_DATA_H
#define PACKET_DATA_H

#include <string>
#include <string_view>
#include <cstdint>
#include <netinet/in.h>  // For IPPROTO_TCP, IPPROTO_UDP constants

struct PacketData {
    std::string src_ip;
    std::string dst_ip;
    std::string_view payload_view;  // Hot-path optimization: defer copying
                                   // WARNING: payload_view points into Snort's packet buffer
                                   // and MUST NOT be stored beyond the eval() call
    mutable std::string payload;    // Materialized only when needed
    std::string session_id;
    size_t size = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;          // NEW: Protocol type (IPPROTO_TCP, IPPROTO_UDP, etc.)
    bool is_syn = false;
    bool is_ack = false;
    bool is_http = false;    
    bool is_multicast = false;     // NEW: Multicast destination
    bool is_broadcast = false;     // NEW: Broadcast destination
    mutable bool payload_materialized = false;
    
    // Helper methods for protocol detection
    bool is_tcp() const { return protocol == IPPROTO_TCP; }
    bool is_udp() const { return protocol == IPPROTO_UDP; }
    
    // Lazy payload materialization
    const std::string& getPayload() const {
        if (!payload_materialized && !payload_view.empty()) {
            payload = std::string(payload_view);
            payload_materialized = true;
        }
        return payload;
    }
};

#endif // PACKET_DATA_H