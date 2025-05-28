#ifndef PACKET_DATA_H
#define PACKET_DATA_H

#include <string>

struct PacketData {
    std::string src_ip;
    std::string dst_ip;
    std::string payload;
    std::string session_id;
    size_t size = 0;
    bool is_syn = false;
    bool is_ack = false;
    bool is_http = false;
};

#endif // PACKET_DATA_H