#pragma once

#include "stdafx.h"
#include "network/l3/l3.h"

#include <netinet/udp.h>

class UdpPacket
{
public:
    // Constructors
    UdpPacket();
    UdpPacket(IpPacket ip_packet_in, udphdr udp_header_in);

    // Properties
    IpPacket GetIpPacket();
    udphdr GetUdpHeader();
    uint16_t GetSourcePort();
    uint16_t GetDestinationPort();
    uint16_t GetLength();
    uint16_t getChecksum();

    // Public Methods
    uint8_t *ToBinary();

private:
    // Private Members
    IpPacket ip_packet;
    udphdr udp_header;
};

