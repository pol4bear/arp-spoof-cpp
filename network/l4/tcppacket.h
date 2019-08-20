#pragma once

#include "stdafx.h"
#include "network/l3/l3.h"

#include <netinet/tcp.h>

class TcpPacket{
public:
    // Constructors
    TcpPacket();
    TcpPacket(IpPacket ip_packet_in, tcphdr tcp_header_in);

    // Properties
    IpPacket GetIpPacket();
    tcphdr GetTcpHeader();
    uint16_t GetSourcePort();
    uint16_t GetDestinationPort();
    tcp_seq GetSequence();
    tcp_seq GetAcknoledgeSequence();
    uint8_t GetOffset();
    uint8_t GetFin();
    uint8_t GetSyn();
    uint8_t GetRst();
    uint8_t GetPsh();
    uint8_t GetAck();
    uint8_t GetUrg();
    uint8_t GetRes2();
    uint16_t GetWindow();
    uint16_t GetChecksum();
    uint16_t GetUrgentPointer();

    // Public Methods
    uint8_t *ToBinary();

private:
    // Private Members
    IpPacket ip_packet;
    tcphdr tcp_header;
};

