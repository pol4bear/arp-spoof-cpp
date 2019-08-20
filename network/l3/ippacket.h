#pragma once

#include "stdafx.h"
#include "network/l2/l2.h"

#include <netinet/ip.h>

class IpPacket{
public:
    // Constructors
    IpPacket();
    IpPacket(ethhdr ethernet_header_in, iphdr ip_header_in);

    // Properties
    ethhdr GetEthernetHeader();
    iphdr GetIpHeader();
    ether_addr GetSourceMac();
    ether_addr GetDestinationMac();
    uint16_t GetProtocolType();
    uint32_t GetIhl();
    uint32_t GetVersion();
    uint8_t GetTos();
    uint16_t GetTotLength();
    uint16_t GetId();
    uint16_t GetFragmentOff();
    uint8_t GetTtl();
    uint8_t GetProtocol();
    uint16_t GetCheck();
    in_addr GetSourceIp();
    in_addr GetDestinationIp();

    // Public Methods
    uint8_t *ToBinary();

private:
    // Private Members
    ethhdr ethernet_header;
    iphdr ip_header;
};
