#pragma once

#include "stdafx.h"
#include "network/l2/l2.h"

#include <netinet/ip_icmp.h>

class IcmpPacket{
public:
    // Constructors
    IcmpPacket();
    IcmpPacket(ethhdr ehternet_header_in, icmp icmp_in);

    // Properties
    ethhdr GetEthernetHeader();
    icmp GetIcmp();
    ether_addr GetSourceMac();
    ether_addr GetDestinationMac();
    uint16_t GetProtocolType();
    uint8_t GetIcmpType();
    uint8_t GetIcmpCode();
    uint16_t GetIcmpChecksum();
    uint8_t GetIhPptr();
    in_addr GetIhGatewayAddress();
    uint32_t GetIhVoid();

    // Public Methods
    uint8_t *ToBinary();

private:
    // Private Members
    ethhdr ethernet_header;
    icmp icmp_header;
};
