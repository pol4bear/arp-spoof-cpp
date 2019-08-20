#pragma once

#include "stdafx.h"
#include "network/l2/l2.h"

#include <netinet/if_ether.h>

class ArpPacket{
public:
    // Constructors
    ArpPacket();
    ArpPacket(ethhdr ethernet_header_in, ether_arp arp_header_in);

    // Properties
    ethhdr GetEthernetHeader();
    ether_arp GetArpHeader();
    ether_addr GetSourceMac();
    ether_addr GetDestinationMac();
    uint16_t GetProtocolType();
    uint16_t GetMacFormat();
    uint16_t GetIpFormat();
    uint8_t GetMacLength();
    uint8_t GetIpLength();
    uint16_t GetOpcode();
    ether_addr GetSenderMac();
    in_addr GetSenderIp();
    ether_addr GetTargetMac();
    in_addr GetTargetIp();

    // Public Methods
    uint8_t *ToBinary();

private:
    // Private Members
    ethhdr ethernet_header;
    ether_arp arp_header;
};
