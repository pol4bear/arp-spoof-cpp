#include "icmppacket.h"


// Constructors
IcmpPacket::IcmpPacket() {

}

IcmpPacket::IcmpPacket(ethhdr ethernet_header_in, icmp icmp_header_in) {
    ethernet_header = ethernet_header_in;
    icmp_header =icmp_header_in;
}


// Properties
ethhdr IcmpPacket::GetEthernetHeader() {
    return ethernet_header;
}

icmp IcmpPacket::GetIcmp() {
    return icmp_header;
}

ether_addr IcmpPacket::GetSourceMac() {
    return ToMac(ethernet_header.h_source);
}

ether_addr IcmpPacket::GetDestinationMac() {
    return ToMac(ethernet_header.h_dest);
}

uint16_t IcmpPacket::GetProtocolType() {
    return ethernet_header.h_proto;
}

uint8_t IcmpPacket::GetIcmpType() {
    return icmp_header.icmp_type;
}

uint8_t IcmpPacket::GetIcmpCode() {
    return icmp_header.icmp_code;
}

uint16_t IcmpPacket::GetIcmpChecksum() {
    return icmp_header.icmp_cksum;
}

uint8_t IcmpPacket::GetIhPptr() {
    return icmp_header.icmp_hun.ih_pptr;
}

in_addr IcmpPacket::GetIhGatewayAddress() {
    return icmp_header.icmp_hun.ih_gwaddr;
}

uint32_t IcmpPacket::GetIhVoid() {
    return icmp_header.icmp_hun.ih_void;
}

uint8_t *IcmpPacket::ToBinary()
{
    return (uint8_t*) this;
}
