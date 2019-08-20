#include "ippacket.h"


// Constructors
IpPacket::IpPacket() {

}

IpPacket::IpPacket(ethhdr ethernet_header_in, iphdr ip_header_in){
    ethernet_header = ethernet_header_in;
    ip_header = ip_header_in;
}


// Properties
ethhdr IpPacket::GetEthernetHeader() {
    return ethernet_header;
}

iphdr IpPacket::GetIpHeader() {
    return ip_header;
}

ether_addr IpPacket::GetSourceMac() {
    return ToMac(ethernet_header.h_source);
}

ether_addr IpPacket::GetDestinationMac() {
    return ToMac(ethernet_header.h_dest);
}

uint16_t IpPacket::GetProtocolType() {
    return ethernet_header.h_proto;
}

uint32_t IpPacket::GetIhl() {
    return ip_header.ihl;
}

uint32_t IpPacket::GetVersion() {
    return ip_header.version;
}

uint8_t IpPacket::GetTos() {
    return ip_header.tos;
}

uint16_t IpPacket::GetTotLength() {
    return ip_header.tot_len;
}

uint16_t IpPacket::GetId() {
    return ip_header.id;
}

uint16_t IpPacket::GetFragmentOff() {
    return ip_header.frag_off;
}

uint8_t IpPacket::GetTtl() {
    return ip_header.ttl;
}

uint8_t IpPacket::GetProtocol() {
    return ip_header.protocol;
}

uint16_t IpPacket::GetCheck() {
    return ip_header.check;
}

in_addr IpPacket::GetSourceIp() {
    return ToIp(ip_header.saddr);
}

in_addr IpPacket::GetDestinationIp() {
    return ToIp(ip_header.daddr);
}

uint8_t *IpPacket::ToBinary()
{
    return (uint8_t*) this;
}
