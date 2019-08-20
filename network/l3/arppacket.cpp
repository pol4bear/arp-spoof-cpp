#include "network/l3/arppacket.h"


// Constructors
ArpPacket::ArpPacket() {

}

ArpPacket::ArpPacket(ethhdr ethernet_header_in, ether_arp arp_header_in) {
    ethernet_header = ethernet_header_in;
    arp_header = arp_header_in;
}


// Properties
ethhdr ArpPacket::GetEthernetHeader() {
    return ethernet_header;
}

ether_arp ArpPacket::GetArpHeader() {
    return arp_header;
}

ether_addr ArpPacket::GetSourceMac() {
    ether_addr* result = reinterpret_cast<ether_addr*>(ethernet_header.h_source);

    return *result;
}

ether_addr ArpPacket::GetDestinationMac() {
    ether_addr* result = reinterpret_cast<ether_addr*>(ethernet_header.h_dest);

    return *result;
}

uint16_t ArpPacket::GetProtocolType() {
    return ethernet_header.h_proto;
}

uint16_t ArpPacket::GetMacFormat() {
    return arp_header.ea_hdr.ar_hrd;
}

uint16_t ArpPacket::GetIpFormat() {
    return arp_header.ea_hdr.ar_pro;
}

uint8_t ArpPacket::GetMacLength() {
    return arp_header.ea_hdr.ar_hln;
}

uint8_t ArpPacket::GetIpLength() {
    return arp_header.ea_hdr.ar_pln;
}

uint16_t ArpPacket::GetOpcode() {
    return arp_header.ea_hdr.ar_op;
}

ether_addr ArpPacket::GetSenderMac()
{
    ether_addr* result = reinterpret_cast<ether_addr*>(arp_header.arp_sha);

    return *result;
}

in_addr ArpPacket::GetSenderIp()
{
    in_addr* result = reinterpret_cast<in_addr*>(arp_header.arp_spa);

    return *result;
}

ether_addr ArpPacket::GetTargetMac()
{
    ether_addr* result = reinterpret_cast<ether_addr*>(arp_header.arp_tha);

    return *result;
}

in_addr ArpPacket::GetTargetIp()
{
    in_addr* result = reinterpret_cast<in_addr*>(arp_header.arp_tpa);

    return *result;
}

uint8_t *ArpPacket::ToBinary()
{
    return (uint8_t*) this;
}
