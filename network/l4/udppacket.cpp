#include "udppacket.h"


// Constructors
UdpPacket::UdpPacket() {

}

UdpPacket::UdpPacket(IpPacket ip_packet_in, udphdr udp_header_in) {
    ip_packet = ip_packet_in;
    udp_header = udp_header_in;
}


// Properties
IpPacket UdpPacket::GetIpPacket() {
    return ip_packet;
}

udphdr UdpPacket::GetUdpHeader() {
    return udp_header;
}

uint16_t UdpPacket::GetSourcePort() {
    return udp_header.source;
}

uint16_t UdpPacket::GetDestinationPort() {
    return udp_header.dest;
}

uint16_t UdpPacket::GetLength() {
    return udp_header.len;
}

uint16_t UdpPacket::getChecksum() {
    return udp_header.check;
}

uint8_t *UdpPacket::ToBinary()
{
    return (uint8_t*) this;
}
