#include "tcppacket.h"


// Constructors
TcpPacket::TcpPacket() {

}

TcpPacket::TcpPacket(IpPacket ip_packet_in, tcphdr tcp_header_in) {
    ip_packet = ip_packet_in;
    tcp_header = tcp_header_in;
}


// Properties
IpPacket TcpPacket::GetIpPacket() {
    return ip_packet;
}

tcphdr TcpPacket::GetTcpHeader() {
    return tcp_header;
}

uint16_t TcpPacket::GetSourcePort() {
    return tcp_header.source;
}

uint16_t TcpPacket::GetDestinationPort() {
    return tcp_header.dest;
}

tcp_seq TcpPacket::GetSequence() {
    return tcp_header.seq;
}

tcp_seq TcpPacket::GetAcknoledgeSequence() {
    return tcp_header.ack_seq;
}

uint8_t TcpPacket::GetOffset() {
    return tcp_header.doff;
}

uint8_t TcpPacket::GetFin() {
    return tcp_header.fin;
}

uint8_t TcpPacket::GetSyn() {
    return tcp_header.syn;
}

uint8_t TcpPacket::GetRst() {
    return tcp_header.rst;
}

uint8_t TcpPacket::GetPsh() {
    return tcp_header.psh;
}

uint8_t TcpPacket::GetAck() {
    return tcp_header.ack;
}

uint8_t TcpPacket::GetUrg() {
    return tcp_header.urg;
}

uint8_t TcpPacket::GetRes2() {
    return tcp_header.res2;
}

uint16_t TcpPacket::GetWindow() {
    return tcp_header.window;
}

uint16_t TcpPacket::GetChecksum() {
    return tcp_header.check;
}

uint16_t TcpPacket::GetUrgentPointer() {
    return tcp_header.urg_ptr;
}

uint8_t *TcpPacket::ToBinary()
{
    return (uint8_t*) this;
}
