#include "packetmanager.h"

using namespace std;


// Constructors
PacketManager::PacketManager() {
    handle = nullptr;
}

PacketManager::~PacketManager() {
    if(handle != nullptr) pcap_close(handle);
}


// Public Methods
void PacketManager::LoadInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];

    interfaces.clear();

    pcap_if_t *interface;

    if(pcap_findalldevs(&interface, errbuf) == -1) throw runtime_error(errbuf);

    do
    {
        interfaces.push_back(interface->name);
        interface = interface->next;
    } while(interface != NULL);
}

vector<string> PacketManager::GetInterfaces() {
    return interfaces;
}

// Throws runtime_error with error message on fail to open interface
void PacketManager::SetInterface(string interface_in) {
    if(handle != nullptr) pcap_close(handle);

    interface = interface_in;

    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if(handle == nullptr) throw invalid_argument(errbuf);
}

// Throws runtime_error with error message on fail to receive next packet
uint8_t *PacketManager::GetPacket(int &packet_size) {
    pcap_pkthdr* header;
    const uint8_t *packet;

    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) return nullptr;
    if (res == -1 || res == -2) throw runtime_error(error_messages.receive_failed);

    packet_size = header->caplen;

    return const_cast<uint8_t*>(packet);
}

void PacketManager::SendPacket(uint8_t* packet_in, int length) {
    if(handle == nullptr) return;

    pcap_sendpacket(handle, packet_in, length);
}
