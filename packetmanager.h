#pragma once

#include "stdafx.h"

#include <pcap.h>

class PacketManager
{
public:
    // Constructors
    PacketManager();

    // Destructors
    ~PacketManager();

    // Public Methods
    void LoadInterfaces();
    std::vector<std::string> GetInterfaces();
    void SetInterface(std::string interface_in);
    uint8_t *GetPacket(int &packet_size);
    void SendPacket(uint8_t* packet_in, int packet_size);

private:
    // Private Classes
    class ErrorMessages {
    public:
        std::string receive_failed = "Cannot receive packet";
    };

    // Private Members
    ErrorMessages error_messages;
    std::vector<std::string> interfaces;
    std::string interface;
    pcap_t* handle = nullptr;
};
