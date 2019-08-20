#pragma once

#include "stdafx.h"
#include "packetmanager.h"
#include "network/networkpacket.h"
#include <thread>
#include <map>
#include <list>
#include <ctime>

class Address{
public:
    // Constructors
    Address();
    Address(uint32_t ip_in, ether_addr mac_in);

    // Public Members
    uint32_t ip;
    ether_addr mac;

    // Operation overload
    bool operator == (const Address& s);
    bool operator != (const Address& s);

};

class SpoofInfo{
public:
    // Constructors
    SpoofInfo(bool relay_in=true);
    SpoofInfo(Address *sender_in, Address *target_in, bool relay_in = true);

    // Public Members
    Address *sender;
    Address *target;

    // Flags
    bool relay;

    // Operation overload
    bool operator == (const SpoofInfo& s);
    bool operator != (const SpoofInfo& s);
};

class ArpSpoofer{
public:
    // Constructors
    ArpSpoofer();
    ArpSpoofer(std::function<void(void)> function_in);

    // Callbacks
    void SetOnScanFinished(std::function<void(void)> function_in);

    // Properties
    std::vector<std::string> GetInterfaces();
    bool IsStarted();
    void SetInterface(std::string interface_in);
    void AddSpoofRule(uint32_t sender_ip, uint32_t target_ip, bool relay, bool is_duplex);
    void RemoveSpoofRule(uint32_t sender_ip, uint32_t target_ip, bool is_duplex = false);

    // Public Methods
    void LoadInterfaces();
    void Start();
    void Stop();
    void Scan(std::vector<uint32_t> scan_hosts_in);

private:   
    // Private Classes
    class ErrorMessages {
    public:
        std::string HostNotFound(std::string host_name) { return "Cannot find " + host_name; }
    };

    // Private Members
    ErrorMessages error_messages;
    LocalAddressParser local_address_parser;
    PacketManager packet_manager;
    in_addr local_ip;
    ether_addr local_mac;
    std::list<uint32_t> scan_hosts;
    std::list<uint32_t> scan_failed;
    std::list<Address> hosts;
    std::list<SpoofInfo> rules;

    // Threads
    std::thread listen_thread;
    std::thread scan_thread;

    // Flags
    bool started;

    // Thread Actions
    void ListenAction();
    void ScanAction();
    void GetMac(uint32_t ip);


    // Private Methods
    bool IsInScanList(uint32_t ip_in);
    Address *FindHost(uint32_t ip);
    SpoofInfo *IsInSpoofList(ether_addr sender_mac_in, in_addr target_ip_in);
    SpoofInfo *IsInSpoofList(ether_addr sender_mac_in);
    SpoofInfo *IsInSpoofList(Address sender, Address target);
    void ArpRequest(uint32_t ip);
    void SendMaliciousResponse(Address sender_in, in_addr target_ip_in);
    void RelayPacket(uint8_t *packet_in, int packet_length, ether_addr dest_mac_in);

    // Callback Methods
    std::function<void(void)> on_scan_finished;
};
