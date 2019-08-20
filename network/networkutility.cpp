#include "networkutility.h"

using namespace std;


// Global Methods
ether_addr ToMac(uint8_t *in) {
    ether_addr* result = reinterpret_cast<ether_addr*>(in);

    return *result;
}

in_addr ToIp(uint32_t in) {
    in_addr result;

    result.s_addr = in;

    return result;
}

in_addr ToIp(uint8_t *in)
{
    uint32_t ip = uint32_t((in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3]);

    return ToIp(ip);
}


// Constructors
LocalAddressParser::LocalAddressParser() {

}


// Public Methods
in_addr LocalAddressParser::GetIp(string interface) {
    libnet_t libnet_object;

    libnet_object.device = const_cast<char*>(interface.c_str());

    return ToIp(libnet_get_ipaddr4(&libnet_object));
}

ether_addr LocalAddressParser::GetMac(string interface) {
    ether_addr *result;
    libnet_t libnet_object;

    libnet_object.device = const_cast<char*>(interface.c_str());

    result = reinterpret_cast<ether_addr*>(libnet_get_hwaddr(&libnet_object));

    return *result;
}
