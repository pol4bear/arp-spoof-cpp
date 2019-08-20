#pragma once

#include "stdafx.h"

#include <netinet/in.h>
#include <netinet/ether.h>
#include <libnet.h>

// Global Methods
ether_addr ToMac(uint8_t* in);
in_addr ToIp(uint32_t in);
in_addr ToIp(uint8_t *in);

class LocalAddressParser{
public:
    // Constructors
    LocalAddressParser();

    // Public Methods
    in_addr GetIp(std::string interface);
    ether_addr GetMac(std::string interface);
};
