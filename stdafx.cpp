#include "stdafx.h"

// Public Methods
bool IsSame(ether_addr addr1, ether_addr addr2) {
    int result = -1;

    try{
        result = memcmp(addr1.ether_addr_octet, addr2.ether_addr_octet, ETH_ALEN);
    }
    catch(error_t){
        return false;
    }

    if(result) return false;

    return true;
}
