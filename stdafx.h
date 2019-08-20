#pragma once

#include <cstdint>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include <vector>
#include <memory>
#include <functional>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "network/networkutility.h"

// Global Methods
bool IsSame(ether_addr addr1, ether_addr addr2);
