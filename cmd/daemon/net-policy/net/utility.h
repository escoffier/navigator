#pragma once

#include "net/filter.h"
#include <string>

namespace net {
std::string ipv4ToString(uint32_t ip);

enum class NetStatus {
    OK,
    Drop
};

}