#pragma once

#include <cstdint>

#include "http/packet.hh"
#include "common/pure.h"
#include "net/utility.h"

namespace net {
class IPProtocol {
public:
  virtual NetStatus receive(seastar::net::packet packet, uint32_t from, uint32_t to) PURE;

  virtual NetworkStat stat() PURE;

  virtual ~IPProtocol() = default;
};
} // namespace net