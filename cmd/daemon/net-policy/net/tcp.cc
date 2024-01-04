
#include <cstdint>
#include <glog/logging.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <boost/endian/conversion.hpp>
#include <utility>

#include "http/connection.h"
#include "http/extension/log.h"
#include "http/filter.h"
#include "http/http_filter_factory.h"
#include "http/packet.hh"
#include "net/filter.h"
#include "net/utility.h"
#include "tcp.h"

namespace net {

std::ostream& operator<<(std::ostream& os, const ConnectionID& conn) {
  os << "connection{ " << ipv4ToString(conn.local_ip) << ":" << conn.local_port << ", "
     << ipv4ToString(conn.foreign_ip) << ":" << conn.foreign_port << " }";
  return os;
}

NetStatus Tcp::Tcb::handlePayload(seastar::net::packet p) {
  auto filsterStatus = http_->processData(std::move(p));
  if (filsterStatus == http::FilterStatus::DropPkt ||
      filsterStatus == http::FilterStatus::StopIteration) {
        VLOG(4) << "drop tcp segment";
    return NetStatus::Drop;
  }
  return NetStatus::OK;
}

NetStatus Tcp::receive(seastar::net::packet p, uint32_t from, uint32_t to) {
  auto th = p.get_header(0, TCP_HDR_LEN);
  VLOG(4) << "receive tcp " << uint64_t(th);

  if (!th) {
    return NetStatus::OK;
  }
  tcphdr* tcpHdr = reinterpret_cast<tcphdr*>(th);
  auto hdrLen = tcpHdr->doff * 4;
  if (hdrLen < TCP_HDR_LEN) {
    return NetStatus::OK;
  }
  VLOG(4) << "tcp payload length: " << (p.len() - hdrLen);

  ConnectionID id{from, to, ntohs(tcpHdr->source), ntohs(tcpHdr->dest)};

  auto tcbIter = tcbs.find(id);
  if (tcbIter == tcbs.end()) {
    if (tcpHdr->rst == 1) {
      return NetStatus::OK;
    }
    if (tcpHdr->syn == 1) {
      auto hashFunc = ConnectionIDHash();
      auto hashId = hashFunc(id);
      auto filterManager = std::make_shared<http::HttpFilterManager>(hashId, from, to);

      net::ConnectionInfo connInfo{net::ipv4ToString(from), net::ipv4ToString(to),
                                   ntohs(tcpHdr->source), ntohs(tcpHdr->dest)};
      if (http::FilterStatus::StopIteration == filterManager->onNewConnection(connInfo)) {
        LOG(INFO) << "terminate connection processing";
        // return;
      }
      auto httpServer = std::make_shared<http::Connection>(true, filterManager);
      auto t = std::make_shared<Tcb>(httpServer);
      t->seq_ = ntohl(tcpHdr->seq) + 1;
      t->seq_ = boost::endian::big_to_native(tcpHdr->seq);
      t->serverSide_ = true;
      tcbs.insert({id, t});
      VLOG(4) << hashId << " new tcp connection: " << id;

      auto httpClient = std::make_shared<http::Connection>(false, filterManager);

      ConnectionID pID{to, from, ntohs(tcpHdr->dest), ntohs(tcpHdr->source)};
      auto t1 = std::make_shared<Tcb>(httpClient);
      tcbs.insert({pID, t1});
      return NetStatus::OK;
    }
    // if (tcpHdr->ack == 1) {
    //   auto t = std::make_shared<Tcb>();
    //   t->seq_ = ntohl(tcpHdr->seq);
    //   t->seq_ = boost::endian::big_to_native(tcpHdr->seq);
    //   t->serverSide_ = false;
    //   tcbs.insert({id, t});
    //   VLOG(4) << "new tcp connection";
    //   return;
    // }

  } else {
    if (tcpHdr->fin == 1) {
      VLOG(4) << "close tcp connection: " << tcbIter->first;
      tcbIter->second->http_->httpFilterManager()->onClose();
      tcbs.erase(tcbIter);

      ConnectionID peerID{to, from, ntohs(tcpHdr->dest), ntohs(tcpHdr->source)};
      tcbs.erase(peerID);
      return NetStatus::OK;
    }
    if ((tcpHdr->ack == 1) && tcpHdr->syn == 1) {
      tcbIter->second->seq_ = boost::endian::big_to_native(tcpHdr->seq);
      tcbIter->second->serverSide_ = false;
      //  tcbIter->second->seq_ = ntohl(tcpHdr->seq);
    }

    tcbIter->second->http_->httpFilterManager()->setTCPSegment(p);

    p.trim_front(hdrLen);

    if (http::FilterStatus::StopIteration ==
        tcbIter->second->http_->httpFilterManager()->onData(p)) {
      return NetStatus::OK;
    }
    return tcbIter->second->handlePayload(std::move(p));
    // return NetStatus::OK;
  }
  return NetStatus::OK;
}

std::ostream& operator<<(std::ostream& os, const Tcp::Tcb& tcb) {
  os << "tcp{" << tcb.seq_ << ", ";
  os << "}";
  return os;
}

} // namespace net