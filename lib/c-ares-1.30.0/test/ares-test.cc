/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_setup.h"
#include "ares.h"
#include "ares_nameser.h"
#include "ares-test.h"
#include "ares-test-ai.h"
#include "dns-proto.h"
#include "ares_dns.h"

extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ares_setup.h"
#include "ares_inet_net_pton.h"
#include "ares_data.h"
#include "ares_strsplit.h"
#include "ares_private.h"
}


#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <functional>
#include <sstream>

#ifdef WIN32
#define BYTE_CAST (char *)
#define mkdir_(d, p) mkdir(d)
#else
#define BYTE_CAST
#define mkdir_(d, p) mkdir(d, p)
#endif

namespace ares {
namespace test {

bool verbose = false;
static constexpr unsigned short dynamic_port = 0;
unsigned short mock_port = dynamic_port;

const std::vector<int> both_families = {AF_INET, AF_INET6};
const std::vector<int> ipv4_family = {AF_INET};
const std::vector<int> ipv6_family = {AF_INET6};

const std::vector<std::pair<int, bool>> both_families_both_modes = {
  std::make_pair<int, bool>(AF_INET, false),
  std::make_pair<int, bool>(AF_INET, true),
  std::make_pair<int, bool>(AF_INET6, false),
  std::make_pair<int, bool>(AF_INET6, true)
};
const std::vector<std::pair<int, bool>> ipv4_family_both_modes = {
  std::make_pair<int, bool>(AF_INET, false),
  std::make_pair<int, bool>(AF_INET, true)
};
const std::vector<std::pair<int, bool>> ipv6_family_both_modes = {
  std::make_pair<int, bool>(AF_INET6, false),
  std::make_pair<int, bool>(AF_INET6, true)
};


const std::vector<std::tuple<ares_evsys_t, int, bool>> all_evsys_ipv4_family_both_modes = {
#ifdef _WIN32
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET, true),
#endif
#ifdef HAVE_KQUEUE
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET, true),
#endif
#ifdef HAVE_EPOLL
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET, true),
#endif
#ifdef HAVE_POLL
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET, true),
#endif
#ifdef HAVE_PIPE
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET, true),
#endif
};

const std::vector<std::tuple<ares_evsys_t, int, bool>> all_evsys_ipv6_family_both_modes = {
#ifdef _WIN32
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET6, true),
#endif
#ifdef HAVE_KQUEUE
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET6, true),
#endif
#ifdef HAVE_EPOLL
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET6, true),
#endif
#ifdef HAVE_POLL
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET6, true),
#endif
#ifdef HAVE_PIPE
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET6, true),
#endif
};

const std::vector<std::tuple<ares_evsys_t, int, bool>> all_evsys_both_families_both_modes = {
#ifdef _WIN32
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET, true),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_WIN32, AF_INET6, true),
#endif
#ifdef HAVE_KQUEUE
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET, true),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_KQUEUE, AF_INET6, true),
#endif
#ifdef HAVE_EPOLL
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET, true),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_EPOLL, AF_INET6, true),
#endif
#ifdef HAVE_POLL
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET, true),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_POLL, AF_INET6, true),
#endif
#ifdef HAVE_PIPE
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET, true),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET6, false),
  std::make_tuple<ares_evsys_t, int, bool>(ARES_EVSYS_SELECT, AF_INET6, true),
#endif
};


std::vector<std::tuple<ares_evsys_t, int, bool>> evsys_families_modes = all_evsys_both_families_both_modes;


const std::vector<std::tuple<ares_evsys_t, int>> all_evsys_ipv4_family = {
#ifdef _WIN32
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_WIN32, AF_INET),
#endif
#ifdef HAVE_KQUEUE
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_KQUEUE, AF_INET),
#endif
#ifdef HAVE_EPOLL
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_EPOLL, AF_INET),
#endif
#ifdef HAVE_POLL
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_POLL, AF_INET),
#endif
#ifdef HAVE_PIPE
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_SELECT, AF_INET),
#endif
};

const std::vector<std::tuple<ares_evsys_t, int>> all_evsys_ipv6_family = {
#ifdef _WIN32
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_WIN32, AF_INET6),
#endif
#ifdef HAVE_KQUEUE
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_KQUEUE, AF_INET6),
#endif
#ifdef HAVE_EPOLL
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_EPOLL, AF_INET6),
#endif
#ifdef HAVE_POLL
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_POLL, AF_INET6),
#endif
#ifdef HAVE_PIPE
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_SELECT, AF_INET6),
#endif
};

const std::vector<std::tuple<ares_evsys_t, int>> all_evsys_both_families = {
#ifdef _WIN32
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_WIN32, AF_INET),
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_WIN32, AF_INET6),
#endif
#ifdef HAVE_KQUEUE
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_KQUEUE, AF_INET),
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_KQUEUE, AF_INET6),
#endif
#ifdef HAVE_EPOLL
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_EPOLL, AF_INET),
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_EPOLL, AF_INET6),
#endif
#ifdef HAVE_POLL
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_POLL, AF_INET),
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_POLL, AF_INET6),
#endif
#ifdef HAVE_PIPE
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_SELECT, AF_INET),
  std::make_tuple<ares_evsys_t, int>(ARES_EVSYS_SELECT, AF_INET6),
#endif
};



std::vector<std::tuple<ares_evsys_t, int>> evsys_families = all_evsys_both_families;


// Which parameters to use in tests
std::vector<int> families = both_families;
std::vector<std::pair<int, bool>> families_modes = both_families_both_modes;

unsigned long long LibraryTest::fails_ = 0;
std::map<size_t, int> LibraryTest::size_fails_;
std::mutex            LibraryTest::lock_;

void ProcessWork(ares_channel_t *channel,
                 std::function<std::set<ares_socket_t>()> get_extrafds,
                 std::function<void(ares_socket_t)> process_extra,
                 unsigned int cancel_ms) {
  int nfds, count;
  fd_set readers, writers;

#ifndef CARES_SYMBOL_HIDING
  ares_timeval_t tv_begin  = ares__tvnow();
  ares_timeval_t tv_cancel = tv_begin;

  if (cancel_ms) {
    if (verbose) std::cerr << "ares_cancel will be called after " << cancel_ms << "ms" << std::endl;
    tv_cancel.sec  += (cancel_ms / 1000);
    tv_cancel.usec += ((cancel_ms % 1000) * 1000);
  }
#else
  if (cancel_ms) {
    std::cerr << "library built with symbol hiding, can't test with cancel support" << std::endl;
    return;
  }
#endif

  while (true) {
#ifndef CARES_SYMBOL_HIDING
    ares_timeval_t  tv_now = ares__tvnow();
    ares_timeval_t  atv_remaining;
#endif
    struct timeval  tv;
    struct timeval *tv_select;

    // Retrieve the set of file descriptors that the library wants us to monitor.
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    nfds = ares_fds(channel, &readers, &writers);
    if (nfds == 0)  // no work left to do in the library
      return;

    // Add in the extra FDs if present.
    std::set<ares_socket_t> extrafds = get_extrafds();
    for (ares_socket_t extrafd : extrafds) {
      FD_SET(extrafd, &readers);
      if (extrafd >= (ares_socket_t)nfds) {
        nfds = (int)extrafd + 1;
      }
    }

    /* If ares_timeout returns NULL, it means there are no requests in queue,
     * so we can break out */
    tv_select = ares_timeout(channel, NULL, &tv);
    if (tv_select == NULL)
      return;

#ifndef CARES_SYMBOL_HIDING
    if (cancel_ms) {
      unsigned int remaining_ms;
      ares__timeval_remaining(&atv_remaining,
                              &tv_now,
                              &tv_cancel);

      remaining_ms = (unsigned int)((atv_remaining.sec * 1000) + (atv_remaining.usec / 1000));
      if (remaining_ms == 0) {
        if (verbose) std::cerr << "Issuing ares_cancel()" << std::endl;
        ares_cancel(channel);
        cancel_ms = 0; /* Disable issuing cancel again */
      } else {
        struct timeval tv_remaining;

        tv_remaining.tv_sec = atv_remaining.sec;
        tv_remaining.tv_usec = (int)atv_remaining.usec;

        /* Recalculate proper timeout since we also have a cancel to wait on */
        tv_select = ares_timeout(channel, &tv_remaining, &tv);
      }
    }
#endif

    count = select(nfds, &readers, &writers, nullptr, tv_select);
    if (count < 0) {
      fprintf(stderr, "select() failed, errno %d\n", errno);
      return;
    }

    // Let the library process any activity.
    ares_process(channel, &readers, &writers);

    // Let the provided callback process any activity on the extra FD.
    for (ares_socket_t extrafd : extrafds) {
      if (FD_ISSET(extrafd, &readers)) {
        process_extra(extrafd);
      }
    }
  }
}


// static
void LibraryTest::SetAllocFail(int nth) {
  lock_.lock();
  assert(nth > 0);
  assert(nth <= (int)(8 * sizeof(fails_)));
  fails_ |= (1LL << (nth - 1));
  lock_.unlock();
}

// static
void LibraryTest::SetAllocSizeFail(size_t size) {
  lock_.lock();
  size_fails_[size]++;
  lock_.unlock();
}

// static
void LibraryTest::ClearFails() {
  lock_.lock();
  fails_ = 0;
  size_fails_.clear();
  lock_.unlock();
}


// static
bool LibraryTest::ShouldAllocFail(size_t size) {
  lock_.lock();
  bool fail = (fails_ & 0x01);
  fails_ >>= 1;
  if (size_fails_[size] > 0) {
    size_fails_[size]--;
    fail = true;
  }
  lock_.unlock();
  return fail;
}

// static
void* LibraryTest::amalloc(size_t size) {
  if (ShouldAllocFail(size) || size == 0) {
    if (verbose) std::cerr << "Failing malloc(" << size << ") request" << std::endl;
    return nullptr;
  } else {
    return malloc(size);
  }
}

// static
void* LibraryTest::arealloc(void *ptr, size_t size) {
  if (ShouldAllocFail(size)) {
    if (verbose) std::cerr << "Failing realloc(" << ptr << ", " << size << ") request" << std::endl;
    return nullptr;
  } else {
    return realloc(ptr, size);
  }
}

// static
void LibraryTest::afree(void *ptr) {
  free(ptr);
}

std::set<ares_socket_t> NoExtraFDs() {
  return std::set<ares_socket_t>();
}

void DefaultChannelTest::Process(unsigned int cancel_ms) {
  ProcessWork(channel_, NoExtraFDs, nullptr, cancel_ms);
}

void FileChannelTest::Process(unsigned int cancel_ms) {
  ProcessWork(channel_, NoExtraFDs, nullptr, cancel_ms);
}

void DefaultChannelModeTest::Process(unsigned int cancel_ms) {
  ProcessWork(channel_, NoExtraFDs, nullptr, cancel_ms);
}

MockServer::MockServer(int family, unsigned short port)
  : udpport_(port), tcpport_(port), qid_(-1) {
  // Create a TCP socket to receive data on.
  tcp_data_ = NULL;
  tcp_data_len_ = 0;
  tcpfd_ = socket(family, SOCK_STREAM, 0);
  EXPECT_NE(ARES_SOCKET_BAD, tcpfd_);
  int optval = 1;
  setsockopt(tcpfd_, SOL_SOCKET, SO_REUSEADDR,
             BYTE_CAST &optval , sizeof(int));
  // Send TCP data right away.
  setsockopt(tcpfd_, IPPROTO_TCP, TCP_NODELAY,
             BYTE_CAST &optval , sizeof(int));

  // Create a UDP socket to receive data on.
  udpfd_ = socket(family, SOCK_DGRAM, 0);
  EXPECT_NE(ARES_SOCKET_BAD, udpfd_);

  // Bind the sockets to the given port.
  if (family == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(tcpport_);
    int tcprc = bind(tcpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, tcprc) << "Failed to bind AF_INET to TCP port " << tcpport_;
    addr.sin_port = htons(udpport_);
    int udprc = bind(udpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, udprc) << "Failed to bind AF_INET to UDP port " << udpport_;
    // retrieve system-assigned port
    if (udpport_ == dynamic_port) {
      ares_socklen_t len = sizeof(addr);
      auto result = getsockname(udpfd_, (struct sockaddr*)&addr, &len);
      EXPECT_EQ(0, result);
      udpport_ = ntohs(addr.sin_port);
      EXPECT_NE(dynamic_port, udpport_);
    }
    if (tcpport_ == dynamic_port) {
      ares_socklen_t len = sizeof(addr);
      auto result = getsockname(tcpfd_, (struct sockaddr*)&addr, &len);
      EXPECT_EQ(0, result);
      tcpport_ = ntohs(addr.sin_port);
      EXPECT_NE(dynamic_port, tcpport_);
    }
  } else {
    EXPECT_EQ(AF_INET6, family);
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    memset(&addr.sin6_addr, 0, sizeof(addr.sin6_addr));  // in6addr_any
    addr.sin6_port = htons(tcpport_);
    int tcprc = bind(tcpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, tcprc) << "Failed to bind AF_INET6 to TCP port " << tcpport_;
    addr.sin6_port = htons(udpport_);
    int udprc = bind(udpfd_, (struct sockaddr*)&addr, sizeof(addr));
    EXPECT_EQ(0, udprc) << "Failed to bind AF_INET6 to UDP port " << udpport_;
    // retrieve system-assigned port
    if (udpport_ == dynamic_port) {
      ares_socklen_t len = sizeof(addr);
      auto result = getsockname(udpfd_, (struct sockaddr*)&addr, &len);
      EXPECT_EQ(0, result);
      udpport_ = ntohs(addr.sin6_port);
      EXPECT_NE(dynamic_port, udpport_);
    }
    if (tcpport_ == dynamic_port) {
      ares_socklen_t len = sizeof(addr);
      auto result = getsockname(tcpfd_, (struct sockaddr*)&addr, &len);
      EXPECT_EQ(0, result);
      tcpport_ = ntohs(addr.sin6_port);
      EXPECT_NE(dynamic_port, tcpport_);
    }
  }
  if (verbose) std::cerr << "Configured "
                         << (family == AF_INET ? "IPv4" : "IPv6")
                         << " mock server with TCP socket " << tcpfd_
                         << " on port " << tcpport_
                         << " and UDP socket " << udpfd_
                         << " on port " << udpport_ << std::endl;

  // For TCP, also need to listen for connections.
  EXPECT_EQ(0, listen(tcpfd_, 5)) << "Failed to listen for TCP connections";
}

MockServer::~MockServer() {
  for (ares_socket_t fd : connfds_) {
    sclose(fd);
  }
  sclose(tcpfd_);
  sclose(udpfd_);
  free(tcp_data_);
}

static unsigned short getaddrport(struct sockaddr_storage *addr)
{
  if (addr->ss_family == AF_INET)
    return ntohs(((struct sockaddr_in *)(void *)addr)->sin_port);

  return ntohs(((struct sockaddr_in6 *)(void *)addr)->sin6_port);
}

void MockServer::ProcessPacket(ares_socket_t fd, struct sockaddr_storage *addr, ares_socklen_t addrlen,
                               byte *data, int len) {

  // Assume the packet is a well-formed DNS request and extract the request
  // details.
  if (len < NS_HFIXEDSZ) {
    std::cerr << "Packet too short (" << len << ")" << std::endl;
    return;
  }
  int qid = DNS_HEADER_QID(data);
  if (DNS_HEADER_QR(data) != 0) {
    std::cerr << "Not a request" << std::endl;
    return;
  }
  if (DNS_HEADER_OPCODE(data) != O_QUERY) {
    std::cerr << "Not a query (opcode " << DNS_HEADER_OPCODE(data)
              << ")" << std::endl;
    return;
  }
  if (DNS_HEADER_QDCOUNT(data) != 1) {
    std::cerr << "Unexpected question count (" << DNS_HEADER_QDCOUNT(data)
              << ")" << std::endl;
    return;
  }
  byte* question = data + NS_HFIXEDSZ;
  int qlen = len - NS_HFIXEDSZ;

  char *name = nullptr;
  long enclen;
  ares_expand_name(question, data, len, &name, &enclen);
  if (!name) {
    std::cerr << "Failed to retrieve name" << std::endl;
    return;
  }
  if (enclen > qlen) {
    std::cerr << "(error, encoded name len " << enclen << "bigger than remaining data " << qlen << " bytes)" << std::endl;
    return;
  }
  qlen -= (int)enclen;
  question += enclen;
  std::string namestr(name);
  ares_free_string(name);

  if (qlen < 4) {
    std::cerr << "Unexpected question size (" << qlen
              << " bytes after name)" << std::endl;
    return;
  }
  if (DNS_QUESTION_CLASS(question) != C_IN) {
    std::cerr << "Unexpected question class (" << DNS_QUESTION_CLASS(question)
              << ")" << std::endl;
    return;
  }
  int rrtype = DNS_QUESTION_TYPE(question);

  std::vector<byte> req(data, data + len);
  std::string reqstr = PacketToString(req);
  if (verbose) {
    std::cerr << "received " << (fd == udpfd_ ? "UDP" : "TCP") << " request " << reqstr
              << " on port " << (fd == udpfd_ ? udpport_ : tcpport_)
              << ":" << getaddrport(addr) << std::endl;
    std::cerr << "ProcessRequest(" << qid << ", '" << namestr
              << "', " << RRTypeToString(rrtype) << ")" << std::endl;
  }
  ProcessRequest(fd, addr, addrlen, reqstr, qid, namestr, rrtype);

}

void MockServer::ProcessFD(ares_socket_t fd) {
  if (fd != tcpfd_ && fd != udpfd_ && connfds_.find(fd) == connfds_.end()) {
    // Not one of our FDs.
    return;
  }
  if (fd == tcpfd_) {
    ares_socket_t connfd = accept(tcpfd_, NULL, NULL);
    if (connfd < 0) {
      std::cerr << "Error accepting connection on fd " << fd << std::endl;
    } else {
      connfds_.insert(connfd);
    }
    return;
  }

  // Activity on a data-bearing file descriptor.
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  byte buffer[2048];
  ares_ssize_t len = (ares_ssize_t)recvfrom(fd, BYTE_CAST buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&addr, &addrlen);

  if (fd != udpfd_) {
    if (len <= 0) {
      connfds_.erase(std::find(connfds_.begin(), connfds_.end(), fd));
      sclose(fd);
      free(tcp_data_);
      tcp_data_ = NULL;
      tcp_data_len_ = 0;
      return;
    }
    tcp_data_ = (unsigned char *)realloc(tcp_data_, tcp_data_len_ + (size_t)len);
    memcpy(tcp_data_ + tcp_data_len_, buffer, (size_t)len);
    tcp_data_len_ += (size_t)len;

    /* TCP might aggregate the various requests into a single packet, so we
     * need to split */
    while (tcp_data_len_ > 2) {
      size_t tcplen = ((size_t)tcp_data_[0] << 8) + (size_t)tcp_data_[1];
      if (tcp_data_len_ - 2 < tcplen)
        break;

      ProcessPacket(fd, &addr, addrlen, tcp_data_ + 2, (int)tcplen);

      /* strip off processed data if connection not terminated */
      if (tcp_data_ != NULL) {
        memmove(tcp_data_, tcp_data_ + tcplen + 2, tcp_data_len_ - 2 - tcplen);
        tcp_data_len_ -= 2 + tcplen;
      }
    }
  } else {
    /* UDP is always a single packet */
    ProcessPacket(fd, &addr, addrlen, buffer, (int)len);
  }

}

std::set<ares_socket_t> MockServer::fds() const {
  std::set<ares_socket_t> result = connfds_;
  result.insert(tcpfd_);
  result.insert(udpfd_);
  return result;
}


void MockServer::ProcessRequest(ares_socket_t fd, struct sockaddr_storage* addr,
                                ares_socklen_t addrlen, const std::string &reqstr,
                                int qid, const std::string& name, int rrtype) {
  // Before processing, let gMock know the request is happening.
  OnRequest(name, rrtype);

  // If we are expecting a specific request then check it matches here.
  if (expected_request_.length() > 0) {
    ASSERT_EQ(expected_request_, reqstr);
  }

  if (reply_.size() == 0) {
    return;
  }

  // Make a local copy of the current pending reply.
  std::vector<byte> reply = reply_;

  if (qid_ >= 0) {
    // Use the explicitly specified query ID.
    qid = qid_;
  }
  if (reply.size() >=  2) {
    // Overwrite the query ID if space to do so.
    reply[0] = (byte)((qid >> 8) & 0xff);
    reply[1] = (byte)(qid & 0xff);
  }
  if (verbose) {
    std::cerr << "sending reply " << PacketToString(reply)
              << " on port " << ((fd == udpfd_) ? udpport_ : tcpport_)
              << ":" << getaddrport(addr) << std::endl;
  }

  // Prefix with 2-byte length if TCP.
  if (fd != udpfd_) {
    int len = (int)reply.size();
    std::vector<byte> vlen = {(byte)((len & 0xFF00) >> 8), (byte)(len & 0xFF)};
    reply.insert(reply.begin(), vlen.begin(), vlen.end());
    // Also, don't bother with the destination address.
    addr = nullptr;
    addrlen = 0;
  }

  ares_ssize_t rc = (ares_ssize_t)sendto(fd, BYTE_CAST reply.data(), (SEND_TYPE_ARG3)reply.size(), 0,
                  (struct sockaddr *)addr, addrlen);
  if (rc < static_cast<ares_ssize_t>(reply.size())) {
    std::cerr << "Failed to send full reply, rc=" << rc << std::endl;
  }
}

// static
MockChannelOptsTest::NiceMockServers MockChannelOptsTest::BuildServers(int count, int family, unsigned short base_port) {
  NiceMockServers servers;
  assert(count > 0);
  for (unsigned short ii = 0; ii < count; ii++) {
    unsigned short port = base_port == dynamic_port ? dynamic_port : base_port + ii;
    std::unique_ptr<NiceMockServer> server(new NiceMockServer(family, port));
    servers.push_back(std::move(server));
  }
  return servers;
}

MockChannelOptsTest::MockChannelOptsTest(int count,
                                         int family,
                                         bool force_tcp,
                                         struct ares_options* givenopts,
                                         int optmask)
  : servers_(BuildServers(count, family, mock_port)),
    server_(*servers_[0].get()), channel_(nullptr) {
  // Set up channel options.
  struct ares_options opts;
  if (givenopts) {
    memcpy(&opts, givenopts, sizeof(opts));
  } else {
    memset(&opts, 0, sizeof(opts));
  }

  // Point the library at the first mock server by default (overridden below).
  opts.udp_port = server_.udpport();
  optmask |= ARES_OPT_UDP_PORT;
  opts.tcp_port = server_.tcpport();
  optmask |= ARES_OPT_TCP_PORT;

  if (!(optmask & (ARES_OPT_TIMEOUTMS|ARES_OPT_TIMEOUT))) {
    // Reduce timeouts significantly to shorten test times.
    opts.timeout = 250;
    optmask |= ARES_OPT_TIMEOUTMS;
  }
  // If not already overridden, set 3 retries.
  if (!(optmask & ARES_OPT_TRIES)) {
    opts.tries = 3;
    optmask |= ARES_OPT_TRIES;
  }
  // If not already overridden, set search domains.
  const char *domains[3] = {"first.com", "second.org", "third.gov"};
  if (!(optmask & ARES_OPT_DOMAINS)) {
    opts.ndomains = 3;
    opts.domains = (char**)domains;
    optmask |= ARES_OPT_DOMAINS;
  }
  if (force_tcp) {
    opts.flags |= ARES_FLAG_USEVC;
    optmask |= ARES_OPT_FLAGS;
  }

  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel_, &opts, optmask));
  EXPECT_NE(nullptr, channel_);

  // Set up servers after construction so we can set individual ports
  struct ares_addr_port_node* prev = nullptr;
  struct ares_addr_port_node* first = nullptr;
  for (const auto& server : servers_) {
    struct ares_addr_port_node* node = (struct ares_addr_port_node*)malloc(sizeof(*node));
    if (prev) {
      prev->next = node;
    } else {
      first = node;
    }
    node->next = nullptr;
    node->family = family;
    node->udp_port = server->udpport();
    node->tcp_port = server->tcpport();
    if (family == AF_INET) {
      node->addr.addr4.s_addr = htonl(0x7F000001);
    } else {
      memset(&node->addr.addr6, 0, sizeof(node->addr.addr6));
      node->addr.addr6._S6_un._S6_u8[15] = 1;
    }
    prev = node;
  }
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_ports(channel_, first));

  while (first) {
    prev = first;
    first = first->next;
    free(prev);
  }
  if (verbose) {
    std::cerr << "Configured library with servers:";
    std::cerr << GetNameServers(channel_);
    std::cerr << std::endl;
  }
}

MockChannelOptsTest::~MockChannelOptsTest() {
  if (channel_) {
    ares_destroy(channel_);
  }
  channel_ = nullptr;
}

std::set<ares_socket_t> MockChannelOptsTest::fds() const {
  std::set<ares_socket_t> fds;
  for (const auto& server : servers_) {
    std::set<ares_socket_t> serverfds = server->fds();
    fds.insert(serverfds.begin(), serverfds.end());
  }
  return fds;
}

void MockChannelOptsTest::ProcessFD(ares_socket_t fd) {
  for (auto& server : servers_) {
    server->ProcessFD(fd);
  }
}

void MockChannelOptsTest::Process(unsigned int cancel_ms) {
  using namespace std::placeholders;
  ProcessWork(channel_,
              std::bind(&MockChannelOptsTest::fds, this),
              std::bind(&MockChannelOptsTest::ProcessFD, this, _1),
              cancel_ms);
}

void MockEventThreadOptsTest::ProcessThread() {
  std::set<ares_socket_t> fds;

#ifndef CARES_SYMBOL_HIDING
  bool has_cancel_ms = false;
  ares_timeval_t tv_begin;
  ares_timeval_t tv_cancel;
#endif

  mutex.lock();

  while (isup) {
    int nfds = 0;
    fd_set readers;
#ifndef CARES_SYMBOL_HIDING
    ares_timeval_t tv_now = ares__tvnow();
    ares_timeval_t atv_remaining;
    if (cancel_ms_ && !has_cancel_ms) {
      tv_begin  = ares__tvnow();
      tv_cancel = tv_begin;
      if (verbose) std::cerr << "ares_cancel will be called after " << cancel_ms_ << "ms" << std::endl;
      tv_cancel.sec  += (cancel_ms_ / 1000);
      tv_cancel.usec += ((cancel_ms_ % 1000) * 1000);
      has_cancel_ms = true;
    }
#else
    if (cancel_ms_) {
      std::cerr << "library built with symbol hiding, can't test with cancel support" << std::endl;
      return;
    }
#endif
    struct timeval  tv;

    /* c-ares is using its own event thread, so we only need to monitor the
     * extrafds passed in */
    FD_ZERO(&readers);
    fds = MockEventThreadOptsTest::fds();
    for (ares_socket_t fd : fds) {
      FD_SET(fd, &readers);
      if (fd >= (ares_socket_t)nfds) {
        nfds = (int)fd + 1;
      }
    }

#ifndef CARES_SYMBOL_HIDING
    if (has_cancel_ms) {
      unsigned int remaining_ms;
      ares__timeval_remaining(&atv_remaining,
                              &tv_now,
                              &tv_cancel);
      remaining_ms = (unsigned int)((atv_remaining.sec * 1000) + (atv_remaining.usec / 1000));
      if (remaining_ms == 0) {
        if (verbose) std::cerr << "Issuing ares_cancel()" << std::endl;
        ares_cancel(channel_);
        cancel_ms_ = 0; /* Disable issuing cancel again */
        has_cancel_ms = false;
      }
    }
#endif

    /* We just always wait 20ms then recheck. Not doing any complex signaling. */
    tv.tv_sec  = 0;
    tv.tv_usec = 20000;

    mutex.unlock();
    if (select(nfds, &readers, nullptr, nullptr, &tv) < 0) {
      fprintf(stderr, "select() failed, errno %d\n", errno);
      return;
    }

    // Let the provided callback process any activity on the extra FD.
    for (ares_socket_t fd : fds) {
      if (FD_ISSET(fd, &readers)) {
        ProcessFD(fd);
      }
    }
    mutex.lock();
  }
  mutex.unlock();

}

std::ostream& operator<<(std::ostream& os, const HostResult& result) {
  os << '{';
  if (result.done_) {
    os << StatusToString(result.status_);
    if (result.host_.addrtype_ != -1) {
      os << " " << result.host_;
    } else {
      os << ", (no hostent)";
    }
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

HostEnt::HostEnt(const struct hostent *hostent) : addrtype_(-1) {
  if (!hostent)
    return;

  if (hostent->h_name)
    name_ = hostent->h_name;

  if (hostent->h_aliases) {
    char** palias = hostent->h_aliases;
    while (*palias != nullptr) {
      aliases_.push_back(*palias);
      palias++;
    }
  }

  addrtype_ = hostent->h_addrtype;

  if (hostent->h_addr_list) {
    char** paddr = hostent->h_addr_list;
    while (*paddr != nullptr) {
      std::string addr = AddressToString(*paddr, hostent->h_length);
      addrs_.push_back(addr);
      paddr++;
    }
  }
}

std::ostream& operator<<(std::ostream& os, const HostEnt& host) {
  os << "{'";
  if (host.name_.length() > 0) {
    os << host.name_;
  }
  os << "' aliases=[";
  for (size_t ii = 0; ii < host.aliases_.size(); ii++) {
    if (ii > 0) os << ", ";
    os << host.aliases_[ii];
  }
  os << "] ";
  os << "addrs=[";
  for (size_t ii = 0; ii < host.addrs_.size(); ii++) {
    if (ii > 0) os << ", ";
    os << host.addrs_[ii];
  }
  os << "]";
  os << '}';
  return os;
}

void HostCallback(void *data, int status, int timeouts,
                  struct hostent *hostent) {
  EXPECT_NE(nullptr, data);
  if (data == nullptr)
    return;

  HostResult* result = reinterpret_cast<HostResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  if (hostent)
    result->host_ = HostEnt(hostent);
  if (verbose) std::cerr << "HostCallback(" << *result << ")" << std::endl;
}

std::ostream& operator<<(std::ostream& os, const AddrInfoResult& result) {
  os << '{';
  if (result.done_ && result.ai_) {
    os << StatusToString(result.status_) << " " << result.ai_;
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

std::ostream& operator<<(std::ostream& os, const AddrInfo& ai) {
  os << '{';
  if (ai == nullptr) {
    os << "nullptr}";
    return os;
  }

  struct ares_addrinfo_cname *next_cname = ai->cnames;
  while(next_cname) {
    if(next_cname->alias) {
      os << next_cname->alias << "->";
    }
    if(next_cname->name) {
      os << next_cname->name;
    }
    if((next_cname = next_cname->next))
      os << ", ";
    else
      os << " ";
  }

  struct ares_addrinfo_node *next = ai->nodes;
  while(next) {
    //if(next->ai_canonname) {
      //os << "'" << next->ai_canonname << "' ";
    //}
    unsigned short port = 0;
    os << "addr=[";
    if(next->ai_family == AF_INET) {
      sockaddr_in* sin = (sockaddr_in *)((void *)next->ai_addr);
      port = ntohs(sin->sin_port);
      os << AddressToString(&sin->sin_addr, 4);
    }
    else if (next->ai_family == AF_INET6) {
      sockaddr_in6* sin = (sockaddr_in6*)((void *)next->ai_addr);
      port = ntohs(sin->sin6_port);
      os << "[" << AddressToString(&sin->sin6_addr, 16) << "]";
    }
    else
      os << "unknown family";
    if(port) {
      os << ":" << port;
    }
    os << "]";
    if((next = next->ai_next))
      os << ", ";
  }
  os << '}';
  return os;
}

void AddrInfoCallback(void *data, int status, int timeouts,
                      struct ares_addrinfo *ai) {
  EXPECT_NE(nullptr, data);
  AddrInfoResult* result = reinterpret_cast<AddrInfoResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_= timeouts;
  if (ai)
    result->ai_ = AddrInfo(ai);
  if (verbose) std::cerr << "AddrInfoCallback(" << *result << ")" << std::endl;
}

std::ostream& operator<<(std::ostream& os, const SearchResult& result) {
  os << '{';
  if (result.done_) {
    os << StatusToString(result.status_) << " " << PacketToString(result.data_);
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

void SearchCallback(void *data, int status, int timeouts,
                    unsigned char *abuf, int alen) {
  EXPECT_NE(nullptr, data);
  SearchResult* result = reinterpret_cast<SearchResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  result->data_.assign(abuf, abuf + alen);
  if (verbose) std::cerr << "SearchCallback(" << *result << ")" << std::endl;
}

void SearchCallbackDnsRec(void *data, ares_status_t status, size_t timeouts,
                          const ares_dns_record_t *dnsrec) {
  EXPECT_NE(nullptr, data);
  SearchResult* result = reinterpret_cast<SearchResult*>(data);
  unsigned char *abuf = NULL;
  size_t alen = 0;
  result->done_ = true;
  result->status_ = (int)status;
  result->timeouts_ = (int)timeouts;
  if (dnsrec != NULL) {
    ares_dns_write(dnsrec, &abuf, &alen);
  }
  result->data_.assign(abuf, abuf + alen);
  ares_free_string(abuf);
  if (verbose) std::cerr << "SearchCallbackDnsRec(" << *result << ")" << std::endl;
}

std::ostream& operator<<(std::ostream& os, const NameInfoResult& result) {
  os << '{';
  if (result.done_) {
    os << StatusToString(result.status_) << " " << result.node_ << " " << result.service_;
  } else {
    os << "(incomplete)";
  }
  os << '}';
  return os;
}

void NameInfoCallback(void *data, int status, int timeouts,
                      char *node, char *service) {
  EXPECT_NE(nullptr, data);
  NameInfoResult* result = reinterpret_cast<NameInfoResult*>(data);
  result->done_ = true;
  result->status_ = status;
  result->timeouts_ = timeouts;
  result->node_ = std::string(node ? node : "");
  result->service_ = std::string(service ? service : "");
  if (verbose) std::cerr << "NameInfoCallback(" << *result << ")" << std::endl;
}

std::string GetNameServers(ares_channel_t *channel) {
  char *csv = ares_get_servers_csv(channel);
  EXPECT_NE((char *)NULL, csv);

  std::string servers(csv);

  ares_free_string(csv);
  return servers;
}

TransientDir::TransientDir(const std::string& dirname) : dirname_(dirname) {
  if (mkdir_(dirname_.c_str(), 0755) != 0) {
    std::cerr << "Failed to create subdirectory '" << dirname_ << "'" << std::endl;
  }
}

TransientDir::~TransientDir() {
  rmdir(dirname_.c_str());
}

TransientFile::TransientFile(const std::string& filename,
                             const std::string& contents)
    : filename_(filename) {
  FILE *f = fopen(filename.c_str(), "w");
  if (f == nullptr) {
    std::cerr << "Error: failed to create '" << filename << "'" << std::endl;
    return;
  }
  size_t rc = (size_t)fwrite(contents.data(), 1, contents.size(), f);
  if (rc != contents.size()) {
    std::cerr << "Error: failed to write contents of '" << filename << "'" << std::endl;
  }
  fclose(f);
}

TransientFile::~TransientFile() {
  unlink(filename_.c_str());
}

std::string TempNam(const char *dir, const char *prefix) {
  char *p = tempnam(dir, prefix);
  std::string result(p);
  free(p);
  return result;
}

TempFile::TempFile(const std::string& contents)
  : TransientFile(TempNam(nullptr, "ares"), contents) {

}

VirtualizeIO::VirtualizeIO(ares_channel_t *c)
  : channel_(c)
{
  ares_set_socket_functions(channel_, &default_functions, 0);
}

VirtualizeIO::~VirtualizeIO() {
  ares_set_socket_functions(channel_, 0, 0);
}

}  // namespace test
}  // namespace ares
