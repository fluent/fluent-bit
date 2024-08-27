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
#include "ares-test.h"
#include "dns-proto.h"

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ares_private.h"
#include "ares_inet_net_pton.h"
#include "ares_data.h"
#include "str/ares_strsplit.h"
#include "dsa/ares__htable.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
}

#include <string>
#include <vector>

namespace ares {
namespace test {

#ifndef CARES_SYMBOL_HIDING
void CheckPtoN4(int size, unsigned int value, const char *input) {
  struct in_addr a4;
  a4.s_addr = 0;
  uint32_t expected = htonl(value);
  EXPECT_EQ(size, ares_inet_net_pton(AF_INET, input, &a4, sizeof(a4)))
    << " for input " << input;
  EXPECT_EQ(expected, a4.s_addr) << " for input " << input;
}
#endif

#ifndef CARES_SYMBOL_HIDING
TEST_F(LibraryTest, Strsplit) {
  using std::vector;
  using std::string;
  size_t n;
  struct {
    vector<string> inputs;
    vector<string> delimiters;
    vector<vector<string>> expected;
  } data = {
    {
      "",
      " ",
      "             ",
      "example.com, example.co",
      "        a, b, A,c,     d, e,,,D,e,e,E",
    },
    { ", ", ", ", ", ", ", ", ", " },
    {
      {}, {}, {},
      { "example.com", "example.co" },
      { "a", "b", "c", "d", "e" },
    },
  };
  for(size_t i = 0; i < data.inputs.size(); i++) {
    char **out = ares__strsplit(data.inputs.at(i).c_str(),
                               data.delimiters.at(i).c_str(), &n);
    if(data.expected.at(i).size() == 0) {
      EXPECT_EQ(out, nullptr);
    }
    else {
      EXPECT_EQ(n, data.expected.at(i).size());
      for(size_t j = 0; j < n && j < data.expected.at(i).size(); j++) {
        EXPECT_STREQ(out[j], data.expected.at(i).at(j).c_str());
      }
    }
    ares__strsplit_free(out, n);
  }
}
#endif

TEST_F(LibraryTest, InetPtoN) {
  struct in_addr a4;
  struct in6_addr a6;

#ifndef CARES_SYMBOL_HIDING
  uint32_t expected;

  CheckPtoN4(4 * 8, 0x01020304, "1.2.3.4");
  CheckPtoN4(4 * 8, 0x81010101, "129.1.1.1");
  CheckPtoN4(4 * 8, 0xC0010101, "192.1.1.1");
  CheckPtoN4(4 * 8, 0xE0010101, "224.1.1.1");
  CheckPtoN4(4 * 8, 0xE1010101, "225.1.1.1");
  CheckPtoN4(4, 0xE0000000, "224");
  CheckPtoN4(4 * 8, 0xFD000000, "253");
  CheckPtoN4(4 * 8, 0xF0010101, "240.1.1.1");
  CheckPtoN4(4 * 8, 0x02030405, "02.3.4.5");
  CheckPtoN4(3 * 8, 0x01020304, "1.2.3.4/24");
  CheckPtoN4(3 * 8, 0x01020300, "1.2.3/24");
  CheckPtoN4(2 * 8, 0xa0000000, "0xa");
  CheckPtoN4(0, 0x02030405, "2.3.4.5/000");
  CheckPtoN4(1 * 8, 0x01020000, "1.2/8");
  CheckPtoN4(2 * 8, 0x01020000, "0x0102/16");
  CheckPtoN4(4 * 8, 0x02030405, "02.3.4.5");

  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "::", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "::1", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "1234:5678::", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(23, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4/23", &a6, sizeof(a6)));
  EXPECT_EQ(3 * 8, ares_inet_net_pton(AF_INET6, "12:34::ff/24", &a6, sizeof(a6)));
  EXPECT_EQ(0, ares_inet_net_pton(AF_INET6, "12:34::ff/0", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ffff:0.2", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));
  EXPECT_EQ(2, ares_inet_net_pton(AF_INET6, "0::00:00:00/2", &a6, sizeof(a6)));

  // Various malformed versions
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, " ", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x ", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "x0", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0xXYZZY", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "xyzzy", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET+AF_INET6, "1.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "257.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "002.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "00.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5.6", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5.6/12", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4:5", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5/120", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5/1x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5/x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/240", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/02", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/2y", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/y", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":x", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ": :1234", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "::12345", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234::2345:3456::0011", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234::", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:257.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4.5.6", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4.5", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.z", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3001.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3..4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.", &a6, sizeof(a6)));

  // Hex constants are allowed.
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x01020304", &a4, sizeof(a4)));
  expected = htonl(0x01020304);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x0a0b0c0d", &a4, sizeof(a4)));
  expected = htonl(0x0a0b0c0d);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x0A0B0C0D", &a4, sizeof(a4)));
  expected = htonl(0x0a0b0c0d);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x0xyz", &a4, sizeof(a4)));
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x1122334", &a4, sizeof(a4)));
  expected = htonl(0x11223340);
  EXPECT_EQ(expected, a4.s_addr);  // huh?

  // No room, no room.
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "1.2.3.4", &a4, sizeof(a4) - 1));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6) - 1));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x01020304", &a4, 2));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x01020304", &a4, 0));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x0a0b0c0d", &a4, 0));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x0xyz", &a4, 0));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x1122334", &a4, sizeof(a4) - 1));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "253", &a4, sizeof(a4) - 1));
#endif

  EXPECT_EQ(1, ares_inet_pton(AF_INET, "1.2.3.4", &a4));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ff", &a6));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6));
  EXPECT_EQ(0, ares_inet_pton(AF_INET, "xyzzy", &a4));
  EXPECT_EQ(-1, ares_inet_pton(AF_INET+AF_INET6, "1.2.3.4", &a4));
}

TEST_F(LibraryTest, FreeCorruptData) {
  // ares_free_data(p) expects that there is a type field and a marker
  // field in the memory before p.  Feed it incorrect versions of each.
  struct ares_data *data = (struct ares_data *)malloc(sizeof(struct ares_data));
  void* p = &(data->data);

  // Invalid type
  data->type = (ares_datatype)ARES_DATATYPE_LAST;
  data->mark = ARES_DATATYPE_MARK;
  ares_free_data(p);

  // Invalid marker
  data->type = (ares_datatype)ARES_DATATYPE_MX_REPLY;
  data->mark = ARES_DATATYPE_MARK + 1;
  ares_free_data(p);

  // Null pointer
  ares_free_data(nullptr);

  free(data);
}

#ifndef CARES_SYMBOL_HIDING
TEST_F(LibraryTest, FreeLongChain) {
  struct ares_addr_node *data = nullptr;
  for (int ii = 0; ii < 100000; ii++) {
    struct ares_addr_node *prev = (struct ares_addr_node*)ares_malloc_data(ARES_DATATYPE_ADDR_NODE);
    prev->next = data;
    data = prev;
  }

  ares_free_data(data);
}

TEST(LibraryInit, StrdupFailures) {
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  char* copy = ares_strdup("string");
  EXPECT_NE(nullptr, copy);
  ares_free(copy);
  ares_library_cleanup();
}

TEST_F(LibraryTest, StrdupFailures) {
  SetAllocFail(1);
  char* copy = ares_strdup("string");
  EXPECT_EQ(nullptr, copy);
}

TEST_F(LibraryTest, MallocDataFail) {
  EXPECT_EQ(nullptr, ares_malloc_data((ares_datatype)99));
  SetAllocSizeFail(sizeof(struct ares_data));
  EXPECT_EQ(nullptr, ares_malloc_data(ARES_DATATYPE_MX_REPLY));
}

TEST_F(FileChannelTest, GetAddrInfoHostsPositive) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{example.com addr=[1.2.3.4]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsSpaces) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "google.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{www.google.com->google.com, www2.google.com->google.com addr=[2.3.4.5]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsByALias) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "www2.google.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{www.google.com->google.com, www2.google.com->google.com addr=[2.3.4.5]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsIPV6) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET6;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "ipv6.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{ipv6.com addr=[[0000:0000:0000:0000:0000:0000:0000:0001]]}", ss.str());
}


TEST_F(FileChannelTest, GetAddrInfoAllocFail) {
  TempFile hostsfile("1.2.3.4 example.com alias1 alias2\n");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;

  // Fail a variety of different memory allocations, and confirm
  // that the operation either fails with ENOMEM or succeeds
  // with the expected result.
  const int kCount = 34;
  AddrInfoResult results[kCount];
  for (int ii = 1; ii <= kCount; ii++) {
    AddrInfoResult* result = &(results[ii - 1]);
    ClearFails();
    SetAllocFail(ii);
    ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback, result);
    Process();
    EXPECT_TRUE(result->done_);
    if (result->status_ == ARES_SUCCESS) {
      std::stringstream ss;
      ss << result->ai_;
      EXPECT_EQ("{alias1->example.com, alias2->example.com addr=[1.2.3.4]}", ss.str()) << " failed alloc #" << ii;
      if (verbose) std::cerr << "Succeeded despite failure of alloc #" << ii << std::endl;
    }
  }
}

TEST(Misc, OnionDomain) {
  EXPECT_EQ(0, ares__is_onion_domain("onion.no"));
  EXPECT_EQ(0, ares__is_onion_domain(".onion.no"));
  EXPECT_EQ(1, ares__is_onion_domain(".onion"));
  EXPECT_EQ(1, ares__is_onion_domain(".onion."));
  EXPECT_EQ(1, ares__is_onion_domain("yes.onion"));
  EXPECT_EQ(1, ares__is_onion_domain("yes.onion."));
  EXPECT_EQ(1, ares__is_onion_domain("YES.ONION"));
  EXPECT_EQ(1, ares__is_onion_domain("YES.ONION."));
}

#endif

TEST_F(LibraryTest, DNSRecord) {
  ares_dns_record_t   *dnsrec = NULL;
  ares_dns_rr_t       *rr     = NULL;
  struct in_addr       addr;
  struct ares_in6_addr addr6;
  unsigned char       *msg    = NULL;
  size_t               msglen = 0;
  size_t               qdcount = 0;
  size_t               ancount = 0;
  size_t               nscount = 0;
  size_t               arcount = 0;

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0x1234,
      ARES_FLAG_QR|ARES_FLAG_AA|ARES_FLAG_RD|ARES_FLAG_RA,
      ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));

  /* == Question == */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_query_add(dnsrec, "example.com",
      ARES_REC_TYPE_ANY,
      ARES_CLASS_IN));

  /* == Answer == */
  /* A */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_A, ARES_CLASS_IN, 300));
  EXPECT_LT(0, ares_inet_pton(AF_INET, "1.1.1.1", &addr));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr));
  /* AAAA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_AAAA, ARES_CLASS_IN, 300));
  EXPECT_LT(0, ares_inet_pton(AF_INET6, "2600::4", &addr6));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &addr6));
  /* MX */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_MX, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_MX_PREFERENCE, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_MX_EXCHANGE, "mail.example.com"));
  /* CNAME */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_CNAME, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, "b.example.com"));
  /* TXT */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_TXT, ARES_CLASS_IN, 3600));
  const char txt1[] = "blah=here blah=there anywhere";
  const char txt2[] = "some other record";
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, (unsigned char *)txt1,
      sizeof(txt1)-1));
   EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, (unsigned char *)txt2,
      sizeof(txt2)-1));
  /* SIG */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_SIG, ARES_CLASS_ANY, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SIG_TYPE_COVERED, ARES_REC_TYPE_TXT));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_SIG_ALGORITHM, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_SIG_LABELS, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SIG_ORIGINAL_TTL, 3200));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SIG_EXPIRATION, (unsigned int)time(NULL)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SIG_INCEPTION, (unsigned int)time(NULL) - (86400 * 365)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SIG_KEY_TAG, 0x1234));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SIG_SIGNERS_NAME, "signer.example.com"));
  const unsigned char sig[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_SIG_SIGNATURE, sig, sizeof(sig)));


  /* == Authority == */
  /* NS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_NS, ARES_CLASS_IN, 38400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, "ns1.example.com"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_NS, ARES_CLASS_IN, 38400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, "ns2.example.com"));
  /* SOA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_SOA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SOA_MNAME, "ns1.example.com"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SOA_RNAME, "tech\\.support.example.com"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_SERIAL, 2023110701));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_REFRESH, 28800));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_RETRY, 7200));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_EXPIRE, 604800));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_MINIMUM, 86400));

  /* == Additional */
  /* OPT */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "",
      ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, 1280));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_OPT_VERSION, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_OPT_FLAGS, 0));
  unsigned char optval[] = { 'c', '-', 'a', 'r', 'e', 's' };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, 3 /* NSID */, optval, sizeof(optval)));
  /* PTR -- doesn't make sense, but ok */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "example.com",
      ARES_REC_TYPE_PTR, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, "b.example.com"));
  /* HINFO */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "example.com",
      ARES_REC_TYPE_HINFO, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_HINFO_CPU, "Virtual"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_HINFO_OS, "Linux"));
  /* SRV */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_ldap.example.com", ARES_REC_TYPE_SRV, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SRV_PRIORITY, 100));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SRV_WEIGHT, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SRV_PORT, 389));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SRV_TARGET, "ldap.example.com"));
  /* TLSA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_443._tcp.example.com", ARES_REC_TYPE_TLSA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_CERT_USAGE, ARES_TLSA_USAGE_CA));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_SELECTOR, ARES_TLSA_SELECTOR_FULL));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_MATCH, ARES_TLSA_MATCH_SHA256));
  const unsigned char tlsa[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_TLSA_DATA, tlsa, sizeof(tlsa)));
  /* SVCB */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_1234._bar.example.com", ARES_REC_TYPE_SVCB, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SVCB_PRIORITY, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SVCB_TARGET, "svc1.example.net"));
  /* IPV6 hint is a list of IPV6 addresses in network byte order, concatenated */
  struct ares_addr svcb_addr;
  svcb_addr.family = AF_UNSPEC;
  size_t               svcb_ipv6hint_len = 0;
  const unsigned char *svcb_ipv6hint = (const unsigned char *)ares_dns_pton("2001:db8::1", &svcb_addr, &svcb_ipv6hint_len);
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_SVCB_PARAMS, ARES_SVCB_PARAM_IPV6HINT,
      svcb_ipv6hint, svcb_ipv6hint_len));
  /* Port is 16bit big endian format */
  unsigned short svcb_port = htons(1234);
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_SVCB_PARAMS, ARES_SVCB_PARAM_PORT,
      (const unsigned char *)&svcb_port, sizeof(svcb_port)));
  /* HTTPS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_HTTPS, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_HTTPS_PRIORITY, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_HTTPS_TARGET, ""));

  /* In DNS string format which is 1 octet length indicator followed by string */
  const unsigned char https_alpn[] = { 0x02, 'h', '3' };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_HTTPS_PARAMS, ARES_SVCB_PARAM_ALPN,
      https_alpn, sizeof(https_alpn)));
  /* URI */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_ftp._tcp.example.com", ARES_REC_TYPE_URI, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_URI_PRIORITY, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_URI_WEIGHT, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_URI_TARGET, "ftp://ftp.example.com/public"));
  /* CAA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_CAA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_CAA_CRITICAL, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_CAA_TAG, "issue"));
  unsigned char caa[] = "letsencrypt.org";
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_CAA_VALUE, caa, sizeof(caa)));
  /* NAPTR */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_NAPTR, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_ORDER, 100));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_PREFERENCE, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_FLAGS, "S"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_SERVICES, "SIP+D2U"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_REGEXP,
      "!^.*$!sip:customer-service@example.com!"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_REPLACEMENT,
      "_sip._udp.example.com."));
  /* RAW_RR */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "",
      ARES_REC_TYPE_RAW_RR, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_RAW_RR_TYPE, 65432));
  unsigned char data[] = { 0x00 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_RAW_RR_DATA, data, sizeof(data)));

  qdcount = ares_dns_record_query_cnt(dnsrec);
  ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  nscount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY);
  arcount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);

  /* Write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

#ifndef CARES_SYMBOL_HIDING
  ares__buf_t *hexdump = ares__buf_create();
  EXPECT_EQ(ARES_SUCCESS, ares__buf_hexdump(hexdump, msg, msglen));
  char *hexdata = ares__buf_finish_str(hexdump, NULL);
  //printf("HEXDUMP\n%s", hexdata);
  ares_free(hexdata);
#endif

  ares_dns_record_destroy(dnsrec); dnsrec = NULL;

  /* Parse */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, 0, &dnsrec));
  ares_free_string(msg); msg = NULL;

  /* Re-write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

  EXPECT_EQ(qdcount, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(ancount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(nscount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(arcount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

#ifndef CARES_SYMBOL_HIDING
  /* Iterate and print */
  ares__buf_t *printmsg = ares__buf_create();
  ares__buf_append_str(printmsg, ";; ->>HEADER<<- opcode: ");
  ares__buf_append_str(printmsg, ares_dns_opcode_tostr(ares_dns_record_get_opcode(dnsrec)));
  ares__buf_append_str(printmsg, ", status: ");
  ares__buf_append_str(printmsg, ares_dns_rcode_tostr(ares_dns_record_get_rcode(dnsrec)));
  ares__buf_append_str(printmsg, ", id: ");
  ares__buf_append_num_dec(printmsg, (size_t)ares_dns_record_get_id(dnsrec), 0);
  ares__buf_append_str(printmsg, "\n;; flags: ");
  ares__buf_append_num_hex(printmsg, (size_t)ares_dns_record_get_flags(dnsrec), 0);
  ares__buf_append_str(printmsg, "; QUERY: ");
  ares__buf_append_num_dec(printmsg, ares_dns_record_query_cnt(dnsrec), 0);
  ares__buf_append_str(printmsg, ", ANSWER: ");
  ares__buf_append_num_dec(printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER), 0);
  ares__buf_append_str(printmsg, ", AUTHORITY: ");
  ares__buf_append_num_dec(printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY), 0);
  ares__buf_append_str(printmsg, ", ADDITIONAL: ");
  ares__buf_append_num_dec(printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL), 0);
  ares__buf_append_str(printmsg, "\n\n");
  ares__buf_append_str(printmsg, ";; QUESTION SECTION:\n");
  for (size_t i = 0; i < ares_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;
    ares_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    ares__buf_append_str(printmsg, ";");
    ares__buf_append_str(printmsg, name);
    ares__buf_append_str(printmsg, ".\t\t\t");
    ares__buf_append_str(printmsg, ares_dns_class_tostr(qclass));
    ares__buf_append_str(printmsg, "\t");
    ares__buf_append_str(printmsg, ares_dns_rec_type_tostr(qtype));
    ares__buf_append_str(printmsg, "\n");
  }
  ares__buf_append_str(printmsg, "\n");
  for (size_t i = ARES_SECTION_ANSWER; i < ARES_SECTION_ADDITIONAL + 1; i++) {
    ares__buf_append_str(printmsg, ";; ");
    ares__buf_append_str(printmsg, ares_dns_section_tostr((ares_dns_section_t)i));
    ares__buf_append_str(printmsg, " SECTION:\n");
    for (size_t j = 0; j < ares_dns_record_rr_cnt(dnsrec, (ares_dns_section_t)i); j++) {
      rr = ares_dns_record_rr_get(dnsrec, (ares_dns_section_t)i, j);
      ares__buf_append_str(printmsg, ares_dns_rr_get_name(rr));
      ares__buf_append_str(printmsg, ".\t\t\t");
      ares__buf_append_str(printmsg, ares_dns_class_tostr(ares_dns_rr_get_class(rr)));
      ares__buf_append_str(printmsg, "\t");
      ares__buf_append_str(printmsg, ares_dns_rec_type_tostr(ares_dns_rr_get_type(rr)));
      ares__buf_append_str(printmsg, "\t");
      ares__buf_append_num_dec(printmsg, ares_dns_rr_get_ttl(rr), 0);
      ares__buf_append_str(printmsg, "\t");

      size_t keys_cnt;
      const ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(ares_dns_rr_get_type(rr), &keys_cnt);
      for (size_t k = 0; k<keys_cnt; k++) {
        char buf[256] = "";
        ares__buf_append_str(printmsg, ares_dns_rr_key_tostr(keys[k]));
        ares__buf_append_str(printmsg, "=");
        switch (ares_dns_rr_key_datatype(keys[k])) {
          case ARES_DATATYPE_INADDR:
            ares_inet_ntop(AF_INET, ares_dns_rr_get_addr(rr, keys[k]), buf, sizeof(buf));
            ares__buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_INADDR6:
            ares_inet_ntop(AF_INET6, ares_dns_rr_get_addr6(rr, keys[k]), buf, sizeof(buf));
            ares__buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_U8:
            ares__buf_append_num_dec(printmsg, ares_dns_rr_get_u8(rr, keys[k]), 0);
            break;
          case ARES_DATATYPE_U16:
            ares__buf_append_num_dec(printmsg, ares_dns_rr_get_u16(rr, keys[k]), 0);
            break;
          case ARES_DATATYPE_U32:
            ares__buf_append_num_dec(printmsg, ares_dns_rr_get_u32(rr, keys[k]), 0);
            break;
          case ARES_DATATYPE_NAME:
          case ARES_DATATYPE_STR:
            ares__buf_append_byte(printmsg, '"');
            ares__buf_append_str(printmsg, ares_dns_rr_get_str(rr, keys[k]));
            ares__buf_append_byte(printmsg, '"');
            break;
          case ARES_DATATYPE_BIN:
            /* TODO */
            break;
          case ARES_DATATYPE_BINP:
            {
              ares__buf_append_byte(printmsg, '"');
              size_t templen;
              ares__buf_append_str(printmsg, (const char *)ares_dns_rr_get_bin(rr, keys[k], &templen));
              ares__buf_append_byte(printmsg, '"');
            }
            break;
          case ARES_DATATYPE_ABINP:
            for (size_t a=0; a<ares_dns_rr_get_abin_cnt(rr, keys[k]); a++) {
              if (a != 0) {
                ares__buf_append_byte(printmsg, ' ');
              }
              ares__buf_append_byte(printmsg, '"');
              size_t templen;
              ares__buf_append_str(printmsg, (const char *)ares_dns_rr_get_abin(rr, keys[k], a, &templen));
              ares__buf_append_byte(printmsg, '"');
            }
            break;
          case ARES_DATATYPE_OPT:
            /* TODO */
            break;
        }
        ares__buf_append_str(printmsg, " ");
      }
      ares__buf_append_str(printmsg, "\n");
    }
  }
  ares__buf_append_str(printmsg, ";; SIZE: ");
  ares__buf_append_num_dec(printmsg, msglen, 0);
  ares__buf_append_str(printmsg, "\n\n");

  char *printdata = ares__buf_finish_str(printmsg, NULL);
  //printf("%s", printdata);
  ares_free(printdata);
#endif

  ares_dns_record_destroy(dnsrec);
  ares_free_string(msg);

  // Invalid
  EXPECT_NE(ARES_SUCCESS, ares_dns_parse(NULL, 0, 0, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_create(NULL, 0, 0, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  EXPECT_EQ(0, ares_dns_record_get_id(NULL));
  EXPECT_EQ(0, ares_dns_record_get_flags(NULL));
  EXPECT_EQ(0, (int)ares_dns_record_get_opcode(NULL));
  EXPECT_EQ(0, (int)ares_dns_record_get_rcode(NULL));
  EXPECT_EQ(0, (int)ares_dns_record_query_cnt(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_query_set_name(NULL, 0, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_query_set_type(NULL, 0, ARES_REC_TYPE_A));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_query_get(NULL, 0, NULL, NULL, NULL));
  EXPECT_EQ(0, ares_dns_record_rr_cnt(NULL, ARES_SECTION_ANSWER));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_rr_add(NULL, NULL, ARES_SECTION_ANSWER, NULL, ARES_REC_TYPE_A, ARES_CLASS_IN, 0));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_rr_del(NULL, ARES_SECTION_ANSWER, 0));
  EXPECT_EQ(nullptr, ares_dns_record_rr_get(NULL, ARES_SECTION_ANSWER, 0));
  EXPECT_EQ(nullptr, ares_dns_rr_get_name(NULL));
  EXPECT_EQ(0, (int)ares_dns_rr_get_type(NULL));
  EXPECT_EQ(0, (int)ares_dns_rr_get_class(NULL));
  EXPECT_EQ(0, ares_dns_rr_get_ttl(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_write(NULL, NULL, NULL));
#ifndef CARES_SYMBOL_HIDING
  ares_dns_record_write_ttl_decrement(NULL, 0);
#endif
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr(NULL, ARES_RR_A_ADDR));
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr6(NULL, ARES_RR_AAAA_ADDR));
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr6(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(0, ares_dns_rr_get_u8(NULL, ARES_RR_SIG_ALGORITHM));
  EXPECT_EQ(0, ares_dns_rr_get_u8(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(0, ares_dns_rr_get_u16(NULL, ARES_RR_MX_PREFERENCE));
  EXPECT_EQ(0, ares_dns_rr_get_u16(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(0, ares_dns_rr_get_u32(NULL, ARES_RR_SOA_SERIAL));
  EXPECT_EQ(0, ares_dns_rr_get_u32(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ares_dns_rr_get_bin(NULL, ARES_RR_TXT_DATA, NULL));
  EXPECT_EQ(nullptr, ares_dns_rr_get_bin(NULL, ARES_RR_NS_NSDNAME, NULL));
  EXPECT_EQ(nullptr, ares_dns_rr_get_str(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ares_dns_rr_get_str(NULL, ARES_RR_MX_PREFERENCE));
  EXPECT_EQ(0, ares_dns_rr_get_opt_cnt(NULL, ARES_RR_OPT_OPTIONS));
  EXPECT_EQ(0, ares_dns_rr_get_opt_cnt(NULL, ARES_RR_A_ADDR));
  EXPECT_EQ(65535, ares_dns_rr_get_opt(NULL, ARES_RR_OPT_OPTIONS, 0, NULL, NULL));
  EXPECT_EQ(65535, ares_dns_rr_get_opt(NULL, ARES_RR_A_ADDR, 0, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_dns_rr_get_opt_byid(NULL, ARES_RR_OPT_OPTIONS, 1, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_dns_rr_get_opt_byid(NULL, ARES_RR_A_ADDR, 1, NULL, NULL));
}

TEST_F(LibraryTest, DNSParseFlags) {
  ares_dns_record_t   *dnsrec = NULL;
  ares_dns_rr_t       *rr     = NULL;
  struct in_addr       addr;
  unsigned char       *msg    = NULL;
  size_t               msglen = 0;

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0x1234,
      ARES_FLAG_QR|ARES_FLAG_AA|ARES_FLAG_RD|ARES_FLAG_RA,
      ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));

  /* == Question == */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_query_add(dnsrec, "example.com",
      ARES_REC_TYPE_ANY,
      ARES_CLASS_IN));

  /* == Answer == */
  /* A */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_A, ARES_CLASS_IN, 300));
  EXPECT_LT(0, ares_inet_pton(AF_INET, "1.1.1.1", &addr));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr));
  /* TLSA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
      "_443._tcp.example.com", ARES_REC_TYPE_TLSA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_CERT_USAGE, ARES_TLSA_USAGE_CA));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_SELECTOR, ARES_TLSA_SELECTOR_FULL));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_MATCH, ARES_TLSA_MATCH_SHA256));
  const unsigned char tlsa[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_TLSA_DATA, tlsa, sizeof(tlsa)));

  /* == Authority == */
  /* NS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_NS, ARES_CLASS_IN, 38400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, "ns1.example.com"));

  /* == Additional */
  /* PTR -- doesn't make sense, but ok */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "example.com",
      ARES_REC_TYPE_PTR, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, "b.example.com"));

  /* Write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

  /* Cleanup - before reuse */
  ares_dns_record_destroy(dnsrec);

  /* Parse "base" type records (1035) */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, ARES_DNS_PARSE_AN_BASE_RAW |
    ARES_DNS_PARSE_NS_BASE_RAW | ARES_DNS_PARSE_AR_BASE_RAW, &dnsrec));

  EXPECT_EQ(1, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(2, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 1);
  EXPECT_EQ(ARES_REC_TYPE_TLSA, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_AUTHORITY, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  /* Cleanup - before reuse */

  ares_dns_record_destroy(dnsrec);

  /* Parse later RFCs (no name compression) type records */

  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, ARES_DNS_PARSE_AN_EXT_RAW |
    ARES_DNS_PARSE_NS_EXT_RAW | ARES_DNS_PARSE_AR_EXT_RAW, &dnsrec));

  EXPECT_EQ(1, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(2, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 0);
  EXPECT_EQ(ARES_REC_TYPE_A, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 1);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_AUTHORITY, 0);
  EXPECT_EQ(ARES_REC_TYPE_NS, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 0);
  EXPECT_EQ(ARES_REC_TYPE_PTR, ares_dns_rr_get_type(rr));

  ares_dns_record_destroy(dnsrec);
  ares_free_string(msg); msg = NULL;
}

#ifndef CARES_SYMBOL_HIDING

TEST_F(LibraryTest, CatDomain) {
  char *s;

  ares__cat_domain("foo", "example.net", &s);
  EXPECT_STREQ("foo.example.net", s);
  ares_free(s);

  ares__cat_domain("foo", ".", &s);
  EXPECT_STREQ("foo.", s);
  ares_free(s);

  ares__cat_domain("foo", "example.net.", &s);
  EXPECT_STREQ("foo.example.net.", s);
  ares_free(s);
}

TEST_F(LibraryTest, ArrayMisuse) {
  EXPECT_EQ(NULL, ares__array_create(0, NULL));
  ares__array_destroy(NULL);
  EXPECT_EQ(NULL, ares__array_finish(NULL, NULL));
  EXPECT_EQ(0, ares__array_len(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__array_insert_at(NULL, NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares__array_insert_last(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares__array_insert_first(NULL, NULL));
  EXPECT_EQ(NULL, ares__array_at(NULL, 0));
  EXPECT_EQ(NULL, ares__array_first(NULL));
  EXPECT_EQ(NULL, ares__array_last(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__array_claim_at(NULL, 0, NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares__array_remove_at(NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares__array_remove_first(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__array_remove_last(NULL));
}

TEST_F(LibraryTest, BufMisuse) {
  EXPECT_EQ(NULL, ares__buf_create_const(NULL, 0));
  ares__buf_reclaim(NULL);
  EXPECT_NE(ARES_SUCCESS, ares__buf_append(NULL, NULL, 55));
  size_t len = 10;
  EXPECT_EQ(NULL, ares__buf_append_start(NULL, &len));
  EXPECT_EQ(NULL, ares__buf_append_start(NULL, NULL));
  ares__buf_append_finish(NULL, 0);
  EXPECT_EQ(NULL, ares__buf_finish_bin(NULL, NULL));
  EXPECT_EQ(NULL, ares__buf_finish_str(NULL, NULL));
  ares__buf_tag(NULL);
  EXPECT_NE(ARES_SUCCESS, ares__buf_tag_rollback(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__buf_tag_clear(NULL));
  EXPECT_EQ(NULL, ares__buf_tag_fetch(NULL, NULL));
  EXPECT_EQ((size_t)0, ares__buf_tag_length(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__buf_tag_fetch_bytes(NULL, NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares__buf_tag_fetch_string(NULL, NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares__buf_fetch_bytes_dup(NULL, 0, ARES_FALSE, NULL));
  EXPECT_NE(ARES_SUCCESS, ares__buf_fetch_str_dup(NULL, 0, NULL));
  EXPECT_EQ((size_t)0, ares__buf_consume_whitespace(NULL, ARES_FALSE));
  EXPECT_EQ((size_t)0, ares__buf_consume_nonwhitespace(NULL));
  EXPECT_EQ((size_t)0, ares__buf_consume_line(NULL, ARES_FALSE));
  EXPECT_EQ(ARES_FALSE, ares__buf_begins_with(NULL, NULL, 0));
  EXPECT_EQ((size_t)0, ares__buf_get_position(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__buf_set_position(NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares__dns_name_parse(NULL, NULL, ARES_FALSE));
  EXPECT_NE(ARES_SUCCESS, ares__buf_parse_dns_binstr(NULL, 0, NULL, NULL));
}

TEST_F(LibraryTest, HtableMisuse) {
  EXPECT_EQ(NULL, ares__htable_create(NULL, NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_insert(NULL, NULL));
  EXPECT_EQ(NULL, ares__htable_get(NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares__htable_num_keys(NULL));
}

TEST_F(LibraryTest, HtableAsvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares__htable_asvp_insert(NULL, ARES_SOCKET_BAD, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_asvp_get(NULL, ARES_SOCKET_BAD, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_asvp_remove(NULL, ARES_SOCKET_BAD));
  EXPECT_EQ((size_t)0, ares__htable_asvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableStrvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares__htable_strvp_insert(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_strvp_get(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_strvp_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares__htable_strvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableSzvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares__htable_szvp_insert(NULL, 0, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_szvp_get(NULL, 0, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_szvp_remove(NULL, 0));
  EXPECT_EQ((size_t)0, ares__htable_szvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableVpvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares__htable_vpvp_insert(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_vpvp_get(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares__htable_vpvp_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares__htable_vpvp_num_keys(NULL));
}

TEST_F(LibraryTest, LlistMisuse) {
  ares__llist_replace_destructor(NULL, NULL);
  EXPECT_EQ(NULL, ares__llist_insert_before(NULL, NULL));
  EXPECT_EQ(NULL, ares__llist_insert_after(NULL, NULL));
  EXPECT_EQ(NULL, ares__llist_node_last(NULL));
  EXPECT_EQ(NULL, ares__llist_node_next(NULL));
  EXPECT_EQ(NULL, ares__llist_node_prev(NULL));
  EXPECT_EQ((size_t)0, ares__llist_len(NULL));
  EXPECT_EQ(NULL, ares__llist_node_parent(NULL));
  EXPECT_EQ(NULL, ares__llist_node_claim(NULL));
  ares__llist_node_replace(NULL, NULL);
}

TEST_F(LibraryTest, SlistMisuse) {
  EXPECT_EQ(NULL, ares__slist_create(NULL, NULL, NULL));
  ares__slist_replace_destructor(NULL, NULL);
  EXPECT_EQ(NULL, ares__slist_insert(NULL, NULL));
  EXPECT_EQ(NULL, ares__slist_node_find(NULL, NULL));
  EXPECT_EQ(NULL, ares__slist_node_first(NULL));
  EXPECT_EQ(NULL, ares__slist_node_last(NULL));
  EXPECT_EQ(NULL, ares__slist_node_next(NULL));
  EXPECT_EQ(NULL, ares__slist_node_prev(NULL));
  EXPECT_EQ(NULL, ares__slist_node_val(NULL));
  EXPECT_EQ((size_t)0, ares__slist_len(NULL));
  EXPECT_EQ(NULL, ares__slist_node_parent(NULL));
  EXPECT_EQ(NULL, ares__slist_first_val(NULL));
  EXPECT_EQ(NULL, ares__slist_last_val(NULL));
  EXPECT_EQ(NULL, ares__slist_node_claim(NULL));
}

typedef struct {
  unsigned int id;
  ares__buf_t *buf;
} array_member_t;

static void array_member_init(void *mb, unsigned int id)
{
  array_member_t *m = (array_member_t *)mb;
  m->id             = id;
  m->buf            = ares__buf_create();
  ares__buf_append_be32(m->buf, id);
}

static void array_member_destroy(void *mb)
{
  array_member_t *m = (array_member_t *)mb;
  ares__buf_destroy(m->buf);
}

static int array_sort_cmp(const void *data1, const void *data2)
{
  const array_member_t *m1 = (const array_member_t *)data1;
  const array_member_t *m2 = (const array_member_t *)data2;
  if (m1->id > m2->id)
    return 1;
  if (m1->id < m2->id)
    return -1;
  return 0;
}

TEST_F(LibraryTest, Array) {
  ares__array_t  *a       = NULL;
  array_member_t *m       = NULL;
  array_member_t  mbuf;
  unsigned int    cnt     = 0;
  unsigned int    removed = 0;
  void           *ptr     = NULL;
  size_t          i;

  a = ares__array_create(sizeof(array_member_t), array_member_destroy);
  EXPECT_NE(nullptr, a);

  /* Add 8 elements */
  for ( ; cnt < 8 ; cnt++) {
    EXPECT_EQ(ARES_SUCCESS, ares__array_insert_last(&ptr, a));
    array_member_init(ptr, cnt+1);
  }

  /* Verify count */
  EXPECT_EQ(cnt, ares__array_len(a));

  /* Remove the first 2 elements */
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_first(a));
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_first(a));
  removed += 2;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares__array_len(a));

  /* Verify id of first element */
  m = (array_member_t *)ares__array_first(a);
  EXPECT_NE(nullptr, m);
  EXPECT_EQ(3, m->id);


  /* Add 100 total elements, this should force a shift of memory at some
   * to make sure moves are working */
  for ( ; cnt < 100 ; cnt++) {
    EXPECT_EQ(ARES_SUCCESS, ares__array_insert_last(&ptr, a));
    array_member_init(ptr, cnt+1);
  }

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares__array_len(a));

  /* Remove 2 from the end */
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_last(a));
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_last(a));
  removed += 2;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares__array_len(a));

  /* Verify expected id of last member */
  m = (array_member_t *)ares__array_last(a);
  EXPECT_NE(nullptr, m);
  EXPECT_EQ(cnt-2, m->id);

  /* Remove 3 middle members */
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_at(a, ares__array_len(a)/2));
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_at(a, ares__array_len(a)/2));
  EXPECT_EQ(ARES_SUCCESS, ares__array_remove_at(a, ares__array_len(a)/2));
  removed += 3;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares__array_len(a));

  /* Claim a middle member then re-add it at the same position */
  i = ares__array_len(a) / 2;
  EXPECT_EQ(ARES_SUCCESS, ares__array_claim_at(&mbuf, sizeof(mbuf), a, i));
  EXPECT_EQ(ARES_SUCCESS, ares__array_insert_at(&ptr, a, i));
  array_member_init(ptr, mbuf.id);
  array_member_destroy((void *)&mbuf);
  /* Verify count */
  EXPECT_EQ(cnt-removed, ares__array_len(a));

  /* Iterate across the array, make sure each entry is greater than the last and
   * the data in the buffer matches the id in the array */
  unsigned int last_id = 0;
  for (i=0; i<ares__array_len(a); i++) {
    m = (array_member_t *)ares__array_at(a, i);
    EXPECT_NE(nullptr, m);
    EXPECT_GT(m->id, last_id);
    last_id = m->id;

    unsigned int bufval = 0;
    ares__buf_tag(m->buf);
    EXPECT_EQ(ARES_SUCCESS, ares__buf_fetch_be32(m->buf, &bufval));
    ares__buf_tag_rollback(m->buf);
    EXPECT_EQ(bufval, m->id);
  }

  /* add a new element in the middle to the beginning with a high id */
  EXPECT_EQ(ARES_SUCCESS, ares__array_insert_at(&ptr, a, ares__array_len(a)/2));
  array_member_init(ptr, 100000);

  /* Sort the array */
  EXPECT_EQ(ARES_SUCCESS, ares__array_sort(a, array_sort_cmp));

  /* Iterate across the array, make sure each entry is greater than the last and
   * the data in the buffer matches the id in the array */
  last_id = 0;
  for (i=0; i<ares__array_len(a); i++) {
    m = (array_member_t *)ares__array_at(a, i);
    EXPECT_NE(nullptr, m);
    EXPECT_GT(m->id, last_id);
    last_id = m->id;

    unsigned int bufval = 0;
    ares__buf_tag(m->buf);
    EXPECT_EQ(ARES_SUCCESS, ares__buf_fetch_be32(m->buf, &bufval));
    ares__buf_tag_rollback(m->buf);
    EXPECT_EQ(bufval, m->id);
  }

  ares__array_destroy(a);
}

TEST_F(LibraryTest, HtableVpvp) {
  ares__llist_t       *l = NULL;
  ares__htable_vpvp_t *h = NULL;
  ares__llist_node_t  *n = NULL;
  size_t               i;

#define VPVP_TABLE_SIZE 1000

  l = ares__llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares__htable_vpvp_create(NULL, ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<VPVP_TABLE_SIZE; i++) {
    void *p = ares_malloc_zero(4);
    EXPECT_NE((void *)NULL, p);
    EXPECT_NE((void *)NULL, ares__llist_insert_last(l, p));
    EXPECT_TRUE(ares__htable_vpvp_insert(h, p, p));
  }

  EXPECT_EQ(VPVP_TABLE_SIZE, ares__llist_len(l));
  EXPECT_EQ(VPVP_TABLE_SIZE, ares__htable_vpvp_num_keys(h));

  n = ares__llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares__llist_node_t *next = ares__llist_node_next(n);
    void               *p    = ares__llist_node_val(n);
    EXPECT_NE((void *)NULL, p);
    EXPECT_EQ(p, ares__htable_vpvp_get_direct(h, p));
    EXPECT_TRUE(ares__htable_vpvp_get(h, p, NULL));
    EXPECT_TRUE(ares__htable_vpvp_remove(h, p));
    ares__llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares__llist_len(l));
  EXPECT_EQ(0, ares__htable_vpvp_num_keys(h));

  ares__llist_destroy(l);
  ares__htable_vpvp_destroy(h);
}

typedef struct {
  ares_socket_t s;
} test_htable_asvp_t;

TEST_F(LibraryTest, HtableAsvp) {
  ares__llist_t       *l = NULL;
  ares__htable_asvp_t *h = NULL;
  ares__llist_node_t  *n = NULL;
  size_t               i;

#define ASVP_TABLE_SIZE 1000

  l = ares__llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares__htable_asvp_create(ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<ASVP_TABLE_SIZE; i++) {
    test_htable_asvp_t *a = (test_htable_asvp_t *)ares_malloc_zero(sizeof(*a));
    EXPECT_NE((void *)NULL, a);
    a->s = (ares_socket_t)i+1;
    EXPECT_NE((void *)NULL, ares__llist_insert_last(l, a));
    EXPECT_TRUE(ares__htable_asvp_insert(h, a->s, a));
  }

  EXPECT_EQ(ASVP_TABLE_SIZE, ares__llist_len(l));
  EXPECT_EQ(ASVP_TABLE_SIZE, ares__htable_asvp_num_keys(h));

  n = ares__llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares__llist_node_t *next = ares__llist_node_next(n);
    test_htable_asvp_t *a    = (test_htable_asvp_t *)ares__llist_node_val(n);
    EXPECT_NE((void *)NULL, a);
    EXPECT_EQ(a, ares__htable_asvp_get_direct(h, a->s));
    EXPECT_TRUE(ares__htable_asvp_get(h, a->s, NULL));
    EXPECT_TRUE(ares__htable_asvp_remove(h, a->s));
    ares__llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares__llist_len(l));
  EXPECT_EQ(0, ares__htable_asvp_num_keys(h));

  ares__llist_destroy(l);
  ares__htable_asvp_destroy(h);
}


typedef struct {
  size_t s;
} test_htable_szvp_t;

TEST_F(LibraryTest, HtableSzvp) {
  ares__llist_t       *l = NULL;
  ares__htable_szvp_t *h = NULL;
  ares__llist_node_t  *n = NULL;
  size_t               i;

#define SZVP_TABLE_SIZE 1000

  l = ares__llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares__htable_szvp_create(ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<SZVP_TABLE_SIZE; i++) {
    test_htable_szvp_t *s = (test_htable_szvp_t *)ares_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    s->s = i+1;
    EXPECT_NE((void *)NULL, ares__llist_insert_last(l, s));
    EXPECT_TRUE(ares__htable_szvp_insert(h, s->s, s));
  }

  EXPECT_EQ(SZVP_TABLE_SIZE, ares__llist_len(l));
  EXPECT_EQ(SZVP_TABLE_SIZE, ares__htable_szvp_num_keys(h));

  n = ares__llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares__llist_node_t *next = ares__llist_node_next(n);
    test_htable_szvp_t *s    = (test_htable_szvp_t *)ares__llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_EQ(s, ares__htable_szvp_get_direct(h, s->s));
    EXPECT_TRUE(ares__htable_szvp_get(h, s->s, NULL));
    EXPECT_TRUE(ares__htable_szvp_remove(h, s->s));
    ares__llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares__llist_len(l));
  EXPECT_EQ(0, ares__htable_szvp_num_keys(h));

  ares__llist_destroy(l);
  ares__htable_szvp_destroy(h);
}

typedef struct {
  char s[32];
} test_htable_strvp_t;

TEST_F(LibraryTest, HtableStrvp) {
  ares__llist_t        *l = NULL;
  ares__htable_strvp_t *h = NULL;
  ares__llist_node_t   *n = NULL;
  size_t                i;

#define STRVP_TABLE_SIZE 1000

  l = ares__llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares__htable_strvp_create(ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<STRVP_TABLE_SIZE; i++) {
    test_htable_strvp_t *s = (test_htable_strvp_t *)ares_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    snprintf(s->s, sizeof(s->s), "%d", (int)i);
    EXPECT_NE((void *)NULL, ares__llist_insert_last(l, s));
    EXPECT_TRUE(ares__htable_strvp_insert(h, s->s, s));
  }

  EXPECT_EQ(STRVP_TABLE_SIZE, ares__llist_len(l));
  EXPECT_EQ(STRVP_TABLE_SIZE, ares__htable_strvp_num_keys(h));

  n = ares__llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares__llist_node_t *next = ares__llist_node_next(n);
    test_htable_strvp_t *s   = (test_htable_strvp_t *)ares__llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_EQ(s, ares__htable_strvp_get_direct(h, s->s));
    EXPECT_TRUE(ares__htable_strvp_get(h, s->s, NULL));
    EXPECT_TRUE(ares__htable_strvp_remove(h, s->s));
    ares__llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares__llist_len(l));
  EXPECT_EQ(0, ares__htable_strvp_num_keys(h));

  ares__llist_destroy(l);
  ares__htable_strvp_destroy(h);
}

TEST_F(LibraryTest, IfaceIPs) {
  ares_status_t      status;
  ares__iface_ips_t *ips = NULL;
  size_t             i;

  status = ares__iface_ips(&ips, ARES_IFACE_IP_DEFAULT, NULL);
  EXPECT_TRUE(status == ARES_SUCCESS || status == ARES_ENOTIMP);

  /* Not implemented, can't run tests */
  if (status == ARES_ENOTIMP)
    return;

  EXPECT_NE(nullptr, ips);

  for (i=0; i<ares__iface_ips_cnt(ips); i++) {
    const char *name = ares__iface_ips_get_name(ips, i);
    EXPECT_NE(nullptr, name);
    int flags = (int)ares__iface_ips_get_flags(ips, i);
    EXPECT_NE(0, (int)flags);
    EXPECT_NE(nullptr, ares__iface_ips_get_addr(ips, i));
    EXPECT_NE(0, ares__iface_ips_get_netmask(ips, i));
    if (flags & ARES_IFACE_IP_LINKLOCAL && flags & ARES_IFACE_IP_V6) {
      /* Hmm, seems not to work at least on MacOS
       * EXPECT_NE(0, ares__iface_ips_get_ll_scope(ips, i));
       */
    } else {
      EXPECT_EQ(0, ares__iface_ips_get_ll_scope(ips, i));
    }
    unsigned int idx = ares__if_nametoindex(name);
    EXPECT_NE(0, idx);
    char namebuf[256];
    EXPECT_EQ(std::string(ares__if_indextoname(idx, namebuf, sizeof(namebuf))), std::string(name));
  }


  /* Negative checking */
  ares__iface_ips_get_name(ips, ares__iface_ips_cnt(ips));
  ares__iface_ips_get_flags(ips, ares__iface_ips_cnt(ips));
  ares__iface_ips_get_addr(ips, ares__iface_ips_cnt(ips));
  ares__iface_ips_get_netmask(ips, ares__iface_ips_cnt(ips));
  ares__iface_ips_get_ll_scope(ips, ares__iface_ips_cnt(ips));

  ares__iface_ips(NULL, ARES_IFACE_IP_DEFAULT, NULL);
  ares__iface_ips_cnt(NULL);
  ares__iface_ips_get_name(NULL, 0);
  ares__iface_ips_get_flags(NULL, 0);
  ares__iface_ips_get_addr(NULL, 0);
  ares__iface_ips_get_netmask(NULL, 0);
  ares__iface_ips_get_ll_scope(NULL, 0);
  ares__iface_ips_destroy(NULL);
  ares__if_nametoindex(NULL);
  ares__if_indextoname(0, NULL, 0);

  ares__iface_ips_destroy(ips);
}


#endif

TEST_F(DefaultChannelTest, SaveInvalidChannel) {
  ares__slist_t *saved = channel_->servers;
  channel_->servers = NULL;
  struct ares_options opts;
  int optmask = 0;
  EXPECT_EQ(ARES_ENODATA, ares_save_options(channel_, &opts, &optmask));
  channel_->servers = saved;
}

// Need to put this in own function due to nested lambda bug
// in VS2013. (C2888)
static int configure_socket(ares_socket_t s) {
  // transposed from ares-process, simplified non-block setter.
#if defined(USE_BLOCKING_SOCKETS)
  return 0; /* returns success */
#elif defined(HAVE_FCNTL_O_NONBLOCK)
  /* most recent unix versions */
  int flags;
  flags = fcntl(s, F_GETFL, 0);
  return fcntl(s, F_SETFL, flags | O_NONBLOCK);
#elif defined(HAVE_IOCTL_FIONBIO)
  /* older unix versions */
  int flags = 1;
  return ioctl(s, FIONBIO, &flags);
#elif defined(HAVE_IOCTLSOCKET_FIONBIO)
#ifdef WATT32
  char flags = 1;
#else
  /* Windows */
  unsigned long flags = 1UL;
#endif
  return ioctlsocket(s, (long)FIONBIO, &flags);
#elif defined(HAVE_IOCTLSOCKET_CAMEL_FIONBIO)
  /* Amiga */
  long flags = 1L;
  return IoctlSocket(s, FIONBIO, flags);
#elif defined(HAVE_SETSOCKOPT_SO_NONBLOCK)
  /* BeOS */
  long b = 1L;
  return setsockopt(s, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
#else
#  error "no non-blocking method was found/used/set"
#endif
}

// TODO: This should not really be in this file, but we need ares config
// flags, and here they are available.
const struct ares_socket_functions VirtualizeIO::default_functions = {
  [](int af, int type, int protocol, void *) -> ares_socket_t {
    auto s = ::socket(af, type, protocol);
    if (s == ARES_SOCKET_BAD) {
      return s;
    }
    if (configure_socket(s) != 0) {
      sclose(s);
      return ares_socket_t(-1);
    }
    return s;
  },
  NULL,
  NULL,
  NULL,
  NULL
};


}  // namespace test
}  // namespace ares
