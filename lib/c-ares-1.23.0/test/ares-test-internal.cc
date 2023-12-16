/*
 * Copyright (C) The c-ares project
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
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
#include "ares__htable.h"
#include "bitncmp.h"

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
  data->type = (ares_datatype)99;
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

TEST(Misc, Bitncmp) {
  byte a[4] = {0x80, 0x01, 0x02, 0x03};
  byte b[4] = {0x80, 0x01, 0x02, 0x04};
  byte c[4] = {0x01, 0xFF, 0x80, 0x02};
  EXPECT_GT(0, ares__bitncmp(a, b, sizeof(a)*8));
  EXPECT_LT(0, ares__bitncmp(b, a, sizeof(a)*8));
  EXPECT_EQ(0, ares__bitncmp(a, a, sizeof(a)*8));

  for (size_t ii = 1; ii < (3*8+5); ii++) {
    EXPECT_EQ(0, ares__bitncmp(a, b, ii));
    EXPECT_EQ(0, ares__bitncmp(b, a, ii));
    EXPECT_LT(0, ares__bitncmp(a, c, ii));
    EXPECT_GT(0, ares__bitncmp(c, a, ii));
  }

  // Last byte differs at 5th bit
  EXPECT_EQ(0, ares__bitncmp(a, b, 3*8 + 3));
  EXPECT_EQ(0, ares__bitncmp(a, b, 3*8 + 4));
  EXPECT_EQ(0, ares__bitncmp(a, b, 3*8 + 5));
  EXPECT_GT(0, ares__bitncmp(a, b, 3*8 + 6));
  EXPECT_GT(0, ares__bitncmp(a, b, 3*8 + 7));
}


TEST_F(LibraryTest, ReadLine) {
  TempFile temp("abcde\n0123456789\nXYZ\n012345678901234567890\n\n");
  FILE *fp = fopen(temp.filename(), "r");
  size_t bufsize = 4;
  char *buf = (char *)ares_malloc(bufsize);

  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("abcde", std::string(buf));
  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("0123456789", std::string(buf));
  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("XYZ", std::string(buf));
  SetAllocFail(1);
  EXPECT_EQ(ARES_ENOMEM, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ(nullptr, buf);

  fclose(fp);
  ares_free(buf);
}

TEST_F(LibraryTest, ReadLineNoBuf) {
  TempFile temp("abcde\n0123456789\nXYZ\n012345678901234567890");
  FILE *fp = fopen(temp.filename(), "r");
  size_t bufsize = 0;
  char *buf = nullptr;

  SetAllocFail(1);
  EXPECT_EQ(ARES_ENOMEM, ares__read_line(fp, &buf, &bufsize));

  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("abcde", std::string(buf));
  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("0123456789", std::string(buf));
  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("XYZ", std::string(buf));
  EXPECT_EQ(ARES_SUCCESS, ares__read_line(fp, &buf, &bufsize));
  EXPECT_EQ("012345678901234567890", std::string(buf));

  fclose(fp);
  ares_free(buf);
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
  EXPECT_LT(0, ares_inet_net_pton(AF_INET, "1.1.1.1", &addr, sizeof(addr)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr));
  /* AAAA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_AAAA, ARES_CLASS_IN, 300));
  EXPECT_LT(0, ares_inet_net_pton(AF_INET6, "2600::4", &addr6, sizeof(addr6)));
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
  const char txt[] = "blah=here blah=there anywhere";
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_TXT_DATA, (unsigned char *)txt,
      sizeof(txt)));

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

  ares__buf_t *hexdump = ares__buf_create();
  EXPECT_EQ(ARES_SUCCESS, ares__buf_hexdump(hexdump, msg, msglen));
  char *hexdata = ares__buf_finish_str(hexdump, NULL);
  //printf("HEXDUMP\n%s", hexdata);
  ares_free(hexdata);
  ares_dns_record_destroy(dnsrec); dnsrec = NULL;

  /* Parse */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, 0, &dnsrec));
  ares_free(msg); msg = NULL;

  /* Re-write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

  EXPECT_EQ(qdcount, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(ancount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(nscount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(arcount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

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
      const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, (ares_dns_section_t)i, j);
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
            ares__buf_append_byte(printmsg, '"');
            size_t templen;
            ares__buf_append_str(printmsg, (const char *)ares_dns_rr_get_bin(rr, keys[k], &templen));
            ares__buf_append_byte(printmsg, '"');
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

  ares_dns_record_destroy(dnsrec);
  ares_free(msg);
}

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

TEST_F(LibraryTest, BufMisuse) {
  EXPECT_EQ(NULL, ares__buf_create_const(NULL, 0));
  ares__buf_reclaim(NULL);
  EXPECT_NE(ARES_SUCCESS, ares__buf_append(NULL, NULL, 0));
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
  EXPECT_NE(ARES_SUCCESS, ares__buf_begins_with(NULL, NULL, 0));
  EXPECT_EQ((size_t)0, ares__buf_get_position(NULL));
  EXPECT_NE(ARES_SUCCESS, ares__buf_set_position(NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares__dns_name_parse(NULL, NULL, ARES_FALSE));
  EXPECT_NE(ARES_SUCCESS, ares__buf_parse_dns_binstr(NULL, 0, NULL, NULL, ARES_FALSE));
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
#endif

#ifdef CARES_EXPOSE_STATICS
// These tests access internal static functions from the library, which
// are only exposed when CARES_EXPOSE_STATICS has been configured. As such
// they are tightly couple to the internal library implementation details.
extern "C" char *ares_striendstr(const char*, const char*);
TEST_F(LibraryTest, Striendstr) {
  EXPECT_EQ(nullptr, ares_striendstr("abc", "12345"));
  EXPECT_NE(nullptr, ares_striendstr("abc12345", "12345"));
  EXPECT_NE(nullptr, ares_striendstr("abcxyzzy", "XYZZY"));
  EXPECT_NE(nullptr, ares_striendstr("xyzzy", "XYZZY"));
  EXPECT_EQ(nullptr, ares_striendstr("xyxzy", "XYZZY"));
  EXPECT_NE(nullptr, ares_striendstr("", ""));
  const char *str = "plugh";
  EXPECT_NE(nullptr, ares_striendstr(str, str));
}

TEST_F(DefaultChannelTest, SingleDomain) {
  TempFile aliases("www www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());

  SetAllocSizeFail(128);
  char *ptr = nullptr;
  EXPECT_EQ(ARES_ENOMEM, ares__single_domain(channel_, "www", &ptr));

  channel_->flags |= ARES_FLAG_NOSEARCH|ARES_FLAG_NOALIASES;
  EXPECT_EQ(ARES_SUCCESS, ares__single_domain(channel_, "www", &ptr));
  EXPECT_EQ("www", std::string(ptr));
  ares_free(ptr);
  ptr = nullptr;

  SetAllocFail(1);
  EXPECT_EQ(ARES_ENOMEM, ares__single_domain(channel_, "www", &ptr));
  EXPECT_EQ(nullptr, ptr);
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
  return ioctlsocket(s, FIONBIO, &flags);
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
