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

extern "C" {
  #include "ares_private.h"
}

// library initialization is only needed for windows builds
#ifdef WIN32
#define EXPECTED_NONINIT ARES_ENOTINITIALIZED
#else
#define EXPECTED_NONINIT ARES_SUCCESS
#endif

namespace ares {
namespace test {

TEST(LibraryInit, Basic) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, UnexpectedCleanup) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, DISABLED_InvalidParam) {
  // TODO: police flags argument to ares_library_init()
  EXPECT_EQ(ARES_EBADQUERY, ares_library_init(ARES_LIB_INIT_ALL << 2));
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  ares_library_cleanup();
}

TEST(LibraryInit, Nested) {
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(ARES_SUCCESS, ares_library_initialized());
  ares_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ares_library_initialized());
}

TEST(LibraryInit, BasicChannelInit) {
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  EXPECT_NE(nullptr, channel);
  ares_destroy(channel);
  ares_library_cleanup();
}

TEST_F(LibraryTest, OptionsChannelInit) {
  struct ares_options opts;
  int optmask = 0;
  memset(&opts, 0, sizeof(opts));
  opts.flags = ARES_FLAG_USEVC | ARES_FLAG_PRIMARY;
  optmask |= ARES_OPT_FLAGS;
  opts.timeout = 2000;
  optmask |= ARES_OPT_TIMEOUTMS;
  opts.tries = 2;
  optmask |= ARES_OPT_TRIES;
  opts.ndots = 4;
  optmask |= ARES_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= ARES_OPT_MAXTIMEOUTMS;
  opts.maxtimeout = 10000;
  optmask |= ARES_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= ARES_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc((size_t)opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= ARES_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc((size_t)opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= ARES_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= ARES_OPT_LOOKUPS;
  optmask |= ARES_OPT_ROTATE;
  opts.resolvconf_path = strdup("/etc/resolv.conf");
  optmask |= ARES_OPT_RESOLVCONF;
  opts.hosts_path = strdup("/etc/hosts");
  optmask |= ARES_OPT_HOSTS_FILE;

  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  ares_channel_t *channel2 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_dup(&channel2, channel));
  EXPECT_NE(nullptr, channel2);

  struct ares_options opts2;
  int optmask2 = 0;
  memset(&opts2, 0, sizeof(opts2));
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel2, &opts2, &optmask2));

  // Note that not all opts-settable fields are saved (e.g.
  // ednspsz, socket_{send,receive}_buffer_size).
  EXPECT_EQ(opts.flags, opts2.flags);
  EXPECT_EQ(opts.timeout, opts2.timeout);
  EXPECT_EQ(opts.tries, opts2.tries);
  EXPECT_EQ(opts.ndots, opts2.ndots);
  EXPECT_EQ(opts.maxtimeout, opts2.maxtimeout);
  EXPECT_EQ(opts.udp_port, opts2.udp_port);
  EXPECT_EQ(opts.tcp_port, opts2.tcp_port);
  EXPECT_EQ(1, opts2.nservers);  // Truncated by ARES_FLAG_PRIMARY
  EXPECT_EQ(opts.servers[0].s_addr, opts2.servers[0].s_addr);
  EXPECT_EQ(opts.ndomains, opts2.ndomains);
  EXPECT_EQ(std::string(opts.domains[0]), std::string(opts2.domains[0]));
  EXPECT_EQ(std::string(opts.domains[1]), std::string(opts2.domains[1]));
  EXPECT_EQ(std::string(opts.lookups), std::string(opts2.lookups));
  EXPECT_EQ(std::string(opts.resolvconf_path), std::string(opts2.resolvconf_path));
  EXPECT_EQ(std::string(opts.hosts_path), std::string(opts2.hosts_path));

  ares_destroy_options(&opts);
  ares_destroy_options(&opts2);
  ares_destroy(channel);
  ares_destroy(channel2);
}

TEST_F(LibraryTest, ChannelAllocFail) {
  ares_channel_t *channel;
  for (int ii = 1; ii <= 25; ii++) {
    ClearFails();
    SetAllocFail(ii);
    channel = nullptr;
    int rc = ares_init(&channel);
    // The number of allocations depends on local environment, so don't expect ENOMEM.
    if (rc == ARES_ENOMEM) {
      EXPECT_EQ(nullptr, channel);
    } else {
      ares_destroy(channel);
    }
  }
}

TEST_F(LibraryTest, OptionsChannelAllocFail) {
  struct ares_options opts;
  int optmask = 0;
  memset(&opts, 0, sizeof(opts));
  opts.flags = ARES_FLAG_USEVC;
  optmask |= ARES_OPT_FLAGS;
  opts.timeout = 2;
  optmask |= ARES_OPT_TIMEOUT;
  opts.tries = 2;
  optmask |= ARES_OPT_TRIES;
  opts.ndots = 4;
  optmask |= ARES_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= ARES_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= ARES_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= ARES_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc((size_t)opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= ARES_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc((size_t)opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= ARES_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= ARES_OPT_LOOKUPS;
  optmask |= ARES_OPT_ROTATE;
  opts.resolvconf_path = strdup("/etc/resolv.conf");
  optmask |= ARES_OPT_RESOLVCONF;
  opts.hosts_path = strdup("/etc/hosts");
  optmask |= ARES_OPT_HOSTS_FILE;

  ares_channel_t *channel = nullptr;
  for (int ii = 1; ii <= 8; ii++) {
    ClearFails();
    SetAllocFail(ii);
    int rc = ares_init_options(&channel, &opts, optmask);
    if (rc == ARES_ENOMEM) {
      EXPECT_EQ(nullptr, channel);
    } else {
      EXPECT_EQ(ARES_SUCCESS, rc);
      ares_destroy(channel);
      channel = nullptr;
    }
  }
  ClearFails();

  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  // Add some servers and a sortlist for flavour.
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_servers_csv(channel, "1.2.3.4,0102:0304:0506:0708:0910:1112:1314:1516,2.3.4.5"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel, "1.2.3.4 2.3.4.5"));

  ares_channel_t *channel2 = nullptr;
  for (int ii = 1; ii <= 18; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_dup(&channel2, channel)) << ii;
    EXPECT_EQ(nullptr, channel2) << ii;
  }

  struct ares_options opts2;
  int optmask2 = 0;
  for (int ii = 1; ii <= 6; ii++) {
    memset(&opts2, 0, sizeof(opts2));
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_save_options(channel, &opts2, &optmask2)) << ii;
    // May still have allocations even after ARES_ENOMEM return code.
    ares_destroy_options(&opts2);
  }
  ares_destroy_options(&opts);
  ares_destroy(channel);
}

TEST_F(LibraryTest, FailChannelInit) {
  EXPECT_EQ(ARES_SUCCESS,
            ares_library_init_mem(ARES_LIB_INIT_ALL,
                                  &LibraryTest::amalloc,
                                  &LibraryTest::afree,
                                  &LibraryTest::arealloc));
  SetAllocFail(1);
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_ENOMEM, ares_init(&channel));
  EXPECT_EQ(nullptr, channel);
  ares_library_cleanup();
}

#ifndef WIN32
TEST_F(LibraryTest, EnvInit) {
  ares_channel_t *channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  ares_destroy(channel);
}

TEST_F(LibraryTest, EnvInitModernOptions) {
  ares_channel_t *channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug retrans:2 ndots:3 attempts:4 timeout:5 rotate");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  channel->optmask |= ARES_OPT_TRIES;
  channel->optmask |= ARES_OPT_TIMEOUTMS;

  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel, &opts, &optmask));
  EXPECT_EQ(5000, opts.timeout);
  EXPECT_EQ(4, opts.tries);

  ares_destroy(channel);
}

TEST_F(LibraryTest, EnvInitAllocFail) {
  ares_channel_t *channel;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  for (int ii = 1; ii <= 10; ii++) {
    ClearFails();
    SetAllocFail(ii);
    channel = nullptr;
    int rc = ares_init(&channel);
    if (rc == ARES_SUCCESS) {
      ares_destroy(channel);
    } else {
      EXPECT_EQ(ARES_ENOMEM, rc);
    }
  }
}
#endif

TEST_F(DefaultChannelTest, SetAddresses) {
  ares_set_local_ip4(channel_, 0x01020304);
  byte addr6[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  ares_set_local_ip6(channel_, addr6);
  ares_set_local_dev(channel_, "dummy");
}

TEST_F(DefaultChannelTest, SetSortlistFailures) {
  EXPECT_EQ(ARES_ENODATA, ares_set_sortlist(nullptr, "1.2.3.4"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "111.111.111.111*/16"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "111.111.111.111/255.255.255.240*"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "1 0123456789012345"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "1 /01234567890123456789012345678901"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "xyzzy ; lwk"));
  EXPECT_EQ(ARES_EBADSTR, ares_set_sortlist(channel_, "xyzzy ; 0x123"));
}

TEST_F(DefaultChannelTest, SetSortlistVariants) {
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "1.2.3.4"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "1.2.3.4 ; 2.3.4.5"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "1.2.3.4/26;1234::5678/126;4.5.6.7;5678::1234"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, " 1.2.3.4/26 1234::5678/126   4.5.6.7 5678::1234  "));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "129.1.1.1"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "192.1.1.1"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "224.1.1.1"));
  EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "225.1.1.1"));
}

TEST_F(DefaultChannelTest, SetSortlistAllocFail) {
  for (int ii = 1; ii <= 3; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_set_sortlist(channel_, "12.13.0.0/16 1234::5678/40 1.2.3.4")) << ii;
  }
}

#ifdef USE_WINSOCK
TEST(Init, NoLibraryInit) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_ENOTINITIALIZED, ares_init(&channel));
}
#endif

#ifdef HAVE_CONTAINER
// These tests rely on the ability of non-root users to create a chroot
// using Linux namespaces.


// The library uses a variety of information sources to initialize a channel,
// in particular to determine:
//  - search: the search domains to use
//  - servers: the name servers to use
//  - lookup: whether to check files or DNS or both (e.g. "fb")
//  - options: various resolver options
//  - sortlist: the order of preference for IP addresses
//
// The first source from the following list is used:
//  - init_by_options(): explicitly specified values in struct ares_options
//  - init_by_environment(): values from the environment:
//     - LOCALDOMAIN -> search (single value)
//     - RES_OPTIONS -> options
//  - init_by_resolv_conf(): values from various config files:
//     - /etc/resolv.conf -> search, lookup, servers, sortlist, options
//     - /etc/nsswitch.conf -> lookup
//     - /etc/host.conf -> lookup
//     - /etc/svc.conf -> lookup
//  - init_by_defaults(): fallback values:
//     - gethostname(3) -> domain
//     - "fb" -> lookup

NameContentList filelist = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"
                       "search first.com second.com\n"},
  {"/etc/hosts", "3.4.5.6 ahostname.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerChannelInit,
                 "myhostname", "mydomainname.org", filelist) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "1.2.3.4:53";
  EXPECT_EQ(expected, actual);
  EXPECT_EQ(2, channel->ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(channel->domains[0]));
  EXPECT_EQ(std::string("second.com"), std::string(channel->domains[1]));

  HostResult result;
  ares_gethostbyname(channel, "ahostname.com", AF_INET, HostCallback, &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;

  EXPECT_EQ("{'ahostname.com' aliases=[] addrs=[3.4.5.6]}", ss.str());

  ares_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerSortlistOptionInit,
                 "myhostname", "mydomainname.org", filelist) {
  ares_channel_t *channel = nullptr;
  struct ares_options opts = {0};
  int optmask = 0;
  optmask |= ARES_OPT_SORTLIST;
  opts.nsort = 0;
  // Explicitly specifying an empty sortlist in the options should override the
  // environment.
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  EXPECT_EQ(0, channel->nsort);
  EXPECT_EQ(nullptr, channel->sortlist);
  EXPECT_EQ(ARES_OPT_SORTLIST, (channel->optmask & ARES_OPT_SORTLIST));

  ares_destroy(channel);
  return HasFailure();
}

NameContentList fullresolv = {
  {"/etc/resolv.conf", " nameserver   1.2.3.4 \n"
                       "search   first.com second.com\n"
                       "lookup bind\n"
                       "options debug ndots:5\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerFullResolvInit,
                 "myhostname", "mydomainname.org", fullresolv) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(std::string("b"), std::string(channel->lookups));
  EXPECT_EQ(5, channel->ndots);

  ares_destroy(channel);
  return HasFailure();
}

// Allow path for resolv.conf to be configurable
NameContentList myresolvconf = {
  {"/tmp/myresolv.cnf", " nameserver   1.2.3.4 \n"
                       "search   first.com second.com\n"
                       "lookup bind\n"
                       "options debug ndots:5\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMyResolvConfInit,
                 "myhostname", "mydomain.org", myresolvconf) {
  char filename[] = "/tmp/myresolv.cnf";
  ares_channel_t *channel = nullptr;
  struct ares_options options = {0};
  options.resolvconf_path = strdup(filename);
  int optmask = ARES_OPT_RESOLVCONF;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &options, optmask));

  optmask = 0;
  free(options.resolvconf_path);
  options.resolvconf_path = NULL;

  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel, &options, &optmask));
  EXPECT_EQ(ARES_OPT_RESOLVCONF, (optmask & ARES_OPT_RESOLVCONF));
  EXPECT_EQ(std::string(filename), std::string(options.resolvconf_path));

  ares_destroy_options(&options);
  ares_destroy(channel);
  return HasFailure();
}

// Allow hosts path to be configurable
NameContentList myhosts = {
  {"/tmp/hosts", "10.0.12.26     foobar\n"
                 "2001:A0:C::1A  foobar\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMyHostsInit,
                 "myhostname", "mydomain.org", myhosts) {
  char filename[] = "/tmp/hosts";
  ares_channel_t *channel = nullptr;
  struct ares_options options = {0};
  options.hosts_path = strdup(filename);
  int optmask = ARES_OPT_HOSTS_FILE;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &options, optmask));

  optmask = 0;
  free(options.hosts_path);
  options.hosts_path = NULL;

  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel, &options, &optmask));
  EXPECT_EQ(ARES_OPT_HOSTS_FILE, (optmask & ARES_OPT_HOSTS_FILE));
  EXPECT_EQ(std::string(filename), std::string(options.hosts_path));

  ares_destroy_options(&options);
  ares_destroy(channel);
  return HasFailure();
}

NameContentList hostconf = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "sortlist1.2.3.4\n"  // malformed line
                       "search first.com second.com\n"},
  {"/etc/host.conf", "order bind hosts\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerHostConfInit,
                 "myhostname", "mydomainname.org", hostconf) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(std::string("bf"), std::string(channel->lookups));

  ares_destroy(channel);
  return HasFailure();
}

NameContentList svcconf = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "search first.com second.com\n"},
  {"/etc/svc.conf", "hosts= bind\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerSvcConfInit,
                 "myhostname", "mydomainname.org", svcconf) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(std::string("b"), std::string(channel->lookups));

  ares_destroy(channel);
  return HasFailure();
}

NameContentList malformedresolvconflookup = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "lookup garbage\n"}};  // malformed line
CONTAINED_TEST_F(LibraryTest, ContainerMalformedResolvConfLookup,
                 "myhostname", "mydomainname.org", malformedresolvconflookup) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(std::string("fb"), std::string(channel->lookups));

  ares_destroy(channel);
  return HasFailure();
}

// Failures when expected config filenames are inaccessible.
class MakeUnreadable {
 public:
  explicit MakeUnreadable(const std::string& filename)
    : filename_(filename) {
    chmod(filename_.c_str(), 0000);
  }
  ~MakeUnreadable() { chmod(filename_.c_str(), 0644); }
 private:
  std::string filename_;
};

CONTAINED_TEST_F(LibraryTest, ContainerResolvConfNotReadable,
                 "myhostname", "mydomainname.org", filelist) {
  ares_channel_t *channel = nullptr;
  MakeUnreadable hide("/etc/resolv.conf");
  // Unavailable /etc/resolv.conf falls back to defaults
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerNsswitchConfNotReadable,
                 "myhostname", "mydomainname.org", filelist) {
  ares_channel_t *channel = nullptr;
  // Unavailable /etc/nsswitch.conf falls back to defaults.
  MakeUnreadable hide("/etc/nsswitch.conf");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(std::string("fb"), std::string(channel->lookups));

  ares_destroy(channel);
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerHostConfNotReadable,
                 "myhostname", "mydomainname.org", hostconf) {
  ares_channel_t *channel = nullptr;
  // Unavailable /etc/host.conf falls back to defaults.
  MakeUnreadable hide("/etc/host.conf");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  ares_destroy(channel);
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerSvcConfNotReadable,
                 "myhostname", "mydomainname.org", svcconf) {
  ares_channel_t *channel = nullptr;
  // Unavailable /etc/svc.conf falls back to defaults.
  MakeUnreadable hide("/etc/svc.conf");
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  ares_destroy(channel);
  return HasFailure();
}

NameContentList rotateenv = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "search first.com second.com\n"
                       "options rotate\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerRotateInit,
                 "myhostname", "mydomainname.org", rotateenv) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(ARES_TRUE, channel->rotate);

  ares_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerRotateOverride,
                 "myhostname", "mydomainname.org", rotateenv) {
  ares_channel_t *channel = nullptr;
  struct ares_options opts = {0};
  int optmask = ARES_OPT_NOROTATE;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  optmask = 0;
  ares_save_options(channel, &opts, &optmask);
  EXPECT_EQ(ARES_OPT_NOROTATE, (optmask & ARES_OPT_NOROTATE));
  ares_destroy_options(&opts);

  ares_destroy(channel);
  return HasFailure();
}

// Test that blacklisted IPv6 resolves are ignored.  They're filtered from any
// source, so resolv.conf is as good as any.
NameContentList blacklistedIpv6 = {
  {"/etc/resolv.conf", " nameserver 254.192.1.1\n" // 0xfe.0xc0.0x01.0x01
                       " nameserver fec0::dead\n"  // Blacklisted
                       " nameserver ffc0::c001\n"  // Not blacklisted
                       " domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerBlacklistedIpv6,
                 "myhostname", "mydomainname.org", blacklistedIpv6) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "254.192.1.1:53,"
                         "[ffc0::c001]:53";
  EXPECT_EQ(expected, actual);

  EXPECT_EQ(1, channel->ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(channel->domains[0]));

  ares_destroy(channel);
  return HasFailure();
}

NameContentList multiresolv = {
  {"/etc/resolv.conf", " nameserver 1::2 ;  ;;\n"
                       " domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMultiResolvInit,
                 "myhostname", "mydomainname.org", multiresolv) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "[1::2]:53";
  EXPECT_EQ(expected, actual);

  EXPECT_EQ(1, channel->ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(channel->domains[0]));

  ares_destroy(channel);
  return HasFailure();
}

NameContentList systemdresolv = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: junk resolve files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerSystemdResolvInit,
                 "myhostname", "mydomainname.org", systemdresolv) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(std::string("bf"), std::string(channel->lookups));

  ares_destroy(channel);
  return HasFailure();
}

NameContentList empty = {};  // no files
CONTAINED_TEST_F(LibraryTest, ContainerEmptyInit,
                 "host.domain.org", "domain.org", empty) {
  ares_channel_t *channel = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "127.0.0.1:53";
  EXPECT_EQ(expected, actual);

  EXPECT_EQ(1, channel->ndomains);
  EXPECT_EQ(std::string("domain.org"), std::string(channel->domains[0]));
  EXPECT_EQ(std::string("fb"), std::string(channel->lookups));

  ares_destroy(channel);
  return HasFailure();
}

#endif

}  // namespace test
}  // namespace ares
