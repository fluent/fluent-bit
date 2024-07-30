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

#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <sstream>
#include <vector>

using testing::InvokeWithoutArgs;
using testing::DoAll;

namespace ares {
namespace test {

class NoDNS0x20MockTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<int> {
 public:
  NoDNS0x20MockTest()
    : MockChannelOptsTest(1, GetParam(), false,
                          FillOptions(&opts_),
                          ARES_OPT_FLAGS) {}
  static struct ares_options* FillOptions(struct ares_options * opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->flags = ARES_FLAG_EDNS;
    return opts;
  }
 private:
  struct ares_options opts_;
};


TEST_P(NoDNS0x20MockTest, Basic) {
  std::vector<byte> reply = {
    0x00, 0x00,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // 1 question
    0x00, 0x01,  // 1 answer RRs
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer
    0x03, 'w', 'w', 'w',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    0x00, 0x00, 0x01, 0x00,  // TTL
    0x00, 0x04,  // rdata length
    0x01, 0x02, 0x03, 0x04
  };

  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReplyData(&server_, reply));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockUDPChannelTest, DNS0x20BadReply) {
  std::vector<byte> reply = {
    0x00, 0x00,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // 1 question
    0x00, 0x01,  // 1 answer RRs
    0x00, 0x00,  // 0 authority RRs
    0x00, 0x00,  // 0 additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x1D, 's', 'o', 'm', 'e', 'l', 'o', 'n', 'g', 'd', 'o', 'm', 'a', 'i', 'n', 'n', 'a', 'm', 'e', 'b', 'e', 'c', 'a', 'u', 's', 'e', 'p', 'r', 'n', 'g',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer
    0x03, 'w', 'w', 'w',
    0x1D, 's', 'o', 'm', 'e', 'l', 'o', 'n', 'g', 'd', 'o', 'm', 'a', 'i', 'n', 'n', 'a', 'm', 'e', 'b', 'e', 'c', 'a', 'u', 's', 'e', 'p', 'r', 'n', 'g',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    0x00, 0x00, 0x01, 0x00,  // TTL
    0x00, 0x04,  // rdata length
    0x01, 0x02, 0x03, 0x04
  };

  ON_CALL(server_, OnRequest("www.somelongdomainnamebecauseprng.com", T_A))
    .WillByDefault(SetReplyData(&server_, reply));

  /* Reply will be thrown out due to mismatched case for DNS 0x20 in response,
   * its technically possible this test case may not fail if somehow the
   * PRNG returns all lowercase domain name so we need to make this domain
   * fairly long to make sure those odds are very very very low */
  HostResult result;
  ares_gethostbyname(channel_, "www.somelongdomainnamebecauseprng.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ETIMEOUT, result.status_);
}

// UDP only so mock server doesn't get confused by concatenated requests
TEST_P(MockUDPChannelTest, GetHostByNameParallelLookups) {
  DNSPacket rsp1;
  rsp1.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp1));
  DNSPacket rsp2;
  rsp2.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", T_A))
    .add_answer(new DNSARR("www.example.com", 100, {1, 2, 3, 4}));
  ON_CALL(server_, OnRequest("www.example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp2));

  HostResult result1;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result1);
  HostResult result2;
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result2);
  HostResult result3;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result3);
  Process();
  EXPECT_TRUE(result1.done_);
  EXPECT_TRUE(result2.done_);
  EXPECT_TRUE(result3.done_);
  std::stringstream ss1;
  ss1 << result1.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss1.str());
  std::stringstream ss2;
  ss2 << result2.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[1.2.3.4]}", ss2.str());
  std::stringstream ss3;
  ss3 << result3.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss3.str());
}

// UDP to TCP specific test
TEST_P(MockUDPChannelTest, TruncationRetry) {
  DNSPacket rsptruncated;
  rsptruncated.set_response().set_aa().set_tc()
    .add_question(new DNSQuestion("www.google.com", T_A));
  DNSPacket rspok;
  rspok.set_response()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {1, 2, 3, 4}));
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsptruncated))
    .WillOnce(SetReply(&server_, &rspok));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockUDPChannelTest, UTF8BadName) {
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("españa.icom.museum", T_A))
    .add_answer(new DNSARR("españa.icom.museum", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("españa.icom.museum", T_A))
    .WillByDefault(SetReply(&server_, &reply));

  HostResult result;
  ares_gethostbyname(channel_, "españa.icom.museum", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EBADNAME, result.status_);
}

static int sock_cb_count = 0;
static int SocketConnectCallback(ares_socket_t fd, int type, void *data) {
  int rc = *(int*)data;
  (void)type;
  if (verbose) std::cerr << "SocketConnectCallback(" << fd << ") invoked" << std::endl;
  sock_cb_count++;
  return rc;
}

TEST_P(MockChannelTest, SockCallback) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsp));

  // Get notified of new sockets
  int rc = ARES_SUCCESS;
  ares_set_socket_callback(channel_, SocketConnectCallback, &rc);

  HostResult result;
  sock_cb_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_EQ(1, sock_cb_count);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SockFailCallback) {
  // Notification of new sockets gives an error.
  int rc = -1;
  ares_set_socket_callback(channel_, SocketConnectCallback, &rc);

  HostResult result;
  sock_cb_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_LT(1, sock_cb_count);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECONNREFUSED, result.status_);
}

static int sock_config_cb_count = 0;
static int SocketConfigureCallback(ares_socket_t fd, int type, void *data) {
  int rc = *(int*)data;
  (void)type;
  if (verbose) std::cerr << "SocketConfigureCallback(" << fd << ") invoked" << std::endl;
  sock_config_cb_count++;
  return rc;
}

TEST_P(MockChannelTest, SockConfigureCallback) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsp));

  // Get notified of new sockets
  int rc = ARES_SUCCESS;
  ares_set_socket_configure_callback(channel_, SocketConfigureCallback, &rc);

  HostResult result;
  sock_config_cb_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_EQ(1, sock_config_cb_count);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SockConfigureFailCallback) {
  // Notification of new sockets gives an error.
  int rc = -1;
  ares_set_socket_configure_callback(channel_, SocketConfigureCallback, &rc);

  HostResult result;
  sock_config_cb_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_LT(1, sock_config_cb_count);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECONNREFUSED, result.status_);
}

// Define a server state callback for testing. The custom userdata should be
// the expected server string that the callback is invoked with.
static int server_state_cb_success_count = 0;
static int server_state_cb_failure_count = 0;
static void ServerStateCallback(const char *server_string,
                                ares_bool_t success, int flags, void *data) {
  // Increment overall success/failure counts appropriately.
  if (verbose) std::cerr << "ServerStateCallback("
                         << server_string << ", "
                         << success       << ", "
                         << flags         << ") invoked" << std::endl;
  if (success == ARES_TRUE) server_state_cb_success_count++;
  else server_state_cb_failure_count++;

  // Check that the server string is as expected.
  char *exp_server_string = *(char **)(data);
  EXPECT_STREQ(exp_server_string, server_string);

  // The callback should be invoked with either the UDP flag or the TCP flag,
  // but not both.
  ares_bool_t udp = (flags & ARES_SERV_STATE_UDP) ? ARES_TRUE: ARES_FALSE;
  ares_bool_t tcp = (flags & ARES_SERV_STATE_TCP) ? ARES_TRUE: ARES_FALSE;
  EXPECT_NE(udp, tcp);
}

TEST_P(MockChannelTest, ServStateCallbackSuccess) {
  // Set up the server response. The server returns successfully with an answer
  // to the query.
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsp));

  // Set up the server state callback. The channel used for this test has a
  // single server configured.
  char *exp_server_string = ares_get_servers_csv(channel_);
  ares_set_server_state_callback(channel_, ServerStateCallback,
                                 &exp_server_string);

  // Perform the hostname lookup. Expect 1 successful query to the server.
  HostResult result;
  server_state_cb_success_count = 0;
  server_state_cb_failure_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_EQ(1, server_state_cb_success_count);
  EXPECT_EQ(0, server_state_cb_failure_count);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());

  ares_free_string(exp_server_string);
}

TEST_P(MockChannelTest, ServStateCallbackFailure) {
  // Set up the server response. The server always returns SERVFAIL.
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(SERVFAIL);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));

  // Set up the server state callback. The channel used for this test has a
  // single server configured.
  char *exp_server_string = ares_get_servers_csv(channel_);
  ares_set_server_state_callback(channel_, ServerStateCallback,
                                 &exp_server_string);

  // Perform the hostname lookup. Expect 3 failed queries to the server (due to
  // retries).
  HostResult result;
  server_state_cb_success_count = 0;
  server_state_cb_failure_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_EQ(0, server_state_cb_success_count);
  EXPECT_EQ(3, server_state_cb_failure_count);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ESERVFAIL, result.status_);

  ares_free_string(exp_server_string);
}

TEST_P(MockChannelTest, ServStateCallbackRecover) {
  // Set up the server response. The server initially times out, but then
  // returns successfully (with NXDOMAIN) on the first retry.
  std::vector<byte> nothing;
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(NXDOMAIN);
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReply(&server_, &rsp));

  // Set up the server state callback. The channel used for this test has a
  // single server configured.
  char *exp_server_string = ares_get_servers_csv(channel_);
  ares_set_server_state_callback(channel_, ServerStateCallback,
                                 &exp_server_string);

  // Perform the hostname lookup. Expect 1 failed query and 1 successful query
  // to the server.
  HostResult result;
  server_state_cb_success_count = 0;
  server_state_cb_failure_count = 0;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback,
                     &result);
  Process();
  EXPECT_EQ(1, server_state_cb_success_count);
  EXPECT_EQ(1, server_state_cb_failure_count);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTFOUND, result.status_);

  ares_free_string(exp_server_string);
}

TEST_P(MockChannelTest, ReInit) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  EXPECT_EQ(ARES_SUCCESS, ares_reinit(channel_));
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

#define MAXUDPQUERIES_TOTAL 32
#define MAXUDPQUERIES_LIMIT 8

class MockUDPMaxQueriesTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<int> {
 public:
  MockUDPMaxQueriesTest()
    : MockChannelOptsTest(1, GetParam(), false,
                          FillOptions(&opts_),
                          ARES_OPT_UDP_MAX_QUERIES) {}
  static struct ares_options* FillOptions(struct ares_options * opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->udp_max_queries = MAXUDPQUERIES_LIMIT;
    return opts;
  }
 private:
  struct ares_options opts_;
};

TEST_P(MockUDPMaxQueriesTest, GetHostByNameParallelLookups) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));

  // Get notified of new sockets so we can validate how many are created
  int rc = ARES_SUCCESS;
  ares_set_socket_callback(channel_, SocketConnectCallback, &rc);
  sock_cb_count = 0;

  HostResult result[MAXUDPQUERIES_TOTAL];
  for (size_t i=0; i<MAXUDPQUERIES_TOTAL; i++) {
    ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result[i]);
  }

  Process();

  EXPECT_EQ(MAXUDPQUERIES_TOTAL / MAXUDPQUERIES_LIMIT, sock_cb_count);

  for (size_t i=0; i<MAXUDPQUERIES_TOTAL; i++) {
    std::stringstream ss;
    EXPECT_TRUE(result[i].done_);
    ss << result[i].host_;
    EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  }
}

class CacheQueriesTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface<int> {
 public:
  CacheQueriesTest()
    : MockChannelOptsTest(1, GetParam(), false,
                          FillOptions(&opts_),
                          ARES_OPT_QUERY_CACHE) {}
  static struct ares_options* FillOptions(struct ares_options * opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->qcache_max_ttl = 3600;
    return opts;
  }
 private:
  struct ares_options opts_;
};

TEST_P(CacheQueriesTest, GetHostByNameCache) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));

  // Get notified of new sockets so we can validate how many are created
  int rc = ARES_SUCCESS;
  ares_set_socket_callback(channel_, SocketConnectCallback, &rc);
  sock_cb_count = 0;

  HostResult result1;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result1);
  Process();

  std::stringstream ss1;
  EXPECT_TRUE(result1.done_);
  ss1 << result1.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss1.str());

  /* Run again, should return cached result */
  HostResult result2;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result2);
  Process();

  std::stringstream ss2;
  EXPECT_TRUE(result2.done_);
  ss2 << result2.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss2.str());

  EXPECT_EQ(1, sock_cb_count);
}

#define TCPPARALLELLOOKUPS 32
TEST_P(MockTCPChannelTest, GetHostByNameParallelLookups) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));

  // Get notified of new sockets so we can validate how many are created
  int rc = ARES_SUCCESS;
  ares_set_socket_callback(channel_, SocketConnectCallback, &rc);
  sock_cb_count = 0;

  HostResult result[TCPPARALLELLOOKUPS];
  for (size_t i=0; i<TCPPARALLELLOOKUPS; i++) {
    ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result[i]);
  }

  Process();

  EXPECT_EQ(1, sock_cb_count);

  for (size_t i=0; i<TCPPARALLELLOOKUPS; i++) {
    std::stringstream ss;
    EXPECT_TRUE(result[i].done_);
    ss << result[i].host_;
    EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  }
}

TEST_P(MockTCPChannelTest, MalformedResponse) {
  std::vector<byte> one = {0x00};
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReplyData(&server_, one));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EBADRESP, result.status_);
}

TEST_P(MockTCPChannelTest, FormErrResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(FORMERR);
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EFORMERR, result.status_);
}

TEST_P(MockTCPChannelTest, ServFailResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(SERVFAIL);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ESERVFAIL, result.status_);
}

TEST_P(MockTCPChannelTest, NotImplResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(NOTIMP);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

TEST_P(MockTCPChannelTest, RefusedResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(REFUSED);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EREFUSED, result.status_);
}

TEST_P(MockTCPChannelTest, YXDomainResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(YXDOMAIN);
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENODATA, result.status_);
}

class MockExtraOptsTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockExtraOptsTest()
    : MockChannelOptsTest(1, GetParam().first, GetParam().second,
                          FillOptions(&opts_),
                          ARES_OPT_SOCK_SNDBUF|ARES_OPT_SOCK_RCVBUF) {}
  static struct ares_options* FillOptions(struct ares_options * opts) {
    memset(opts, 0, sizeof(struct ares_options));
    // Set a few options that affect socket communications
    opts->socket_send_buffer_size = 514;
    opts->socket_receive_buffer_size = 514;
    return opts;
  }
 private:
  struct ares_options opts_;
};

TEST_P(MockExtraOptsTest, SimpleQuery) {
  ares_set_local_ip4(channel_, 0x7F000001);
  byte addr6[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  ares_set_local_ip6(channel_, addr6);
  ares_set_local_dev(channel_, "dummy");

  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

class MockFlagsChannelOptsTest
    : public MockChannelOptsTest,
      public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockFlagsChannelOptsTest(int flags)
    : MockChannelOptsTest(1, GetParam().first, GetParam().second,
                          FillOptions(&opts_, flags), ARES_OPT_FLAGS) {}
  static struct ares_options* FillOptions(struct ares_options * opts, int flags) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->flags = flags;
    return opts;
  }
 private:
  struct ares_options opts_;
};

class MockNoCheckRespChannelTest : public MockFlagsChannelOptsTest {
 public:
  MockNoCheckRespChannelTest() : MockFlagsChannelOptsTest(ARES_FLAG_NOCHECKRESP) {}
};

TEST_P(MockNoCheckRespChannelTest, ServFailResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(SERVFAIL);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ESERVFAIL, result.status_);
}

TEST_P(MockNoCheckRespChannelTest, NotImplResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(NOTIMP);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOTIMP, result.status_);
}

TEST_P(MockNoCheckRespChannelTest, RefusedResponse) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A));
  rsp.set_rcode(REFUSED);
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EREFUSED, result.status_);
}

class MockEDNSChannelTest : public MockFlagsChannelOptsTest {
 public:
  MockEDNSChannelTest() : MockFlagsChannelOptsTest(ARES_FLAG_EDNS) {}
};

TEST_P(MockEDNSChannelTest, RetryWithoutEDNS) {
  DNSPacket rspfail;
  rspfail.set_response().set_aa().set_rcode(FORMERR)
    .add_question(new DNSQuestion("www.google.com", T_A));
  DNSPacket rspok;
  rspok.set_response()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 100, {1, 2, 3, 4}));
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReply(&server_, &rspfail))
    .WillOnce(SetReply(&server_, &rspok));
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, SearchDomains) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.first.com", T_A));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.second.org", T_A));
  ON_CALL(server_, OnRequest("www.second.org", T_A))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", T_A))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillByDefault(SetReply(&server_, &yesthird));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, SearchDomainsWithResentReply) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.first.com", T_A));
  EXPECT_CALL(server_, OnRequest("www.first.com", T_A))
    .WillOnce(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.second.org", T_A));
  EXPECT_CALL(server_, OnRequest("www.second.org", T_A))
    .WillOnce(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", T_A))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  // Before sending the real answer, resend an earlier reply
  EXPECT_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillOnce(DoAll(SetReply(&server_, &nofirst),
                    SetReplyQID(&server_, 123)))
    .WillOnce(DoAll(SetReply(&server_, &yesthird),
                    SetReplyQID(&server_, -1)));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchDomainsBare) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.first.com", T_A));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.second.org", T_A));
  ON_CALL(server_, OnRequest("www.second.org", T_A))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.third.gov", T_A));
  ON_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillByDefault(SetReply(&server_, &nothird));
  DNSPacket yesbare;
  yesbare.set_response().set_aa()
    .add_question(new DNSQuestion("www", T_A))
    .add_answer(new DNSARR("www", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www", T_A))
    .WillByDefault(SetReply(&server_, &yesbare));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchNoDataThenSuccess) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", T_A));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", T_A));
  ON_CALL(server_, OnRequest("www.second.org", T_A))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", T_A))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillByDefault(SetReply(&server_, &yesthird));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, SearchNoDataThenNoDataBare) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", T_A));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", T_A));
  ON_CALL(server_, OnRequest("www.second.org", T_A))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", T_A));
  ON_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillByDefault(SetReply(&server_, &nothird));
  DNSPacket nobare;
  nobare.set_response().set_aa()
    .add_question(new DNSQuestion("www", T_A));
  ON_CALL(server_, OnRequest("www", T_A))
    .WillByDefault(SetReply(&server_, &nobare));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENODATA, result.status_);
}

TEST_P(MockChannelTest, SearchNoDataThenFail) {
  // First two search domains recognize the name but have no A records.
  DNSPacket nofirst;
  nofirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", T_A));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa()
    .add_question(new DNSQuestion("www.second.org", T_A));
  ON_CALL(server_, OnRequest("www.second.org", T_A))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket nothird;
  nothird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", T_A));
  ON_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillByDefault(SetReply(&server_, &nothird));
  DNSPacket nobare;
  nobare.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www", T_A));
  ON_CALL(server_, OnRequest("www", T_A))
    .WillByDefault(SetReply(&server_, &nobare));

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENODATA, result.status_);
}

TEST_P(MockChannelTest, SearchAllocFailure) {
  SearchResult result;
  SetAllocFail(1);
  ares_search(channel_, "fully.qualified.", C_IN, T_A, SearchCallback, &result);
  /* Already done */
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENOMEM, result.status_);
}

TEST_P(MockChannelTest, SearchHighNdots) {
  DNSPacket nobare;
  nobare.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("a.b.c.w.w.w", T_A));
  ON_CALL(server_, OnRequest("a.b.c.w.w.w", T_A))
    .WillByDefault(SetReply(&server_, &nobare));
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("a.b.c.w.w.w.first.com", T_A))
    .add_answer(new DNSARR("a.b.c.w.w.w.first.com", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("a.b.c.w.w.w.first.com", T_A))
    .WillByDefault(SetReply(&server_, &yesfirst));

  SearchResult result;
  ares_search(channel_, "a.b.c.w.w.w", C_IN, T_A, SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << PacketToString(result.data_);
  EXPECT_EQ("RSP QRY AA NOERROR Q:{'a.b.c.w.w.w.first.com' IN A} "
            "A:{'a.b.c.w.w.w.first.com' IN A TTL=512 2.3.4.5}",
            ss.str());
}

// Test that performing an EDNS search with an OPT RR options value works. The
// options value should be included on the requests to the mock server.
TEST_P(MockEDNSChannelTest, SearchOptVal) {
  /* Define the OPT RR options code and value to use. */
  unsigned short opt_opt = 3;
  unsigned char opt_val[] = { 'c', '-', 'a', 'r', 'e', 's' };

  /* Set up the expected request and reply on the mock server for the first,
   * second and third domains. The expected requests contain the OPT RR options
   * value defined above.
   */
  std::string nofirst_req = "REQ QRY RD  Q:{'example.first.com' IN A} "
    "ADD:{'' MAXUDP=1232 OPT RCODE2=0 "
    "0003"  // opt_opt
    "0006"  // length of opt_val
    "632d61726573"  // opt_val in hex
    "}";
  DNSPacket nofirst_rep;
  nofirst_rep.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("example.first.com", T_A));
  ON_CALL(server_, OnRequest("example.first.com", T_A))
    .WillByDefault(SetReplyExpRequest(&server_, &nofirst_rep, nofirst_req));

  std::string nosecond_req = "REQ QRY RD  Q:{'example.second.org' IN A} "
    "ADD:{'' MAXUDP=1232 OPT RCODE2=0 "
    "0003"  // opt_opt
    "0006"  // length of opt_val
    "632d61726573"  // opt_val in hex
    "}";
  DNSPacket nosecond_rep;
  nosecond_rep.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("example.second.org", T_A));
  ON_CALL(server_, OnRequest("example.second.org", T_A))
    .WillByDefault(SetReplyExpRequest(&server_, &nosecond_rep, nosecond_req));

  std::string nothird_req = "REQ QRY RD  Q:{'example.third.gov' IN A} "
    "ADD:{'' MAXUDP=1232 OPT RCODE2=0 "
    "0003"  // opt_opt
    "0006"  // length of opt_val
    "632d61726573"  // opt_val in hex
    "}";
  DNSPacket nothird_rep;
  nothird_rep.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("example.third.gov", T_A));
  ON_CALL(server_, OnRequest("example.third.gov", T_A))
    .WillByDefault(SetReplyExpRequest(&server_, &nothird_rep, nothird_req));

  /* Set up the expected request and reply on the mock server for the bare
   * domain. The expected request contains the OPT RR options value defined
   * above.
   */
  std::string yesbare_req = "REQ QRY RD  Q:{'example' IN A} "
    "ADD:{'' MAXUDP=1232 OPT RCODE2=0 "
    "0003"  // opt_opt
    "0006"  // length of opt_val
    "632d61726573"  // opt_val in hex
    "}";
  DNSPacket yesbare_rep;
  yesbare_rep.set_response().set_aa()
    .add_question(new DNSQuestion("example", T_A))
    .add_answer(new DNSARR("example", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example", T_A))
    .WillByDefault(SetReplyExpRequest(&server_, &yesbare_rep, yesbare_req));

  /* Construct the DNS record to search. */
  ares_dns_record_t *dnsrec = NULL;
  ares_dns_rr_t *rr = NULL;
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0, ARES_FLAG_RD, ARES_OPCODE_QUERY,
      ARES_RCODE_NOERROR));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_query_add(dnsrec, "example", (ares_dns_rec_type_t)T_A,
      (ares_dns_class_t)C_IN));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "",
      ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, 1232));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_u8(rr, ARES_RR_OPT_VERSION, 0));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_u16(rr, ARES_RR_OPT_FLAGS, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, opt_opt, opt_val,
      sizeof(opt_val)));

  /* Perform the search. Check that it succeeds with the expected response. */
  SearchResult result;
  ares_search_dnsrec(channel_, dnsrec, SearchCallbackDnsRec, &result);
  ares_dns_record_destroy(dnsrec);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << PacketToString(result.data_);
  EXPECT_EQ("RSP QRY AA NOERROR Q:{'example' IN A} "
            "A:{'example' IN A TTL=512 2.3.4.5}",
            ss.str());
}

TEST_P(MockChannelTest, V4WorksV6Timeout) {
  std::vector<byte> nothing;
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));

  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &reply));

  ON_CALL(server_, OnRequest("www.google.com", T_AAAA))
    .WillByDefault(SetReplyData(&server_, nothing));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(1, result.timeouts_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

// Test case for Issue #662
TEST_P(MockChannelTest, PartialQueryCancel) {
  std::vector<byte> nothing;
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));

  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &reply));

  ON_CALL(server_, OnRequest("www.google.com", T_AAAA))
    .WillByDefault(SetReplyData(&server_, nothing));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_UNSPEC, HostCallback, &result);
  // After 100ms, issues ares_cancel(), this should be enough time for the A
  // record reply, but before the timeout on the AAAA record.
  Process(100);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
}

TEST_P(MockChannelTest, UnspecifiedFamilyV6) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", T_AAAA))
    .WillByDefault(SetReply(&server_, &rsp6));

  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A));
  ON_CALL(server_, OnRequest("example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  // Default to IPv6 when both are available.
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2121:0000:0000:0000:0000:0000:0000:0303]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyV4) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA));
  ON_CALL(server_, OnRequest("example.com", T_AAAA))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyNoData) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSCnameRR("example.com", 100, "elsewhere.com"));
  ON_CALL(server_, OnRequest("example.com", T_AAAA))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A));
  ON_CALL(server_, OnRequest("example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'' aliases=[] addrs=[]}", ss.str());
}

TEST_P(MockChannelTest, UnspecifiedFamilyCname6A4) {
  DNSPacket rsp6;
  rsp6.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSCnameRR("example.com", 100, "elsewhere.com"));
  ON_CALL(server_, OnRequest("example.com", T_AAAA))
    .WillByDefault(SetReply(&server_, &rsp6));
  DNSPacket rsp4;
  rsp4.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A))
    .add_answer(new DNSARR("example.com", 100, {1, 2, 3, 4}));
  ON_CALL(server_, OnRequest("example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp4));

  HostResult result;
  ares_gethostbyname(channel_, "example.com.", AF_UNSPEC, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'example.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, ExplicitIP) {
  HostResult result;
  ares_gethostbyname(channel_, "1.2.3.4", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);  // Immediate return
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'1.2.3.4' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, ExplicitIPAllocFail) {
  HostResult result;
  SetAllocSizeFail(strlen("1.2.3.4") + 1);
  ares_gethostbyname(channel_, "1.2.3.4", AF_INET, HostCallback, &result);
  EXPECT_TRUE(result.done_);  // Immediate return
  EXPECT_EQ(ARES_ENOMEM, result.status_);
}

TEST_P(MockChannelTest, SortListV4) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_A))
    .add_answer(new DNSARR("example.com", 100, {22, 23, 24, 25}))
    .add_answer(new DNSARR("example.com", 100, {12, 13, 14, 15}))
    .add_answer(new DNSARR("example.com", 100, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("example.com", T_A))
    .WillByDefault(SetReply(&server_, &rsp));

  {
    EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "12.13.0.0/255.255.0.0 1234::5678"));
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[12.13.14.15, 22.23.24.25, 2.3.4.5]}", ss.str());
  }
  {
    EXPECT_EQ(ARES_SUCCESS, ares_set_sortlist(channel_, "2.3.0.0/16 130.140.150.160/26"));
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[2.3.4.5, 22.23.24.25, 12.13.14.15]}", ss.str());
  }
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel_, &options, &optmask));
  EXPECT_TRUE((optmask & ARES_OPT_SORTLIST) == ARES_OPT_SORTLIST);
  ares_destroy_options(&options);
}

TEST_P(MockChannelTest, SortListV6) {
  DNSPacket rsp;
  rsp.set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02}))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x21, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03}));
  ON_CALL(server_, OnRequest("example.com", T_AAAA))
    .WillByDefault(SetReply(&server_, &rsp));

  {
    ares_set_sortlist(channel_, "1111::/16 2.3.0.0/255.255.0.0");
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET6, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[1111:0000:0000:0000:0000:0000:0000:0202, "
              "2121:0000:0000:0000:0000:0000:0000:0303]}", ss.str());
  }
  {
    ares_set_sortlist(channel_, "2121::/8");
    HostResult result;
    ares_gethostbyname(channel_, "example.com.", AF_INET6, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'example.com' aliases=[] addrs=[2121:0000:0000:0000:0000:0000:0000:0303, "
              "1111:0000:0000:0000:0000:0000:0000:0202]}", ss.str());
  }
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, SearchDomainsAllocFail) {
  DNSPacket nofirst;
  nofirst.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.first.com", T_A));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &nofirst));
  DNSPacket nosecond;
  nosecond.set_response().set_aa().set_rcode(NXDOMAIN)
    .add_question(new DNSQuestion("www.second.org", T_A));
  ON_CALL(server_, OnRequest("www.second.org", T_A))
    .WillByDefault(SetReply(&server_, &nosecond));
  DNSPacket yesthird;
  yesthird.set_response().set_aa()
    .add_question(new DNSQuestion("www.third.gov", T_A))
    .add_answer(new DNSARR("www.third.gov", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.third.gov", T_A))
    .WillByDefault(SetReply(&server_, &yesthird));

  // Fail a variety of different memory allocations, and confirm
  // that the operation either fails with ENOMEM or succeeds
  // with the expected result.
  const int kCount = 34;
  HostResult results[kCount];
  for (int ii = 1; ii <= kCount; ii++) {
    HostResult* result = &(results[ii - 1]);
    ClearFails();
    SetAllocFail(ii);
    ares_gethostbyname(channel_, "www", AF_INET, HostCallback, result);
    Process();
    EXPECT_TRUE(result->done_);
    if (result->status_ == ARES_SUCCESS) {
      std::stringstream ss;
      ss << result->host_;
      EXPECT_EQ("{'www.third.gov' aliases=[] addrs=[2.3.4.5]}", ss.str()) << " failed alloc #" << ii;
      if (verbose) std::cerr << "Succeeded despite failure of alloc #" << ii << std::endl;
    }
  }

  // Explicitly destroy the channel now, so that the HostResult objects
  // are still valid (in case any pending work refers to them).
  ares_destroy(channel_);
  channel_ = nullptr;
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, Resend) {
  std::vector<byte> nothing;
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));

  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(SetReply(&server_, &reply));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(2, result.timeouts_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, CancelImmediate) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  ares_cancel(channel_);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, CancelImmediateGetHostByAddr) {
  HostResult result;
  struct in_addr addr;
  addr.s_addr = htonl(0x08080808);

  ares_gethostbyaddr(channel_, &addr, sizeof(addr), AF_INET, HostCallback, &result);
  ares_cancel(channel_);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

// Relies on retries so is UDP-only
TEST_P(MockUDPChannelTest, CancelLater) {
  std::vector<byte> nothing;

  // On second request, cancel the channel.
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(SetReplyData(&server_, nothing))
    .WillOnce(CancelChannel(&server_, channel_));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ECANCELLED, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, DisconnectFirstAttempt) {
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));

  // On second request, cancel the channel.
  EXPECT_CALL(server_, OnRequest("www.google.com", T_A))
    .WillOnce(Disconnect(&server_))
    .WillOnce(SetReply(&server_, &reply));

  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, GetHostByNameDestroyAbsolute) {
  HostResult result;
  ares_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);

  ares_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByNameDestroyRelative) {
  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);

  ares_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

TEST_P(MockChannelTest, GetHostByNameCNAMENoData) {
  DNSPacket response;
  response.set_response().set_aa()
    .add_question(new DNSQuestion("cname.first.com", T_A))
    .add_answer(new DNSCnameRR("cname.first.com", 100, "a.first.com"));
  ON_CALL(server_, OnRequest("cname.first.com", T_A))
    .WillByDefault(SetReply(&server_, &response));

  HostResult result;
  ares_gethostbyname(channel_, "cname.first.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_ENODATA, result.status_);
}

TEST_P(MockChannelTest, GetHostByAddrDestroy) {
  unsigned char gdns_addr4[4] = {0x08, 0x08, 0x08, 0x08};
  HostResult result;
  ares_gethostbyaddr(channel_, gdns_addr4, sizeof(gdns_addr4), AF_INET, HostCallback, &result);

  ares_destroy(channel_);
  channel_ = nullptr;

  EXPECT_TRUE(result.done_);  // Synchronous
  EXPECT_EQ(ARES_EDESTRUCTION, result.status_);
  EXPECT_EQ(0, result.timeouts_);
}

#ifndef WIN32
TEST_P(MockChannelTest, HostAlias) {
  DNSPacket reply;
  reply.set_response().set_aa()
    .add_question(new DNSQuestion("www.google.com", T_A))
    .add_answer(new DNSARR("www.google.com", 0x0100, {0x01, 0x02, 0x03, 0x04}));
  ON_CALL(server_, OnRequest("www.google.com", T_A))
    .WillByDefault(SetReply(&server_, &reply));

  TempFile aliases("\n\n# www commentedout\nwww www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.google.com' aliases=[] addrs=[1.2.3.4]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasMissing) {
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", T_A))
    .add_answer(new DNSARR("www.first.com", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &yesfirst));

  TempFile aliases("\n\n# www commentedout\nww www.google.com\n");
  EnvValue with_env("HOSTALIASES", aliases.filename());
  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.first.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasMissingFile) {
  DNSPacket yesfirst;
  yesfirst.set_response().set_aa()
    .add_question(new DNSQuestion("www.first.com", T_A))
    .add_answer(new DNSARR("www.first.com", 0x0200, {2, 3, 4, 5}));
  ON_CALL(server_, OnRequest("www.first.com", T_A))
    .WillByDefault(SetReply(&server_, &yesfirst));

  EnvValue with_env("HOSTALIASES", "bogus.mcfile");
  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'www.first.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
}

TEST_P(MockChannelTest, HostAliasUnreadable) {
  TempFile aliases("www www.google.com\n");
  EXPECT_EQ(chmod(aliases.filename(), 0), 0);

  /* Perform OS sanity checks.  We are observing on Debian after the chmod(fn, 0)
   * that we are still able to fopen() the file which is unexpected.  Skip the
   * test if we observe this behavior */
  struct stat st;
  EXPECT_EQ(stat(aliases.filename(), &st), 0);
  EXPECT_EQ(st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO), 0);
  FILE *fp = fopen(aliases.filename(), "r");
  if (fp != NULL) {
    if (verbose) std::cerr << "Skipping Test due to OS incompatibility (open file caching)" << std::endl;
    fclose(fp);
    return;
  }

  EnvValue with_env("HOSTALIASES", aliases.filename());

  HostResult result;
  ares_gethostbyname(channel_, "www", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_EFILE, result.status_);
  chmod(aliases.filename(), 0777);
}
#endif

class MockMultiServerChannelTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface< std::pair<int, bool> > {
 public:
  MockMultiServerChannelTest(ares_options *opts, int optmask)
    : MockChannelOptsTest(3, GetParam().first, GetParam().second, opts, optmask) {}
  void CheckExample() {
    HostResult result;
    ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
    Process();
    EXPECT_TRUE(result.done_);
    std::stringstream ss;
    ss << result.host_;
    EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  }
};

class NoRotateMultiMockTest : public MockMultiServerChannelTest {
 public:
  NoRotateMultiMockTest() : MockMultiServerChannelTest(nullptr, ARES_OPT_NOROTATE) {}
};


TEST_P(NoRotateMultiMockTest, ThirdServer) {
  struct ares_options opts;
  int optmask = 0;
  memset(&opts, 0, sizeof(opts));
  EXPECT_EQ(ARES_SUCCESS, ares_save_options(channel_, &opts, &optmask));
  EXPECT_EQ(ARES_OPT_NOROTATE, (optmask & ARES_OPT_NOROTATE));
  ares_destroy_options(&opts);

  DNSPacket servfailrsp;
  servfailrsp.set_response().set_aa().set_rcode(SERVFAIL)
    .add_question(new DNSQuestion("www.example.com", T_A));
  DNSPacket notimplrsp;
  notimplrsp.set_response().set_aa().set_rcode(NOTIMP)
    .add_question(new DNSQuestion("www.example.com", T_A));
  DNSPacket okrsp;
  okrsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", T_A))
    .add_answer(new DNSARR("www.example.com", 100, {2,3,4,5}));

  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &notimplrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &okrsp));
  CheckExample();

  // Second time around, still starts from server [2], as [0] and [1] both
  // recorded failures
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &servfailrsp));
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &notimplrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &okrsp));
  CheckExample();

  // Third time around, server order is [1] (f0), [2] (f1), [0] (f2), which
  // means [1] will get called twice in a row as after the first call
  // order will be  [1] (f1), [2] (f1), [0] (f2) since sort order is
  // (failure count, index)
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &servfailrsp))
    .WillOnce(SetReply(servers_[1].get(), &notimplrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &notimplrsp));
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &okrsp));
  CheckExample();
}

TEST_P(NoRotateMultiMockTest, ServerNoResponseFailover) {
  std::vector<byte> nothing;
  DNSPacket okrsp;
  okrsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", T_A))
    .add_answer(new DNSARR("www.example.com", 100, {2,3,4,5}));

  /* Server #1 works fine on first attempt, then acts like its offline on
   * second, then backonline on the third. */
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &okrsp))
    .WillOnce(SetReplyData(servers_[0].get(), nothing))
    .WillOnce(SetReply(servers_[0].get(), &okrsp));

  /* Server #2 always acts like its offline */
  ON_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillByDefault(SetReplyData(servers_[1].get(), nothing));

  /* Server #3 works fine on first and second request, then no reply on 3rd */
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &okrsp))
    .WillOnce(SetReply(servers_[2].get(), &okrsp))
    .WillOnce(SetReplyData(servers_[2].get(), nothing));

  HostResult result;

  /* 1. First server returns a response on the first request immediately, normal
   *    operation on channel. */
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(0, result.timeouts_);
  std::stringstream ss1;
  ss1 << result.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss1.str());

  /* 2. On the second request, simulate the first and second servers not
   *    returning a response at all, but the 3rd server works, so should have
   *    2 timeouts. */
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(2, result.timeouts_);
  std::stringstream ss2;
  ss2 << result.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss2.str());

  /* 3. On the third request, the active server should be #3, so should respond
   *    immediately with no timeouts */
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(0, result.timeouts_);
  std::stringstream ss3;
  ss3 << result.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss3.str());

  /* 4. On the fourth request, the active server should be #3, but will timeout,
   *    and the first server should then respond */
  ares_gethostbyname(channel_, "www.example.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(1, result.timeouts_);
  std::stringstream ss4;
  ss4 << result.host_;
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss4.str());
}

#define SERVER_FAILOVER_RETRY_DELAY 750
class ServerFailoverOptsMultiMockTest : public MockMultiServerChannelTest {
 public:
  ServerFailoverOptsMultiMockTest()
    : MockMultiServerChannelTest(FillOptions(&opts_),
                                 ARES_OPT_SERVER_FAILOVER | ARES_OPT_NOROTATE) {}
  static struct ares_options* FillOptions(struct ares_options *opts) {
    memset(opts, 0, sizeof(struct ares_options));
    opts->server_failover_opts.retry_chance = 1;
    opts->server_failover_opts.retry_delay = SERVER_FAILOVER_RETRY_DELAY;
    return opts;
  }
 private:
  struct ares_options opts_;
};

// Test case to trigger server failover behavior. We use a retry chance of
// 100% and a retry delay so that we can test behavior reliably.
TEST_P(ServerFailoverOptsMultiMockTest, ServerFailoverOpts) {
 DNSPacket servfailrsp;
  servfailrsp.set_response().set_aa().set_rcode(SERVFAIL)
    .add_question(new DNSQuestion("www.example.com", T_A));
  DNSPacket okrsp;
  okrsp.set_response().set_aa()
    .add_question(new DNSQuestion("www.example.com", T_A))
    .add_answer(new DNSARR("www.example.com", 100, {2,3,4,5}));

  auto tv_begin = std::chrono::high_resolution_clock::now();
  auto tv_now   = std::chrono::high_resolution_clock::now();
  unsigned int delay_ms;

  // 1. If all servers are healthy, then the first server should be selected.
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: First server should be selected" << std::endl;
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &okrsp));
  CheckExample();

  // 2. Failed servers should be retried after the retry delay.
  //
  // Fail server #0 but leave server #1 as healthy.
  tv_now = std::chrono::high_resolution_clock::now();
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: Server0 will fail but leave Server1 as healthy" << std::endl;
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &okrsp));
  CheckExample();

  // Sleep for the retry delay (actually a little more than the retry delay to account
  // for unreliable timing, e.g. NTP slew) and send in another query. Server #0
  // should be retried.
  tv_now = std::chrono::high_resolution_clock::now();
  delay_ms = SERVER_FAILOVER_RETRY_DELAY + (SERVER_FAILOVER_RETRY_DELAY / 10);
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: sleep " << delay_ms << "ms" << std::endl;
  ares_sleep_time(delay_ms);
  tv_now = std::chrono::high_resolution_clock::now();
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: Server0 should be past retry delay and should be tried again successfully" << std::endl;
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &okrsp));
  CheckExample();

  // 3. If there are multiple failed servers, then the servers should be
  //    retried in sorted order.
  //
  // Fail all servers for the first round of tries. On the second round server
  // #1 responds successfully.
  tv_now = std::chrono::high_resolution_clock::now();
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: All 3 servers will fail on the first attempt. On second attempt, Server0 will fail, but Server1 will answer correctly." << std::endl;
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &servfailrsp))
    .WillOnce(SetReply(servers_[1].get(), &okrsp));
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &servfailrsp));
  CheckExample();

  // At this point the sorted servers look like [1] (f0) [2] (f1) [0] (f2).
  // Sleep for the retry delay and send in another query. Server #2 should be
  // retried first, and then server #0.
  tv_now = std::chrono::high_resolution_clock::now();
  delay_ms = SERVER_FAILOVER_RETRY_DELAY + (SERVER_FAILOVER_RETRY_DELAY / 10);
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: sleep " << delay_ms << "ms" << std::endl;
  ares_sleep_time(delay_ms);
  tv_now = std::chrono::high_resolution_clock::now();
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: Past retry delay, so will choose Server2 and Server0 that are down. Server2 will fail but Server0 will succeed." << std::endl;
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &servfailrsp));
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &okrsp));
  CheckExample();

  // Test might take a while to run and the sleep may not be accurate, so we
  // want to track this interval otherwise we may not pass the last test case
  // on slow systems.
  auto elapse_start = tv_now;

  // 4. If there are multiple failed servers, then servers which have not yet
  //    met the retry delay should be skipped.
  //
  // The sorted servers currently look like [0] (f0) [1] (f0) [2] (f2) and
  // server #2 has just been retried.
  // Sleep for 1/2 the retry delay and trigger a failure on server #0.
  tv_now = std::chrono::high_resolution_clock::now();
  delay_ms = (SERVER_FAILOVER_RETRY_DELAY/2);
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: sleep " << delay_ms << "ms" << std::endl;
  ares_sleep_time(delay_ms);
  tv_now = std::chrono::high_resolution_clock::now();

  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: Retry delay has not been hit yet. Server0 was last successful, so should be tried first (and will fail), Server1 is also healthy so will respond." << std::endl;
  EXPECT_CALL(*servers_[0], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[0].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &okrsp));
  CheckExample();

  // The sorted servers now look like [1] (f0) [0] (f1) [2] (f2). Server #0
  // has just failed whilst server #2 is somewhere in its retry delay.
  // Sleep until we know server #2s retry delay has elapsed but Server #0 has
  // not.
  tv_now = std::chrono::high_resolution_clock::now();

  unsigned int elapsed_time = (unsigned int)std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - elapse_start).count();
  delay_ms = (SERVER_FAILOVER_RETRY_DELAY) + (SERVER_FAILOVER_RETRY_DELAY / 10);
  if (elapsed_time > delay_ms) {
    if (verbose) std::cerr << "elapsed duration " << elapsed_time << "ms greater than desired delay of " << delay_ms << "ms, not sleeping" << std::endl;
  } else {
    delay_ms -= elapsed_time; // subtract already elapsed time
    if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: sleep " << delay_ms << "ms" << std::endl;
    ares_sleep_time(delay_ms);
  }
  tv_now = std::chrono::high_resolution_clock::now();
  if (verbose) std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(tv_now - tv_begin).count() << "ms: Retry delay has expired on Server2 but not Server0, will try on Server2 and fail, then Server1 will answer" << std::endl;
  EXPECT_CALL(*servers_[2], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[2].get(), &servfailrsp));
  EXPECT_CALL(*servers_[1], OnRequest("www.example.com", T_A))
    .WillOnce(SetReply(servers_[1].get(), &okrsp));
  CheckExample();
}

const char *af_tostr(int af)
{
  switch (af) {
    case AF_INET:
      return "ipv4";
    case AF_INET6:
      return "ipv6";
  }
  return "ipunknown";
}

const char *mode_tostr(bool mode)
{
  return mode?"ForceTCP":"DefaultUDP";
}

std::string PrintFamilyMode(const testing::TestParamInfo<std::pair<int, bool>> &info)
{
  std::string name;

  name += af_tostr(std::get<0>(info.param));
  name += "_";
  name += mode_tostr(std::get<1>(info.param));
  return name;
}

std::string PrintFamily(const testing::TestParamInfo<int> &info)
{
  std::string name;

  name += af_tostr(info.param);
  return name;
}

INSTANTIATE_TEST_SUITE_P(AddressFamilies, NoDNS0x20MockTest, ::testing::ValuesIn(ares::test::families), PrintFamily);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockChannelTest, ::testing::ValuesIn(ares::test::families_modes), PrintFamilyMode);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockUDPChannelTest, ::testing::ValuesIn(ares::test::families), PrintFamily);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockUDPMaxQueriesTest, ::testing::ValuesIn(ares::test::families), PrintFamily);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, CacheQueriesTest, ::testing::ValuesIn(ares::test::families), PrintFamily);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockTCPChannelTest, ::testing::ValuesIn(ares::test::families), PrintFamily);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockExtraOptsTest, ::testing::ValuesIn(ares::test::families_modes), PrintFamilyMode);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockNoCheckRespChannelTest, ::testing::ValuesIn(ares::test::families_modes), PrintFamilyMode);

INSTANTIATE_TEST_SUITE_P(AddressFamilies, MockEDNSChannelTest, ::testing::ValuesIn(ares::test::families_modes), PrintFamilyMode);

INSTANTIATE_TEST_SUITE_P(TransportModes, NoRotateMultiMockTest, ::testing::ValuesIn(ares::test::families_modes), PrintFamilyMode);

INSTANTIATE_TEST_SUITE_P(TransportModes, ServerFailoverOptsMultiMockTest, ::testing::ValuesIn(ares::test::families_modes), PrintFamilyMode);

}  // namespace test
}  // namespace ares
