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

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseAaaaReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}))
    .add_answer(new DNSARR("example.com", 0x01020304, {2,3,4,5}));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addr6ttl info[5];
  int count = 5;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(100, info[0].ttl);
  EXPECT_EQ(0x01, info[0].ip6addr._S6_un._S6_u8[0]);
  EXPECT_EQ(0x02, info[0].ip6addr._S6_un._S6_u8[4]);
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'example.com' aliases=[] addrs=[0101:0101:0202:0202:0303:0303:0404:0404]}", ss.str());
  ares_free_hostent(host);

  // Repeat without providing places to put the results
  count = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                nullptr, info, &count));
}

TEST_F(LibraryTest, ParseAaaaReplyCname) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSCnameRR("example.com", 50, "c.example.com"))
    .add_answer(new DNSAaaaRR("c.example.com", 100,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addr6ttl info[5];
  int count = 5;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  EXPECT_EQ(1, count);
  // CNAME TTL overrides AAAA TTL.
  EXPECT_EQ(50, info[0].ttl);
  EXPECT_EQ(0x01, info[0].ip6addr._S6_un._S6_u8[0]);
  EXPECT_EQ(0x02, info[0].ip6addr._S6_un._S6_u8[4]);
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'c.example.com' aliases=[example.com] addrs=[0101:0101:0202:0202:0303:0303:0404:0404]}", ss.str());
  ares_free_hostent(host);

  // Repeat without providing a hostent
  count = 5;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                nullptr, info, &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(50, info[0].ttl);
  EXPECT_EQ(0x01, info[0].ip6addr._S6_un._S6_u8[0]);
  EXPECT_EQ(0x02, info[0].ip6addr._S6_un._S6_u8[4]);
}

TEST_F(LibraryTest, ParseAaaaReplyNoData) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addr6ttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_ENODATA, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  EXPECT_EQ(0, count);
  EXPECT_EQ(nullptr, host);

  // Again but with a CNAME.
  pkt.add_answer(new DNSCnameRR("example.com", 200, "c.example.com"));
  EXPECT_EQ(ARES_ENODATA, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  EXPECT_EQ(0, count);
  EXPECT_EQ(nullptr, host);
}

TEST_F(LibraryTest, ParseAaaaReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSAaaaRR("example.com", 100,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));
  std::vector<byte> data;

  struct hostent *host = nullptr;
  struct ares_addr6ttl info[2];
  int count = 2;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                 &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.add_question(new DNSQuestion("example.com", T_AAAA));

  // Question != answer, this is ok as of Issue #683
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", T_AAAA));
  data = pkt.data();
  EXPECT_EQ(ARES_SUCCESS, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'Axample.com' aliases=[] addrs=[0101:0101:0202:0202:0303:0303:0404:0404]}", ss.str());
  ares_free_hostent(host);

  host = nullptr;
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_AAAA));

  // Two questions.
  pkt.add_question(new DNSQuestion("example.com", T_AAAA));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                 &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_AAAA));

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 100, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.answers_.clear();
  pkt.add_answer(new DNSAaaaRR("example.com", 100,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.add_answer(new DNSAaaaRR("example.com", 100,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), (int)len,
                                                   &host, info, &count));
    EXPECT_EQ(nullptr, host);
    EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), (int)len,
                                                   nullptr, info, &count));
  }

  // Negative length
  EXPECT_EQ(ARES_EBADRESP, ares_parse_aaaa_reply(data.data(), -1,
                                                 &host, info, &count));
}

TEST_F(LibraryTest, ParseAaaaReplyAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_AAAA))
    .add_answer(new DNSCnameRR("example.com", 300, "c.example.com"))
    .add_answer(new DNSAaaaRR("c.example.com", 100,
                              {0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                               0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04}));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addr6ttl info[2];
  int count = 2;

  for (int ii = 1; ii <= 8; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_aaaa_reply(data.data(), (int)data.size(),
                                                 &host, info, &count)) << ii;
    EXPECT_EQ(nullptr, host);
  }
}

}  // namespace test
}  // namespace ares
