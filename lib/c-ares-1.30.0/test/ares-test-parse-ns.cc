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

TEST_F(LibraryTest, ParseNsReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_NS))
    .add_answer(new DNSNsRR("example.com", 100, "ns.example.com"));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'example.com' aliases=[ns.example.com] addrs=[]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseNsReplyMultiple) {
  DNSPacket pkt;
  pkt.set_qid(10501).set_response().set_rd().set_ra()
    .add_question(new DNSQuestion("google.com", T_NS))
    .add_answer(new DNSNsRR("google.com", 59, "ns1.google.com"))
    .add_answer(new DNSNsRR("google.com", 59, "ns2.google.com"))
    .add_answer(new DNSNsRR("google.com", 59, "ns3.google.com"))
    .add_answer(new DNSNsRR("google.com", 59, "ns4.google.com"))
    .add_additional(new DNSARR("ns4.google.com", 247, {216,239,38,10}))
    .add_additional(new DNSARR("ns2.google.com", 247, {216,239,34,10}))
    .add_additional(new DNSARR("ns1.google.com", 247, {216,239,32,10}))
    .add_additional(new DNSARR("ns3.google.com", 247, {216,239,36,10}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'google.com' aliases=[ns1.google.com, ns2.google.com, ns3.google.com, ns4.google.com] addrs=[]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseNsReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_NS))
    .add_answer(new DNSNsRR("example.com", 100, "ns.example.com"));
  std::vector<byte> data;
  struct hostent *host = nullptr;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  pkt.add_question(new DNSQuestion("example.com", T_NS));

#ifdef DISABLED
  // Question != answer
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", T_NS));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_NS));
#endif

  // Two questions.
  pkt.add_question(new DNSQuestion("example.com", T_NS));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_NS));

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 100, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  pkt.answers_.clear();
  pkt.add_answer(new DNSNsRR("example.com", 100, "ns.example.com"));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_ns_reply(data.data(), (int)data.size(), &host));
  pkt.add_answer(new DNSNsRR("example.com", 100, "ns.example.com"));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    EXPECT_EQ(ARES_EBADRESP, ares_parse_ns_reply(data.data(), (int)len, &host));
  }
}

TEST_F(LibraryTest, ParseNsReplyAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_NS))
    .add_answer(new DNSCnameRR("example.com", 300, "c.example.com"))
    .add_answer(new DNSNsRR("c.example.com", 100, "ns.example.com"));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;

  for (int ii = 1; ii <= 8; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_ns_reply(data.data(), (int)data.size(), &host)) << ii;
  }
}


}  // namespace test
}  // namespace ares
