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

TEST_F(LibraryTest, ParseSoaReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_SOA))
    .add_answer(new DNSSoaRR("example.com", 100,
                             "soa1.example.com", "fred.example.com",
                             1, 2, 3, 4, 5));
  std::vector<byte> data = pkt.data();

  struct ares_soa_reply* soa = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_soa_reply(data.data(), (int)data.size(), &soa));
  ASSERT_NE(nullptr, soa);
  EXPECT_EQ("soa1.example.com", std::string(soa->nsname));
  EXPECT_EQ("fred.example.com", std::string(soa->hostmaster));
  EXPECT_EQ((unsigned int)1, soa->serial);
  EXPECT_EQ((unsigned int)2, soa->refresh);
  EXPECT_EQ((unsigned int)3, soa->retry);
  EXPECT_EQ((unsigned int)4, soa->expire);
  EXPECT_EQ((unsigned int)5, soa->minttl);
  ares_free_data(soa);
}

TEST_F(LibraryTest, ParseSoaReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_SOA))
    .add_answer(new DNSSoaRR("example.com", 100,
                             "soa1.example.com", "fred.example.com",
                             1, 2, 3, 4, 5));
  std::vector<byte> data;
  struct ares_soa_reply* soa = nullptr;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), (int)data.size(), &soa));
  pkt.add_question(new DNSQuestion("example.com", T_SOA));

#ifdef DISABLED
  // Question != answer
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", T_SOA));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), (int)data.size(), &soa));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_SOA));
#endif

  // Two questions
  pkt.add_question(new DNSQuestion("example.com", T_SOA));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), (int)data.size(), &soa));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_SOA));

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 100, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), (int)data.size(), &soa));
  pkt.answers_.clear();
  pkt.add_answer(new DNSSoaRR("example.com", 100,
                             "soa1.example.com", "fred.example.com",
                             1, 2, 3, 4, 5));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), (int)data.size(), &soa));
  pkt.add_answer(new DNSSoaRR("example.com", 100,
                             "soa1.example.com", "fred.example.com",
                             1, 2, 3, 4, 5));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), (int)len, &soa));
  }

  // Negative Length
  EXPECT_EQ(ARES_EBADRESP, ares_parse_soa_reply(data.data(), -1, &soa));
}

TEST_F(LibraryTest, ParseSoaReplyAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_SOA))
    .add_answer(new DNSSoaRR("example.com", 100,
                             "soa1.example.com", "fred.example.com",
                             1, 2, 3, 4, 5));
  std::vector<byte> data = pkt.data();
  struct ares_soa_reply* soa = nullptr;

  for (int ii = 1; ii <= 5; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_soa_reply(data.data(), (int)data.size(), &soa)) << ii;
  }
}

}  // namespace test
}  // namespace ares
