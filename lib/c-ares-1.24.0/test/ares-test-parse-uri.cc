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

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseUriReplyOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_URI))
    .add_answer(new DNSUriRR("example.com", 100, 10, 20, "uri.example.com"))
    .add_answer(new DNSUriRR("example.com", 200, 11, 21, "uri2.example.com"));
  std::vector<byte> data = pkt.data();

  struct ares_uri_reply* uri = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  ASSERT_NE(nullptr, uri);

  EXPECT_EQ("uri.example.com", std::string(uri->uri));
  EXPECT_EQ(10, uri->priority);
  EXPECT_EQ(20, uri->weight);
  EXPECT_EQ(100, uri->ttl);

  struct ares_uri_reply* uri2 = uri->next;
  ASSERT_NE(nullptr, uri2);
  EXPECT_EQ("uri2.example.com", std::string(uri2->uri));
  EXPECT_EQ(11, uri2->priority);
  EXPECT_EQ(21, uri2->weight);
  EXPECT_EQ(200, uri2->ttl);
  EXPECT_EQ(nullptr, uri2->next);

  ares_free_data(uri);
}

TEST_F(LibraryTest, ParseUriReplySingle) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_URI))
    .add_answer(new DNSUriRR("example.abc.def.com", 180, 0, 10, "example.abc.def.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else1.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else2.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else3.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else4.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else5.where.com"))
    .add_additional(new DNSARR("else2.where.com", 42, {172,19,0,1}))
    .add_additional(new DNSARR("else5.where.com", 42, {172,19,0,2}));
  std::vector<byte> data = pkt.data();

  struct ares_uri_reply* uri = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  ASSERT_NE(nullptr, uri);

  EXPECT_EQ("example.abc.def.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(10, uri->weight);
  EXPECT_EQ(180, uri->ttl);
  EXPECT_EQ(nullptr, uri->next);

  ares_free_data(uri);
}

TEST_F(LibraryTest, ParseUriReplyMalformed) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x01, 0x00,  // type URI
    0x00, 0x01,  // class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x01, 0x00,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length -- too short
    0x02, 0x03, 0x04, 0x05,
  };

  struct ares_uri_reply* uri = nullptr;
  EXPECT_EQ(ARES_EBADRESP, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  ASSERT_EQ(nullptr, uri);
}

TEST_F(LibraryTest, ParseUriReplyMultiple) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_ra().set_rd()
    .add_question(new DNSQuestion("uri.example.com", T_URI))
    .add_answer(new DNSUriRR("uri.example.com", 600, 0, 5, "a1.uri.example.com"))
    .add_answer(new DNSUriRR("uri.example.com", 660, 0, 5, "a2.uri.example.com"))
    .add_answer(new DNSUriRR("uri.example.com", 720, 0, 5, "a3.uri.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns1.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns2.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns3.example.com"))
    .add_additional(new DNSARR("a1.uri.example.com", 300, {172,19,1,1}))
    .add_additional(new DNSARR("a2.uri.example.com", 300, {172,19,1,2}))
    .add_additional(new DNSARR("a3.uri.example.com", 300, {172,19,1,3}))
    .add_additional(new DNSARR("n1.example.com", 300, {172,19,0,1}))
    .add_additional(new DNSARR("n2.example.com", 300, {172,19,0,2}))
    .add_additional(new DNSARR("n3.example.com", 300, {172,19,0,3}));
  std::vector<byte> data = pkt.data();

  struct ares_uri_reply* uri0 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_uri_reply(data.data(), (int)data.size(), &uri0));
  ASSERT_NE(nullptr, uri0);
  struct ares_uri_reply* uri = uri0;

  EXPECT_EQ("a1.uri.example.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(5, uri->weight);
  EXPECT_EQ(600, uri->ttl);
  EXPECT_NE(nullptr, uri->next);
  uri = uri->next;

  EXPECT_EQ("a2.uri.example.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(5, uri->weight);
  EXPECT_EQ(660, uri->ttl);
  EXPECT_NE(nullptr, uri->next);
  uri = uri->next;

  EXPECT_EQ("a3.uri.example.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(5, uri->weight);
  EXPECT_EQ(720, uri->ttl);
  EXPECT_EQ(nullptr, uri->next);

  ares_free_data(uri0);
}

TEST_F(LibraryTest, ParseUriReplyCname) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_URI))
    .add_answer(new DNSCnameRR("example.abc.def.com", 300, "cname.abc.def.com"))
    .add_answer(new DNSUriRR("cname.abc.def.com", 600, 0, 10, "uri.abc.def.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else1.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else2.where.com"))
    .add_auth(new DNSNsRR("abc.def.com", 44, "else3.where.com"))
    .add_additional(new DNSARR("example.abc.def.com", 300, {172,19,0,1}))
    .add_additional(new DNSARR("else1.where.com", 42, {172,19,0,1}))
    .add_additional(new DNSARR("else2.where.com", 42, {172,19,0,2}))
    .add_additional(new DNSARR("else3.where.com", 42, {172,19,0,3}));
  std::vector<byte> data = pkt.data();

  struct ares_uri_reply* uri = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  ASSERT_NE(nullptr, uri);

  EXPECT_EQ("uri.abc.def.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(10, uri->weight);
  EXPECT_EQ(600, uri->ttl);
  EXPECT_EQ(nullptr, uri->next);

  ares_free_data(uri);
}

TEST_F(LibraryTest, ParseUriReplyCnameMultiple) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_ra().set_rd()
    .add_question(new DNSQuestion("query.example.com", T_URI))
    .add_answer(new DNSCnameRR("query.example.com", 300, "uri.example.com"))
    .add_answer(new DNSUriRR("uri.example.com", 600, 0, 5, "a1.uri.example.com"))
    .add_answer(new DNSUriRR("uri.example.com", 660, 0, 5, "a2.uri.example.com"))
    .add_answer(new DNSUriRR("uri.example.com", 720, 0, 5, "a3.uri.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns1.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns2.example.com"))
    .add_auth(new DNSNsRR("example.com", 300, "ns3.example.com"))
    .add_additional(new DNSARR("a1.uri.example.com", 300, {172,19,1,1}))
    .add_additional(new DNSARR("a2.uri.example.com", 300, {172,19,1,2}))
    .add_additional(new DNSARR("a3.uri.example.com", 300, {172,19,1,3}))
    .add_additional(new DNSARR("n1.example.com", 300, {172,19,0,1}))
    .add_additional(new DNSARR("n2.example.com", 300, {172,19,0,2}))
    .add_additional(new DNSARR("n3.example.com", 300, {172,19,0,3}));
  std::vector<byte> data = pkt.data();

  struct ares_uri_reply* uri0 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_uri_reply(data.data(), (int)data.size(), &uri0));
  ASSERT_NE(nullptr, uri0);
  struct ares_uri_reply* uri = uri0;

  EXPECT_EQ("a1.uri.example.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(5, uri->weight);
  EXPECT_EQ(600, uri->ttl);
  EXPECT_NE(nullptr, uri->next);
  uri = uri->next;

  EXPECT_EQ("a2.uri.example.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(5, uri->weight);
  EXPECT_EQ(660, uri->ttl);
  EXPECT_NE(nullptr, uri->next);
  uri = uri->next;

  EXPECT_EQ("a3.uri.example.com", std::string(uri->uri));
  EXPECT_EQ(0, uri->priority);
  EXPECT_EQ(5, uri->weight);
  EXPECT_EQ(720, uri->ttl);
  EXPECT_EQ(nullptr, uri->next);

  ares_free_data(uri0);
}

TEST_F(LibraryTest, ParseUriReplyErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_URI))
    .add_answer(new DNSUriRR("example.abc.def.com", 180, 0, 10, "example.abc.def.com"));
  std::vector<byte> data;
  struct ares_uri_reply* uri = nullptr;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  pkt.add_question(new DNSQuestion("example.abc.def.com", T_URI));

#ifdef DISABLED
  // Question != answer
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", T_URI));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", T_URI));
#endif

  // Two questions.
  pkt.add_question(new DNSQuestion("example.abc.def.com", T_URI));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("64.48.32.16.in-addr.arpa", T_PTR));

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 100, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_SUCCESS, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  EXPECT_EQ(nullptr, uri);
  pkt.answers_.clear();
  pkt.add_answer(new DNSUriRR("example.abc.def.com", 180, 0, 10, "example.abc.def.com"));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  pkt.add_answer(new DNSUriRR("example.abc.def.com", 180, 0, 10, "example.abc.def.com"));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    int rc = ares_parse_uri_reply(data.data(), (int)len, &uri);
    EXPECT_TRUE(rc == ARES_EBADRESP || rc == ARES_EBADNAME);
  }
}

TEST_F(LibraryTest, ParseUriReplyAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.abc.def.com", T_URI))
    .add_answer(new DNSCnameRR("example.com", 300, "c.example.com"))
    .add_answer(new DNSUriRR("example.abc.def.com", 180, 0, 10, "example.abc.def.com"));
  std::vector<byte> data = pkt.data();
  struct ares_uri_reply* uri = nullptr;

  for (int ii = 1; ii <= 5; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_uri_reply(data.data(), (int)data.size(), &uri)) << ii;
  }
}

}  // namespace test
}  // namespace ares
