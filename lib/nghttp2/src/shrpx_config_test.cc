/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "shrpx_config_test.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

#include <CUnit/CUnit.h>

#include "shrpx_config.h"
#include "shrpx_log.h"

namespace shrpx {

void test_shrpx_config_parse_header(void) {
  BlockAllocator balloc(4096, 4096);

  auto p = parse_header(balloc, StringRef::from_lit("a: b"));
  CU_ASSERT("a" == p.name);
  CU_ASSERT("b" == p.value);

  p = parse_header(balloc, StringRef::from_lit("a:  b"));
  CU_ASSERT("a" == p.name);
  CU_ASSERT("b" == p.value);

  p = parse_header(balloc, StringRef::from_lit(":a: b"));
  CU_ASSERT(p.name.empty());

  p = parse_header(balloc, StringRef::from_lit("a: :b"));
  CU_ASSERT("a" == p.name);
  CU_ASSERT(":b" == p.value);

  p = parse_header(balloc, StringRef::from_lit(": b"));
  CU_ASSERT(p.name.empty());

  p = parse_header(balloc, StringRef::from_lit("alpha: bravo charlie"));
  CU_ASSERT("alpha" == p.name);
  CU_ASSERT("bravo charlie" == p.value);

  p = parse_header(balloc, StringRef::from_lit("a,: b"));
  CU_ASSERT(p.name.empty());

  p = parse_header(balloc, StringRef::from_lit("a: b\x0a"));
  CU_ASSERT(p.name.empty());
}

void test_shrpx_config_parse_log_format(void) {
  BlockAllocator balloc(4096, 4096);

  auto res = parse_log_format(
      balloc, StringRef::from_lit(
                  R"($remote_addr - $remote_user [$time_local] )"
                  R"("$request" $status $body_bytes_sent )"
                  R"("${http_referer}" $http_host "$http_user_agent")"));
  CU_ASSERT(16 == res.size());

  CU_ASSERT(LogFragmentType::REMOTE_ADDR == res[0].type);

  CU_ASSERT(LogFragmentType::LITERAL == res[1].type);
  CU_ASSERT(" - $remote_user [" == res[1].value);

  CU_ASSERT(LogFragmentType::TIME_LOCAL == res[2].type);

  CU_ASSERT(LogFragmentType::LITERAL == res[3].type);
  CU_ASSERT("] \"" == res[3].value);

  CU_ASSERT(LogFragmentType::REQUEST == res[4].type);

  CU_ASSERT(LogFragmentType::LITERAL == res[5].type);
  CU_ASSERT("\" " == res[5].value);

  CU_ASSERT(LogFragmentType::STATUS == res[6].type);

  CU_ASSERT(LogFragmentType::LITERAL == res[7].type);
  CU_ASSERT(" " == res[7].value);

  CU_ASSERT(LogFragmentType::BODY_BYTES_SENT == res[8].type);

  CU_ASSERT(LogFragmentType::LITERAL == res[9].type);
  CU_ASSERT(" \"" == res[9].value);

  CU_ASSERT(LogFragmentType::HTTP == res[10].type);
  CU_ASSERT("referer" == res[10].value);

  CU_ASSERT(LogFragmentType::LITERAL == res[11].type);
  CU_ASSERT("\" " == res[11].value);

  CU_ASSERT(LogFragmentType::AUTHORITY == res[12].type);

  CU_ASSERT(LogFragmentType::LITERAL == res[13].type);
  CU_ASSERT(" \"" == res[13].value);

  CU_ASSERT(LogFragmentType::HTTP == res[14].type);
  CU_ASSERT("user-agent" == res[14].value);

  CU_ASSERT(LogFragmentType::LITERAL == res[15].type);
  CU_ASSERT("\"" == res[15].value);

  res = parse_log_format(balloc, StringRef::from_lit("$"));

  CU_ASSERT(1 == res.size());

  CU_ASSERT(LogFragmentType::LITERAL == res[0].type);
  CU_ASSERT("$" == res[0].value);

  res = parse_log_format(balloc, StringRef::from_lit("${"));

  CU_ASSERT(1 == res.size());

  CU_ASSERT(LogFragmentType::LITERAL == res[0].type);
  CU_ASSERT("${" == res[0].value);

  res = parse_log_format(balloc, StringRef::from_lit("${a"));

  CU_ASSERT(1 == res.size());

  CU_ASSERT(LogFragmentType::LITERAL == res[0].type);
  CU_ASSERT("${a" == res[0].value);

  res = parse_log_format(balloc, StringRef::from_lit("${a "));

  CU_ASSERT(1 == res.size());

  CU_ASSERT(LogFragmentType::LITERAL == res[0].type);
  CU_ASSERT("${a " == res[0].value);

  res = parse_log_format(balloc, StringRef::from_lit("$$remote_addr"));

  CU_ASSERT(2 == res.size());

  CU_ASSERT(LogFragmentType::LITERAL == res[0].type);
  CU_ASSERT("$" == res[0].value);

  CU_ASSERT(LogFragmentType::REMOTE_ADDR == res[1].type);
  CU_ASSERT("" == res[1].value);
}

void test_shrpx_config_read_tls_ticket_key_file(void) {
  char file1[] = "/tmp/nghttpx-unittest.XXXXXX";
  auto fd1 = mkstemp(file1);
  CU_ASSERT(fd1 != -1);
  CU_ASSERT(48 ==
            write(fd1, "0..............12..............34..............5", 48));
  char file2[] = "/tmp/nghttpx-unittest.XXXXXX";
  auto fd2 = mkstemp(file2);
  CU_ASSERT(fd2 != -1);
  CU_ASSERT(48 ==
            write(fd2, "6..............78..............9a..............b", 48));

  close(fd1);
  close(fd2);
  auto ticket_keys = read_tls_ticket_key_file(
      {StringRef{file1}, StringRef{file2}}, EVP_aes_128_cbc(), EVP_sha256());
  unlink(file1);
  unlink(file2);
  CU_ASSERT(ticket_keys.get() != nullptr);
  CU_ASSERT(2 == ticket_keys->keys.size());
  auto key = &ticket_keys->keys[0];
  CU_ASSERT(std::equal(std::begin(key->data.name), std::end(key->data.name),
                       "0..............1"));
  CU_ASSERT(std::equal(std::begin(key->data.enc_key),
                       std::begin(key->data.enc_key) + 16, "2..............3"));
  CU_ASSERT(std::equal(std::begin(key->data.hmac_key),
                       std::begin(key->data.hmac_key) + 16,
                       "4..............5"));
  CU_ASSERT(16 == key->hmac_keylen);

  key = &ticket_keys->keys[1];
  CU_ASSERT(std::equal(std::begin(key->data.name), std::end(key->data.name),
                       "6..............7"));
  CU_ASSERT(std::equal(std::begin(key->data.enc_key),
                       std::begin(key->data.enc_key) + 16, "8..............9"));
  CU_ASSERT(std::equal(std::begin(key->data.hmac_key),
                       std::begin(key->data.hmac_key) + 16,
                       "a..............b"));
  CU_ASSERT(16 == key->hmac_keylen);
}

void test_shrpx_config_read_tls_ticket_key_file_aes_256(void) {
  char file1[] = "/tmp/nghttpx-unittest.XXXXXX";
  auto fd1 = mkstemp(file1);
  CU_ASSERT(fd1 != -1);
  CU_ASSERT(80 == write(fd1,
                        "0..............12..............................34..."
                        "...........................5",
                        80));
  char file2[] = "/tmp/nghttpx-unittest.XXXXXX";
  auto fd2 = mkstemp(file2);
  CU_ASSERT(fd2 != -1);
  CU_ASSERT(80 == write(fd2,
                        "6..............78..............................9a..."
                        "...........................b",
                        80));

  close(fd1);
  close(fd2);
  auto ticket_keys = read_tls_ticket_key_file(
      {StringRef{file1}, StringRef{file2}}, EVP_aes_256_cbc(), EVP_sha256());
  unlink(file1);
  unlink(file2);
  CU_ASSERT(ticket_keys.get() != nullptr);
  CU_ASSERT(2 == ticket_keys->keys.size());
  auto key = &ticket_keys->keys[0];
  CU_ASSERT(std::equal(std::begin(key->data.name), std::end(key->data.name),
                       "0..............1"));
  CU_ASSERT(std::equal(std::begin(key->data.enc_key),
                       std::end(key->data.enc_key),
                       "2..............................3"));
  CU_ASSERT(std::equal(std::begin(key->data.hmac_key),
                       std::end(key->data.hmac_key),
                       "4..............................5"));

  key = &ticket_keys->keys[1];
  CU_ASSERT(std::equal(std::begin(key->data.name), std::end(key->data.name),
                       "6..............7"));
  CU_ASSERT(std::equal(std::begin(key->data.enc_key),
                       std::end(key->data.enc_key),
                       "8..............................9"));
  CU_ASSERT(std::equal(std::begin(key->data.hmac_key),
                       std::end(key->data.hmac_key),
                       "a..............................b"));
}

} // namespace shrpx
