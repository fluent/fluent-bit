/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "shrpx_http_test.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

#include <CUnit/CUnit.h>

#include "shrpx_http.h"
#include "shrpx_config.h"
#include "shrpx_log.h"

namespace shrpx {

void test_shrpx_http_create_forwarded(void) {
  BlockAllocator balloc(1024, 1024);

  CU_ASSERT("by=\"example.com:3000\";for=\"[::1]\";host=\"www.example.com\";"
            "proto=https" ==
            http::create_forwarded(balloc,
                                   FORWARDED_BY | FORWARDED_FOR |
                                       FORWARDED_HOST | FORWARDED_PROTO,
                                   StringRef::from_lit("example.com:3000"),
                                   StringRef::from_lit("[::1]"),
                                   StringRef::from_lit("www.example.com"),
                                   StringRef::from_lit("https")));

  CU_ASSERT("for=192.168.0.1" ==
            http::create_forwarded(
                balloc, FORWARDED_FOR, StringRef::from_lit("alpha"),
                StringRef::from_lit("192.168.0.1"),
                StringRef::from_lit("bravo"), StringRef::from_lit("charlie")));

  CU_ASSERT("by=_hidden;for=\"[::1]\"" ==
            http::create_forwarded(
                balloc, FORWARDED_BY | FORWARDED_FOR,
                StringRef::from_lit("_hidden"), StringRef::from_lit("[::1]"),
                StringRef::from_lit(""), StringRef::from_lit("")));

  CU_ASSERT("by=\"[::1]\";for=_hidden" ==
            http::create_forwarded(
                balloc, FORWARDED_BY | FORWARDED_FOR,
                StringRef::from_lit("[::1]"), StringRef::from_lit("_hidden"),
                StringRef::from_lit(""), StringRef::from_lit("")));

  CU_ASSERT("" ==
            http::create_forwarded(
                balloc,
                FORWARDED_BY | FORWARDED_FOR | FORWARDED_HOST | FORWARDED_PROTO,
                StringRef::from_lit(""), StringRef::from_lit(""),
                StringRef::from_lit(""), StringRef::from_lit("")));
}

void test_shrpx_http_create_via_header_value(void) {
  std::array<char, 16> buf;

  auto end = http::create_via_header_value(std::begin(buf), 1, 1);

  CU_ASSERT(("1.1 nghttpx" == StringRef{std::begin(buf), end}));

  std::fill(std::begin(buf), std::end(buf), '\0');

  end = http::create_via_header_value(std::begin(buf), 2, 0);

  CU_ASSERT(("2 nghttpx" == StringRef{std::begin(buf), end}));
}

void test_shrpx_http_create_affinity_cookie(void) {
  BlockAllocator balloc(1024, 1024);
  StringRef c;

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("cookie-val"),
                                   0xf1e2d3c4u, StringRef{}, false);

  CU_ASSERT("cookie-val=f1e2d3c4" == c);

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("alpha"),
                                   0x00000000u, StringRef{}, true);

  CU_ASSERT("alpha=00000000; Secure" == c);

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("bravo"),
                                   0x01111111u, StringRef::from_lit("bar"),
                                   false);

  CU_ASSERT("bravo=01111111; Path=bar" == c);

  c = http::create_affinity_cookie(balloc, StringRef::from_lit("charlie"),
                                   0x01111111u, StringRef::from_lit("bar"),
                                   true);

  CU_ASSERT("charlie=01111111; Path=bar; Secure" == c);
}

void test_shrpx_http_create_altsvc_header_value(void) {
  {
    BlockAllocator balloc(1024, 1024);
    std::vector<AltSvc> altsvcs{
        AltSvc{
            .protocol_id = StringRef::from_lit("h3"),
            .host = StringRef::from_lit("127.0.0.1"),
            .service = StringRef::from_lit("443"),
            .params = StringRef::from_lit("ma=3600"),
        },
    };

    CU_ASSERT(R"(h3="127.0.0.1:443"; ma=3600)" ==
              http::create_altsvc_header_value(balloc, altsvcs));
  }

  {
    BlockAllocator balloc(1024, 1024);
    std::vector<AltSvc> altsvcs{
        AltSvc{
            .protocol_id = StringRef::from_lit("h3"),
            .service = StringRef::from_lit("443"),
            .params = StringRef::from_lit("ma=3600"),
        },
        AltSvc{
            .protocol_id = StringRef::from_lit("h3%"),
            .host = StringRef::from_lit("\"foo\""),
            .service = StringRef::from_lit("4433"),
        },
    };

    CU_ASSERT(R"(h3=":443"; ma=3600, h3%25="\"foo\":4433")" ==
              http::create_altsvc_header_value(balloc, altsvcs));
  }
}

void test_shrpx_http_check_http_scheme(void) {
  CU_ASSERT(http::check_http_scheme(StringRef::from_lit("https"), true));
  CU_ASSERT(!http::check_http_scheme(StringRef::from_lit("https"), false));
  CU_ASSERT(!http::check_http_scheme(StringRef::from_lit("http"), true));
  CU_ASSERT(http::check_http_scheme(StringRef::from_lit("http"), false));
  CU_ASSERT(!http::check_http_scheme(StringRef::from_lit("foo"), true));
  CU_ASSERT(!http::check_http_scheme(StringRef::from_lit("foo"), false));
  CU_ASSERT(!http::check_http_scheme(StringRef{}, true));
  CU_ASSERT(!http::check_http_scheme(StringRef{}, false));
}

} // namespace shrpx
