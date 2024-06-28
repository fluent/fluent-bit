/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "shrpx_downstream_test.h"

#include <iostream>

#include <CUnit/CUnit.h>

#include "shrpx_downstream.h"

namespace shrpx {

void test_downstream_field_store_append_last_header(void) {
  BlockAllocator balloc(16, 16);
  FieldStore fs(balloc, 0);
  fs.alloc_add_header_name(StringRef::from_lit("alpha"));
  auto bravo = StringRef::from_lit("BRAVO");
  fs.append_last_header_key(bravo.c_str(), bravo.size());
  // Add more characters so that relloc occurs
  auto golf = StringRef::from_lit("golF0123456789");
  fs.append_last_header_key(golf.c_str(), golf.size());

  auto charlie = StringRef::from_lit("Charlie");
  fs.append_last_header_value(charlie.c_str(), charlie.size());
  auto delta = StringRef::from_lit("deltA");
  fs.append_last_header_value(delta.c_str(), delta.size());
  // Add more characters so that relloc occurs
  auto echo = StringRef::from_lit("echo0123456789");
  fs.append_last_header_value(echo.c_str(), echo.size());

  fs.add_header_token(StringRef::from_lit("echo"),
                      StringRef::from_lit("foxtrot"), false, -1);

  auto ans =
      HeaderRefs{{StringRef::from_lit("alphabravogolf0123456789"),
                  StringRef::from_lit("CharliedeltAecho0123456789")},
                 {StringRef::from_lit("echo"), StringRef::from_lit("foxtrot")}};
  CU_ASSERT(ans == fs.headers());
}

void test_downstream_field_store_header(void) {
  BlockAllocator balloc(16, 16);
  FieldStore fs(balloc, 0);
  fs.add_header_token(StringRef::from_lit("alpha"), StringRef::from_lit("0"),
                      false, -1);
  fs.add_header_token(StringRef::from_lit(":authority"),
                      StringRef::from_lit("1"), false, http2::HD__AUTHORITY);
  fs.add_header_token(StringRef::from_lit("content-length"),
                      StringRef::from_lit("2"), false,
                      http2::HD_CONTENT_LENGTH);

  // By token
  CU_ASSERT(HeaderRef(StringRef{":authority"}, StringRef{"1"}) ==
            *fs.header(http2::HD__AUTHORITY));
  CU_ASSERT(nullptr == fs.header(http2::HD__METHOD));

  // By name
  CU_ASSERT(HeaderRef(StringRef{"alpha"}, StringRef{"0"}) ==
            *fs.header(StringRef::from_lit("alpha")));
  CU_ASSERT(nullptr == fs.header(StringRef::from_lit("bravo")));
}

void test_downstream_crumble_request_cookie(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();
  req.fs.add_header_token(StringRef::from_lit(":method"),
                          StringRef::from_lit("get"), false, -1);
  req.fs.add_header_token(StringRef::from_lit(":path"),
                          StringRef::from_lit("/"), false, -1);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("alpha; bravo; ; ;; charlie;;"),
                          true, http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit(";delta"), false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("echo"), false, http2::HD_COOKIE);

  std::vector<nghttp2_nv> nva;
  d.crumble_request_cookie(nva);

  auto num_cookies = d.count_crumble_request_cookie();

  CU_ASSERT(5 == nva.size());
  CU_ASSERT(5 == num_cookies);

  HeaderRefs cookies;
  std::transform(std::begin(nva), std::end(nva), std::back_inserter(cookies),
                 [](const nghttp2_nv &nv) {
                   return HeaderRef(StringRef{nv.name, nv.namelen},
                                    StringRef{nv.value, nv.valuelen},
                                    nv.flags & NGHTTP2_NV_FLAG_NO_INDEX);
                 });

  HeaderRefs ans = {
      {StringRef::from_lit("cookie"), StringRef::from_lit("alpha")},
      {StringRef::from_lit("cookie"), StringRef::from_lit("bravo")},
      {StringRef::from_lit("cookie"), StringRef::from_lit("charlie")},
      {StringRef::from_lit("cookie"), StringRef::from_lit("delta")},
      {StringRef::from_lit("cookie"), StringRef::from_lit("echo")}};

  CU_ASSERT(ans == cookies);
  CU_ASSERT(cookies[0].no_index);
  CU_ASSERT(cookies[1].no_index);
  CU_ASSERT(cookies[2].no_index);
}

void test_downstream_assemble_request_cookie(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();

  req.fs.add_header_token(StringRef::from_lit(":method"),
                          StringRef::from_lit("get"), false, -1);
  req.fs.add_header_token(StringRef::from_lit(":path"),
                          StringRef::from_lit("/"), false, -1);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("alpha"), false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("bravo;"), false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("charlie; "), false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("delta;;"), false,
                          http2::HD_COOKIE);
  CU_ASSERT("alpha; bravo; charlie; delta" == d.assemble_request_cookie());
}

void test_downstream_rewrite_location_response_header(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();
  auto &resp = d.response();
  d.set_request_downstream_host(StringRef::from_lit("localhost2"));
  req.authority = StringRef::from_lit("localhost:8443");
  resp.fs.add_header_token(StringRef::from_lit("location"),
                           StringRef::from_lit("http://localhost2:3000/"),
                           false, http2::HD_LOCATION);
  d.rewrite_location_response_header(StringRef::from_lit("https"));
  auto location = resp.fs.header(http2::HD_LOCATION);
  CU_ASSERT("https://localhost:8443/" == (*location).value);
}

void test_downstream_supports_non_final_response(void) {
  Downstream d(nullptr, nullptr, 0);
  auto &req = d.request();

  req.http_major = 3;
  req.http_minor = 0;

  CU_ASSERT(d.supports_non_final_response());

  req.http_major = 2;
  req.http_minor = 0;

  CU_ASSERT(d.supports_non_final_response());

  req.http_major = 1;
  req.http_minor = 1;

  CU_ASSERT(d.supports_non_final_response());

  req.http_major = 1;
  req.http_minor = 0;

  CU_ASSERT(!d.supports_non_final_response());

  req.http_major = 0;
  req.http_minor = 9;

  CU_ASSERT(!d.supports_non_final_response());
}

void test_downstream_find_affinity_cookie(void) {
  Downstream d(nullptr, nullptr, 0);

  auto &req = d.request();
  req.fs.add_header_token(StringRef::from_lit("cookie"), StringRef{}, false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("a=b;;c=d"), false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("content-length"),
                          StringRef::from_lit("599"), false,
                          http2::HD_CONTENT_LENGTH);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("lb=deadbeef;LB=f1f2f3f4"), false,
                          http2::HD_COOKIE);
  req.fs.add_header_token(StringRef::from_lit("cookie"),
                          StringRef::from_lit("short=e1e2e3e"), false,
                          http2::HD_COOKIE);

  uint32_t aff;

  aff = d.find_affinity_cookie(StringRef::from_lit("lb"));

  CU_ASSERT(0xdeadbeef == aff);

  aff = d.find_affinity_cookie(StringRef::from_lit("LB"));

  CU_ASSERT(0xf1f2f3f4 == aff);

  aff = d.find_affinity_cookie(StringRef::from_lit("short"));

  CU_ASSERT(0 == aff);
}

} // namespace shrpx
