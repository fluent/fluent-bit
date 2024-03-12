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
#include "shrpx_worker_test.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

#include <CUnit/CUnit.h>

#include "shrpx_worker.h"
#include "shrpx_connect_blocker.h"
#include "shrpx_log.h"

namespace shrpx {

void test_shrpx_worker_match_downstream_addr_group(void) {
  auto groups = std::vector<std::shared_ptr<DownstreamAddrGroup>>();
  for (auto &s : {"nghttp2.org/", "nghttp2.org/alpha/bravo/",
                  "nghttp2.org/alpha/charlie", "nghttp2.org/delta%3A",
                  "www.nghttp2.org/", "[::1]/", "nghttp2.org/alpha/bravo/delta",
                  // Check that match is done in the single node
                  "example.com/alpha/bravo", "192.168.0.1/alpha/", "/golf/"}) {
    auto g = std::make_shared<DownstreamAddrGroup>();
    g->pattern = ImmutableString(s);
    groups.push_back(std::move(g));
  }

  BlockAllocator balloc(1024, 1024);
  RouterConfig routerconf;

  auto &router = routerconf.router;
  auto &wcrouter = routerconf.rev_wildcard_router;
  auto &wp = routerconf.wildcard_patterns;

  for (size_t i = 0; i < groups.size(); ++i) {
    auto &g = groups[i];
    router.add_route(StringRef{g->pattern}, i);
  }

  CU_ASSERT(0 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/"), groups, 255, balloc));

  // port is removed
  CU_ASSERT(0 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org:8080"),
                     StringRef::from_lit("/"), groups, 255, balloc));

  // host is case-insensitive
  CU_ASSERT(4 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("WWW.nghttp2.org"),
                     StringRef::from_lit("/alpha"), groups, 255, balloc));

  CU_ASSERT(1 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo/"), groups, 255,
                     balloc));

  // /alpha/bravo also matches /alpha/bravo/
  CU_ASSERT(1 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo"), groups, 255, balloc));

  // path part is case-sensitive
  CU_ASSERT(0 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/Alpha/bravo"), groups, 255, balloc));

  CU_ASSERT(1 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo/charlie"), groups, 255,
                     balloc));

  CU_ASSERT(2 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/charlie"), groups, 255,
                     balloc));

  // pattern which does not end with '/' must match its entirely.  So
  // this matches to group 0, not group 2.
  CU_ASSERT(0 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/charlie/"), groups, 255,
                     balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("example.org"),
                       StringRef::from_lit("/"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit(""),
                       StringRef::from_lit("/"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit(""),
                       StringRef::from_lit("alpha"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("foo/bar"),
                       StringRef::from_lit("/"), groups, 255, balloc));

  // If path is StringRef::from_lit("*", only match with host + "/").
  CU_ASSERT(0 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("*"), groups, 255, balloc));

  CU_ASSERT(5 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("[::1]"),
                     StringRef::from_lit("/"), groups, 255, balloc));
  CU_ASSERT(5 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("[::1]:8080"),
                     StringRef::from_lit("/"), groups, 255, balloc));
  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("[::1"),
                       StringRef::from_lit("/"), groups, 255, balloc));
  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("[::1]8000"),
                       StringRef::from_lit("/"), groups, 255, balloc));

  // Check the case where adding route extends tree
  CU_ASSERT(6 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo/delta"), groups, 255,
                     balloc));

  CU_ASSERT(1 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo/delta/"), groups, 255,
                     balloc));

  // Check the case where query is done in a single node
  CU_ASSERT(7 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("example.com"),
                     StringRef::from_lit("/alpha/bravo"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("example.com"),
                       StringRef::from_lit("/alpha/bravo/"), groups, 255,
                       balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("example.com"),
                       StringRef::from_lit("/alpha"), groups, 255, balloc));

  // Check the case where quey is done in a single node
  CU_ASSERT(8 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("192.168.0.1"),
                     StringRef::from_lit("/alpha"), groups, 255, balloc));

  CU_ASSERT(8 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("192.168.0.1"),
                     StringRef::from_lit("/alpha/"), groups, 255, balloc));

  CU_ASSERT(8 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("192.168.0.1"),
                     StringRef::from_lit("/alpha/bravo"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("192.168.0.1"),
                       StringRef::from_lit("/alph"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit("192.168.0.1"),
                       StringRef::from_lit("/"), groups, 255, balloc));

  // Test for wildcard hosts
  auto g1 = std::make_shared<DownstreamAddrGroup>();
  g1->pattern = ImmutableString::from_lit("git.nghttp2.org");
  groups.push_back(std::move(g1));

  auto g2 = std::make_shared<DownstreamAddrGroup>();
  g2->pattern = ImmutableString::from_lit(".nghttp2.org");
  groups.push_back(std::move(g2));

  auto g3 = std::make_shared<DownstreamAddrGroup>();
  g3->pattern = ImmutableString::from_lit(".local");
  groups.push_back(std::move(g3));

  wp.emplace_back(StringRef::from_lit("git.nghttp2.org"));
  wcrouter.add_route(StringRef::from_lit("gro.2ptthgn.tig"), 0);
  wp.back().router.add_route(StringRef::from_lit("/echo/"), 10);

  wp.emplace_back(StringRef::from_lit(".nghttp2.org"));
  wcrouter.add_route(StringRef::from_lit("gro.2ptthgn."), 1);
  wp.back().router.add_route(StringRef::from_lit("/echo/"), 11);
  wp.back().router.add_route(StringRef::from_lit("/echo/foxtrot"), 12);

  wp.emplace_back(StringRef::from_lit(".local"));
  wcrouter.add_route(StringRef::from_lit("lacol."), 2);
  wp.back().router.add_route(StringRef::from_lit("/"), 13);

  CU_ASSERT(11 == match_downstream_addr_group(
                      routerconf, StringRef::from_lit("git.nghttp2.org"),
                      StringRef::from_lit("/echo"), groups, 255, balloc));

  CU_ASSERT(10 == match_downstream_addr_group(
                      routerconf, StringRef::from_lit("0git.nghttp2.org"),
                      StringRef::from_lit("/echo"), groups, 255, balloc));

  CU_ASSERT(11 == match_downstream_addr_group(
                      routerconf, StringRef::from_lit("it.nghttp2.org"),
                      StringRef::from_lit("/echo"), groups, 255, balloc));

  CU_ASSERT(255 == match_downstream_addr_group(
                       routerconf, StringRef::from_lit(".nghttp2.org"),
                       StringRef::from_lit("/echo/foxtrot"), groups, 255,
                       balloc));

  CU_ASSERT(9 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("alpha.nghttp2.org"),
                     StringRef::from_lit("/golf"), groups, 255, balloc));

  CU_ASSERT(0 == match_downstream_addr_group(
                     routerconf, StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/echo"), groups, 255, balloc));

  CU_ASSERT(13 == match_downstream_addr_group(
                      routerconf, StringRef::from_lit("test.local"),
                      StringRef{}, groups, 255, balloc));
}

} // namespace shrpx
