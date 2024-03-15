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
#include "shrpx_router_test.h"

#include <CUnit/CUnit.h>

#include "shrpx_router.h"

namespace shrpx {

struct Pattern {
  StringRef pattern;
  size_t idx;
  bool wildcard;
};

void test_shrpx_router_match(void) {
  auto patterns = std::vector<Pattern>{
      {StringRef::from_lit("nghttp2.org/"), 0},
      {StringRef::from_lit("nghttp2.org/alpha"), 1},
      {StringRef::from_lit("nghttp2.org/alpha/"), 2},
      {StringRef::from_lit("nghttp2.org/alpha/bravo/"), 3},
      {StringRef::from_lit("www.nghttp2.org/alpha/"), 4},
      {StringRef::from_lit("/alpha"), 5},
      {StringRef::from_lit("example.com/alpha/"), 6},
      {StringRef::from_lit("nghttp2.org/alpha/bravo2/"), 7},
      {StringRef::from_lit("www2.nghttp2.org/alpha/"), 8},
      {StringRef::from_lit("www2.nghttp2.org/alpha2/"), 9},
  };

  Router router;

  for (auto &p : patterns) {
    router.add_route(p.pattern, p.idx);
  }

  ssize_t idx;

  idx = router.match(StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/"));

  CU_ASSERT(0 == idx);

  idx = router.match(StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha"));

  CU_ASSERT(1 == idx);

  idx = router.match(StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/"));

  CU_ASSERT(2 == idx);

  idx = router.match(StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/charlie"));

  CU_ASSERT(2 == idx);

  idx = router.match(StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo/"));

  CU_ASSERT(3 == idx);

  // matches pattern when last '/' is missing in path
  idx = router.match(StringRef::from_lit("nghttp2.org"),
                     StringRef::from_lit("/alpha/bravo"));

  CU_ASSERT(3 == idx);

  idx = router.match(StringRef::from_lit("www2.nghttp2.org"),
                     StringRef::from_lit("/alpha"));

  CU_ASSERT(8 == idx);

  idx = router.match(StringRef{}, StringRef::from_lit("/alpha"));

  CU_ASSERT(5 == idx);
}

void test_shrpx_router_match_wildcard(void) {
  constexpr auto patterns = std::array<Pattern, 6>{{
      {StringRef::from_lit("nghttp2.org/"), 0},
      {StringRef::from_lit("nghttp2.org/"), 1, true},
      {StringRef::from_lit("nghttp2.org/alpha/"), 2},
      {StringRef::from_lit("nghttp2.org/alpha/"), 3, true},
      {StringRef::from_lit("nghttp2.org/bravo"), 4},
      {StringRef::from_lit("nghttp2.org/bravo"), 5, true},
  }};

  Router router;

  for (auto &p : patterns) {
    router.add_route(p.pattern, p.idx, p.wildcard);
  }

  CU_ASSERT(0 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/")));

  CU_ASSERT(1 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/a")));

  CU_ASSERT(1 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/charlie")));

  CU_ASSERT(2 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/alpha")));

  CU_ASSERT(2 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/alpha/")));

  CU_ASSERT(3 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/alpha/b")));

  CU_ASSERT(4 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/bravo")));

  CU_ASSERT(5 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/bravocharlie")));

  CU_ASSERT(5 == router.match(StringRef::from_lit("nghttp2.org"),
                              StringRef::from_lit("/bravo/")));
}

void test_shrpx_router_match_prefix(void) {
  auto patterns = std::vector<Pattern>{
      {StringRef::from_lit("gro.2ptthgn."), 0},
      {StringRef::from_lit("gro.2ptthgn.www."), 1},
      {StringRef::from_lit("gro.2ptthgn.gmi."), 2},
      {StringRef::from_lit("gro.2ptthgn.gmi.ahpla."), 3},
  };

  Router router;

  for (auto &p : patterns) {
    router.add_route(p.pattern, p.idx);
  }

  ssize_t idx;
  const RNode *node;
  size_t nread;

  node = nullptr;

  idx = router.match_prefix(&nread, &node,
                            StringRef::from_lit("gro.2ptthgn.gmi.ahpla.ovarb"));

  CU_ASSERT(0 == idx);
  CU_ASSERT(12 == nread);

  idx = router.match_prefix(&nread, &node,
                            StringRef::from_lit("gmi.ahpla.ovarb"));

  CU_ASSERT(2 == idx);
  CU_ASSERT(4 == nread);

  idx = router.match_prefix(&nread, &node, StringRef::from_lit("ahpla.ovarb"));

  CU_ASSERT(3 == idx);
  CU_ASSERT(6 == nread);
}

} // namespace shrpx
