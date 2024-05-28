/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#include "memchunk_test.h"

#include <CUnit/CUnit.h>

#include <nghttp2/nghttp2.h>

#include "memchunk.h"
#include "util.h"

namespace nghttp2 {

void test_pool_recycle(void) {
  MemchunkPool pool;

  CU_ASSERT(!pool.pool);
  CU_ASSERT(0 == pool.poolsize);
  CU_ASSERT(nullptr == pool.freelist);

  auto m1 = pool.get();

  CU_ASSERT(m1 == pool.pool);
  CU_ASSERT(MemchunkPool::value_type::size == pool.poolsize);
  CU_ASSERT(nullptr == pool.freelist);

  auto m2 = pool.get();

  CU_ASSERT(m2 == pool.pool);
  CU_ASSERT(2 * MemchunkPool::value_type::size == pool.poolsize);
  CU_ASSERT(nullptr == pool.freelist);
  CU_ASSERT(m1 == m2->knext);
  CU_ASSERT(nullptr == m1->knext);

  auto m3 = pool.get();

  CU_ASSERT(m3 == pool.pool);
  CU_ASSERT(3 * MemchunkPool::value_type::size == pool.poolsize);
  CU_ASSERT(nullptr == pool.freelist);

  pool.recycle(m3);

  CU_ASSERT(m3 == pool.pool);
  CU_ASSERT(3 * MemchunkPool::value_type::size == pool.poolsize);
  CU_ASSERT(m3 == pool.freelist);

  auto m4 = pool.get();

  CU_ASSERT(m3 == m4);
  CU_ASSERT(m4 == pool.pool);
  CU_ASSERT(3 * MemchunkPool::value_type::size == pool.poolsize);
  CU_ASSERT(nullptr == pool.freelist);

  pool.recycle(m2);
  pool.recycle(m1);

  CU_ASSERT(m1 == pool.freelist);
  CU_ASSERT(m2 == m1->next);
  CU_ASSERT(nullptr == m2->next);
}

using Memchunk16 = Memchunk<16>;
using MemchunkPool16 = Pool<Memchunk16>;
using Memchunks16 = Memchunks<Memchunk16>;
using PeekMemchunks16 = PeekMemchunks<Memchunk16>;

void test_memchunks_append(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  chunks.append("012");

  auto m = chunks.tail;

  CU_ASSERT(3 == m->len());
  CU_ASSERT(13 == m->left());

  chunks.append("3456789abcdef@");

  CU_ASSERT(16 == m->len());
  CU_ASSERT(0 == m->left());

  m = chunks.tail;

  CU_ASSERT(1 == m->len());
  CU_ASSERT(15 == m->left());
  CU_ASSERT(17 == chunks.rleft());

  char buf[16];
  size_t nread;

  nread = chunks.remove(buf, 8);

  CU_ASSERT(8 == nread);
  CU_ASSERT(0 == memcmp("01234567", buf, nread));
  CU_ASSERT(9 == chunks.rleft());

  nread = chunks.remove(buf, sizeof(buf));

  CU_ASSERT(9 == nread);
  CU_ASSERT(0 == memcmp("89abcdef@", buf, nread));
  CU_ASSERT(0 == chunks.rleft());
  CU_ASSERT(nullptr == chunks.head);
  CU_ASSERT(nullptr == chunks.tail);
  CU_ASSERT(32 == pool.poolsize);
}

void test_memchunks_drain(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  chunks.append("0123456789");

  size_t nread;

  nread = chunks.drain(3);

  CU_ASSERT(3 == nread);

  char buf[16];

  nread = chunks.remove(buf, sizeof(buf));

  CU_ASSERT(7 == nread);
  CU_ASSERT(0 == memcmp("3456789", buf, nread));
}

void test_memchunks_riovec(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  std::array<char, 3 * 16> buf{};

  chunks.append(buf.data(), buf.size());

  std::array<struct iovec, 2> iov;
  auto iovcnt = chunks.riovec(iov.data(), iov.size());

  auto m = chunks.head;

  CU_ASSERT(2 == iovcnt);
  CU_ASSERT(m->buf.data() == iov[0].iov_base);
  CU_ASSERT(m->len() == iov[0].iov_len);

  m = m->next;

  CU_ASSERT(m->buf.data() == iov[1].iov_base);
  CU_ASSERT(m->len() == iov[1].iov_len);

  chunks.drain(2 * 16);

  iovcnt = chunks.riovec(iov.data(), iov.size());

  CU_ASSERT(1 == iovcnt);

  m = chunks.head;
  CU_ASSERT(m->buf.data() == iov[0].iov_base);
  CU_ASSERT(m->len() == iov[0].iov_len);
}

void test_memchunks_recycle(void) {
  MemchunkPool16 pool;
  {
    Memchunks16 chunks(&pool);
    std::array<char, 32> buf{};
    chunks.append(buf.data(), buf.size());
  }
  CU_ASSERT(32 == pool.poolsize);
  CU_ASSERT(nullptr != pool.freelist);

  auto m = pool.freelist;
  m = m->next;

  CU_ASSERT(nullptr != m);
  CU_ASSERT(nullptr == m->next);
}

void test_memchunks_reset(void) {
  MemchunkPool16 pool;
  Memchunks16 chunks(&pool);

  std::array<uint8_t, 32> b{};

  chunks.append(b.data(), b.size());

  CU_ASSERT(32 == chunks.rleft());

  chunks.reset();

  CU_ASSERT(0 == chunks.rleft());
  CU_ASSERT(nullptr == chunks.head);
  CU_ASSERT(nullptr == chunks.tail);

  auto m = pool.freelist;

  CU_ASSERT(nullptr != m);
  CU_ASSERT(nullptr != m->next);
  CU_ASSERT(nullptr == m->next->next);
}

void test_peek_memchunks_append(void) {
  MemchunkPool16 pool;
  PeekMemchunks16 pchunks(&pool);

  std::array<uint8_t, 32> b{
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
  },
      d;

  pchunks.append(b.data(), b.size());

  CU_ASSERT(32 == pchunks.rleft());
  CU_ASSERT(32 == pchunks.rleft_buffered());

  CU_ASSERT(0 == pchunks.remove(nullptr, 0));

  CU_ASSERT(32 == pchunks.rleft());
  CU_ASSERT(32 == pchunks.rleft_buffered());

  CU_ASSERT(12 == pchunks.remove(d.data(), 12));

  CU_ASSERT(std::equal(std::begin(b), std::begin(b) + 12, std::begin(d)));

  CU_ASSERT(20 == pchunks.rleft());
  CU_ASSERT(32 == pchunks.rleft_buffered());

  CU_ASSERT(20 == pchunks.remove(d.data(), d.size()));

  CU_ASSERT(std::equal(std::begin(b) + 12, std::end(b), std::begin(d)));

  CU_ASSERT(0 == pchunks.rleft());
  CU_ASSERT(32 == pchunks.rleft_buffered());
}

void test_peek_memchunks_disable_peek_drain(void) {
  MemchunkPool16 pool;
  PeekMemchunks16 pchunks(&pool);

  std::array<uint8_t, 32> b{
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
  },
      d;

  pchunks.append(b.data(), b.size());

  CU_ASSERT(12 == pchunks.remove(d.data(), 12));

  pchunks.disable_peek(true);

  CU_ASSERT(!pchunks.peeking);
  CU_ASSERT(20 == pchunks.rleft());
  CU_ASSERT(20 == pchunks.rleft_buffered());

  CU_ASSERT(20 == pchunks.remove(d.data(), d.size()));

  CU_ASSERT(std::equal(std::begin(b) + 12, std::end(b), std::begin(d)));

  CU_ASSERT(0 == pchunks.rleft());
  CU_ASSERT(0 == pchunks.rleft_buffered());
}

void test_peek_memchunks_disable_peek_no_drain(void) {
  MemchunkPool16 pool;
  PeekMemchunks16 pchunks(&pool);

  std::array<uint8_t, 32> b{
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
  },
      d;

  pchunks.append(b.data(), b.size());

  CU_ASSERT(12 == pchunks.remove(d.data(), 12));

  pchunks.disable_peek(false);

  CU_ASSERT(!pchunks.peeking);
  CU_ASSERT(32 == pchunks.rleft());
  CU_ASSERT(32 == pchunks.rleft_buffered());

  CU_ASSERT(32 == pchunks.remove(d.data(), d.size()));

  CU_ASSERT(std::equal(std::begin(b), std::end(b), std::begin(d)));

  CU_ASSERT(0 == pchunks.rleft());
  CU_ASSERT(0 == pchunks.rleft_buffered());
}

void test_peek_memchunks_reset(void) {
  MemchunkPool16 pool;
  PeekMemchunks16 pchunks(&pool);

  std::array<uint8_t, 32> b{
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
  },
      d;

  pchunks.append(b.data(), b.size());

  CU_ASSERT(12 == pchunks.remove(d.data(), 12));

  pchunks.disable_peek(true);
  pchunks.reset();

  CU_ASSERT(0 == pchunks.rleft());
  CU_ASSERT(0 == pchunks.rleft_buffered());

  CU_ASSERT(nullptr == pchunks.cur);
  CU_ASSERT(nullptr == pchunks.cur_pos);
  CU_ASSERT(nullptr == pchunks.cur_last);
  CU_ASSERT(pchunks.peeking);
}

} // namespace nghttp2
