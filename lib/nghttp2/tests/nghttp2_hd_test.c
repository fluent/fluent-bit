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
#include "nghttp2_hd_test.h"

#include <stdio.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include "nghttp2_hd.h"
#include "nghttp2_frame.h"
#include "nghttp2_test_helper.h"

void test_nghttp2_hd_deflate(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva1[] = {MAKE_NV(":path", "/my-example/index.html"),
                       MAKE_NV(":scheme", "https"), MAKE_NV("hello", "world")};
  nghttp2_nv nva2[] = {MAKE_NV(":path", "/script.js"),
                       MAKE_NV(":scheme", "https")};
  nghttp2_nv nva3[] = {MAKE_NV("cookie", "k1=v1"), MAKE_NV("cookie", "k2=v2"),
                       MAKE_NV("via", "proxy")};
  nghttp2_nv nva4[] = {MAKE_NV(":path", "/style.css"),
                       MAKE_NV("cookie", "k1=v1"), MAKE_NV("cookie", "k1=v1")};
  nghttp2_nv nva5[] = {MAKE_NV(":path", "/style.css"),
                       MAKE_NV("x-nghttp2", "")};
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nva_out out;
  int rv;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  CU_ASSERT(0 == nghttp2_hd_deflate_init(&deflater, mem));
  CU_ASSERT(0 == nghttp2_hd_inflate_init(&inflater, mem));

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva1, ARRLEN(nva1));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva1, out.nva, 3, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Second headers */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva2, ARRLEN(nva2));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(2 == out.nvlen);
  assert_nv_equal(nva2, out.nva, 2, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Third headers, including same header field name, but value is not
     the same. */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva3, ARRLEN(nva3));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva3, out.nva, 3, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Fourth headers, including duplicate header fields. */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva4, ARRLEN(nva4));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva4, out.nva, 3, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Fifth headers includes empty value */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva5, ARRLEN(nva5));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(2 == out.nvlen);
  assert_nv_equal(nva5, out.nva, 2, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Cleanup */
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_deflate_same_indexed_repr(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva1[] = {MAKE_NV("host", "alpha"), MAKE_NV("host", "alpha")};
  nghttp2_nv nva2[] = {MAKE_NV("host", "alpha"), MAKE_NV("host", "alpha"),
                       MAKE_NV("host", "alpha")};
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nva_out out;
  int rv;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  CU_ASSERT(0 == nghttp2_hd_deflate_init(&deflater, mem));
  CU_ASSERT(0 == nghttp2_hd_inflate_init(&inflater, mem));

  /* Encode 2 same headers.  Emit 1 literal reprs and 1 index repr. */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva1, ARRLEN(nva1));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(2 == out.nvlen);
  assert_nv_equal(nva1, out.nva, 2, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Encode 3 same headers.  This time, emits 3 index reprs. */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva2, ARRLEN(nva2));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen == 3);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(3 == out.nvlen);
  assert_nv_equal(nva2, out.nva, 3, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Cleanup */
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_inflate_indexed(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv = MAKE_NV(":path", "/");
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater, mem);

  nghttp2_bufs_addb(&bufs, (1 << 7) | 4);

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(1 == blocklen);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);

  assert_nv_equal(&nv, out.nva, 1, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* index = 0 is error */
  nghttp2_bufs_addb(&bufs, 1 << 7);

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(1 == blocklen);
  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_noinc(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv[] = {/* Huffman */
                     MAKE_NV("user-agent", "nghttp2"),
                     /* Expecting no huffman */
                     MAKE_NV("user-agent", "x")};
  size_t i;
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater, mem);

  for (i = 0; i < ARRLEN(nv); ++i) {
    CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 57, &nv[i],
                                                 NGHTTP2_HD_WITHOUT_INDEXING));

    blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

    CU_ASSERT(blocklen > 0);
    CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

    CU_ASSERT(1 == out.nvlen);
    assert_nv_equal(&nv[i], out.nva, 1, mem);
    CU_ASSERT(0 == inflater.ctx.hd_table.len);
    CU_ASSERT(61 == nghttp2_hd_inflate_get_num_table_entries(&inflater));

    nva_out_reset(&out, mem);
    nghttp2_bufs_reset(&bufs);
  }

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_inc(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv = MAKE_NV("user-agent", "nghttp2");
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater, mem);

  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 57, &nv,
                                               NGHTTP2_HD_WITH_INDEXING));

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1, mem);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);
  CU_ASSERT(62 == nghttp2_hd_inflate_get_num_table_entries(&inflater));
  assert_nv_equal(
      &nv,
      nghttp2_hd_inflate_get_table_entry(
          &inflater, NGHTTP2_STATIC_TABLE_LENGTH + inflater.ctx.hd_table.len),
      1, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_indname_inc_eviction(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  uint8_t value[1025];
  nva_out out;
  nghttp2_nv nv;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater, mem);

  memset(value, '0', sizeof(value));
  value[sizeof(value) - 1] = '\0';
  nv.value = value;
  nv.valuelen = sizeof(value) - 1;

  nv.flags = NGHTTP2_NV_FLAG_NONE;

  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 14, &nv,
                                               NGHTTP2_HD_WITH_INDEXING));
  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 15, &nv,
                                               NGHTTP2_HD_WITH_INDEXING));
  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 16, &nv,
                                               NGHTTP2_HD_WITH_INDEXING));
  CU_ASSERT(0 == nghttp2_hd_emit_indname_block(&bufs, 17, &nv,
                                               NGHTTP2_HD_WITH_INDEXING));

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(4 == out.nvlen);
  CU_ASSERT(14 == out.nva[0].namelen);
  CU_ASSERT(0 == memcmp("accept-charset", out.nva[0].name, out.nva[0].namelen));
  CU_ASSERT(sizeof(value) - 1 == out.nva[0].valuelen);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  CU_ASSERT(3 == inflater.ctx.hd_table.len);
  CU_ASSERT(64 == nghttp2_hd_inflate_get_num_table_entries(&inflater));

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_newname_noinc(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv[] = {/* Expecting huffman for both */
                     MAKE_NV("my-long-content-length", "nghttp2"),
                     /* Expecting no huffman for both */
                     MAKE_NV("x", "y"),
                     /* Huffman for key only */
                     MAKE_NV("my-long-content-length", "y"),
                     /* Huffman for value only */
                     MAKE_NV("x", "nghttp2")};
  size_t i;
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater, mem);
  for (i = 0; i < ARRLEN(nv); ++i) {
    CU_ASSERT(0 == nghttp2_hd_emit_newname_block(&bufs, &nv[i],
                                                 NGHTTP2_HD_WITHOUT_INDEXING));

    blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

    CU_ASSERT(blocklen > 0);
    CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

    CU_ASSERT(1 == out.nvlen);
    assert_nv_equal(&nv[i], out.nva, 1, mem);
    CU_ASSERT(0 == inflater.ctx.hd_table.len);

    nva_out_reset(&out, mem);
    nghttp2_bufs_reset(&bufs);
  }

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_newname_inc(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv = MAKE_NV("x-rel", "nghttp2");
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  nghttp2_hd_inflate_init(&inflater, mem);

  CU_ASSERT(
      0 == nghttp2_hd_emit_newname_block(&bufs, &nv, NGHTTP2_HD_WITH_INDEXING));

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1, mem);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);
  assert_nv_equal(
      &nv,
      nghttp2_hd_inflate_get_table_entry(
          &inflater, NGHTTP2_STATIC_TABLE_LENGTH + inflater.ctx.hd_table.len),
      1, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_clearall_inc(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nv;
  uint8_t value[4061];
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  bufs_large_init(&bufs, 8192);

  nva_out_init(&out);
  /* Total 4097 bytes space required to hold this entry */
  nv.name = (uint8_t *)"alpha";
  nv.namelen = strlen((char *)nv.name);
  memset(value, '0', sizeof(value));
  value[sizeof(value) - 1] = '\0';
  nv.value = value;
  nv.valuelen = sizeof(value) - 1;

  nv.flags = NGHTTP2_NV_FLAG_NONE;

  nghttp2_hd_inflate_init(&inflater, mem);

  CU_ASSERT(
      0 == nghttp2_hd_emit_newname_block(&bufs, &nv, NGHTTP2_HD_WITH_INDEXING));

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1, mem);
  CU_ASSERT(0 == inflater.ctx.hd_table.len);

  nva_out_reset(&out, mem);

  /* Do it again */
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1, mem);
  CU_ASSERT(0 == inflater.ctx.hd_table.len);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* This time, 4096 bytes space required, which is just fits in the
     header table */
  nv.valuelen = sizeof(value) - 2;

  CU_ASSERT(
      0 == nghttp2_hd_emit_newname_block(&bufs, &nv, NGHTTP2_HD_WITH_INDEXING));

  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1, mem);
  CU_ASSERT(1 == inflater.ctx.hd_table.len);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_zero_length_huffman(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  /* Literal header without indexing - new name */
  uint8_t data[] = {0x40, 0x01, 0x78 /* 'x' */, 0x80};
  nva_out out;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  nghttp2_bufs_add(&bufs, data, sizeof(data));

  /* /\* Literal header without indexing - new name *\/ */
  /* ptr[0] = 0x40; */
  /* ptr[1] = 1; */
  /* ptr[2] = 'x'; */
  /* ptr[3] = 0x80; */

  nghttp2_hd_inflate_init(&inflater, mem);
  CU_ASSERT(4 == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(1 == out.nvlen);
  CU_ASSERT(1 == out.nva[0].namelen);
  CU_ASSERT('x' == out.nva[0].name[0]);
  CU_ASSERT(NULL == out.nva[0].value);
  CU_ASSERT(0 == out.nva[0].valuelen);

  nva_out_reset(&out, mem);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_inflate_expect_table_size_update(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  nghttp2_mem *mem;
  /* Indexed Header: :method: GET */
  uint8_t data[] = {0x82};
  nva_out out;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);
  nva_out_init(&out);

  nghttp2_bufs_add(&bufs, data, sizeof(data));
  nghttp2_hd_inflate_init(&inflater, mem);
  /* This will make inflater require table size update in the next
     inflation. */
  nghttp2_hd_inflate_change_table_size(&inflater, 4095);
  nghttp2_hd_inflate_change_table_size(&inflater, 4096);
  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_hd_inflate_free(&inflater);

  /* This does not require for encoder to emit table size update since
   * size is not changed. */
  nghttp2_hd_inflate_init(&inflater, mem);
  nghttp2_hd_inflate_change_table_size(&inflater, 4096);
  CU_ASSERT((ssize_t)nghttp2_bufs_len(&bufs) ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_hd_inflate_free(&inflater);

  /* This does not require for encodre to emit table size update since
     new size is larger than current size. */
  nghttp2_hd_inflate_init(&inflater, mem);
  nghttp2_hd_inflate_change_table_size(&inflater, 4097);
  CU_ASSERT((ssize_t)nghttp2_bufs_len(&bufs) ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_hd_inflate_free(&inflater);

  /* Received table size is strictly larger than minimum table size */
  nghttp2_hd_inflate_init(&inflater, mem);
  nghttp2_hd_inflate_change_table_size(&inflater, 111);
  nghttp2_hd_inflate_change_table_size(&inflater, 4096);

  nghttp2_bufs_reset(&bufs);
  nghttp2_hd_emit_table_size(&bufs, 112);

  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_hd_inflate_free(&inflater);

  /* Receiving 2 table size updates, min and last value */
  nghttp2_hd_inflate_init(&inflater, mem);
  nghttp2_hd_inflate_change_table_size(&inflater, 111);
  nghttp2_hd_inflate_change_table_size(&inflater, 4096);

  nghttp2_bufs_reset(&bufs);
  nghttp2_hd_emit_table_size(&bufs, 111);
  nghttp2_hd_emit_table_size(&bufs, 4096);

  CU_ASSERT((ssize_t)nghttp2_bufs_len(&bufs) ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_hd_inflate_free(&inflater);

  /* 2nd update is larger than last value */
  nghttp2_hd_inflate_init(&inflater, mem);
  nghttp2_hd_inflate_change_table_size(&inflater, 111);
  nghttp2_hd_inflate_change_table_size(&inflater, 4095);

  nghttp2_bufs_reset(&bufs);
  nghttp2_hd_emit_table_size(&bufs, 111);
  nghttp2_hd_emit_table_size(&bufs, 4096);

  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_hd_inflate_free(&inflater);

  nghttp2_bufs_free(&bufs);
}

void test_nghttp2_hd_inflate_unexpected_table_size_update(void) {
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  nghttp2_mem *mem;
  /* Indexed Header: :method: GET, followed by table size update.
     This violates RFC 7541. */
  uint8_t data[] = {0x82, 0x20};
  nva_out out;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);
  nva_out_init(&out);

  nghttp2_bufs_add(&bufs, data, sizeof(data));
  nghttp2_hd_inflate_init(&inflater, mem);
  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
}

void test_nghttp2_hd_ringbuf_reserve(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nv;
  nghttp2_bufs bufs;
  nva_out out;
  int i;
  ssize_t rv;
  ssize_t blocklen;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);
  nva_out_init(&out);

  nv.flags = NGHTTP2_NV_FLAG_NONE;
  nv.name = (uint8_t *)"a";
  nv.namelen = strlen((const char *)nv.name);
  nv.valuelen = 4;
  nv.value = mem->malloc(nv.valuelen + 1, NULL);
  memset(nv.value, 0, nv.valuelen);

  nghttp2_hd_deflate_init2(&deflater, 8000, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  nghttp2_hd_inflate_change_table_size(&inflater, 8000);
  nghttp2_hd_deflate_change_table_size(&deflater, 8000);

  for (i = 0; i < 150; ++i) {
    memcpy(nv.value, &i, sizeof(i));
    rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, &nv, 1);
    blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

    CU_ASSERT(0 == rv);
    CU_ASSERT(blocklen > 0);

    CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

    CU_ASSERT(1 == out.nvlen);
    assert_nv_equal(&nv, out.nva, 1, mem);

    nva_out_reset(&out, mem);
    nghttp2_bufs_reset(&bufs);
  }

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  mem->free(nv.value, NULL);
}

void test_nghttp2_hd_change_table_size(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nva[] = {MAKE_NV("alpha", "bravo"), MAKE_NV("charlie", "delta")};
  nghttp2_nv nva2[] = {MAKE_NV(":path", "/")};
  nghttp2_bufs bufs;
  ssize_t rv;
  nva_out out;
  ssize_t blocklen;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  nghttp2_hd_deflate_init(&deflater, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  /* inflater changes notifies 8000 max header table size */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 8000));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 8000));

  CU_ASSERT(4096 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(4096 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  /* This will emit encoding context update with header table size 4096 */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(63 == nghttp2_hd_deflate_get_num_table_entries(&deflater));
  CU_ASSERT(4096 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(63 == nghttp2_hd_inflate_get_num_table_entries(&inflater));
  CU_ASSERT(4096 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* inflater changes header table size to 1024 */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 1024));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 1024));

  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(1024 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(1024 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(63 == nghttp2_hd_deflate_get_num_table_entries(&deflater));
  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(63 == nghttp2_hd_inflate_get_num_table_entries(&inflater));
  CU_ASSERT(1024 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(1024 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* inflater changes header table size to 0 */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 0));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 0));

  CU_ASSERT(0 == deflater.ctx.hd_table.len);
  CU_ASSERT(61 == nghttp2_hd_deflate_get_num_table_entries(&deflater));
  CU_ASSERT(0 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(0 == inflater.ctx.hd_table.len);
  CU_ASSERT(61 == nghttp2_hd_inflate_get_num_table_entries(&inflater));
  CU_ASSERT(0 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(0 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(0 == deflater.ctx.hd_table.len);
  CU_ASSERT(61 == nghttp2_hd_deflate_get_num_table_entries(&deflater));
  CU_ASSERT(0 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(0 == inflater.ctx.hd_table.len);
  CU_ASSERT(61 == nghttp2_hd_inflate_get_num_table_entries(&inflater));
  CU_ASSERT(0 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(0 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  /* Check table buffer is expanded */
  frame_pack_bufs_init(&bufs);

  nghttp2_hd_deflate_init2(&deflater, 8192, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  /* First inflater changes header table size to 8000 */
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 8000));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 8000));

  CU_ASSERT(8000 == deflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == nghttp2_hd_deflate_get_max_dynamic_table_size(&deflater));
  CU_ASSERT(4096 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(4096 == nghttp2_hd_inflate_get_max_dynamic_table_size(&inflater));
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(8000 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(8000 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 16383));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 16383));

  CU_ASSERT(8192 == deflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8192 == nghttp2_hd_deflate_get_max_dynamic_table_size(&deflater));

  CU_ASSERT(8000 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(8000 == nghttp2_hd_inflate_get_max_dynamic_table_size(&inflater));
  CU_ASSERT(16383 == inflater.settings_hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(8192 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(8192 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(16383 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  /* Lastly, check the error condition */

  rv = nghttp2_hd_emit_table_size(&bufs, 25600);
  CU_ASSERT(rv == 0);
  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP ==
            inflate_hd(&inflater, &out, &bufs, 0, mem));

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  /* Check that encoder can handle the case where its allowable buffer
     size is less than default size, 4096 */
  nghttp2_hd_deflate_init2(&deflater, 1024, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  /* This emits context update with buffer size 1024 */
  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(2 == deflater.ctx.hd_table.len);
  CU_ASSERT(1024 == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(2 == inflater.ctx.hd_table.len);
  CU_ASSERT(1024 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(4096 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  /* Check that table size UINT32_MAX can be received */
  nghttp2_hd_deflate_init2(&deflater, UINT32_MAX, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, UINT32_MAX));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, UINT32_MAX));

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(UINT32_MAX == deflater.ctx.hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(UINT32_MAX == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(UINT32_MAX == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  /* Check that context update emitted twice */
  nghttp2_hd_deflate_init2(&deflater, 4096, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 0));
  CU_ASSERT(0 == nghttp2_hd_inflate_change_table_size(&inflater, 3000));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 0));
  CU_ASSERT(0 == nghttp2_hd_deflate_change_table_size(&deflater, 3000));

  CU_ASSERT(0 == deflater.min_hd_table_bufsize_max);
  CU_ASSERT(3000 == deflater.ctx.hd_table_bufsize_max);

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva2, 1);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(3 < blocklen);
  CU_ASSERT(3000 == deflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(UINT32_MAX == deflater.min_hd_table_bufsize_max);

  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));
  CU_ASSERT(3000 == inflater.ctx.hd_table_bufsize_max);
  CU_ASSERT(3000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out, mem);
  nghttp2_bufs_reset(&bufs);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);

  nghttp2_bufs_free(&bufs);
}

static void check_deflate_inflate(nghttp2_hd_deflater *deflater,
                                  nghttp2_hd_inflater *inflater,
                                  nghttp2_nv *nva, size_t nvlen,
                                  nghttp2_mem *mem) {
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nva_out out;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  rv = nghttp2_hd_deflate_hd_bufs(deflater, &bufs, nva, nvlen);
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen >= 0);

  CU_ASSERT(blocklen == inflate_hd(inflater, &out, &bufs, 0, mem));

  CU_ASSERT(nvlen == out.nvlen);
  assert_nv_equal(nva, out.nva, nvlen, mem);

  nva_out_reset(&out, mem);
  nghttp2_bufs_free(&bufs);
}

void test_nghttp2_hd_deflate_inflate(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_nv nv1[] = {
      MAKE_NV(":status", "200 OK"),
      MAKE_NV("access-control-allow-origin", "*"),
      MAKE_NV("cache-control", "private, max-age=0, must-revalidate"),
      MAKE_NV("content-length", "76073"),
      MAKE_NV("content-type", "text/html"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("server", "Apache"),
      MAKE_NV("vary", "foobar"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "MISS from alphabravo"),
      MAKE_NV("x-cache-action", "MISS"),
      MAKE_NV("x-cache-age", "0"),
      MAKE_NV("x-cache-lookup", "MISS from alphabravo:3128"),
      MAKE_NV("x-lb-nocache", "true"),
  };
  nghttp2_nv nv2[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682045"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:15 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128")};
  nghttp2_nv nv3[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682072"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:23:24 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:13 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv4[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682022"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:22:34 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:14 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv5[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=4461139"),
      MAKE_NV("content-type", "application/x-javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Mon, 16 Sep 2013 21:34:31 GMT"),
      MAKE_NV("last-modified", "Thu, 05 May 2011 09:15:59 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv6[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=18645951"),
      MAKE_NV("content-type", "application/x-javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Fri, 28 Feb 2014 01:48:03 GMT"),
      MAKE_NV("last-modified", "Tue, 12 Jul 2011 16:02:59 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv7[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=31536000"),
      MAKE_NV("content-type", "application/javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("etag", "\"6807-4dc5b54e0dcc0\""),
      MAKE_NV("expires", "Wed, 21 May 2014 08:32:17 GMT"),
      MAKE_NV("last-modified", "Fri, 10 May 2013 11:18:51 GMT"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv8[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=31536000"),
      MAKE_NV("content-type", "application/javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("etag", "\"41c6-4de7d28585b00\""),
      MAKE_NV("expires", "Thu, 12 Jun 2014 10:00:58 GMT"),
      MAKE_NV("last-modified", "Thu, 06 Jun 2013 14:30:36 GMT"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv9[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=31536000"),
      MAKE_NV("content-type", "application/javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("etag", "\"19d6e-4dc5b35a541c0\""),
      MAKE_NV("expires", "Wed, 21 May 2014 08:32:18 GMT"),
      MAKE_NV("last-modified", "Fri, 10 May 2013 11:10:07 GMT"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_nv nv10[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682045"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:21:53 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();

  nghttp2_hd_deflate_init(&deflater, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  check_deflate_inflate(&deflater, &inflater, nv1, ARRLEN(nv1), mem);
  check_deflate_inflate(&deflater, &inflater, nv2, ARRLEN(nv2), mem);
  check_deflate_inflate(&deflater, &inflater, nv3, ARRLEN(nv3), mem);
  check_deflate_inflate(&deflater, &inflater, nv4, ARRLEN(nv4), mem);
  check_deflate_inflate(&deflater, &inflater, nv5, ARRLEN(nv5), mem);
  check_deflate_inflate(&deflater, &inflater, nv6, ARRLEN(nv6), mem);
  check_deflate_inflate(&deflater, &inflater, nv7, ARRLEN(nv7), mem);
  check_deflate_inflate(&deflater, &inflater, nv8, ARRLEN(nv8), mem);
  check_deflate_inflate(&deflater, &inflater, nv9, ARRLEN(nv9), mem);
  check_deflate_inflate(&deflater, &inflater, nv10, ARRLEN(nv10), mem);

  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_no_index(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_hd_inflater inflater;
  nghttp2_bufs bufs;
  ssize_t blocklen;
  nghttp2_nv nva[] = {
      MAKE_NV(":method", "GET"), MAKE_NV(":method", "POST"),
      MAKE_NV(":path", "/foo"),  MAKE_NV("version", "HTTP/1.1"),
      MAKE_NV(":method", "GET"),
  };
  size_t i;
  nva_out out;
  int rv;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();

  /* 1st :method: GET can be indexable, last one is not */
  for (i = 1; i < ARRLEN(nva); ++i) {
    nva[i].flags = NGHTTP2_NV_FLAG_NO_INDEX;
  }

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  nghttp2_hd_deflate_init(&deflater, mem);
  nghttp2_hd_inflate_init(&inflater, mem);

  rv = nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, ARRLEN(nva));
  blocklen = (ssize_t)nghttp2_bufs_len(&bufs);

  CU_ASSERT(0 == rv);
  CU_ASSERT(blocklen > 0);
  CU_ASSERT(blocklen == inflate_hd(&inflater, &out, &bufs, 0, mem));

  CU_ASSERT(ARRLEN(nva) == out.nvlen);
  assert_nv_equal(nva, out.nva, ARRLEN(nva), mem);

  CU_ASSERT(out.nva[0].flags == NGHTTP2_NV_FLAG_NONE);
  for (i = 1; i < ARRLEN(nva); ++i) {
    CU_ASSERT(out.nva[i].flags == NGHTTP2_NV_FLAG_NO_INDEX);
  }

  nva_out_reset(&out, mem);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_inflate_free(&inflater);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_deflate_bound(void) {
  nghttp2_hd_deflater deflater;
  nghttp2_nv nva[] = {MAKE_NV(":method", "GET"), MAKE_NV("alpha", "bravo")};
  nghttp2_bufs bufs;
  size_t bound, bound2;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();
  frame_pack_bufs_init(&bufs);

  nghttp2_hd_deflate_init(&deflater, mem);

  bound = nghttp2_hd_deflate_bound(&deflater, nva, ARRLEN(nva));

  CU_ASSERT(12 + 6 * 2 * 2 + nva[0].namelen + nva[0].valuelen + nva[1].namelen +
                nva[1].valuelen ==
            bound);

  nghttp2_hd_deflate_hd_bufs(&deflater, &bufs, nva, ARRLEN(nva));

  CU_ASSERT(bound > (size_t)nghttp2_bufs_len(&bufs));

  bound2 = nghttp2_hd_deflate_bound(&deflater, nva, ARRLEN(nva));

  CU_ASSERT(bound == bound2);

  nghttp2_bufs_free(&bufs);
  nghttp2_hd_deflate_free(&deflater);
}

void test_nghttp2_hd_public_api(void) {
  nghttp2_hd_deflater *deflater;
  nghttp2_hd_inflater *inflater;
  nghttp2_nv nva[] = {MAKE_NV("alpha", "bravo"), MAKE_NV("charlie", "delta")};
  uint8_t buf[4096];
  size_t buflen;
  ssize_t blocklen;
  nghttp2_bufs bufs;
  nghttp2_mem *mem;

  mem = nghttp2_mem_default();

  CU_ASSERT(0 == nghttp2_hd_deflate_new(&deflater, 4096));
  CU_ASSERT(0 == nghttp2_hd_inflate_new(&inflater));

  buflen = nghttp2_hd_deflate_bound(deflater, nva, ARRLEN(nva));

  blocklen = nghttp2_hd_deflate_hd(deflater, buf, buflen, nva, ARRLEN(nva));

  CU_ASSERT(blocklen > 0);

  nghttp2_bufs_wrap_init(&bufs, buf, (size_t)blocklen, mem);
  bufs.head->buf.last += blocklen;

  CU_ASSERT(blocklen == inflate_hd(inflater, NULL, &bufs, 0, mem));

  nghttp2_bufs_wrap_free(&bufs);

  nghttp2_hd_inflate_del(inflater);
  nghttp2_hd_deflate_del(deflater);

  /* See NGHTTP2_ERR_INSUFF_BUFSIZE */
  CU_ASSERT(0 == nghttp2_hd_deflate_new(&deflater, 4096));

  blocklen = nghttp2_hd_deflate_hd(deflater, buf, (size_t)(blocklen - 1), nva,
                                   ARRLEN(nva));

  CU_ASSERT(NGHTTP2_ERR_INSUFF_BUFSIZE == blocklen);

  nghttp2_hd_deflate_del(deflater);
}

void test_nghttp2_hd_deflate_hd_vec(void) {
  nghttp2_hd_deflater *deflater;
  nghttp2_hd_inflater *inflater;
  nghttp2_nv nva[] = {
      MAKE_NV(":method", "PUT"),
      MAKE_NV(":scheme", "https"),
      MAKE_NV(":authority", "localhost:3000"),
      MAKE_NV(":path", "/usr/foo/alpha/bravo"),
      MAKE_NV("content-type", "image/png"),
      MAKE_NV("content-length", "1000000007"),
  };
  uint8_t buf[4096];
  ssize_t blocklen;
  nghttp2_mem *mem;
  nghttp2_vec vec[256];
  size_t buflen;
  nghttp2_bufs bufs;
  nva_out out;
  size_t i;

  mem = nghttp2_mem_default();

  nva_out_init(&out);

  nghttp2_hd_deflate_new(&deflater, 4096);
  nghttp2_hd_inflate_new(&inflater);

  buflen = nghttp2_hd_deflate_bound(deflater, nva, ARRLEN(nva));

  vec[0].base = &buf[0];
  vec[0].len = buflen / 2;
  vec[1].base = &buf[buflen / 2];
  vec[1].len = buflen / 2;

  blocklen = nghttp2_hd_deflate_hd_vec(deflater, vec, 2, nva, ARRLEN(nva));

  CU_ASSERT(blocklen > 0);

  nghttp2_bufs_wrap_init(&bufs, buf, (size_t)blocklen, mem);
  bufs.head->buf.last += blocklen;

  CU_ASSERT(blocklen == inflate_hd(inflater, &out, &bufs, 0, mem));

  CU_ASSERT(ARRLEN(nva) == out.nvlen);
  assert_nv_equal(nva, out.nva, ARRLEN(nva), mem);

  nghttp2_bufs_wrap_free(&bufs);

  nghttp2_hd_inflate_del(inflater);
  nghttp2_hd_deflate_del(deflater);
  nva_out_reset(&out, mem);

  /* check the case when veclen is 0 */
  nghttp2_hd_deflate_new(&deflater, 4096);
  nghttp2_hd_inflate_new(&inflater);

  blocklen = nghttp2_hd_deflate_hd_vec(deflater, NULL, 0, nva, ARRLEN(nva));

  CU_ASSERT(NGHTTP2_ERR_INSUFF_BUFSIZE == blocklen);

  nghttp2_hd_inflate_del(inflater);
  nghttp2_hd_deflate_del(deflater);

  /* check the case when chunk length is 0 */
  vec[0].base = NULL;
  vec[0].len = 0;
  vec[1].base = NULL;
  vec[1].len = 0;

  nghttp2_hd_deflate_new(&deflater, 4096);
  nghttp2_hd_inflate_new(&inflater);

  blocklen = nghttp2_hd_deflate_hd_vec(deflater, vec, 2, nva, ARRLEN(nva));

  CU_ASSERT(NGHTTP2_ERR_INSUFF_BUFSIZE == blocklen);

  nghttp2_hd_inflate_del(inflater);
  nghttp2_hd_deflate_del(deflater);

  /* check the case where chunk size differs in each chunk */
  nghttp2_hd_deflate_new(&deflater, 4096);
  nghttp2_hd_inflate_new(&inflater);

  buflen = nghttp2_hd_deflate_bound(deflater, nva, ARRLEN(nva));

  vec[0].base = &buf[0];
  vec[0].len = buflen / 2;
  vec[1].base = &buf[buflen / 2];
  vec[1].len = (buflen / 2) + 1;

  blocklen = nghttp2_hd_deflate_hd_vec(deflater, vec, 2, nva, ARRLEN(nva));

  CU_ASSERT(blocklen > 0);

  nghttp2_bufs_wrap_init(&bufs, buf, (size_t)blocklen, mem);
  bufs.head->buf.last += blocklen;

  CU_ASSERT(blocklen == inflate_hd(inflater, &out, &bufs, 0, mem));
  CU_ASSERT(ARRLEN(nva) == out.nvlen);
  assert_nv_equal(nva, out.nva, ARRLEN(nva), mem);

  nghttp2_bufs_wrap_free(&bufs);

  nghttp2_hd_inflate_del(inflater);
  nghttp2_hd_deflate_del(deflater);
  nva_out_reset(&out, mem);

  /* check the case where chunk size is 1 */
  nghttp2_hd_deflate_new(&deflater, 4096);
  nghttp2_hd_inflate_new(&inflater);

  buflen = nghttp2_hd_deflate_bound(deflater, nva, ARRLEN(nva));

  assert(buflen <= ARRLEN(vec));

  for (i = 0; i < buflen; ++i) {
    vec[i].base = &buf[i];
    vec[i].len = 1;
  }

  blocklen = nghttp2_hd_deflate_hd_vec(deflater, vec, buflen, nva, ARRLEN(nva));

  CU_ASSERT(blocklen > 0);

  nghttp2_bufs_wrap_init(&bufs, buf, (size_t)blocklen, mem);
  bufs.head->buf.last += blocklen;

  CU_ASSERT(blocklen == inflate_hd(inflater, &out, &bufs, 0, mem));
  CU_ASSERT(ARRLEN(nva) == out.nvlen);
  assert_nv_equal(nva, out.nva, ARRLEN(nva), mem);

  nghttp2_bufs_wrap_free(&bufs);

  nghttp2_hd_inflate_del(inflater);
  nghttp2_hd_deflate_del(deflater);
  nva_out_reset(&out, mem);
}

static size_t encode_length(uint8_t *buf, uint64_t n, size_t prefix) {
  size_t k = (size_t)((1 << prefix) - 1);
  size_t len = 0;
  *buf = (uint8_t)(*buf & ~k);
  if (n >= k) {
    *buf = (uint8_t)(*buf | k);
    ++buf;
    n -= k;
    ++len;
  } else {
    *buf = (uint8_t)(*buf | n);
    ++buf;
    return 1;
  }
  do {
    ++len;
    if (n >= 128) {
      *buf = (uint8_t)((1 << 7) | (n & 0x7f));
      ++buf;
      n >>= 7;
    } else {
      *buf++ = (uint8_t)n;
      break;
    }
  } while (n);
  return len;
}

void test_nghttp2_hd_decode_length(void) {
  uint32_t out;
  size_t shift;
  int fin;
  uint8_t buf[16];
  uint8_t *bufp;
  size_t len;
  ssize_t rv;
  size_t i;

  memset(buf, 0, sizeof(buf));
  len = encode_length(buf, UINT32_MAX, 7);

  rv = nghttp2_hd_decode_length(&out, &shift, &fin, 0, 0, buf, buf + len, 7);

  CU_ASSERT((ssize_t)len == rv);
  CU_ASSERT(0 != fin);
  CU_ASSERT(UINT32_MAX == out);

  /* Make sure that we can decode integer if we feed 1 byte at a
     time */
  out = 0;
  shift = 0;
  fin = 0;
  bufp = buf;

  for (i = 0; i < len; ++i, ++bufp) {
    rv = nghttp2_hd_decode_length(&out, &shift, &fin, out, shift, bufp,
                                  bufp + 1, 7);

    CU_ASSERT(rv == 1);

    if (fin) {
      break;
    }
  }

  CU_ASSERT(i == len - 1);
  CU_ASSERT(0 != fin);
  CU_ASSERT(UINT32_MAX == out);

  /* Check overflow case */
  memset(buf, 0, sizeof(buf));
  len = encode_length(buf, 1ll << 32, 7);

  rv = nghttp2_hd_decode_length(&out, &shift, &fin, 0, 0, buf, buf + len, 7);

  CU_ASSERT(-1 == rv);

  /* Check the case that shift goes beyond 32 bits */
  buf[0] = 255;
  buf[1] = 128;
  buf[2] = 128;
  buf[3] = 128;
  buf[4] = 128;
  buf[5] = 128;
  buf[6] = 1;

  rv = nghttp2_hd_decode_length(&out, &shift, &fin, 0, 0, buf, buf + 7, 8);

  CU_ASSERT(-1 == rv);
}

void test_nghttp2_hd_huff_encode(void) {
  int rv;
  ssize_t len;
  nghttp2_buf outbuf;
  nghttp2_bufs bufs;
  nghttp2_hd_huff_decode_context ctx;
  const uint8_t t1[] = {22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                        10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0};
  uint8_t b[256];

  nghttp2_buf_wrap_init(&outbuf, b, sizeof(b));
  frame_pack_bufs_init(&bufs);

  rv = nghttp2_hd_huff_encode(&bufs, t1, sizeof(t1));

  CU_ASSERT(rv == 0);

  nghttp2_hd_huff_decode_context_init(&ctx);

  len = nghttp2_hd_huff_decode(&ctx, &outbuf, bufs.cur->buf.pos,
                               nghttp2_bufs_len(&bufs), 1);

  CU_ASSERT((ssize_t)nghttp2_bufs_len(&bufs) == len);
  CU_ASSERT((ssize_t)sizeof(t1) == nghttp2_buf_len(&outbuf));

  CU_ASSERT(0 == memcmp(t1, outbuf.pos, sizeof(t1)));

  nghttp2_bufs_free(&bufs);
}

void test_nghttp2_hd_huff_decode(void) {
  const uint8_t e[] = {0x1f, 0xff, 0xff, 0xff, 0xff, 0xff};
  nghttp2_hd_huff_decode_context ctx;
  nghttp2_buf outbuf;
  uint8_t b[256];
  ssize_t len;

  nghttp2_buf_wrap_init(&outbuf, b, sizeof(b));
  nghttp2_hd_huff_decode_context_init(&ctx);
  len = nghttp2_hd_huff_decode(&ctx, &outbuf, e, 1, 1);

  CU_ASSERT(1 == len);
  CU_ASSERT(0 == memcmp("a", outbuf.pos, 1));

  /* Premature sequence must elicit decoding error */
  nghttp2_buf_wrap_init(&outbuf, b, sizeof(b));
  nghttp2_hd_huff_decode_context_init(&ctx);
  len = nghttp2_hd_huff_decode(&ctx, &outbuf, e, 2, 1);

  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP == len);

  /* Fully decoding EOS is error */
  nghttp2_buf_wrap_init(&outbuf, b, sizeof(b));
  nghttp2_hd_huff_decode_context_init(&ctx);
  len = nghttp2_hd_huff_decode(&ctx, &outbuf, e, 2, 6);

  CU_ASSERT(NGHTTP2_ERR_HEADER_COMP == len);

  /* Check failure state */
  nghttp2_buf_wrap_init(&outbuf, b, sizeof(b));
  nghttp2_hd_huff_decode_context_init(&ctx);
  len = nghttp2_hd_huff_decode(&ctx, &outbuf, e, 5, 0);

  CU_ASSERT(5 == len);
  CU_ASSERT(nghttp2_hd_huff_decode_failure_state(&ctx));
}
