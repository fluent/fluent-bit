/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#include "malloc_wrapper.h"

int nghttp2_failmalloc = 0;
int nghttp2_failstart = 0;
int nghttp2_countmalloc = 1;
int nghttp2_nmalloc = 0;

#define CHECK_PREREQ                                                           \
  do {                                                                         \
    if (nghttp2_failmalloc && nghttp2_nmalloc >= nghttp2_failstart) {          \
      return NULL;                                                             \
    }                                                                          \
    if (nghttp2_countmalloc) {                                                 \
      ++nghttp2_nmalloc;                                                       \
    }                                                                          \
  } while (0)

static void *my_malloc(size_t size, void *mud) {
  (void)mud;

  CHECK_PREREQ;
  return malloc(size);
}

static void my_free(void *ptr, void *mud) {
  (void)mud;

  free(ptr);
}

static void *my_calloc(size_t nmemb, size_t size, void *mud) {
  (void)mud;

  CHECK_PREREQ;
  return calloc(nmemb, size);
}

static void *my_realloc(void *ptr, size_t size, void *mud) {
  (void)mud;

  CHECK_PREREQ;
  return realloc(ptr, size);
}

static nghttp2_mem mem = {NULL, my_malloc, my_free, my_calloc, my_realloc};

nghttp2_mem *nghttp2_mem_fm(void) { return &mem; }

static int failmalloc_bk, countmalloc_bk;

void nghttp2_failmalloc_pause(void) {
  failmalloc_bk = nghttp2_failmalloc;
  countmalloc_bk = nghttp2_countmalloc;
  nghttp2_failmalloc = 0;
  nghttp2_countmalloc = 0;
}

void nghttp2_failmalloc_unpause(void) {
  nghttp2_failmalloc = failmalloc_bk;
  nghttp2_countmalloc = countmalloc_bk;
}
