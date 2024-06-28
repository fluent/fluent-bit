/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2017 ngtcp2 contributors
 * Copyright (c) 2012 nghttp2 contributors
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
#include "nghttp2_map_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "nghttp2_map.h"

typedef struct strentry {
  nghttp2_map_key_type key;
  const char *str;
} strentry;

static void strentry_init(strentry *entry, nghttp2_map_key_type key,
                          const char *str) {
  entry->key = key;
  entry->str = str;
}

void test_nghttp2_map(void) {
  strentry foo, FOO, bar, baz, shrubbery;
  nghttp2_map map;
  nghttp2_map_init(&map, nghttp2_mem_default());

  strentry_init(&foo, 1, "foo");
  strentry_init(&FOO, 1, "FOO");
  strentry_init(&bar, 2, "bar");
  strentry_init(&baz, 3, "baz");
  strentry_init(&shrubbery, 4, "shrubbery");

  CU_ASSERT(0 == nghttp2_map_insert(&map, foo.key, &foo));
  CU_ASSERT(strcmp("foo", ((strentry *)nghttp2_map_find(&map, 1))->str) == 0);
  CU_ASSERT(1 == nghttp2_map_size(&map));

  CU_ASSERT(NGHTTP2_ERR_INVALID_ARGUMENT ==
            nghttp2_map_insert(&map, FOO.key, &FOO));

  CU_ASSERT(1 == nghttp2_map_size(&map));
  CU_ASSERT(strcmp("foo", ((strentry *)nghttp2_map_find(&map, 1))->str) == 0);

  CU_ASSERT(0 == nghttp2_map_insert(&map, bar.key, &bar));
  CU_ASSERT(2 == nghttp2_map_size(&map));

  CU_ASSERT(0 == nghttp2_map_insert(&map, baz.key, &baz));
  CU_ASSERT(3 == nghttp2_map_size(&map));

  CU_ASSERT(0 == nghttp2_map_insert(&map, shrubbery.key, &shrubbery));
  CU_ASSERT(4 == nghttp2_map_size(&map));

  CU_ASSERT(strcmp("baz", ((strentry *)nghttp2_map_find(&map, 3))->str) == 0);

  nghttp2_map_remove(&map, 3);
  CU_ASSERT(3 == nghttp2_map_size(&map));
  CU_ASSERT(NULL == nghttp2_map_find(&map, 3));

  nghttp2_map_remove(&map, 1);
  CU_ASSERT(2 == nghttp2_map_size(&map));
  CU_ASSERT(NULL == nghttp2_map_find(&map, 1));

  /* Erasing non-existent entry */
  nghttp2_map_remove(&map, 1);
  CU_ASSERT(2 == nghttp2_map_size(&map));
  CU_ASSERT(NULL == nghttp2_map_find(&map, 1));

  CU_ASSERT(strcmp("bar", ((strentry *)nghttp2_map_find(&map, 2))->str) == 0);
  CU_ASSERT(strcmp("shrubbery", ((strentry *)nghttp2_map_find(&map, 4))->str) ==
            0);

  nghttp2_map_free(&map);
}

static void shuffle(int *a, int n) {
  int i;
  for (i = n - 1; i >= 1; --i) {
    size_t j = (size_t)((double)(i + 1) * rand() / (RAND_MAX + 1.0));
    int t = a[j];
    a[j] = a[i];
    a[i] = t;
  }
}

static int eachfun(void *data, void *ptr) {
  (void)data;
  (void)ptr;

  return 0;
}

#define NUM_ENT 6000
static strentry arr[NUM_ENT];
static int order[NUM_ENT];

void test_nghttp2_map_functional(void) {
  nghttp2_map map;
  int i;
  strentry *ent;

  nghttp2_map_init(&map, nghttp2_mem_default());
  for (i = 0; i < NUM_ENT; ++i) {
    strentry_init(&arr[i], (nghttp2_map_key_type)(i + 1), "foo");
    order[i] = i + 1;
  }
  /* insertion */
  shuffle(order, NUM_ENT);
  for (i = 0; i < NUM_ENT; ++i) {
    ent = &arr[order[i] - 1];
    CU_ASSERT(0 == nghttp2_map_insert(&map, ent->key, ent));
  }

  CU_ASSERT(NUM_ENT == nghttp2_map_size(&map));

  /* traverse */
  nghttp2_map_each(&map, eachfun, NULL);
  /* find */
  shuffle(order, NUM_ENT);
  for (i = 0; i < NUM_ENT; ++i) {
    CU_ASSERT(NULL != nghttp2_map_find(&map, (nghttp2_map_key_type)order[i]));
  }
  /* remove */
  for (i = 0; i < NUM_ENT; ++i) {
    CU_ASSERT(0 == nghttp2_map_remove(&map, (nghttp2_map_key_type)order[i]));
  }

  /* each_free (but no op function for testing purpose) */
  for (i = 0; i < NUM_ENT; ++i) {
    strentry_init(&arr[i], (nghttp2_map_key_type)(i + 1), "foo");
  }
  /* insert once again */
  for (i = 0; i < NUM_ENT; ++i) {
    ent = &arr[i];
    CU_ASSERT(0 == nghttp2_map_insert(&map, ent->key, ent));
  }
  nghttp2_map_each_free(&map, eachfun, NULL);
  nghttp2_map_free(&map);
}

static int entry_free(void *data, void *ptr) {
  const nghttp2_mem *mem = ptr;

  mem->free(data, NULL);
  return 0;
}

void test_nghttp2_map_each_free(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  strentry *foo = mem->malloc(sizeof(strentry), NULL),
           *bar = mem->malloc(sizeof(strentry), NULL),
           *baz = mem->malloc(sizeof(strentry), NULL),
           *shrubbery = mem->malloc(sizeof(strentry), NULL);
  nghttp2_map map;
  nghttp2_map_init(&map, nghttp2_mem_default());

  strentry_init(foo, 1, "foo");
  strentry_init(bar, 2, "bar");
  strentry_init(baz, 3, "baz");
  strentry_init(shrubbery, 4, "shrubbery");

  nghttp2_map_insert(&map, foo->key, foo);
  nghttp2_map_insert(&map, bar->key, bar);
  nghttp2_map_insert(&map, baz->key, baz);
  nghttp2_map_insert(&map, shrubbery->key, shrubbery);

  nghttp2_map_each_free(&map, entry_free, (void *)mem);
  nghttp2_map_free(&map);
}

void test_nghttp2_map_clear(void) {
  nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_map map;
  strentry foo;

  strentry_init(&foo, 1, "foo");

  nghttp2_map_init(&map, mem);

  CU_ASSERT(0 == nghttp2_map_insert(&map, foo.key, &foo));

  nghttp2_map_clear(&map);

  CU_ASSERT(0 == nghttp2_map_size(&map));

  nghttp2_map_free(&map);
}
