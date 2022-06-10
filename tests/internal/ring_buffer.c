/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_ring_buffer.h>

#include "flb_tests_internal.h"

struct check {
    char *buf_a;
    char *buf_b;
};

struct check checks[] = {
	{"a1", "a2"},
	{"b1", "b2"},
	{"c1", "c2"},
	{"d1", "d2"},
	{"e1", "e2"},
};

static void test_basic()
{
	int i;
	int ret;
	int elements;
	struct check *c;
	struct check *tmp;
	struct flb_ring_buffer *rb;

	elements = sizeof(checks) / sizeof(struct check);

	rb = flb_ring_buffer_create(sizeof(struct check *) * elements);
	TEST_CHECK(rb != NULL);
	if (!rb) {
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < elements; i++) {
		c = &checks[i];
		ret = flb_ring_buffer_write(rb, (void *) &c, sizeof(c));
		TEST_CHECK(ret == 0);
	}

	/* try to write another record, it must fail */
	tmp = c;
	ret = flb_ring_buffer_write(rb, (void *) &tmp, sizeof(tmp));
	TEST_CHECK(ret == -1);

	c = NULL;

	/* consume one entry */
	ret = flb_ring_buffer_read(rb, (void *) &c, sizeof(c));
	TEST_CHECK(ret == 0);

	/* the consumed entry must be equal to the first one */
	c = &checks[0];
	TEST_CHECK(strcmp(c->buf_a, "a1") == 0 && strcmp(c->buf_b, "a2") ==0);

	/* try 'again' to write 'c2', it should succeed */
	ret = flb_ring_buffer_write(rb, (void *) &tmp, sizeof(tmp));
	TEST_CHECK(ret == 0);

	flb_ring_buffer_destroy(rb);
}

TEST_LIST = {
    { "basic",   test_basic},
    { 0 }
};
