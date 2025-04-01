/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_bucket_queue.h>

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

static void test_smart_flush()
{
    int i;
    int ret;
    int n_events;
    int elements;
    size_t slots;
    uint64_t window;
    struct check *c;
    struct check *tmp;
    int flush_event_detected;
	char signal_buffer[512];
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct flb_ring_buffer *rb;
    struct flb_bucket_queue *bktq;

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    evl = mk_event_loop_create(100);
    TEST_CHECK(evl != NULL);
    if (!evl) {
        exit(EXIT_FAILURE);
    }

    bktq = flb_bucket_queue_create(10);
    TEST_CHECK(bktq != NULL);
    if (!bktq) {
        exit(EXIT_FAILURE);
    }

    elements = sizeof(checks) / sizeof(struct check);
    slots = elements * 2;
    window = (((double) (elements + 1)) / slots) * 100;

    /* The slot count was chosen to trigger the flush request
     * after writing the predefined elements + 1
     */

    rb = flb_ring_buffer_create(sizeof(struct check *) * slots);
    TEST_CHECK(rb != NULL);
    if (!rb) {
        exit(EXIT_FAILURE);
    }

    ret = flb_ring_buffer_add_event_loop(rb, evl, window);
    TEST_CHECK(ret == 0);
    if (ret) {
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < elements; i++) {
        c = &checks[i];
        ret = flb_ring_buffer_write(rb, (void *) &c, sizeof(c));
        TEST_CHECK(ret == 0);

        n_events = mk_event_wait_2(evl, 0);
        TEST_CHECK(n_events == 0);
    }

    /* write another record, a signal must be produced */
    ret = flb_ring_buffer_write(rb, (void *) &tmp, sizeof(tmp));
    TEST_CHECK(ret == 0);

    n_events = mk_event_wait_2(evl, 0);
    TEST_CHECK(n_events == 1);

    flush_event_detected = FLB_FALSE;
    flb_event_priority_live_foreach(event, bktq, evl, 10) {
        if(event->type == FLB_ENGINE_EV_THREAD_INPUT) {
            flb_pipe_r(event->fd, signal_buffer, sizeof(signal_buffer));

		    flush_event_detected = FLB_TRUE;
        }
    }

    TEST_CHECK(flush_event_detected == FLB_TRUE);

    /* write another record, a signal must not be produced because the previous one
     * was not acknowledged by setting `flush_pending` to `FLB_FALSE`
     */
    ret = flb_ring_buffer_write(rb, (void *) &tmp, sizeof(tmp));
    TEST_CHECK(ret == 0);

    n_events = mk_event_wait_2(evl, 0);
    TEST_CHECK(n_events == 0);

    flb_ring_buffer_destroy(rb);
    flb_bucket_queue_destroy(bktq);
    mk_event_loop_destroy(evl);
}

void test_peek_seek()
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
    ret = flb_ring_buffer_peek(rb, 0, (void *) &c, sizeof(c));
    TEST_CHECK(ret == 0);

    /* the consumed entry must be equal to the first one */
    c = &checks[0];
    TEST_CHECK(strcmp(c->buf_a, "a1") == 0 && strcmp(c->buf_b, "a2") ==0);

    /* consume one entry */
    ret = flb_ring_buffer_peek(rb, 0, (void *) &c, sizeof(c));
    TEST_CHECK(ret == 0);

    /* the consumed entry must be equal to the first one */
    c = &checks[0];
    TEST_CHECK(strcmp(c->buf_a, "a1") == 0 && strcmp(c->buf_b, "a2") ==0);

    flb_ring_buffer_destroy(rb);
}

TEST_LIST = {
    { "basic",       test_basic},
    { "smart_flush", test_smart_flush},
    { 0 }
};
