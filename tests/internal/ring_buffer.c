/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_bucket_queue.h>
#include <fluent-bit/flb_input_chunk.h>

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

    /* A partial drain must request another pass without another write. */
    flb_ring_buffer_mark_flushed(rb);
    TEST_CHECK(mk_event_wait_2(evl, 0) == 1);
    flb_pipe_r(rb->signal_channels[0], signal_buffer, sizeof(signal_buffer));

    /* A full notification pipe already provides a wakeup; do not wait for room. */
    do {
        ret = flb_pipe_w(rb->signal_channels[1], ".", 1);
    } while (ret == 1);
    TEST_ASSERT(ret == -1);
    TEST_ASSERT(FLB_PIPE_WOULDBLOCK());
    flb_ring_buffer_mark_flushed(rb);
    TEST_CHECK(rb->flush_pending == FLB_TRUE);
    TEST_CHECK(mk_event_wait_2(evl, 0) == 1);
    while (flb_pipe_r(rb->signal_channels[0], signal_buffer, sizeof(signal_buffer)) > 0) {
    }

    while (flb_ring_buffer_read(rb, &tmp, sizeof(tmp)) == 0) {
    }
    flb_ring_buffer_mark_flushed(rb);
    TEST_CHECK(rb->flush_pending == FLB_FALSE);
    TEST_CHECK(mk_event_wait_2(evl, 0) == 0);

    /* Below the window, a future producer write must still trigger a flush. */
    for (i = 0; i < elements; i++) {
        TEST_CHECK(flb_ring_buffer_write(rb, &tmp, sizeof(tmp)) == 0);
    }
    flb_ring_buffer_mark_flushed(rb);
    TEST_CHECK(rb->flush_pending == FLB_FALSE);
    TEST_CHECK(mk_event_wait_2(evl, 0) == 0);
    TEST_CHECK(flb_ring_buffer_write(rb, &tmp, sizeof(tmp)) == 0);
    TEST_CHECK(mk_event_wait_2(evl, 0) == 1);

    flb_ring_buffer_destroy(rb);
    flb_bucket_queue_destroy(bktq);
    mk_event_loop_destroy(evl);
}

static void test_collector_bounded_pass(void)
{
    int i;
    int remaining = 0;
    void *entry = NULL;
    struct flb_config config = {0};
    struct flb_input_instance first = {0};
    struct flb_input_instance second = {0};

    mk_list_init(&config.inputs);
    first.mem_buf_status = second.mem_buf_status = FLB_INPUT_RUNNING;
    first.storage_buf_status = second.storage_buf_status = FLB_INPUT_RUNNING;
#ifdef FLB_HAVE_METRICS
    first.rate_gate_status = second.rate_gate_status = FLB_INPUT_RUNNING;
#endif
    first.rb = flb_ring_buffer_create(64 * sizeof(entry));
    second.rb = flb_ring_buffer_create(sizeof(entry));
    TEST_ASSERT(first.rb != NULL);
    TEST_ASSERT(second.rb != NULL);
    mk_list_add(&first._head, &config.inputs);
    mk_list_add(&second._head, &config.inputs);

    /* Null entries exercise scheduling without invoking storage or filters. */
    for (i = 0; i < 64; i++) {
        TEST_CHECK(flb_ring_buffer_write(first.rb, &entry, sizeof(entry)) == 0);
    }
    TEST_CHECK(flb_ring_buffer_write(second.rb, &entry, sizeof(entry)) == 0);

    flb_input_chunk_ring_buffer_collector(&config, NULL);
    TEST_CHECK(flb_ring_buffer_read(second.rb, &entry, sizeof(entry)) == -1);
    while (flb_ring_buffer_read(first.rb, &entry, sizeof(entry)) == 0) {
        remaining++;
    }
    TEST_CHECK(remaining > 0);
    TEST_CHECK(remaining < 64);

    first.mem_buf_status = FLB_INPUT_PAUSED;
    TEST_CHECK(flb_ring_buffer_write(first.rb, &entry, sizeof(entry)) == 0);
    flb_input_chunk_ring_buffer_collector(&config, NULL);
    TEST_CHECK(flb_ring_buffer_read(first.rb, &entry, sizeof(entry)) == 0);
    TEST_CHECK(flb_ring_buffer_write(first.rb, &entry, sizeof(entry)) == 0);
    first.mem_buf_status = FLB_INPUT_RUNNING;
    flb_input_chunk_ring_buffer_collector(&config, NULL);
    TEST_CHECK(flb_ring_buffer_read(first.rb, &entry, sizeof(entry)) == -1);

    flb_ring_buffer_destroy(first.rb);
    flb_ring_buffer_destroy(second.rb);
}

TEST_LIST = {
    { "basic",       test_basic},
    { "smart_flush", test_smart_flush},
    { "collector_bounded_pass", test_collector_bounded_pass},
    { 0 }
};
