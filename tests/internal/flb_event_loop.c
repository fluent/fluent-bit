/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_bucket_queue.h>
#include <monkey/mk_core/mk_list.h>

#define EVENT_LOOP_TEST_PRIORITIES 7
#define EVENT_LOOP_MAX_EVENTS 64
#ifdef _WIN32
    #define TIME_EPSILON_MS 30
#elif FLB_SYSTEM_MACOS
    #define TIME_EPSILON_MS 200
#else
    #define TIME_EPSILON_MS 50
#endif

#define TIMER_COARSE_EPSION_MS 300
#define LOOP_SIZE 3

struct test_evl_context {
    struct mk_event_loop *evl;
    struct flb_bucket_queue *bktq;
};

/*
 * The following implements a uniform custom delayed event
 * primarily to help Windows. It is needed to simulate
 * another thread or network call writing to fd
 * activating an event without disrupting the event (libevent)
 * loop. LibEvent timeouts disrupt the libevent loop
 * making the testcases non-homogeneous between platforms
 */
struct delay_worker_args {
    int fd; /* pipefd */
    int sec; /* seconds */
};

/* Writes to pipe after set delay. Cleans self up after pipe closure */
void _delay_worker(void *arg) {
    int ret;
    uint64_t val = 1;
    char tmp[100];

    struct delay_worker_args *args = (struct delay_worker_args *) arg;
    static int idx = 0;

    sprintf(tmp, "delay-timer-%i", ++idx);
    mk_utils_worker_rename(tmp);

    /* Sleep for the delay period */
    sleep(args->sec);

    /* Send delayed event a notification */
    flb_pipe_set_nonblocking(args->fd);
    ret = flb_pipe_w(args->fd, &val, sizeof(uint64_t)); /* supposedly blocking */
    if (ret == -1) {
        flb_error("Delayed event: unable to trigger event via write to pipe");
    }

    /* Clean up */
    flb_pipe_close(args->fd);
    flb_free(args);
}

void test_timeout_create(struct mk_event_loop *loop,
                         time_t sec, long nsec, void *data)
{
    flb_pipefd_t fd[2];
    int ret;
    pthread_t tid;

    ret = flb_pipe_create(fd);
    if (ret == -1) {
        flb_error("pipe creation failure");
        return;
    }

    /*
     * Spin up another thread to keep
     * track of our delay (don't let register in event loop (like libevent))
     */
    struct delay_worker_args *args = flb_malloc(sizeof(struct delay_worker_args));

    /* Register write end of data pipe */
    args->fd = fd[1];
    args->sec = sec;
    ret = mk_utils_worker_spawn(_delay_worker, args, &tid); /* worker handles freeing up args. */

    /* Convert read end to monkey event */
    MK_EVENT_NEW(data);
    mk_event_add(loop, fd[0], MK_EVENT_NOTIFICATION, MK_EVENT_READ, data);
}

void test_timeout_destroy(struct mk_event_loop *loop, void *data)
{
    struct mk_event *event = (struct mk_event *) data;
    mk_event_del(loop, event);
    flb_pipe_close(event->fd);
}

struct test_evl_context *evl_context_create()
{
    struct test_evl_context *ctx = flb_malloc(sizeof(struct test_evl_context));
    ctx->evl = mk_event_loop_create(EVENT_LOOP_MAX_EVENTS);
    ctx->bktq = flb_bucket_queue_create(EVENT_LOOP_TEST_PRIORITIES);
    return ctx;
}

void evl_context_destroy(struct test_evl_context *ctx)
{
    flb_bucket_queue_destroy(ctx->bktq);
    mk_event_loop_destroy(ctx->evl);
    flb_free(ctx);
}

void test_simple_timeout_1000ms()
{
    struct test_evl_context *ctx;

    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb;
    int target;

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    target = 1000;
    ctx = evl_context_create();

    flb_time_get(&start_time);

    mk_event_wait_2(ctx->evl, target);

    flb_time_get(&end_time);
    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb < target + TIME_EPSILON_MS
              && elapsed_time_flb > target - TIME_EPSILON_MS);
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);

    evl_context_destroy(ctx);

#ifdef _WIN32
    WSACleanup();
#endif
}

/*
 * Non-block wait: 0ms, no event
 * Add timer - 1s (very inexact)
 * Non-block wait: 0ms, no event
 * Blocking wait with 2.1s timeout: ~1s (very inexact), 1event
 * Non-blocking wait: 0ms, 1 event
 * Remove timer event
 * Blocking wait with 2.1s timeout: 2.1s, no event
 */
void test_non_blocking_and_blocking_timeout()
{
    struct test_evl_context *ctx;

    struct mk_event event = {0};

    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb;
    int n_events;

    int target;
    int wait_2_timeout = 2100;
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    ctx = evl_context_create();

    /* Non blocking wait -- no event */
    target = 0;
    flb_time_get(&start_time);
    n_events = mk_event_wait_2(ctx->evl, 0);
    flb_time_get(&end_time);

    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb <= target + TIME_EPSILON_MS);
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);
    TEST_CHECK(n_events == 0);

    /* Add somewhat inexact 1 second timer */
    target = 1000;
    event.mask   = MK_EVENT_EMPTY;
    event.status = MK_EVENT_NONE;
    test_timeout_create(ctx->evl, target / 1000, 0, &event);

    /* Non blocking wait -- one event */
    target = 0;
    flb_time_get(&start_time);
    n_events = mk_event_wait_2(ctx->evl, 0);
    flb_time_get(&end_time);

    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb <= target + TIME_EPSILON_MS);
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);
    TEST_CHECK(n_events == 0);

    /* Blocking wait with unused timeout */
    target = 1000;
    flb_time_get(&start_time);
    n_events = mk_event_wait_2(ctx->evl, wait_2_timeout);
    flb_time_get(&end_time);

    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb < target + TIMER_COARSE_EPSION_MS
              && elapsed_time_flb > 100); /* accommodate for timer inaccuracy */
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);
    TEST_CHECK(n_events == 1);

    /* Non blocking wait -- one event */
    target = 0;
    flb_time_get(&start_time);
    n_events = mk_event_wait_2(ctx->evl, 0);
    flb_time_get(&end_time);

    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb <= target + TIME_EPSILON_MS);
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);
    TEST_CHECK(n_events == 1);

    /* Remove triggered 1s timer event */
    test_timeout_destroy(ctx->evl, &event);

    /* Blocking wait, used timeout */
    target = wait_2_timeout;
    flb_time_get(&start_time);
    n_events = mk_event_wait_2(ctx->evl, wait_2_timeout);
    flb_time_get(&end_time);
    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb < target + TIME_EPSILON_MS
              && elapsed_time_flb > target - TIME_EPSILON_MS);
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);
    TEST_CHECK(n_events == 0);

    evl_context_destroy(ctx);
#ifdef _WIN32
    WSACleanup();
#endif
}

/*
 * Add 1s timer
 * Infinite wait: 1 event, < 1s + epsilon
 * Remove timer
 */
void test_infinite_wait()
{
    struct test_evl_context *ctx;

    struct mk_event event = {0};

    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb;
    int n_events;

    int target;
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    ctx = evl_context_create();

    /* Add somewhat inexact 1 second timer */
    target = 1000;
    test_timeout_create(ctx->evl, target / 1000, 0, &event);

    /* Infinite wait -- 1 event */
    target = 1000;
    flb_time_get(&start_time);
    n_events = mk_event_wait(ctx->evl);
    flb_time_get(&end_time);

    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;
    TEST_CHECK(elapsed_time_flb < target + TIMER_COARSE_EPSION_MS
                && elapsed_time_flb > 100); /* expect timer to be inexact */
    TEST_MSG("Target time failed for mk_wait_2. Expect %d ms. Waited %d ms\n", target,
             (int) elapsed_time_flb);
    TEST_CHECK(n_events == 1);

    /* Remove triggered 1s timer event */
    test_timeout_destroy(ctx->evl, &event);

    evl_context_destroy(ctx);
#ifdef _WIN32
    WSACleanup();
#endif
}

void synchronize_tests()
{
    test_non_blocking_and_blocking_timeout();
    test_infinite_wait();
}

/*
 * Add non-delayed and delayed timers of varying priority to priority event loop, and
 * verify timers are processed by order of priority and order of activation. Delete also
 * checked by deleting events in several cases and confirming deleted events are not
 * processed.
 *
 * Method:
 * Add n_timers / 2 non-delayed timers
 * delete 1/4th of the non-delayed timers
 * Wait for non_delayed timers to activate
 * delete 1/4th of the non-delayed timers
 * Process events with mk_event_loop deleting each processed event
 * Add n_timers / 2 non-delayed timers
 * Add n_timers / 2 2s delayed timers
 * Wait for non_delayed timers to activate
 * Start looping though processing the events
 *      on the first iteration, (after initial events are tracked)
 *          Delete 1/2 of the non-delayed timers
 *          Wait for the delayed timers to activate
 *      Check that deleted events are not processed
 *      Check that non-delayed timers which are tracked first are processed before
 *          non-delayed events.
 *
 * Summary:
 * Track priorities and confirm that all added events were processed
 * Verify non-delayed timers are triggered before delayed timers
 * Confirm delete properly deletes events before ready, after ready,
 *      and after tracked by event loop.
 */
void event_loop_stress_priority_add_delete()
{
    struct test_evl_context *ctx;

    const int n_timers = EVENT_LOOP_MAX_EVENTS;
    struct mk_event events[EVENT_LOOP_MAX_EVENTS] = {0};
    struct mk_event *event_cronology[EVENT_LOOP_TEST_PRIORITIES] = {0}; /* event loop priority fifo */
    int priority_cronology = 0;

    struct mk_event *event;
    int immediate_timers[EVENT_LOOP_TEST_PRIORITIES] = {0}; /* by priority */
    int delayed_timers[EVENT_LOOP_TEST_PRIORITIES] = {0}; /* by priority */

    int immediate_timers_triggered[EVENT_LOOP_TEST_PRIORITIES] = {0};
    int delayed_timers_triggered[EVENT_LOOP_TEST_PRIORITIES] = {0};

    int priority;
    int n_events;
    int target;

    int i;
    int j;
    int ret = 0;
    int immediate_timer_count;
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    ctx = evl_context_create();
    srand(20);

    /* Add timers with no delay */
    for (i = 0; i < n_timers / 2; ++i) {
        priority = rand() % EVENT_LOOP_TEST_PRIORITIES;
        target = 0;
        memset(&events[i], 0, sizeof(struct mk_event));
        test_timeout_create(ctx->evl, 0, 0, &events[i]);
        events[i].priority = priority;
        ++immediate_timers[priority];
    }

    usleep(400000); /* sleep 400 milliseconds for the 0delay events to register */

    /* Remove the first n/8 events */
    for (i = 0; i < n_timers / 8; ++i) {
        test_timeout_destroy(ctx->evl, &events[i]);
        --immediate_timers[(int) events[i].priority];
    }

    /* Wait on the no delay timers */
    n_events = mk_event_wait(ctx->evl);
    TEST_CHECK(n_events == n_timers / 2 - n_timers / 8);
    TEST_MSG("Expected %i ready events from the no delay timers. Recieved %i",
            n_timers / 2 - n_timers / 8, ret);

    /* Remove the first n/8 events */
    for (i = n_timers / 8; i < n_timers / 4; ++i) {
        test_timeout_destroy(ctx->evl, &events[i]);
        --immediate_timers[(int) events[i].priority];
    }

    i = 0;
    do { /* variable closure */
    flb_event_priority_live_foreach(event, ctx->bktq, ctx->evl, n_timers) {
        /* check priority cronology */
        TEST_CHECK(event->priority >= priority_cronology);
        TEST_MSG("Priority event loop processed events out of order.");
        priority_cronology = event->priority;

        /* check none of the deleted records appear */
        TEST_CHECK(event >= &events[n_timers / 4]);
        TEST_MSG("Deleted event appeared in priority event loop.");

        /* update records */

        /* delete event */
        test_timeout_destroy(ctx->evl, event);

        /* update records */
        test_timeout_destroy(ctx->evl, event);
        if (event < &events[n_timers/2]) {
            /* immediate timer */
            --immediate_timers[(int) event->priority];
            ++immediate_timers_triggered[(int) event->priority];
        }
        else {
            /* delayed timer */
            --delayed_timers[(int) event->priority];
            ++delayed_timers_triggered[(int) event->priority];
        }
        ++i;
    }
    } while (0);
    TEST_CHECK(i == n_timers / 4);
    TEST_MSG("Not all no-wait timers activated");

    /* verify number of immediate timers triggered */
    for (i = 0; i < EVENT_LOOP_TEST_PRIORITIES; ++i) {
        TEST_CHECK(immediate_timers[i] == 0);
        TEST_MSG("Priority event register and triggered mismatch for priority %i. "
                "Remaining: %i out of: %i", i, immediate_timers[i],
                immediate_timers_triggered[i]);
    }

    /* Re-add timers with no delay */
    for (i = 0; i < n_timers / 2; ++i) {
        priority = rand() % EVENT_LOOP_TEST_PRIORITIES;
        target = 0;
        memset(&events[i], 0, sizeof(struct mk_event));
        test_timeout_create(ctx->evl, target, 0, &events[i]);
        events[i].priority = priority;
        ++immediate_timers[priority];
    }

    usleep(400000); /* sleep 200 milliseconds for the 0delay events to register */

    /* Add timers with delay */
    for (i = n_timers / 2; i < n_timers; ++i) {
        priority = rand() % EVENT_LOOP_TEST_PRIORITIES;
        target = 2; /* 2 second delay */
        memset(&events[i], 0, sizeof(struct mk_event));
        test_timeout_create(ctx->evl, target, 0, &events[i]);
        events[i].priority = priority;
        ++delayed_timers[priority];
    }

    /* Wait on the timers */
    n_events = mk_event_wait(ctx->evl);
    TEST_CHECK(n_events == n_timers / 2);
    TEST_MSG("Expected %i ready events from the no delay timers. Recieved %i", n_timers / 2, ret);
    j = 0;
    priority_cronology = 0;
    do { /* variable closure */
    flb_event_priority_live_foreach(event, ctx->bktq, ctx->evl, n_timers) {

        /* first round, delete half of all 0delay timers */
        if (j == 0) {

            /* this tests propper removal from bucket queue */
            for (i = 0; i < n_timers/4; ++i) {
                if (&events[i] == event) {
                    continue;
                }
                test_timeout_destroy(ctx->evl, &events[i]);
                --immediate_timers[(int) events[i].priority];
            }

            /* check priority cronology */
            TEST_CHECK(event->priority >= priority_cronology);
            priority_cronology = event->priority;

            /* delete actual event */
            test_timeout_destroy(ctx->evl, event);
            --immediate_timers[(int) event->priority];
            TEST_CHECK(event < &events[n_timers/2]);
            TEST_MSG("Processed delayed timer first. Should process immediate timer first");

            /* delay for the delayed timers to register */
            usleep(2500000); /* 2.5 seconds */
            ++j;
            continue;
        }

        /* validate fifo nature. inspect cross from no-timeout to timeout event */
        /* check event fifo cronology */
        /* (priority A) [immediate timer] -> [delay timer]: check all immediate timers processed */
        if (event_cronology[(int) event->priority] < &events[n_timers / 2]
           && event >= &events[n_timers / 2]) {
            /* verify that all of the immediate_timers in priority have been removed */
            immediate_timer_count = 0;
            for (i = 0; i < EVENT_LOOP_TEST_PRIORITIES; ++i) {
                immediate_timer_count += immediate_timers[i];
            }
            TEST_CHECK(immediate_timers[(int) event->priority] == 0);
            TEST_MSG("immediate timer events are not all processed before delayed timer events for priority %i", event->priority);
        }
        /* check for non fifo behavior */
        /* (priority A) [delay timer] -> [immediate timer]: disallow */
        if (!TEST_CHECK(!(event_cronology[(int) event->priority] >= &events[n_timers / 2]
           && event < &events[n_timers / 2]))) {
            TEST_MSG("Non fifo behavior within priority. Delayed event processed before immediate event.");
        }
        event_cronology[(int) event->priority] = event;

        /* check priority cronology */
        TEST_CHECK(event->priority >= priority_cronology);
        TEST_MSG("Priority event loop processed events out of order.");
        priority_cronology = event->priority;

        /* verify none of the deleted timers are processed */
        TEST_CHECK(event >= &events[n_timers / 4]);
        TEST_MSG("Processed a deleted timer. Delete performed after event is registered in the event loop bucket queue.");

        /* update records */
        test_timeout_destroy(ctx->evl, event);
        if (event < &events[n_timers/2]) {
            /* immediate timer */
            --immediate_timers[(int) event->priority];
        }
        else {
            /* delayed timer */
            --delayed_timers[(int) event->priority];
        }
        ++j;
    }
    } while (0);

    /* validate all timers processed */
    for (i = 0; i < EVENT_LOOP_TEST_PRIORITIES; ++i) {
        TEST_CHECK(immediate_timers[i] == 0);
        TEST_MSG("Not all immediate timers processed");
    }
    for (i = 0; i < EVENT_LOOP_TEST_PRIORITIES; ++i) {
        TEST_CHECK(delayed_timers[i] == 0);
        TEST_MSG("Not all delayed timers processed");
    }

    evl_context_destroy(ctx);
#ifdef _WIN32
    WSACleanup();
#endif
}

void test_inject_event_priority_loop()
{
    int i;
    int iter;
    struct mk_event priority_0_events[LOOP_SIZE];
    struct mk_event priority_2_events[LOOP_SIZE];
    struct mk_event injected_event;
    struct mk_event *event;
    struct test_evl_context *ctx = evl_context_create();

    /* add priority 0 events to the event loop */
    for (i = 0; i < LOOP_SIZE; i++) {
        test_timeout_create(ctx->evl, 0, 0, &priority_0_events[i]);
        priority_0_events[i].priority = 0;
    }

    /* add priority 2 events to the event loop */
    for (i = 0; i < LOOP_SIZE; i++) {
        test_timeout_create(ctx->evl, 0, 0, &priority_2_events[i]);
        priority_2_events[i].priority = 2;
    }

    /* create priority 1 event that we will inject */
    MK_EVENT_ZERO(&injected_event);
    injected_event._priority_head.next = NULL;
    injected_event._priority_head.prev = NULL;
    injected_event.priority = 1;

    usleep(400000);
    mk_event_wait_2(ctx->evl, 0);

    do {
        iter = 0;
        /* first loop, event priorities: {0, 0, 0, 2, 2, 2} */
        flb_event_priority_live_foreach(event, ctx->bktq, ctx->evl, LOOP_SIZE) {
            if (iter == 0) {
                /* inject an event, new priorities: {0, 0, 0, 1, 2, 2, 2} */
                mk_event_inject(ctx->evl, &injected_event, MK_EVENT_READ, FLB_TRUE);
            }
            /* delete event */
            test_timeout_destroy(ctx->evl, event);

            iter++;
        }
    } while(0);

    do {
        iter = 0;
        /* second loop, event priorities: {1, 2, 2, 2} */
        flb_event_priority_live_foreach(event, ctx->bktq, ctx->evl, LOOP_SIZE + 1) {
            if (iter == 0) {
                TEST_CHECK(event->priority == 1);
                TEST_MSG("Expected injected event with priority 1, "
                         "got event with priority %i instead",
                         event->priority);
            }
            /* delete event */
            test_timeout_destroy(ctx->evl, event);

            iter++;
        }
    } while(0);

    evl_context_destroy(ctx);
}

TEST_LIST = {
    {"test_simple_timeout_1000ms", test_simple_timeout_1000ms},
    {"test_non_blocking_and_blocking_timeout", test_non_blocking_and_blocking_timeout},
    {"test_infinite_wait", test_infinite_wait},
    {"event_loop_stress_priority_add_delete", event_loop_stress_priority_add_delete},
    {"test_inject_event_priority_loop", test_inject_event_priority_loop},
    { 0 }
};
