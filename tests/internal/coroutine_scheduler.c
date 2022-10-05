/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <math.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_coroutine_scheduler.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_bucket_queue.h>

#include "flb_tests_internal.h"

#define FLB_TIME_MILLISECONDS_TO_MICROSECONDS(ts)       ((uint64_t) (floor(((ts) * 1000.0))))
#define FLB_TIME_SECONDS_TO_MICROSECONDS(ts)            ((uint64_t) (floor(((ts) * 1000000.0))))
#define FLB_TIME_SECONDS_TO_MILLISECONDS(ts)            ((uint64_t) (floor(((ts) * 1000.0))))
#define FLB_TIME_MICROSECONDS_TO_SECONDS(ts)            ((double)   (((ts) / 1000000.0)))

#define DELAY_MODE_FORCE_YIELD                          ((size_t) -1)

#define DELAY_SELECTOR_DISABLED                         0
#define DELAY_SELECTOR_PAIR_CYCLES                      1
#define DELAY_SELECTOR_ODD_CYCLES                       2
#define DELAY_SELECTOR_EVERY_CYCLE                      3

#define SIMPLE_TEST_COROUTINE_COUNT                     50
#define SIMPLE_TEST_COROUTINE_ITERATIONS                100

#define OFFSET_TEST_COROUTINE_COUNT                     10
#define OFFSET_TEST_COROUTINE_ITERATIONS                10
#define OFFSET_TEST_COROUTINE_TIMESLICE                 FLB_TIME_MILLISECONDS_TO_MICROSECONDS(1)
#define OFFSET_TEST_COROUTINE_SLEEP_TIME                FLB_TIME_MILLISECONDS_TO_MICROSECONDS(1.1)

#define COLLECTIVE_TEST_TIME_LIMIT                      FLB_TIME_SECONDS_TO_MICROSECONDS(5)
#define COLLECTIVE_TEST_COROUTINE_COUNT                 20
#define COLLECTIVE_TEST_COROUTINE_ITERATIONS            100
#define COLLECTIVE_TEST_ACCUMULATOR_OBJECTIVE           (COLLECTIVE_TEST_COROUTINE_COUNT * \
                                                         COLLECTIVE_TEST_COROUTINE_ITERATIONS)
#define COLLECTIVE_TEST_COROUTINE_TIMESLICE             FLB_TIME_MILLISECONDS_TO_MICROSECONDS(1)
#define COLLECTIVE_TEST_COROUTINE_SLEEP_TIME            FLB_TIME_MILLISECONDS_TO_MICROSECONDS(1.1)
#define COLLECTIVE_TEST_COLLECTIVE_TIMESLICE            FLB_TIME_MILLISECONDS_TO_MICROSECONDS(15)
#define COLLECTIVE_TEST_SKEW_TOLERANCE_PERCENTAGE       25

#define EVENT_LOOP_TEST_TIME_LIMIT                      FLB_TIME_SECONDS_TO_MICROSECONDS(10)
#define EVENT_LOOP_TEST_COROUTINE_COUNT                 20
#define EVENT_LOOP_TEST_COROUTINE_ITERATIONS            150
#define EVENT_LOOP_TEST_ACCUMULATOR_OBJECTIVE           (EVENT_LOOP_TEST_COROUTINE_COUNT * \
                                                         EVENT_LOOP_TEST_COROUTINE_ITERATIONS)
#define EVENT_LOOP_TEST_COROUTINE_TIMESLICE             FLB_TIME_MILLISECONDS_TO_MICROSECONDS(15)
#define EVENT_LOOP_TEST_COROUTINE_SLEEP_TIME            FLB_TIME_MILLISECONDS_TO_MICROSECONDS(1)
#define EVENT_LOOP_TEST_COLLECTIVE_TIMESLICE            FLB_TIME_MILLISECONDS_TO_MICROSECONDS(80)
#define EVENT_LOOP_TEST_EVENT_LOOP_WAIT_LIMIT           FLB_TIME_SECONDS_TO_MICROSECONDS(1)
#define EVENT_LOOP_TEST_TIMER_CYCLE_DELAY               FLB_TIME_SECONDS_TO_MICROSECONDS(0.5)
#define EVENT_LOOP_TEST_TIMER_SKEW_TOLERANCE_PERCENTAGE 25
#define EVENT_LOOP_TEST_TOTAL_SKEW_TOLERANCE_PERCENTAGE 25

static int thread_termination_acknowledgement = FLB_FALSE;
static int thread_termination_request         = FLB_FALSE;

struct flb_test_coro_context {
    size_t           id;
    struct flb_coro *coroutine;
    uint64_t         timeslice;
    size_t           iterations;
    size_t           accumulator;
    size_t           delay_length;
    int              delay_selector;
};

struct timer_context {
    struct mk_event       event;
    pthread_t             thread_id;
    struct mk_event_loop *event_loop;
    flb_pipefd_t          channels[2];
    time_t                cycle_delay;
};

static inline void initialize_networking()
{
#ifdef _WIN32
    WSADATA wsa_data;

    WSAStartup(0x0201, &wsa_data);
#endif
}

static inline void uninitialize_networking()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

/* Writes to pipe after set delay. Cleans self up after pipe closure */
void timer_worker_entry_point(void *arg) {
    struct timer_context *context;
    int                   result;

    context = (struct timer_context *) arg;

    mk_utils_worker_rename("timer_tick_emitter");

    while (!thread_termination_request) {
        usleep(context->cycle_delay);

        result = flb_pipe_w(context->channels[1], "1", 1);

        if (result == -1) {
            flb_error("timer thread: pipe write error");
        }
    }

    thread_termination_acknowledgement = FLB_TRUE;
}


static int test_timer_create(struct mk_event_loop *event_loop,
                             struct timer_context *context,
                             time_t cycle_delay)
{
    int result;

    context->thread_id = 0;
    context->channels[0] = -1;
    context->channels[1] = -1;

    result = flb_pipe_create(context->channels);

    if (result == -1) {
        return -1;
    }

    context->cycle_delay = cycle_delay;
    context->event_loop = event_loop;

    MK_EVENT_NEW(&context->event);

    result = mk_event_add(event_loop,
                          context->channels[0],
                          MK_EVENT_NOTIFICATION,
                          MK_EVENT_READ,
                          &context->event);

    if (result != 0) {
        flb_pipe_close(context->channels[0]);
        flb_pipe_close(context->channels[1]);

        context->channels[0] = -1;
        context->channels[1] = -1;

        return -3;
    }

    result = mk_utils_worker_spawn(timer_worker_entry_point,
                                   (void *) context,
                                   &context->thread_id);

    if (result != 0) {
        mk_event_del(event_loop, &context->event);

        flb_pipe_close(context->channels[0]);
        flb_pipe_close(context->channels[1]);

        context->channels[0] = -1;
        context->channels[1] = -1;

        return -2;
    }

    return 0;
}

void test_timer_destroy(struct timer_context *context)
{
    size_t thread_termination_retry;

    if (context->thread_id != 0) {
        /* This is a placeholder for proper thread termination */
        thread_termination_request = FLB_TRUE;

        for (thread_termination_retry = 0 ;
             thread_termination_retry < 5 &&
             !thread_termination_acknowledgement;
             thread_termination_retry++) {
            sleep(1);
        }
    }

    if (context->channels[0] != -1) {
        mk_event_del(context->event_loop, &context->event);

        flb_pipe_close(context->channels[0]);
        flb_pipe_close(context->channels[1]);

        context->channels[0] = -1;
        context->channels[1] = -1;
    }
}

void coroutine_entry_point()
{
    int                           pair_cycle;
    struct flb_coro              *coroutine;
    struct flb_test_coro_context *context;
    size_t                        index;

    coroutine = flb_coro_get();
    context = (struct flb_test_coro_context *) coroutine->data;

    if (context != NULL) {
        context->accumulator = 0;

        for (index = 0 ; index < context->iterations ; index++) {
            context->accumulator++;

            pair_cycle = ((index % 2) == 0);

            if (((context->delay_selector == DELAY_SELECTOR_PAIR_CYCLES) && pair_cycle) ||
                ((context->delay_selector == DELAY_SELECTOR_ODD_CYCLES) && !pair_cycle) ||
                ((context->delay_selector == DELAY_SELECTOR_EVERY_CYCLE))) {

                if (context->delay_length == DELAY_MODE_FORCE_YIELD) {
                    flb_coro_collab_yield(coroutine, FLB_TRUE);
                }
                else {
                    usleep(context->delay_length);
                }
            }

            if (context->delay_length != DELAY_MODE_FORCE_YIELD) {
                flb_coro_collab_yield(coroutine, FLB_FALSE);
            }
        }
    }

    while (1) {
        flb_coro_yield(coroutine, FLB_TRUE);
    }
}

static int create_coroutine(struct flb_test_coro_context *context,
                            void *entry_point,
                            size_t stack_size)
{
    context->coroutine = flb_coro_create(context);

    if (context->coroutine == NULL) {
        return -1;
    }

    if (stack_size == 0) {
        stack_size = 4096;
    }

    context->coroutine->caller = co_active();
    context->coroutine->callee = co_create(stack_size,
                                           entry_point,
                                           &stack_size);

    if (context->coroutine->callee == NULL) {
        flb_coro_destroy(context->coroutine);

        return -2;
    }

    flb_coro_set_time_slice_limit(context->coroutine,
                                  context->timeslice);

    return 0;
}


static int create_coroutines(struct flb_coroutine_scheduler *scheduler,
                             struct flb_test_coro_context *coroutine_contexts,
                             size_t count,
                             uint64_t timeslice,
                             void *entry_point)
{
    int    result;
    size_t index;

    for (index = 0 ; index < count ; index++) {
        coroutine_contexts[index].id = index;
        coroutine_contexts[index].timeslice = timeslice;

        result = create_coroutine(&coroutine_contexts[index], entry_point, 0);

        TEST_CHECK(result == 0);

        if (result != 0) {
            return -1;
        }

        flb_coro_enqueue(coroutine_contexts[index].coroutine);
    }

    return 0;
}

static void destroy_coroutine(struct flb_test_coro_context *context)
{
    if (context->coroutine != NULL) {
        flb_coro_destroy(context->coroutine);
        context->coroutine = NULL;
    }
}

static void destroy_coroutines(struct flb_test_coro_context *coroutine_contexts,
                               size_t count)
{
    size_t index;

    for (index = 0 ; index < count ; index++) {
        destroy_coroutine(&coroutine_contexts[index]);
    }
}

static size_t get_total_accumulator_value(struct flb_test_coro_context *contexts,
                                          size_t count)
{
    size_t result;
    size_t index;

    result = 0;

    for (index = 0 ; index < count ; index++) {
        result += contexts[index].accumulator;
    }

    return result;
}

static int verify_accumulator_lockstep_state(struct flb_test_coro_context *contexts,
                                             size_t count)
{
    size_t expected_value;
    size_t index;

    expected_value = contexts[0].accumulator;

    for (index = 1 ; index < count ; index++) {
        if (expected_value != contexts[index].accumulator) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int verify_accumulator_offset_step_state(struct flb_test_coro_context *contexts,
                                                size_t count)
{
    size_t pair_expected_value;
    size_t odd_expected_value;
    size_t index;

    pair_expected_value = contexts[0].accumulator;
    odd_expected_value = contexts[1].accumulator;

    for (index = 1 ; index < count ; index++) {
         if ((index % 2) == 0) {
            if (pair_expected_value != contexts[index].accumulator) {
                return FLB_FALSE;
            }
        }
        else {
            if (odd_expected_value != contexts[index].accumulator) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

/* This test case runs 50 coroutines which will iterate 100 times
 * incrementing an accumulator and yielding on each cycle.
 *
 * It is expected that the 50 accumulators should grow in lockstep executing
 * one iteration per scheduler cycle.
 */
static void test_simple_coroutine_scheduler_usage()
{
    struct flb_test_coro_context   contexts[SIMPLE_TEST_COROUTINE_COUNT];
    struct flb_coroutine_scheduler coro_scheduler;
    int                            result;
    size_t                         index;

    memset(contexts, 0, sizeof(contexts));

    flb_coroutine_scheduler_init(&coro_scheduler, -1);
    flb_coroutine_scheduler_set(&coro_scheduler);

    result = create_coroutines(&coro_scheduler,
                               contexts,
                               SIMPLE_TEST_COROUTINE_COUNT,
                               FLB_TIMESLICE_UNLIMITED,
                               coroutine_entry_point);

    TEST_CHECK(result == 0);

    if (result != 0) {
        return;
    }

    for (index = 0 ;
         index < SIMPLE_TEST_COROUTINE_COUNT;
         index++) {
        contexts[index].iterations = SIMPLE_TEST_COROUTINE_ITERATIONS;
        contexts[index].delay_length = DELAY_MODE_FORCE_YIELD;
        contexts[index].delay_selector = DELAY_SELECTOR_EVERY_CYCLE;
    }

    for (index = 0 ;
         index < SIMPLE_TEST_COROUTINE_ITERATIONS;
         index++) {
        result = flb_coroutine_scheduler_resume_enqueued_coroutines();

        if (!TEST_CHECK(result >= 0)) {
            break;
        }

        result = verify_accumulator_lockstep_state(contexts,
                                                   SIMPLE_TEST_COROUTINE_COUNT);

        if (!TEST_CHECK(result == FLB_TRUE)) {
            break;
        }
    }
}

/* This test case runs 10 coroutines each with a 100 microsecond timeslice
 * and a selective sleep mechanism that should cause half of them to yield
 * on odd cycles and the other half to yield on pair cycles. This is not
 * achieved by performing a forceful collaborative yield but rather by
 * exhausting the allowed timeslice.
 *
 * It is expected that the coroutines maintain their accumulators offset
 * until the end.
 */
static void test_offset_coroutine_scheduler_usage()
{
    struct flb_test_coro_context   contexts[OFFSET_TEST_COROUTINE_COUNT];
    struct flb_coroutine_scheduler coro_scheduler;
    int                            result;
    size_t                         index;

    memset(contexts, 0, sizeof(contexts));

    flb_coroutine_scheduler_init(&coro_scheduler, -1);
    flb_coroutine_scheduler_set(&coro_scheduler);

    result = create_coroutines(&coro_scheduler,
                               contexts,
                               OFFSET_TEST_COROUTINE_COUNT,
                               OFFSET_TEST_COROUTINE_TIMESLICE,
                               coroutine_entry_point);

    if (!TEST_CHECK(result == 0)) {
        return;
    }

    for (index = 0 ;
         index < OFFSET_TEST_COROUTINE_COUNT;
         index++) {
        contexts[index].delay_length = OFFSET_TEST_COROUTINE_SLEEP_TIME;
        contexts[index].iterations = OFFSET_TEST_COROUTINE_ITERATIONS;

        if ((index % 2) == 0) {
            contexts[index].delay_selector = DELAY_SELECTOR_PAIR_CYCLES;
        }
        else {
            contexts[index].delay_selector = DELAY_SELECTOR_ODD_CYCLES;
        }
    }

    for (index = 0 ;
         index < OFFSET_TEST_COROUTINE_ITERATIONS;
         index++) {
        result = flb_coroutine_scheduler_resume_enqueued_coroutines();

        if (!TEST_CHECK(result >= 0)) {
            break;
        }

        result = verify_accumulator_offset_step_state(contexts,
                                                      OFFSET_TEST_COROUTINE_COUNT);

        if (!TEST_CHECK(result == FLB_TRUE)) {
            break;
        }
    }
}

/* This test case runs 20 coroutines each with a 1 millisecond individual
 * timeslice and a 15 millisecond collective timeslice where each coroutine
 * iterates 100 times incrementing an accumulator and performing a sleep
 * that should cause them to exhaust their timeslice allowance.
 *
 * Additionally this test validates that the practical deviation does not
 * exceed the collective timeslice by more than 25 percent.
 *
 */
static void test_collective_coroutine_scheduler_usage()
{
    struct flb_test_coro_context   contexts[COLLECTIVE_TEST_COROUTINE_COUNT];
    uint64_t                       cycle_duration_failure_window;
    struct flb_coroutine_scheduler coro_scheduler;
    uint64_t                       cycle_duration;
    uint64_t                       test_duration;
    uint64_t                       cycle_start;
    uint64_t                       cycle_end;
    int                            result;
    size_t                         index;

    cycle_duration_failure_window  = COLLECTIVE_TEST_COLLECTIVE_TIMESLICE;
    cycle_duration_failure_window *= (100 + COLLECTIVE_TEST_SKEW_TOLERANCE_PERCENTAGE);
    cycle_duration_failure_window /= 100;

    memset(contexts, 0, sizeof(contexts));

    flb_coroutine_scheduler_init(&coro_scheduler, -1);
    flb_coroutine_scheduler_set(&coro_scheduler);

    flb_coroutine_scheduler_set_collective_timeslice(&coro_scheduler,
                                                     COLLECTIVE_TEST_COLLECTIVE_TIMESLICE);

    result = create_coroutines(&coro_scheduler,
                               contexts,
                               COLLECTIVE_TEST_COROUTINE_COUNT,
                               COLLECTIVE_TEST_COROUTINE_TIMESLICE,
                               coroutine_entry_point);

    if (!TEST_CHECK(result == 0)) {
        return;
    }

    for (index = 0 ;
         index < COLLECTIVE_TEST_COROUTINE_COUNT;
         index++) {
        contexts[index].iterations = COLLECTIVE_TEST_COROUTINE_ITERATIONS;
        contexts[index].delay_length = COLLECTIVE_TEST_COROUTINE_SLEEP_TIME;
        contexts[index].delay_selector = DELAY_SELECTOR_EVERY_CYCLE;
    }

    test_duration = 0;

    for (index = 0 ;
         test_duration < COLLECTIVE_TEST_TIME_LIMIT;
         index++) {
        cycle_start = flb_time_get_cpu_timestamp();

        result = flb_coroutine_scheduler_resume_enqueued_coroutines();

        if (!TEST_CHECK(result >= 0)) {
            break;
        }

        cycle_end = flb_time_get_cpu_timestamp();

        cycle_duration = cycle_end - cycle_start;

        if (!TEST_CHECK(cycle_duration < cycle_duration_failure_window)) {
            break;
        }

        test_duration += cycle_duration;

        result = get_total_accumulator_value(contexts,
                                             COLLECTIVE_TEST_COROUTINE_COUNT);

        if (result == COLLECTIVE_TEST_ACCUMULATOR_OBJECTIVE) {
            break;
        }
    }

    TEST_CHECK(test_duration < COLLECTIVE_TEST_TIME_LIMIT);
}

/* This test case emulates the use case where there are time intensive coroutines
 * running alongside time sensitive processes such as the timers used by the engine
 * for flush orchestration and timeout management.
 *
 * In this case we are running 20 coroutines with a time allowance of 15 ms per
 * scheduler cycle each and an 80 ms collective allowance per scheduler cycle
 * alongisde with a simulated timer that ticks every 500 ms while accounting for
 * a 25% time skew both between timer ticks and total execution time.
 */
static void test_event_loop_coroutine_scheduler_usage()
{
    struct flb_test_coro_context   contexts[EVENT_LOOP_TEST_COROUTINE_COUNT];
    double                         expected_test_duration_upper_limit;
    double                         expected_test_duration_lower_limit;
    uint64_t                       timer_skew_failure_window;
    double                         expected_test_duration;
    uint64_t                       successful_tick_count;
    uint64_t                       previous_timer_tick;
    uint64_t                       current_timer_tick;
    char                           dummy_pipe_buffer;
    uint64_t                       timer_tick_delay;
    size_t                         coroutine_count;
    struct flb_coroutine_scheduler coro_scheduler;
    uint64_t                       cycle_duration;
    int                            error_detected;
    struct flb_bucket_queue       *bucket_queues;
    uint64_t                       test_duration;
    struct timer_context           timer_context;
    struct mk_event               *current_event;
    uint64_t                       cycle_start;
    struct mk_event_loop          *event_loop;
    uint64_t                       cycle_end;
    int                            result;
    size_t                         index;

    timer_skew_failure_window  = EVENT_LOOP_TEST_TIMER_CYCLE_DELAY;
    timer_skew_failure_window *= (100 + EVENT_LOOP_TEST_TIMER_SKEW_TOLERANCE_PERCENTAGE);
    timer_skew_failure_window /= 100;

    coroutine_count = EVENT_LOOP_TEST_COROUTINE_COUNT;

    memset(contexts, 0, sizeof(contexts));

    initialize_networking();

    event_loop = mk_event_loop_create(128);

    if (!TEST_CHECK(event_loop != NULL)) {
        uninitialize_networking();

        return;
    }

    bucket_queues = flb_bucket_queue_create(10);

    if (!TEST_CHECK(bucket_queues != NULL)) {
        mk_event_loop_destroy(event_loop);
        uninitialize_networking();

        return;
    }

    flb_coroutine_scheduler_init(&coro_scheduler, -1);
    flb_coroutine_scheduler_set(&coro_scheduler);

    result = flb_coroutine_scheduler_add_event_loop(&coro_scheduler, event_loop);

    if (!TEST_CHECK(result == 0)) {
        flb_bucket_queue_destroy(bucket_queues);
        mk_event_loop_destroy(event_loop);
        uninitialize_networking();

        return;
    }

    flb_coroutine_scheduler_set_collective_timeslice(&coro_scheduler,
                                                     EVENT_LOOP_TEST_COLLECTIVE_TIMESLICE);

    result = create_coroutines(&coro_scheduler,
                               contexts,
                               coroutine_count,
                               EVENT_LOOP_TEST_COROUTINE_TIMESLICE,
                               coroutine_entry_point);

    if (!TEST_CHECK(result == 0)) {
        flb_bucket_queue_destroy(bucket_queues);
        mk_event_loop_destroy(event_loop);
        uninitialize_networking();

        return;
    }

    for (index = 0 ;
         index < coroutine_count;
         index++) {
        contexts[index].iterations = EVENT_LOOP_TEST_COROUTINE_ITERATIONS;
        contexts[index].delay_length = EVENT_LOOP_TEST_COROUTINE_SLEEP_TIME;
        contexts[index].delay_selector = DELAY_SELECTOR_EVERY_CYCLE;
    }

    test_duration = 0;

    result = test_timer_create(event_loop,
                               &timer_context,
                               EVENT_LOOP_TEST_TIMER_CYCLE_DELAY);

    if (!TEST_CHECK(result == 0)) {
        destroy_coroutines(contexts, coroutine_count);
        flb_bucket_queue_destroy(bucket_queues);
        mk_event_loop_destroy(event_loop);
        uninitialize_networking();

        return;
    }

    result = flb_coroutine_scheduler_resume_enqueued_coroutines();

    if (!TEST_CHECK(result >= 0)) {
        test_timer_destroy(&timer_context);
        destroy_coroutines(contexts, coroutine_count);
        flb_bucket_queue_destroy(bucket_queues);
        mk_event_loop_destroy(event_loop);
        uninitialize_networking();

        return;
    }

    successful_tick_count = 0;
    previous_timer_tick = flb_time_get_cpu_timestamp();
    current_timer_tick = flb_time_get_cpu_timestamp();
    timer_tick_delay = 0;
    error_detected = FLB_FALSE;

    for (index = 0 ;
         test_duration < EVENT_LOOP_TEST_TIME_LIMIT &&
         !error_detected;
         index++) {
        cycle_start = flb_time_get_cpu_timestamp();

        result = mk_event_wait_2(event_loop, EVENT_LOOP_TEST_EVENT_LOOP_WAIT_LIMIT);

        flb_event_priority_live_foreach (current_event,
                                         bucket_queues,
                                         event_loop,
                                         10) {

            if (current_event == &timer_context.event) {
                current_timer_tick = flb_time_get_cpu_timestamp();

                timer_tick_delay = current_timer_tick - previous_timer_tick;

                previous_timer_tick = current_timer_tick;

                if (timer_tick_delay > 0) {
                    if (!TEST_CHECK(timer_tick_delay < timer_skew_failure_window)) {
                        error_detected = FLB_TRUE;

                        break;
                    }
                    else {
                        successful_tick_count++;
                    }
                }
                result = (int) flb_pipe_r(timer_context.channels[0],
                                          &dummy_pipe_buffer, 1);
            }
            else if (current_event->type == FLB_ENGINE_EV_CORO_SCHEDULER) {
                flb_coroutine_scheduler_consume_continuation_signal(NULL);
                result = flb_coroutine_scheduler_resume_enqueued_coroutines();

                if (!TEST_CHECK(result >= 0)) {
                    break;
                }
            }
        }

        cycle_end = flb_time_get_cpu_timestamp();

        cycle_duration = cycle_end - cycle_start;

        test_duration += cycle_duration;

        result = get_total_accumulator_value(contexts, coroutine_count);

        if (result == EVENT_LOOP_TEST_ACCUMULATOR_OBJECTIVE) {
            break;
        }
    }

    if (TEST_CHECK(!error_detected)) {
        if (TEST_CHECK(test_duration < EVENT_LOOP_TEST_TIME_LIMIT)) {
            expected_test_duration  = FLB_TIME_MICROSECONDS_TO_SECONDS(EVENT_LOOP_TEST_TIMER_CYCLE_DELAY);
            expected_test_duration *= successful_tick_count;

            expected_test_duration_lower_limit  = FLB_TIME_MICROSECONDS_TO_SECONDS(test_duration);
            expected_test_duration_lower_limit *= (100 - EVENT_LOOP_TEST_TOTAL_SKEW_TOLERANCE_PERCENTAGE);
            expected_test_duration_lower_limit /= 100;

            expected_test_duration_upper_limit  = FLB_TIME_MICROSECONDS_TO_SECONDS(test_duration);
            expected_test_duration_upper_limit *= (100 + EVENT_LOOP_TEST_TOTAL_SKEW_TOLERANCE_PERCENTAGE);
            expected_test_duration_upper_limit /= 100;

            TEST_CHECK(expected_test_duration >= expected_test_duration_lower_limit &&
                       expected_test_duration <= expected_test_duration_upper_limit);
        }
    }

    test_timer_destroy(&timer_context);
    destroy_coroutines(contexts, coroutine_count);
    flb_bucket_queue_destroy(bucket_queues);
    mk_event_loop_destroy(event_loop);
    uninitialize_networking();
}

TEST_LIST = {
    { "simple_coroutine_scheduler_usage",     test_simple_coroutine_scheduler_usage},
    { "offset_coroutine_scheduler_usage",     test_offset_coroutine_scheduler_usage},
    { "collective_coroutine_scheduler_usage", test_collective_coroutine_scheduler_usage},
    { "event_loop_coroutine_scheduler_usage", test_event_loop_coroutine_scheduler_usage},
    { 0 }
};
