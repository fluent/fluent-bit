/* SPDX-License-Identifier: Apache-2.0 */
/* Readiness waits must work from a coroutine and leave pthread exit intact. */
#include <libco.h>
#include <mk_core/mk_event.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "event fiber: line %d: %s\n", __LINE__, #condition); abort(); \
} } while (0)

static cothread_t primary;
static cothread_t fiber;
static struct mk_event_loop *loop;
static int writer;

static void *write_later(void *data)
{
    uint64_t value = 42;

    (void) data;
    usleep(50000);
    CHECK(write(writer, &value, sizeof(value)) == sizeof(value));
    return (void *) 42;
}

static void wait_in_fiber(void)
{
    struct mk_event channel = {0};
    struct mk_event timer = {0};
    pthread_t thread;
    void *result;
    uint64_t value;
    int reader;

    CHECK(co_active() == fiber);
    loop = mk_event_loop_create(2);
    CHECK(loop != NULL);
    CHECK(mk_event_channel_create(loop, &reader, &writer, &channel) == 0);
    CHECK(mk_event_wait_2(loop, 0) == 0);
    CHECK(pthread_create(&thread, NULL, write_later, NULL) == 0);
    CHECK(mk_event_wait_2(loop, -1) == 1);
    CHECK(read(reader, &value, sizeof(value)) == sizeof(value) && value == 42);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *) 42);
    CHECK(mk_event_channel_destroy(loop, reader, writer, &channel) == 0);
    CHECK(mk_event_timeout_create(loop, 0, 20000000, &timer) >= 0);
    CHECK(mk_event_wait_2(loop, 1000) == 1);
    CHECK(read(timer.fd, &value, sizeof(value)) == sizeof(value) && value > 0);
    CHECK(mk_event_timeout_destroy(loop, &timer) == 0);
    CHECK(mk_event_wait_2(loop, 10) == 0);
    mk_event_loop_destroy(loop);
    co_switch(primary);
    abort();
}

int main(void)
{
    size_t stack_size;

    primary = co_active();
    fiber = co_create(65536, wait_in_fiber, &stack_size);
    CHECK(fiber != NULL);
    co_switch(fiber);
    CHECK(co_active() == primary);
    co_delete(fiber);
    puts("WASM fiber events passed: nonblocking, blocking, timers, pthread return");
    return 0;
}
