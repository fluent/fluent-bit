/* Monkey event-loop browser regression tests. SPDX-License-Identifier: Apache-2.0 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <emscripten.h>
#include <mk_core/mk_event.h>
#include <mk_core/mk_utils.h>

#define CHECK(condition) do { if (!(condition)) { abort(); } } while (0)

static void worker(void *data)
{
    int *result;

    result = data;
    *result = 42;
}

static void delayed_writer(void *data)
{
    int fd;
    uint64_t value;

    fd = *(int *) data;
    value = 456;
    usleep(25000);
    CHECK(write(fd, &value, sizeof(value)) == sizeof(value));
}

int main(void)
{
    struct mk_event_loop *loop;
    struct mk_event timer = {0};
    struct mk_event channel = {0};
    struct mk_event overflow = {0};
    struct mk_event *removed_timer;
    pthread_t thread;
    uint64_t value;
    double start;
    int result;
    int reader;
    int writer;
    int index;

    result = 0;
    CHECK(mk_utils_worker_spawn(worker, &result, &thread) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && result == 42);
    for (index = 0; index < 20; index++) {
        loop = mk_event_loop_create(2);
        CHECK(loop != NULL);
        CHECK(mk_event_timeout_create(loop, 0, 0, &timer) == -1);
        CHECK(mk_event_timeout_create(loop, 0, 1000000000L, &timer) == -1);
        CHECK(mk_event_timeout_create(loop, 0, 20000000, &timer) >= 0);
        CHECK(mk_event_channel_create(loop, &reader, &writer, &channel) == 0);
        CHECK(mk_event_timeout_create(loop, 0, 1000000, &overflow) == -1);
        CHECK(mk_event_wait_2(loop, 1000) > 0);
        CHECK(read(timer.fd, &value, sizeof(value)) == sizeof(value) && value > 0);
        CHECK(mk_event_timeout_disable(loop, &timer) == 0);
        start = emscripten_get_now();
        CHECK(mk_event_wait_2(loop, 20) == 0);
        CHECK(emscripten_get_now() - start >= 19.0);
        CHECK(mk_event_add(loop, timer.fd, MK_EVENT_NOTIFICATION, MK_EVENT_READ, &timer) == 0);
        CHECK(mk_event_wait_2(loop, 1000) > 0);
        CHECK(read(timer.fd, &value, sizeof(value)) == sizeof(value));
        CHECK(mk_event_timeout_destroy(loop, &timer) == 0);
        /* Exercise the SDK readiness queue, including an unbounded wait that
         * must wake when a different pthread makes the channel readable.
         */
        CHECK(mk_utils_worker_spawn(delayed_writer, &writer, &thread) == 0);
        CHECK(mk_event_wait_2(loop, -1) == 1);
        CHECK(read(reader, &value, sizeof(value)) == sizeof(value) && value == 456);
        CHECK(pthread_join(thread, NULL) == 0);
        value = 123;
        CHECK(write(writer, &value, sizeof(value)) == sizeof(value));
        CHECK(mk_event_wait_2(loop, 1000) == 1);
        CHECK(read(reader, &value, sizeof(value)) == sizeof(value) && value == 123);
        CHECK(mk_event_channel_destroy(loop, reader, writer, &channel) == 0);
        CHECK(mk_event_wait_2(loop, 0) == 0);
        mk_event_loop_destroy(loop);
    }
    /* A disabled registration is no longer used by the caller. Destroying
     * the loop must close its timer descriptors without reading that object.
     */
    loop = mk_event_loop_create(1);
    CHECK(loop != NULL);
    removed_timer = calloc(1, sizeof(*removed_timer));
    CHECK(removed_timer != NULL);
    reader = mk_event_timeout_create(loop, 1, 0, removed_timer);
    CHECK(reader >= 0);
    CHECK(mk_event_timeout_disable(loop, removed_timer) == 0);
    free(removed_timer);
    mk_event_loop_destroy(loop);
    errno = 0;
    CHECK(fcntl(reader, F_GETFD) == -1 && errno == EBADF);
    puts("WASM events passed: timers, disable/rearm, channels, capacity, worker cleanup");
    return 0;
}
