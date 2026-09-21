/* libco Emscripten regression test; license: public domain */

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libco.h>

#if defined(LIBCO_TESTS_ASAN) && !__has_feature(address_sanitizer)
#error "LIBCO_TESTS_ASAN requires compiling and linking with -fsanitize=address"
#endif

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        abort(); \
    } \
} while (0)

#if __has_feature(address_sanitizer)
const char *__asan_default_options(void)
{
    /* Abort the whole runtime on a worker fault instead of exiting one thread. */
    return "abort_on_error=1";
}
#endif

static const char *fault;
static volatile unsigned int fault_index = 8;
static __thread cothread_t primary;
static __thread cothread_t first;
static __thread cothread_t second;
static __thread int switches;

static __attribute__((noinline)) void memory_fault(void)
{
    volatile unsigned char local[8];
    volatile unsigned char *heap;

    if (strcmp(fault, "heap") == 0) {
        heap = malloc(8);
        CHECK(heap != NULL);
        heap[fault_index] = 1;
        free((void *) heap);
    }
    else {
        local[fault_index] = 1;
    }
}

static __attribute__((noinline)) void stack_fault(unsigned int depth)
{
    volatile unsigned char local[4096];

    local[depth % sizeof(local)] = (unsigned char) depth;
    if (depth != 0) {
        stack_fault(depth - 1);
    }
    CHECK(local[depth % sizeof(local)] == (unsigned char) depth);
}

static void second_entry(void)
{
    volatile unsigned int local = 0;

    if (fault != NULL) {
        if (strcmp(fault, "limits") == 0) {
            stack_fault(64);
        }
        else {
            memory_fault();
        }
        abort();
    }
    while (1) {
        CHECK(co_active() == second);
        CHECK(local == (unsigned int) switches);
        local++;
        switches++;
        co_switch(first);
    }
}

static void first_entry(void)
{
    volatile unsigned int local = 0;

    while (1) {
        CHECK(co_active() == first);
        CHECK(local == (unsigned int) switches);
        co_switch(second);
        local++;
        CHECK(local == (unsigned int) switches);
        co_switch(primary);
    }
}

static void *exercise(void *data)
{
    size_t actual_size;
    int iteration;
    int index;

    primary = co_active();
    CHECK(primary != NULL);
    co_switch(primary);
    CHECK(co_create(0, first_entry, &actual_size) == NULL && actual_size == 0);
    CHECK(co_create(UINT_MAX, first_entry, &actual_size) == NULL);
    CHECK(co_create(65536, NULL, &actual_size) == NULL);
    co_delete(NULL);

    for (iteration = 0; iteration < 20; iteration++) {
        switches = 0;
        first = co_create(65536, first_entry, &actual_size);
        CHECK(first != NULL && actual_size >= 65536);
        second = co_create(65536, second_entry, &actual_size);
        CHECK(second != NULL);
        for (index = 0; index < 100; index++) {
            co_switch(first);
            CHECK(switches == index + 1);
            CHECK(co_active() == primary);
        }
        co_delete(second);
        co_delete(first);
    }
    if ((uintptr_t) data == 1) {
        pthread_exit(data);
    }
    return data;
}

static void *without_fibers(void *data)
{
    return data;
}

int main(int argc, char **argv)
{
    pthread_t workers[3];
    void *result;
    int index;
    int worker_count;
    int round;

    if (argc == 2) {
        fault = argv[1];
        CHECK(strcmp(fault, "heap") == 0 || strcmp(fault, "stack") == 0 ||
              strcmp(fault, "limits") == 0);
    }
    worker_count = fault == NULL ? 3 : 1;
    for (round = 0; round < 3; round++) {
        for (index = 0; index < worker_count; index++) {
            CHECK(pthread_create(&workers[index], NULL, exercise,
                                  (void *) (uintptr_t) index) == 0);
        }
        for (index = 0; index < worker_count; index++) {
            CHECK(pthread_join(workers[index], &result) == 0);
            CHECK(result == (void *) (uintptr_t) index);
        }
        CHECK(pthread_create(&workers[0], NULL, without_fibers, (void *) 123) == 0);
        CHECK(pthread_join(workers[0], &result) == 0 && result == (void *) 123);
    }
    puts("WASM coroutines passed: nested switches, thread isolation, cleanup, pthread return/reuse");
    return 0;
}
