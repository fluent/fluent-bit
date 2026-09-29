/* libco Emscripten regression test; license: public domain */
#include <emscripten.h>
#include <emscripten/fiber.h>
#include <emscripten/eventloop.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libco.h>

#if __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
const char *__asan_default_options(void)
{
    return "abort_on_error=1";
}
#endif

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); abort(); \
} } while (0)

/* Threads run sequentially. Static stacks let a thread exit from a fiber
 * without leaving a dynamically allocated coroutine behind.
 */
static emscripten_fiber_t primary;
static emscripten_fiber_t secondary;
static _Alignas(16) unsigned char c_stack[65536];
static unsigned char primary_async[65536];
static unsigned char secondary_async[65536];
static int exit_on_entry;
static int hits;
#if __has_feature(address_sanitizer)
static void *primary_fake;
static void *secondary_fake;
#endif

static void swap(emscripten_fiber_t *from, emscripten_fiber_t *to)
{
#if __has_feature(address_sanitizer)
    void **fake = from == &primary ? &primary_fake : &secondary_fake;
    __sanitizer_start_switch_fiber(fake, to->stack_limit,
                                   (uintptr_t) to->stack_base - (uintptr_t) to->stack_limit);
#endif
    emscripten_fiber_swap(from, to);
#if __has_feature(address_sanitizer)
    __sanitizer_finish_switch_fiber(*fake, NULL, NULL);
#endif
}

static void entry(void *data)
{
    (void) data;
#if __has_feature(address_sanitizer)
    __sanitizer_finish_switch_fiber(secondary_fake, NULL, NULL);
#endif
    emscripten_runtime_keepalive_pop();
    if (exit_on_entry) {
        pthread_exit((void *) 42);
    }
    while (1) {
        hits++;
        swap(&secondary, &primary);
    }
}

static void run_fibers(void)
{
    int index;

    hits = 0;
#if __has_feature(address_sanitizer)
    primary_fake = NULL;
    secondary_fake = NULL;
#endif
    emscripten_fiber_init_from_current_context(&primary, primary_async, sizeof(primary_async));
    emscripten_fiber_init(&secondary, entry, NULL, c_stack, sizeof(c_stack),
                          secondary_async, sizeof(secondary_async));
    for (index = 0; index < 3; index++) {
        swap(&primary, &secondary);
    }
    CHECK(hits == 3);
    pthread_exit((void *) 42);
}

static void *install_and_exit(void *data)
{
    CHECK(co_active() != NULL);
    EM_ASM({ globalThis.coReuseMarker = $0; }, (int) (intptr_t) data);
    run_fibers();
    abort();
}

static void *other_fiber_user(void *data)
{
    /* No co_active(): a different fiber user must inherit clean runtime state. */
    CHECK(EM_ASM_INT({ return globalThis.coReuseMarker; }) == (int) (intptr_t) data);
    CHECK(EM_ASM_INT({ return Fibers.trampolineRunning ? 1 : 0; }) == 0);
    CHECK(EM_ASM_INT({ return Fibers.nextFiber; }) == 0);
    run_fibers();
    abort();
}

static void wait_for_worker_reuse(void)
{
    double deadline = emscripten_get_now() + 5000;

    /* With PROXY_TO_PTHREAD and a pool of two, main occupies one worker.
     * pthread_join posts cleanup to the JS main thread; it need not have
     * returned the other worker to the pool yet. Node can otherwise spawn a
     * fresh worker, even with PTHREAD_POOL_SIZE_STRICT, invalidating this test.
     * Wait for the actual pool state, not an assumed scheduling delay.
     */
    while (MAIN_THREAD_EM_ASM_INT({ return PThread.unusedWorkers.length; }) != 1) {
        CHECK(emscripten_get_now() < deadline);
        emscripten_sleep(1);
    }
}

int main(void)
{
    pthread_t thread;
    void *result;
    int mode;

    for (mode = 0; mode < 2; mode++) {
        exit_on_entry = mode;
        CHECK(pthread_create(&thread, NULL, install_and_exit, (void *) (intptr_t) (mode + 1)) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == (void *) 42);
        wait_for_worker_reuse();
        exit_on_entry = 0;
        CHECK(pthread_create(&thread, NULL, other_fiber_user, (void *) (intptr_t) (mode + 1)) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == (void *) 42);
        wait_for_worker_reuse();
    }
    puts("WASM worker reuse passed: first-entry/rewind exit followed by a non-libco fiber user");
    return 0;
}
