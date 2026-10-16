/*
  libco.emscripten
  license: public domain
*/

#define LIBCO_C
#include "libco.h"
#include "settings.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <emscripten/fiber.h>
#include <emscripten/eventloop.h>
#include <emscripten/version.h>

#if __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
#define LIBCO_ASAN 1
#endif

#if __EMSCRIPTEN_MAJOR__ != 6 || __EMSCRIPTEN_MINOR__ != 0 || __EMSCRIPTEN_TINY__ != 9
#error "The experimental libco fiber backend currently requires Emscripten 6.0.9"
#endif

#if defined(__wasm64__)
#error "The experimental libco fiber backend currently requires wasm32"
#endif

/*
 * In 6.0.9, doRewind invokes callUserCallback, which can finalize a pthread
 * while its original entry wrapper is still on the JavaScript stack. Fiber
 * switches are synchronous: that wrapper, not a nested rewind, owns exit.
 * Keep the workaround local to this thread and fiber rewinds; ordinary
 * Asyncify operations retain the SDK implementation. Remove after an SDK
 * with corrected fiber lifecycle handling has been validated.
 */
EM_JS(void, co_runtime_init, (size_t base_offset, size_t limit_offset,
                            size_t pointer_offset, size_t entry_offset,
                            size_t data_offset, size_t asyncify_offset,
                            emscripten_fiber_t *primary), {
    /* A worker can be reused for another pthread with a different TLS block. */
    Asyncify.coPrimaryRewind = primary + asyncify_offset;
    Asyncify.coHasResult = false;
    if (Asyncify.coRuntimeInitialized) {
        return;
    }
    Asyncify.coRuntimeInitialized = true;
    /* Both first entry and rewind can throw (including pthread_exit). Clean
     * up at the owning trampoline boundary, not when a later libco user
     * happens to initialize. Nested trampoline calls must not clear the
     * outer invocation's pending switch or running flag.
     */
    var originalTrampoline = Fibers.trampoline;
    Fibers.trampoline = function() {
        var ownsTrampoline = !Fibers.trampolineRunning;
        try {
            return originalTrampoline.call(Fibers);
        }
        catch (error) {
            if (ownsTrampoline) {
                Fibers.trampolineRunning = false;
                Fibers.nextFiber = 0;
            }
            throw error;
        }
    };
    var original = Asyncify.doRewind;
    Asyncify.doRewind = function(ptr) {
        if (!Fibers.trampolineRunning) {
            return original.call(Asyncify, ptr);
        }
        runtimeKeepalivePop();
        var id = Asyncify.getDataRewindFunc(ptr);
        var result = Asyncify.funcWrappers.get(id)();
        if (ptr === Asyncify.coPrimaryRewind && Asyncify.currData === null &&
            Asyncify.state === Asyncify.State.Normal) {
            Asyncify.coResult = result;
            Asyncify.coHasResult = true;
        }
        return result;
    };

    /* The outer export returns the unwind placeholder, not the rewind result. */
    if (typeof __emscripten_thread_exit === 'function') {
        var threadExit = __emscripten_thread_exit;
        __emscripten_thread_exit = function(result) {
            if (Asyncify.coHasResult) {
                result = Asyncify.coResult;
                Asyncify.coHasResult = false;
            }
            return threadExit(result);
        };
    }

    /*
     * The SDK loads stack_ptr after installing the destination stack bounds.
     * With ASan, that heap load calls C while the old stack pointer is still
     * active, so the stack check fails. Read the descriptor before changing
     * bounds, keeping all instrumented heap accesses outside the transition.
     * Neither ASan instrumentation nor stack overflow checks are disabled.
     */
    Fibers.finishContextSwitch = function(fiber) {
        var base = HEAPU32[(fiber + base_offset) >> 2];
        var limit = HEAPU32[(fiber + limit_offset) >> 2];
        var pointer = HEAPU32[(fiber + pointer_offset) >> 2];
        var entry = HEAPU32[(fiber + entry_offset) >> 2];
        var data = HEAPU32[(fiber + data_offset) >> 2];

        if (entry) {
            HEAPU32[(fiber + entry_offset) >> 2] = 0;
        }
        _emscripten_stack_set_limits(base, limit);
        if (typeof ___set_stack_limits === 'function') {
            ___set_stack_limits(base, limit);
        }
        stackRestore(pointer);

        if (entry) {
            if (typeof writeStackCookie === 'function') {
                writeStackCookie();
            }
            Asyncify.currData = null;
            dynCall_vi(entry, data);
        }
        else {
            var rewind = fiber + asyncify_offset;
            Asyncify.currData = rewind;
            Asyncify.state = Asyncify.State.Rewinding;
            _asyncify_start_rewind(rewind);
            Asyncify.doRewind(rewind);
        }
    };
});

#ifndef LIBCO_ASYNCIFY_STACK_SIZE
#define LIBCO_ASYNCIFY_STACK_SIZE (64 * 1024)
#endif

struct co_emscripten_context {
    emscripten_fiber_t fiber;
    struct co_emscripten_context *owner;
    void (*entry)(void);
    void *stack;
    void *asyncify_stack;
#ifdef LIBCO_ASAN
    void *fake_stack;
    struct co_emscripten_context *cleanup_caller;
#endif
};

static thread_local struct co_emscripten_context co_primary;
static thread_local struct co_emscripten_context *co_running;
static thread_local unsigned char co_primary_stack[LIBCO_ASYNCIFY_STACK_SIZE];

static void co_entry(void *data)
{
    struct co_emscripten_context *context;

    context = data;
#ifdef LIBCO_ASAN
    __sanitizer_finish_switch_fiber(context->fake_stack, NULL, NULL);
#endif
    /*
     * Emscripten 6.0.9 balances Asyncify's keepalive on fiber rewind, but
     * not on the first entry. Balance that first switch as well, otherwise
     * a pthread that used a fiber can never complete normally.
     */
    emscripten_runtime_keepalive_pop();
    context->entry();
    /* Like the native backends, an entry point must switch out before returning. */
    abort();
}

cothread_t co_active(void)
{
    if (co_running == NULL) {
        co_runtime_init(offsetof(emscripten_fiber_t, stack_base),
                        offsetof(emscripten_fiber_t, stack_limit),
                        offsetof(emscripten_fiber_t, stack_ptr),
                        offsetof(emscripten_fiber_t, entry),
                        offsetof(emscripten_fiber_t, user_data),
                        offsetof(emscripten_fiber_t, asyncify_data), &co_primary.fiber);
        emscripten_fiber_init_from_current_context(&co_primary.fiber,
                                                  co_primary_stack,
                                                  sizeof(co_primary_stack));
        co_primary.owner = &co_primary;
        co_running = &co_primary;
    }
    return co_running;
}

cothread_t co_create(unsigned int size, void (*entry)(void), size_t *out_size)
{
    struct co_emscripten_context *context;
    size_t stack_size;

    if (out_size != NULL) {
        *out_size = 0;
    }
    if (size == 0 || entry == NULL || size > (SIZE_MAX - 15) / 2) {
        return NULL;
    }

    co_active();
    stack_size = ((size_t) size + 15) & ~(size_t) 15;
    context = calloc(1, sizeof(*context));
    if (context == NULL) {
        return NULL;
    }
    if (posix_memalign(&context->stack, 16, stack_size) != 0) {
        free(context);
        return NULL;
    }
    context->asyncify_stack = malloc(stack_size);
    if (context->asyncify_stack == NULL) {
        free(context->stack);
        free(context);
        return NULL;
    }
    context->entry = entry;
    context->owner = &co_primary;
    emscripten_fiber_init(&context->fiber, co_entry, context,
                          context->stack, stack_size, context->asyncify_stack, stack_size);
    if (out_size != NULL) {
        *out_size = stack_size;
    }
    return context;
}

void co_delete(cothread_t thread)
{
    struct co_emscripten_context *context;

    context = thread;
    if (context == NULL) {
        return;
    }
    assert(context != &co_primary && context != co_running);
    assert(context->owner == &co_primary);
#ifdef LIBCO_ASAN
    /* Dispose of an optional ASan fake stack on its owning fiber. */
    if (context->fake_stack != NULL) {
        context->cleanup_caller = co_running;
        co_switch(context);
    }
#endif
    free(context->asyncify_stack);
    free(context->stack);
    free(context);
}

void co_switch(cothread_t thread)
{
    struct co_emscripten_context *previous;
    struct co_emscripten_context *next;

    previous = co_active();
    next = thread;
    assert(next != NULL && next->owner == &co_primary);
    if (previous == next) {
        return;
    }
    co_running = next;
#ifdef LIBCO_ASAN
    __sanitizer_start_switch_fiber(&previous->fake_stack, next->fiber.stack_limit,
                                   (uintptr_t) next->fiber.stack_base -
                                   (uintptr_t) next->fiber.stack_limit);
#endif
    emscripten_fiber_swap(&previous->fiber, &next->fiber);
#ifdef LIBCO_ASAN
    __sanitizer_finish_switch_fiber(previous->fake_stack, NULL, NULL);
    if (previous->cleanup_caller != NULL) {
        /* This suspended fiber is being deleted; never reenter user code. */
        next = previous->cleanup_caller;
        co_running = next;
        __sanitizer_start_switch_fiber(NULL, next->fiber.stack_limit,
                                       (uintptr_t) next->fiber.stack_base -
                                       (uintptr_t) next->fiber.stack_limit);
        emscripten_fiber_swap(&previous->fiber, &next->fiber);
        abort();
    }
#endif
}
