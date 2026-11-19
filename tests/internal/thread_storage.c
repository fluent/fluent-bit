/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_thread_storage.h>
#include <fluent-bit/flb_input.h>

#include "flb_tests_internal.h"

struct thread_storage_test {
    int value;
};

#define THREAD_STORAGE_THREADS 8

struct thread_storage_thread {
    int index;
    int result;
    int *ready;
    int *start;
    pthread_mutex_t *lock;
    pthread_cond_t *cond;
    struct thread_storage_test context;
};

FLB_TLS_DEFINE(struct thread_storage_test, thread_storage_ctx);

static void *thread_storage_concurrent_worker(void *data)
{
    struct thread_storage_thread *thread;
    struct thread_storage_test *context;

    thread = data;
    context = &thread->context;
    context->value = thread->index;

    pthread_mutex_lock(thread->lock);
    (*thread->ready)++;
    pthread_cond_broadcast(thread->cond);

    while (*thread->start == FLB_FALSE) {
        pthread_cond_wait(thread->cond, thread->lock);
    }
    pthread_mutex_unlock(thread->lock);

    if (FLB_TLS_GET(thread_storage_ctx) != NULL) {
        thread->result = -1;
        return NULL;
    }

    FLB_TLS_SET(thread_storage_ctx, context);

    if (FLB_TLS_GET(thread_storage_ctx) != context) {
        thread->result = -2;
        return NULL;
    }

    if (((struct thread_storage_test *) FLB_TLS_GET(thread_storage_ctx))->value != thread->index) {
        thread->result = -3;
        return NULL;
    }

    thread->result = 0;
    return NULL;
}

void test_thread_storage_concurrent_access(void)
{
    int i;
    int ret;
    int ready;
    int start;
    int created;
    pthread_t threads[THREAD_STORAGE_THREADS];
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct thread_storage_thread contexts[THREAD_STORAGE_THREADS];

    ready = 0;
    start = FLB_FALSE;
    created = 0;

    pthread_mutex_init(&lock, NULL);
    pthread_cond_init(&cond, NULL);

    FLB_TLS_INIT(thread_storage_ctx);

    for (i = 0; i < THREAD_STORAGE_THREADS; i++) {
        contexts[i].index = i;
        contexts[i].result = -4;
        contexts[i].ready = &ready;
        contexts[i].start = &start;
        contexts[i].lock = &lock;
        contexts[i].cond = &cond;

        ret = pthread_create(&threads[i], NULL, thread_storage_concurrent_worker, &contexts[i]);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            break;
        }
        created++;
    }

    pthread_mutex_lock(&lock);
    while (ready < created) {
        pthread_cond_wait(&cond, &lock);
    }
    start = FLB_TRUE;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);

    TEST_CHECK(created == THREAD_STORAGE_THREADS);

    for (i = 0; i < created; i++) {
        ret = pthread_join(threads[i], NULL);
        TEST_CHECK(ret == 0);
        TEST_CHECK(contexts[i].result == 0);
    }

    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == NULL);

    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&lock);
}

void test_thread_storage_get_after_init(void)
{
    struct thread_storage_test context;

    context.value = 42;

    FLB_TLS_INIT(thread_storage_ctx);
    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == NULL);

    FLB_TLS_SET(thread_storage_ctx, &context);
    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == &context);
    TEST_CHECK(((struct thread_storage_test *) FLB_TLS_GET(thread_storage_ctx))->value == 42);

    FLB_TLS_SET(thread_storage_ctx, NULL);
    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == NULL);
}

struct input_coro_storage_thread {
    struct flb_config *config;
    int result;
};

static void *input_coro_storage_worker(void *data)
{
    int i;
    pthread_key_t first_key = 0;
    struct input_coro_storage_thread *thread = data;
    struct flb_input_instance instance;
    struct flb_input_collector collector;
    struct flb_input_coro *input_coro;

    memset(&instance, 0, sizeof(instance));
    memset(&collector, 0, sizeof(collector));
    mk_list_init(&instance.input_coro_list);
    collector.instance = &instance;
    flb_coro_thread_init();
    thread->result = 0;

    /* More callbacks than the POSIX minimum TLS-key capacity. */
    for (i = 0; i < 2048; i++) {
        input_coro = flb_input_coro_collect(&collector, thread->config);
        if (input_coro == NULL) {
            thread->result = -1;
            break;
        }
        if (i == 0) {
            first_key = libco_in_param_key;
        }
        else if (first_key != libco_in_param_key) {
            thread->result = -2;
        }
        mk_list_del(&input_coro->_head);
        flb_coro_destroy(input_coro->coro);
        flb_free(input_coro);
        if (thread->result != 0) {
            break;
        }
    }
    return NULL;
}

static void input_coro_storage_check(int count)
{
    int i;
    int created;
    int ret;
    struct flb_config *config;
    struct input_coro_storage_thread contexts[THREAD_STORAGE_THREADS];
    pthread_t threads[THREAD_STORAGE_THREADS];

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    created = 0;
    for (i = 0; i < count; i++) {
        contexts[i].config = config;
        contexts[i].result = -3;
        ret = pthread_create(&threads[i], NULL, input_coro_storage_worker, &contexts[i]);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            break;
        }
        created++;
    }
    TEST_CHECK(created == count);
    for (i = 0; i < created; i++) {
        TEST_CHECK(pthread_join(threads[i], NULL) == 0);
        TEST_CHECK_(contexts[i].result == 0, "collector TLS result=%d", contexts[i].result);
    }
    flb_config_exit(config);
}

static void test_input_coro_storage_reuses_key()
{
    input_coro_storage_check(1);
}

static void test_input_coro_storage_concurrent_collectors()
{
    input_coro_storage_check(THREAD_STORAGE_THREADS);
}

TEST_LIST = {
    {"concurrent_access", test_thread_storage_concurrent_access},
    {"get_after_init", test_thread_storage_get_after_init},
    {"input_coro_reuses_key", test_input_coro_storage_reuses_key},
    {"input_coro_concurrent_collectors", test_input_coro_storage_concurrent_collectors},
    { 0 }
};
