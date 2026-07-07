/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_thread_storage.h>

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

TEST_LIST = {
    {"concurrent_access", test_thread_storage_concurrent_access},
    {"get_after_init", test_thread_storage_get_after_init},
    { 0 }
};
