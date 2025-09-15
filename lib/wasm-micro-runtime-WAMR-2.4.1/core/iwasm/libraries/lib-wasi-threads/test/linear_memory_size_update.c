/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <stdlib.h>
#include <pthread.h>

typedef enum {
    APP_STARTED,
    THREAD_STARTED,
    MEMORY_ALLOCATED,
} app_state_t;
typedef struct {

    pthread_cond_t cond;
    pthread_mutex_t mutex;
    app_state_t state;
    char *data;
} context_t;

void
context_init(context_t *ctx)
{
    pthread_cond_init(&ctx->cond, NULL);
    pthread_mutex_init(&ctx->mutex, NULL);
    ctx->state = APP_STARTED;
    ctx->data = NULL;
}

void
context_destroy(context_t *ctx)
{
    pthread_cond_destroy(&ctx->cond);
    pthread_mutex_destroy(&ctx->mutex);
    if (ctx->data) {
        free(ctx->data);
    }
}

void
context_set_state(context_t *ctx, app_state_t state)
{
    pthread_mutex_lock(&ctx->mutex);
    ctx->state = state;
    pthread_mutex_unlock(&ctx->mutex);
    pthread_cond_signal(&ctx->cond);
}

void
context_wait_for_state(context_t *ctx, app_state_t state)
{
    pthread_mutex_lock(&ctx->mutex);
    while (ctx->state != state) {
        pthread_cond_wait(&ctx->cond, &ctx->mutex);
    }
    pthread_mutex_unlock(&ctx->mutex);
}

void *
fnc(void *p)
{
    context_t *ctx = (context_t *)p;
    context_set_state(ctx, THREAD_STARTED);

    context_wait_for_state(ctx, MEMORY_ALLOCATED);

    // trigger memory.copy
    __builtin_memcpy(ctx->data + 512 * 1024, ctx->data + 1024, 1024);

    return NULL;
}

int
main()
{
    context_t ctx;
    context_init(&ctx);

    pthread_t th;
    pthread_create(&th, NULL, fnc, &ctx);

    context_wait_for_state(&ctx, THREAD_STARTED);

    // trigger memory.grow
    ctx.data = calloc(1024 * 1024, 1);

    context_set_state(&ctx, MEMORY_ALLOCATED);

    pthread_join(th, NULL);

    context_destroy(&ctx);

    return 0;
}
