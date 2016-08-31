/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015-2016 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <signal.h>
#include <unistd.h>
#include <stdarg.h>

#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>

#ifdef FLB_HAVE_MTRACE
#include <mcheck.h>
#endif

extern struct flb_input_plugin in_lib_plugin;

flb_ctx_t *flb_create()
{
    int ret;
    flb_ctx_t *ctx;
    struct flb_config *config;

#ifdef FLB_HAVE_MTRACE
    /* Start tracing malloc and free */
    mtrace();
#endif

    ctx = calloc(1, sizeof(flb_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    config = flb_config_init();
    if (!config) {
        free(ctx);
        return NULL;
    }
    ctx->config = config;

    /* Initialize logger */
    flb_log_init(FLB_LOG_STDERR, FLB_LOG_INFO, NULL);

    /* Initialize our pipe to send data to our worker */
    ret = pipe(config->ch_data);
    if (ret == -1) {
        perror("pipe");
        free(ctx);
        return NULL;
    }

    /* Create the event loop to receive notifications */
    ctx->event_loop = mk_event_loop_create(256);
    if (!ctx->event_loop) {
        free(ctx);
        return NULL;
    }
    config->ch_evl = ctx->event_loop;

    /* Prepare the notification channels */
    ctx->event_channel = calloc(1, sizeof(struct mk_event));
    ret = mk_event_channel_create(config->ch_evl,
                                  &config->ch_notif[0],
                                  &config->ch_notif[1],
                                  ctx->event_channel);
    if (ret != 0) {
        flb_error("[lib] could not create notification channels");
        flb_destroy(ctx);
        return NULL;
    }

    return ctx;
}

/* Release resources associated to the library context */
void flb_destroy(flb_ctx_t *ctx)
{
    if (ctx->event_channel) {
        mk_event_del(ctx->event_loop, ctx->event_channel);
        free(ctx->event_channel);
    }

    /* Remove resources from the event loop */
    mk_event_loop_destroy(ctx->event_loop);
    free(ctx);

#ifdef FLB_HAVE_MTRACE
    /* Stop tracing malloc and free */
    muntrace();
#endif
}

/* Defines a new input instance */
flb_input_t *flb_input(flb_ctx_t *ctx, char *input, void *data)
{
    return (flb_input_t *) flb_input_new(ctx->config, input, data);
}

/* Defines a new output instance */
flb_output_t *flb_output(flb_ctx_t *ctx, char *output, void *data)
{
    return (flb_output_t *) flb_output_new(ctx->config, output, data);
}

/* Set an input interface property */
int flb_input_set(flb_input_t *input, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;

    va_start(va, input);

    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            return -1;
        }
        ret = flb_input_set_property(input, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

/* Set an input interface property */
int flb_output_set(flb_output_t *output, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;

    va_start(va, output);

    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            return -1;
        }

        ret = flb_output_set_property(output, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

/* Set a service property */
int flb_service_set(flb_ctx_t *ctx, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;

    va_start(va, ctx);

    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            return -1;
        }

        ret = flb_config_set_property(ctx->config, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

/* Load a configuration file that may be used by the input or output plugin */
int flb_lib_config_file(struct flb_lib_ctx *ctx, char *path)
{
    if (access(path, R_OK) != 0) {
        perror("access");
        return -1;
    }

    ctx->config->file = mk_rconf_open(path);
    if (!ctx->config->file) {
        fprintf(stderr, "Error reading configuration file: %s\n", path);
        return -1;
    }

    return 0;
}

/* Push some data into the Engine */
int flb_lib_push(flb_input_t *input, void *data, size_t len)
{
    int ret;

    ret = write(input->channel[1], data, len);
    if (ret == -1) {
        perror("write");
    }
    return ret;
}

static void flb_lib_worker(void *data)
{
    struct flb_config *config = data;

    flb_log_init(FLB_LOG_STDERR, FLB_LOG_INFO, NULL);
    flb_engine_start(config);
}

/* Start the engine */
int flb_start(flb_ctx_t *ctx)
{
    int fd;
    int bytes;
    int ret;
    uint64_t val;
    pthread_t tid;
    struct mk_event *event;
    struct flb_config *config;

    config = ctx->config;
    ret = mk_utils_worker_spawn(flb_lib_worker, config, &tid);
    if (ret == -1) {
        return -1;
    }
    config->worker = tid;

    /* Wait for the started signal so we can return to the caller */
    mk_event_wait(config->ch_evl);
    mk_event_foreach(event, config->ch_evl) {
        fd = event->fd;
        bytes = read(fd, &val, sizeof(uint64_t));
        if (bytes <= 0) {
            return -1;
        }

        if (val == FLB_ENGINE_STARTED) {
            flb_debug("[lib] backend started");
            break;
        }
    }

    return 0;
}

/* Stop the engine */
int flb_stop(flb_ctx_t *ctx)
{
    int ret;
    uint64_t val;

    if (ctx->config->file) {
        mk_rconf_free(ctx->config->file);
    }

    flb_debug("[lib] sending STOP signal to the engine");
    val = FLB_ENGINE_EV_STOP;
    write(ctx->config->ch_manager[1], &val, sizeof(uint64_t));
    ret = pthread_join(ctx->config->worker, NULL);

    flb_debug("[lib] Fluent Bit engine stopped");
    return ret;
}
