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

#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>

extern struct flb_input_plugin in_lib_plugin;

static struct flb_lib_ctx *flb_lib_context_create()
{
    struct flb_lib_ctx *ctx;

    ctx = calloc(1, sizeof(struct flb_lib_ctx));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    ctx->config = flb_config_init();
    if (!ctx->config) {
        free(ctx);
        return NULL;
    }

    ctx->config->lib_ctx = ctx;
    return ctx;
}

/* Release resources associated to a flb_lib context */
static void flb_lib_context_destroy(struct flb_lib_ctx *ctx)
{

    if (!ctx) {
        flb_error("[lib] invalid context");
        return;
    }

    if (ctx->event_channel) {
        mk_event_del(ctx->event_loop, ctx->event_channel);
        free(ctx->event_channel);
    }

    /* Remove resources from the event loop */
    mk_event_loop_destroy(ctx->event_loop);
    free(ctx);
}

/*
 * The library initialization routine basically register the in_lib
 * plugin for the configuration context in question. This is a mandatory step
 * for callers who wants to ingest data directly into the engine.
 */
struct flb_lib_ctx *flb_lib_init(char *input, char *output, void *data)
{
    int ret;
    struct flb_lib_ctx *ctx;
    struct flb_config *config;

    ctx = flb_lib_context_create();
    if (!ctx) {
        return NULL;
    }
    config = ctx->config;

    if (!input) {
        ret = flb_input_set(config, "lib", data);
    }
    else {
        ret = flb_input_set(config, input, data);
    }

    if (ret == -1) {
        return NULL;
    }

    /* Initialize our pipe to send data to our worker */
    ret = pipe(config->ch_data);
    if (ret == -1) {
        perror("pipe");
        return NULL;
    }

    /* Set the output interface */
    ret = flb_output_set(config, output, data);
    if (ret == -1) {
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
        flb_lib_context_destroy(ctx);
        return NULL;
    }

    return ctx;
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
int flb_lib_push(struct flb_lib_ctx *ctx, void *data, size_t len)
{
    int ret;

    ret = write(ctx->config->ch_data[1], data, len);
    if (ret == -1) {
        perror("write");
    }
    return ret;
}

static void flb_lib_worker(void *data)
{
    struct flb_config *config = data;
    flb_engine_start(config);
}

/* Start the engine */
int flb_lib_start(struct flb_lib_ctx *ctx)
{
    int fd;
    int bytes;
    uint64_t val;
    pthread_t tid;
    struct mk_event *event;
    struct flb_config *config;

    config = ctx->config;
    tid = mk_utils_worker_spawn(flb_lib_worker, config);
    if (tid == -1) {
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
int flb_lib_stop(struct flb_lib_ctx *ctx)
{
    int ret;
    uint64_t val;

    if (ctx->config->file) {
        mk_rconf_free(ctx->config->file);
    }

    flb_debug("[lib] sending STOP signal to the engine");
    val = FLB_ENGINE_STOP;
    write(ctx->config->ch_manager[1], &val, sizeof(uint64_t));
    ret = pthread_join(ctx->config->worker, NULL);

    flb_debug("[lib] Fluent Bit engine stopped");
    return ret;
}

/* Release resources associated to the library context */
void flb_lib_exit(struct flb_lib_ctx *ctx)
{
    flb_lib_context_destroy(ctx);
}
