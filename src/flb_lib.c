/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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


#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_callback.h>

#include <signal.h>
#include <stdarg.h>

#ifdef FLB_HAVE_MTRACE
#include <mcheck.h>
#endif

/* thread initializator */
static pthread_once_t flb_lib_once = PTHREAD_ONCE_INIT;

#ifdef FLB_SYSTEM_WINDOWS
static inline int flb_socket_init_win32(void)
{
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", err);
        return err;
    }
    return 0;
}
#endif

static inline struct flb_input_instance *in_instance_get(flb_ctx_t *ctx,
                                                         int ffd)
{
    struct mk_list *head;
    struct flb_input_instance *i_ins;

    mk_list_foreach(head, &ctx->config->inputs) {
        i_ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (i_ins->id == ffd) {
            return i_ins;
        }
    }

    return NULL;
}

static inline struct flb_output_instance *out_instance_get(flb_ctx_t *ctx,
                                                           int ffd)
{
    struct mk_list *head;
    struct flb_output_instance *o_ins;

    mk_list_foreach(head, &ctx->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (o_ins->id == ffd) {
            return o_ins;
        }
    }

    return NULL;
}

static inline struct flb_filter_instance *filter_instance_get(flb_ctx_t *ctx,
                                                              int ffd)
{
    struct mk_list *head;
    struct flb_filter_instance *f_ins;

    mk_list_foreach(head, &ctx->config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
        if (f_ins->id == ffd) {
            return f_ins;
        }
    }

    return NULL;
}

void flb_init_env()
{
    flb_thread_prepare();
    flb_output_prepare();
}

flb_ctx_t *flb_create()
{
    int ret;
    flb_ctx_t *ctx;
    struct flb_config *config;

#ifdef FLB_HAVE_MTRACE
    /* Start tracing malloc and free */
    mtrace();
#endif

#ifdef FLB_SYSTEM_WINDOWS
    /* Ensure we initialized Windows Sockets */
    if (flb_socket_init_win32()) {
        return NULL;
    }
#endif

    ctx = flb_calloc(1, sizeof(flb_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    config = flb_config_init();
    if (!config) {
        flb_free(ctx);
        return NULL;
    }
    ctx->config = config;
    ctx->status = FLB_LIB_NONE;

    /*
     * Initialize our pipe to send data to our worker, used
     * by 'lib' input plugin.
     */
    ret = flb_pipe_create(config->ch_data);
    if (ret == -1) {
        perror("pipe");
        flb_config_exit(ctx->config);
        flb_free(ctx);
        return NULL;
    }

    /* Create the event loop to receive notifications */
    ctx->event_loop = mk_event_loop_create(256);
    if (!ctx->event_loop) {
        flb_config_exit(ctx->config);
        flb_free(ctx);
        return NULL;
    }
    config->ch_evl = ctx->event_loop;

    /* Prepare the notification channels */
    ctx->event_channel = flb_calloc(1, sizeof(struct mk_event));
    if (!ctx->event_channel) {
        perror("calloc");
        flb_config_exit(ctx->config);
        flb_free(ctx);
        return NULL;
    }

    MK_EVENT_ZERO(ctx->event_channel);

    ret = mk_event_channel_create(config->ch_evl,
                                  &config->ch_notif[0],
                                  &config->ch_notif[1],
                                  ctx->event_channel);
    if (ret != 0) {
        flb_error("[lib] could not create notification channels");
        flb_config_exit(ctx->config);
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
        flb_free(ctx->event_channel);
    }

    /* Remove resources from the event loop */
    mk_event_loop_destroy(ctx->event_loop);
    flb_free(ctx);

#ifdef FLB_HAVE_MTRACE
    /* Stop tracing malloc and free */
    muntrace();
#endif
}

/* Defines a new input instance */
int flb_input(flb_ctx_t *ctx, const char *input, void *data)
{
    struct flb_input_instance *i_ins;

    i_ins = flb_input_new(ctx->config, input, data, FLB_TRUE);
    if (!i_ins) {
        return -1;
    }

    return i_ins->id;
}

/* Defines a new output instance */
int flb_output(flb_ctx_t *ctx, const char *output, void *data)
{
    struct flb_output_instance *o_ins;

    o_ins = flb_output_new(ctx->config, output, data);
    if (!o_ins) {
        return -1;
    }

    return o_ins->id;
}

/* Defines a new filter instance */
int flb_filter(flb_ctx_t *ctx, const char *filter, void *data)
{
    struct flb_filter_instance *f_ins;

    f_ins = flb_filter_new(ctx->config, filter, data);
    if (!f_ins) {
        return -1;
    }

    return f_ins->id;
}

/* Set an input interface property */
int flb_input_set(flb_ctx_t *ctx, int ffd, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;
    struct flb_input_instance *i_ins;

    i_ins = in_instance_get(ctx, ffd);
    if (!i_ins) {
        return -1;
    }

    va_start(va, ffd);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            va_end(va);
            return -1;
        }
        ret = flb_input_set_property(i_ins, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

/* Set an output interface property */
int flb_output_set(flb_ctx_t *ctx, int ffd, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;
    struct flb_output_instance *o_ins;

    o_ins = out_instance_get(ctx, ffd);
    if (!o_ins) {
        return -1;
    }

    va_start(va, ffd);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            va_end(va);
            return -1;
        }

        ret = flb_output_set_property(o_ins, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

int flb_output_set_callback(flb_ctx_t *ctx, int ffd, char *name,
                            void (*cb)(char *, void *, void *))
{
    struct flb_output_instance *o_ins;

    o_ins = out_instance_get(ctx, ffd);
    if (!o_ins) {
        return -1;
    }

    return flb_callback_set(o_ins->callback, name, cb);
}

/* Set an filter interface property */
int flb_filter_set(flb_ctx_t *ctx, int ffd, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;
    struct flb_filter_instance *f_ins;

    f_ins = filter_instance_get(ctx, ffd);
    if (!f_ins) {
        return -1;
    }

    va_start(va, ffd);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            va_end(va);
            return -1;
        }

        ret = flb_filter_set_property(f_ins, key, value);
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
            va_end(va);
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
int flb_lib_config_file(struct flb_lib_ctx *ctx, const char *path)
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

/* This is a wrapper to release a buffer which comes from out_lib_flush() */
int flb_lib_free(void* data)
{
    if (data == NULL) {
        return -1;
    }
    flb_free(data);
    return 0;
}


/* Push some data into the Engine */
int flb_lib_push(flb_ctx_t *ctx, int ffd, const void *data, size_t len)
{
    int ret;
    struct flb_input_instance *i_ins;


    if (ctx->status == FLB_LIB_NONE || ctx->status == FLB_LIB_ERROR) {
        flb_error("[lib] cannot push data, engine is not running");
        return -1;
    }

    i_ins = in_instance_get(ctx, ffd);
    if (!i_ins) {
        return -1;
    }

    ret = flb_pipe_w(i_ins->channel[1], data, len);
    if (ret == -1) {
        flb_errno();
        return -1;
    }
    return ret;
}

static void flb_lib_worker(void *data)
{
    int ret;
    struct flb_config *config = data;

    flb_log_init(config, FLB_LOG_STDERR, FLB_LOG_INFO, NULL);
    ret = flb_engine_start(config);
    if (ret == -1) {
        flb_engine_failed(config);
        flb_engine_shutdown(config);
    }
}

/* Return the current time to be used by lib callers */
double flb_time_now()
{
    struct flb_time t;

    flb_time_get(&t);
    return flb_time_to_double(&t);
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

    pthread_once(&flb_lib_once, flb_init_env);

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
        bytes = flb_pipe_r(fd, &val, sizeof(uint64_t));
        if (bytes <= 0) {
            ctx->status = FLB_LIB_ERROR;
            return -1;
        }

        if (val == FLB_ENGINE_STARTED) {
            flb_debug("[lib] backend started");
            ctx->status = FLB_LIB_OK;
            break;
        }
        else if (val == FLB_ENGINE_FAILED) {
            flb_error("[lib] backend failed");
            ctx->status = FLB_LIB_ERROR;
            return -1;
        }
    }

    return 0;
}

/* Stop the engine */
int flb_stop(flb_ctx_t *ctx)
{
    int ret;
    pthread_t tid;

    if (ctx->status == FLB_LIB_NONE || ctx->status == FLB_LIB_ERROR) {
        return 0;
    }

    if (!ctx->config) {
        return 0;
    }

    if (ctx->config->file) {
        mk_rconf_free(ctx->config->file);
    }

    flb_debug("[lib] sending STOP signal to the engine");

    tid = ctx->config->worker;
    flb_engine_exit(ctx->config);
    ret = pthread_join(tid, NULL);
    flb_debug("[lib] Fluent Bit engine stopped");

    return ret;
}
