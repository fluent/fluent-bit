/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <mk_core/mk_pthread.h>
#include <mk_core/mk_unistd.h>

#include <monkey/mk_core.h>
#include <monkey/mk_config.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_tls.h>

#ifdef _WIN32
static struct tm* localtime_r(const time_t* timep, struct tm* result)
{
    localtime_s(result, timep);

    return result;
}

static struct tm* gmtime_r(const time_t* timep, struct tm* result)
{
    gmtime_s(result, timep);

    return result;
}
#endif


/*
 * The mk_ptr_ts have two buffers for avoid in half-way access from
 * another thread while a buffer is being modified. The function below returns
 * one of two buffers to work with.
 */
static inline char *_next_buffer(mk_ptr_t *pointer, char **buffers)
{
    if (pointer->data == buffers[0]) {
        return buffers[1];
    }
    else {
        return buffers[0];
    }
}

static void mk_clock_log_set_time(time_t utime, struct mk_server *server)
{
    char *time_string;
    struct tm result;

    time_string = _next_buffer(&server->clock_context->log_current_time, server->clock_context->log_time_buffers);
    server->clock_context->log_current_utime = utime;

    strftime(time_string, LOG_TIME_BUFFER_SIZE, "[%d/%b/%G %T %z]",
             localtime_r(&utime, &result));

    server->clock_context->log_current_time.data = time_string;
}

static void mk_clock_headers_preset(time_t utime, struct mk_server *server)
{
    int len1;
    int len2;
    struct tm *gmt_tm;
    struct tm result;
    char *buffer;

    buffer = _next_buffer(&server->clock_context->headers_preset,
                          server->clock_context->header_time_buffers);

    gmt_tm = gmtime_r(&utime, &result);

    len1 = snprintf(buffer,
                    HEADER_TIME_BUFFER_SIZE,
                    "%s",
                    server->server_signature_header);

    len2 = strftime(buffer + len1,
                    HEADER_PRESET_SIZE - len1,
                    MK_CLOCK_GMT_DATEFORMAT,
                    gmt_tm);

    server->clock_context->headers_preset.data = buffer;
    server->clock_context->headers_preset.len  = len1 + len2;
}

void *mk_clock_worker_init(void *data)
{
    time_t cur_time;
    struct mk_server *server = data;

    mk_utils_worker_rename("monkey: clock");
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    server->clock_context->mk_clock_tid = pthread_self();

    while (1) {
        cur_time = time(NULL);

        if(cur_time != ((time_t)-1)) {
            mk_clock_log_set_time(cur_time, server);
            mk_clock_headers_preset(cur_time, server);
        }
        sleep(1);
    }

    return NULL;
}

void mk_clock_exit(struct mk_server *server)
{
    pthread_cancel(server->clock_context->mk_clock_tid);
    pthread_join(server->clock_context->mk_clock_tid, NULL);

    mk_mem_free(server->clock_context->header_time_buffers[0]);
    mk_mem_free(server->clock_context->header_time_buffers[1]);
    mk_mem_free(server->clock_context->log_time_buffers[0]);
    mk_mem_free(server->clock_context->log_time_buffers[1]);

    mk_mem_free(server->clock_context);
}

/* This function must be called before any threads are created */
void mk_clock_sequential_init(struct mk_server *server)
{
    server->clock_context = mk_mem_alloc_z(sizeof(struct mk_clock_context));

    if (server->clock_context == NULL) {
        return;
    }

    /* Time when monkey was started */
    server->clock_context->monkey_init_time = time(NULL);

    server->clock_context->log_current_time.len = LOG_TIME_BUFFER_SIZE - 2;
    server->clock_context->headers_preset.len = HEADER_PRESET_SIZE - 1;

    server->clock_context->header_time_buffers[0] = mk_mem_alloc_z(HEADER_PRESET_SIZE);
    server->clock_context->header_time_buffers[1] = mk_mem_alloc_z(HEADER_PRESET_SIZE);

    server->clock_context->log_time_buffers[0] = mk_mem_alloc_z(LOG_TIME_BUFFER_SIZE);
    server->clock_context->log_time_buffers[1] = mk_mem_alloc_z(LOG_TIME_BUFFER_SIZE);

    /* Set the time once */
    time_t cur_time = time(NULL);

    if (cur_time != ((time_t)-1)) {
        mk_clock_log_set_time(cur_time, server);
        mk_clock_headers_preset(cur_time, server);
    }
}
