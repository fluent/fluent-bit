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

/* clock.h */

#ifndef MK_CLOCK_H
#define MK_CLOCK_H

#include <time.h>
#include <monkey/mk_core.h>

extern time_t log_current_utime;
extern time_t monkey_init_time;

extern mk_ptr_t log_current_time;
extern mk_ptr_t headers_preset;

#define MK_CLOCK_GMT_DATEFORMAT "Date: %a, %d %b %Y %H:%M:%S GMT\r\n"
#define HEADER_PRESET_SIZE 128
#define HEADER_TIME_BUFFER_SIZE 64
#define LOG_TIME_BUFFER_SIZE 30

struct mk_server;

struct mk_clock_context {
    pthread_t mk_clock_tid;

    time_t log_current_utime;
    time_t monkey_init_time;

    mk_ptr_t log_current_time;
    mk_ptr_t headers_preset;

    char *log_time_buffers[2];
    char *header_time_buffers[2];
};

void *mk_clock_worker_init(void *args);
void mk_clock_set_time(void);
void mk_clock_sequential_init(struct mk_server *server);
void mk_clock_exit(struct mk_server *server);

#endif
