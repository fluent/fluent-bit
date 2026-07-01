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

/* s_log status */
#ifndef MK_LOGGER_H
#define MK_LOGGER_H

#include <stdio.h>
#include <monkey/mk_api.h>

#define MK_LOGGER_PIPE_LIMIT 0.75
#define MK_LOGGER_TIMEOUT_DEFAULT 3

int mk_logger_timeout;

/* MasterLog variables */
char *mk_logger_master_path;
FILE *mk_logger_master_stdout;
FILE *mk_logger_master_stderr;

pthread_key_t cache_content_length;
pthread_key_t cache_status;
pthread_key_t cache_ip_str;
pthread_key_t cache_iov;

struct log_target
{
    struct mk_event event;

    /* Pipes */
    int is_ok;
    int pipe[2];
    char *file;

    struct mk_vhost *host;
    struct mk_list _head;
};

struct mk_list targets_list;


#endif
