/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_IN_FW_H
#define FLB_IN_FW_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>

#ifdef FLB_HAVE_TLS
#include <fluent-bit/ssl/flb_ssl.h>
#endif

struct flb_in_fw_config {
    int server_fd;               /* TCP server file descriptor  */
    size_t buffer_max_size;      /* Max Buffer size             */
    size_t buffer_chunk_size;    /* Chunk allocation size       */

    /* Network */
    char *listen;                /* Listen interface            */
    char *tcp_port;              /* TCP Port                    */

    /* Unix Socket (TCP only) */
    char *unix_path;             /* Unix path for socket        */

    struct mk_list connections;    /* List of active connections */
    struct mk_event_loop *evl;     /* Event loop file descriptor */
    struct flb_input_instance *in; /* Input plugin instace       */

#ifdef FLB_HAVE_TLS
    const char *tls_crt_file;
    const char *tls_key_file;
    const char *tls_key_passwd;

    struct flb_ssl *ssl;
    struct flb_ssl_config *ssl_config;
#endif
};

#endif
