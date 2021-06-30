/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#ifndef FLB_IN_GELF_H
#define FLB_IN_GELF_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_sds.h>
#include <msgpack.h>

/* GELF modes */
#define FLB_GELF_TCP 1
#define FLB_GELF_UDP 2

struct flb_in_gelf_config {

    int server_fd;                  /* UDP/TCP server file descriptor */
    size_t buffer_size;             /* Buffer size for each reader */
    size_t chunk_size;              /* Chunk allocation size       */
    int mode;                       /* Listening mode: tcp or udp  */
    char *listen;                   /* Listen interface            */
    char *port;                     /* Port                        */
    struct mk_list connections;     /* List of active connections  */
    struct mk_event_loop *evl;      /* Event loop file descriptor  */
    struct flb_input_instance *ins; /* Input plugin instace        */
};

#endif
