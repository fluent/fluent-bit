/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct flb_in_fw_config {
    size_t buffer_max_size;         /* Max Buffer size             */
    size_t buffer_chunk_size;       /* Chunk allocation size       */

    /* Network */
    char *listen;                   /* Listen interface            */
    char *tcp_port;                 /* TCP Port                    */

    flb_sds_t tag_prefix;           /* tag prefix                  */

    /* Unix Socket */
    char *unix_path;                /* Unix path for socket        */
    unsigned int unix_perm;         /* Permission for socket       */
    flb_sds_t unix_perm_str;        /* Permission (config map)     */

    int coll_fd;
    struct flb_downstream *downstream; /* Client manager          */
    struct mk_list connections;     /* List of active connections */
    struct flb_input_instance *ins; /* Input plugin instace       */

    struct flb_log_event_decoder *log_decoder;
    struct flb_log_event_encoder *log_encoder;
};

#endif
