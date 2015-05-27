/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_IN_KMSG
#define FLB_IN_KMSG

#include <stdint.h>

#define FLB_KMSG_DEV  "/dev/kmsg"

/* Alert levels, taken from util-linux sources */
#define FLB_LOG_EMERG      0
#define FLB_LOG_ALERT      1
#define FLB_LOG_CRIT       2
#define FLB_LOG_ERR        3
#define FLB_LOG_WARNING    4
#define FLB_LOG_NOTICE     5
#define FLB_LOG_INFO       6
#define FLB_LOG_DEBUG      7

#define FLB_LOG_PRIMASK    0x07
#define FLB_LOG_PRI(p)     ((p) & FLB_LOG_PRIMASK)

#define KMSG_BUFFER_SIZE   256
#define KMSG_USEC_PER_SEC  1000000

struct flb_in_kmsg_config {
    int fd;                    /* descriptor -> FLB_KMSG_DEV */
    struct timeval boot_time;  /* System boot time           */

    /* Tag: used to extend original tag */
    int  tag_len;              /* The real string length     */
    char tag[32];              /* Custom Tag for this input  */

    /* Line processing */
    int buffer_id;

    /* MessagePack buffers */
    msgpack_packer  mp_pck;
    msgpack_sbuffer mp_sbuf;
};

int in_kmsg_start();

extern struct flb_input_plugin in_kmsg_plugin;

#endif
