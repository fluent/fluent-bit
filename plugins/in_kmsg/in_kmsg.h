/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <stdint.h>

#define FLB_KMSG_DEV        "/dev/kmsg"
#define FLB_KMSG_BUF_SIZE   4096

/* Alert levels, taken from util-linux sources */
#define FLB_KLOG_EMERG      0
#define FLB_KLOG_ALERT      1
#define FLB_KLOG_CRIT       2
#define FLB_KLOG_ERR        3
#define FLB_KLOG_WARNING    4
#define FLB_KLOG_NOTICE     5
#define FLB_KLOG_INFO       6
#define FLB_KLOG_DEBUG      7

#define FLB_KLOG_PRIMASK    0x07
#define FLB_KLOG_PRI(p)     ((p) & FLB_KLOG_PRIMASK)

#define KMSG_BUFFER_SIZE   256
#define KMSG_USEC_PER_SEC  1000000

struct flb_in_kmsg_config {
    int fd;                    /* descriptor -> FLB_KMSG_DEV */
    struct timeval boot_time;  /* System boot time           */

    int prio_level;

    /* Line processing */
    int buffer_id;

    /* Buffer */
    char *buf_data;
    size_t buf_len;
    size_t buf_size;
    struct flb_log_event_encoder log_encoder;
    struct flb_input_instance *ins;
};


extern struct flb_input_plugin in_kmsg_plugin;

#endif
