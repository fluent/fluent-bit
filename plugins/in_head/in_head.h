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
#ifndef FLB_IN_HEAD_H
#define FLB_IN_HEAD_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <msgpack.h>

#define DEFAULT_BUF_SIZE      "256"
#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

struct flb_in_head_config {
    int          coll_fd;
    size_t       buf_size; /* size of buf */
    ssize_t      buf_len;  /* read size */
    char         *buf;     /* read buf */
    flb_sds_t    key;
    int          key_len;

    flb_sds_t    filepath; /* to read */

    int          add_path; /* add path mode */
    size_t       path_len;

    int          lines; /* line num to read */
    int          split_line;

    int          interval_sec;
    int          interval_nsec;

    struct flb_log_event_encoder log_encoder;

    struct flb_input_instance *ins;
};

extern struct flb_input_plugin in_head_plugin;

#endif /* FLB_IN_HEAD_H */
