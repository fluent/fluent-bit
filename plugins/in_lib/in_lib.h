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

#ifndef FLB_IN_LIB_H
#define FLB_IN_LIB_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_pthread.h>

#define LIB_BUF_CHUNK   65536

pthread_key_t flb_active_lib_context;

/* Library input configuration & context */
struct flb_in_lib_config {
    int fd;                     /* instance input channel  */
    int buf_size;               /* buffer size / capacity  */
    int buf_len;                /* read buffer length      */
    char *buf_data;             /* the real buffer         */

    struct flb_log_event_encoder log_encoder;
    struct flb_pack_state state;
    struct flb_input_instance *ins;
};

#endif
