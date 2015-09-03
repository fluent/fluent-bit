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

#ifndef FLB_IN_STDIN_H
#define FLB_IN_STDIN_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

/* STDIN Input configuration & context */
struct flb_in_stdin_config {
    int fd;                           /* stdin file descriptor */
    int buf_len;                      /* read buffer length    */
    char buf[8192 * 2];               /* read buffer: 16Kb max */

    int buffer_id;
    struct msgpack_sbuffer mp_sbuf;  /* msgpack sbuffer        */
    struct msgpack_packer mp_pck;    /* msgpack packer         */
};

int in_stdin_init(struct flb_config *config);
int in_stdin_collect(struct flb_config *config, void *in_context);
void *in_stdin_flush(void *in_context, int *size);

extern struct flb_input_plugin in_stdin_plugin;

#endif
