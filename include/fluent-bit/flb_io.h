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

#ifndef FLB_IO_H
#define FLB_IO_H

#include <fluent-bit/flb_config.h>

struct flb_io_upstream {
    struct mk_event event;
    struct mk_event_loop *evl;

    int fd;
    int flags;
    int tcp_port;
    char *tcp_host;
};

struct flb_io_upstream *flb_io_upstream_new(struct flb_config *config,
                                            char *host, int port, int flags);
int flb_io_write(struct flb_output_plugin *out, void *data,
                 size_t len, size_t *out_len);
int flb_io_connect(struct flb_io_upstream *u);

#endif
