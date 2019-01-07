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

#ifndef FLB_IO_TLS_RW_H
#define FLB_IO_TLS_RW_H

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_TLS

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_upstream.h>

int flb_io_tls_net_read(struct flb_thread *th, struct flb_upstream_conn *u_conn,
                        void *buf, size_t len);
int flb_io_tls_net_write(struct flb_thread *th, struct flb_upstream_conn *u_conn,
                         void *data, size_t len, size_t *out_len);

#endif

#endif
