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

#ifndef FLB_OUT_GELF_H
#define FLB_OUT_GELF_H

#define FLB_GELF_UDP 0
#define FLB_GELF_TCP 1
#define FLB_GELF_TLS 2

#include <fluent-bit/flb_output_plugin.h>

struct flb_out_gelf_config {

    struct flb_gelf_fields fields;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;
    flb_sockfd_t fd;

    int pckt_size;
    char *pckt_buf;
    int compress;
    unsigned int seed;
    flb_sds_t tag_key;

    int mode;

    struct flb_output_instance *ins;
};

#endif
