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

#ifndef FLB_CONFIG_H
#define FLB_CONFIG_H

#include <mk_config/mk_list.h>

#define FLB_CONFIG_DEFAULT_TAG  "fluent_bit"

/* Main struct to hold the configuration of the runtime service */
struct flb_config {
    char *tag;          /* Message Tag, used by Fluentd   */

    /* Collectors */
    struct mk_list collectors;

    /* Inputs */
    struct mk_list inputs;

    /* Output */
    int  out_protocol;  /* Output protocol                */
    char *out_address;  /* Original Output address (full) */
    char *out_host;     /* Output host if any             */
    char *out_port;     /* Output TCP port                */
};

#endif
