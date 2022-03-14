/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_FILTER_NIGHTFALL_H
#define FLB_FILTER_NIGHTFALL_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

struct nested_obj {
    msgpack_object *obj;
    int cur_index;
    char start_at_val;

    struct mk_list _head;
};

struct payload {
    msgpack_object *obj;
    msgpack_object *key_to_scan_with;

    struct mk_list _head;
};

struct flb_filter_nightfall {
    /* Config values */
    flb_sds_t nightfall_api_key;
    flb_sds_t policy_id;
    double sampling_rate;
    int tls_debug;
    int tls_verify;
    char *tls_ca_path;
    flb_sds_t tls_vhost;

    struct flb_tls *tls;
    struct flb_upstream *upstream;
    struct flb_filter_instance *ins;
    flb_sds_t auth_header;
};

#endif
