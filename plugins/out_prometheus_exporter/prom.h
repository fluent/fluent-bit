/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_PROMETHEUS_EXPORTER_H
#define FLB_PROMETHEUS_EXPORTER_H

#include <fluent-bit/flb_output_plugin.h>

/* Plugin context */
struct prom_exporter {
    void *http;

    /* networking */
    flb_sds_t listen;
    flb_sds_t tcp_port;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /* internal labels ready to append */
    struct mk_list kv_labels;

    /* instance context */
    struct flb_output_instance *ins;
};

#endif
