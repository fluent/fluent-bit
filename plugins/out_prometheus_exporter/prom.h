/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#define PROM_BUFFER_MAX_SIZE    "4M"
#define PROM_BUFFER_CHUNK_SIZE  "512K"

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_hash_table.h>

#include <monkey/monkey.h>
#include <monkey/mk_lib.h>

/* Plugin context */
struct prom_exporter {
    /* hash table for metrics reported */
    struct flb_hash_table *ht_metrics;

    /* add timestamp to every metric */
    int add_timestamp;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /* internal labels ready to append */
    struct mk_list kv_labels;

    /* Buffer chunk size */
    size_t buffer_chunk_size;
    size_t buffer_max_size;

    /* Downstream connection management */
    struct flb_downstream *downstream;
    struct mk_event *request_event;
    struct mk_list connections;
    mk_ctx_t *mk_ctx;

    /* instance context */
    struct flb_output_instance *ins;
};

#endif
