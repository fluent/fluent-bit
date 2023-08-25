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

#ifndef FLB_PROMETHEUS_EXPORTER_METRICS_H
#define FLB_PROMETHEUS_EXPORTER_METRICS_H

#include <fluent-bit/flb_output_plugin.h>
#include <monkey/mk_lib.h>

#include "prom.h"

/* HTTP response payload received through a Message Queue */
struct prom_metrics_buf {
    int users;
    char *buf_data;
    size_t buf_size;
    struct mk_list _head;
};

int prom_metrics_push_new_metrics(void *data, size_t size);
struct prom_metrics_buf *prom_metrics_get_latest();
void prom_metrics_destroy_metrics();

#endif