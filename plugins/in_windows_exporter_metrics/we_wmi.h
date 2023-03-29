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

#ifndef FLB_WE_WMI_H
#define FLB_WE_WMI_H

#include "we.h"

#define WE_WMI_METRIC_LABEL_LIST_SIZE        64

typedef double (*we_wmi_value_adjuster) (double);
struct wmi_query_spec {
    void *metric_instance;
    int type;
    we_wmi_value_adjuster value_adjuster;
    char *wmi_counter;
    char *wmi_property;
    int label_property_count;
    char **label_property_keys;
};

int we_wmi_init(struct flb_we *ctx);
int we_wmi_cleanup(struct flb_we *ctx);
int we_wmi_exit(struct flb_we *ctx);

/* Abstract APIs */
int we_wmi_query(struct flb_we *ctx, struct wmi_query_specs *spec);
int we_wmi_query_fixed_val(struct flb_we *ctx, struct wmi_query_specs *spec);
int we_wmi_query_namespace(struct flb_we *ctx, struct wmi_query_specs *spec, char *namepsace);

/* Concrete APIs */
int we_wmi_coinitialize(struct flb_we *ctx);
int we_wmi_execute_query(struct flb_we *ctx, struct wmi_query_spec *spec, IEnumWbemClassObject **out_enumerator);
double we_wmi_get_value(struct flb_we *ctx, struct wmi_query_spec *spec, IWbemClassObject *class_obj);
double we_wmi_get_property_value(struct flb_we *ctx, char *raw_property_key, IWbemClassObject *class_obj);
int we_wmi_update_counters(struct flb_we *ctx, struct wmi_query_spec *spec,
                           uint64_t timestamp, double val, int metric_label_count, char **metric_label_set);

#endif
