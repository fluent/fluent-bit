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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_cpu.h"
#include "we_util.h"
#include "we_perflib.h"

static int we_expand_perflib_label_set(char     *input_raw_label_set,
                                       char   ***output_label_set,
                                       size_t   *output_label_set_size)
{
    flb_sds_t raw_label_set;
    size_t    label_index;
    size_t    label_count;
    char     *label_name;
    char    **label_set;
    int       result;

    raw_label_set = flb_sds_create(input_raw_label_set);

    if (raw_label_set == NULL) {
        return -1;
    }

    label_count = 0;
    label_name  = (char *) raw_label_set;

    while (label_name != NULL) {
        result = mk_string_char_search(label_name, ',', -1);

        if (result != -1) {
            label_name[result] = '\0';
            label_name = &label_name[result + 1];
        }
        else {
            label_name = NULL;
        }

        label_count++;
    }

    label_set = (char **) flb_calloc(label_count, sizeof(char *));

    if (label_set == NULL) {
        flb_sds_destroy(raw_label_set);

        return -2;
    }

    label_name  = (char *) raw_label_set;

    for (label_index = 0 ; label_index < label_count ; label_index++) {
        label_set[label_index] = label_name;
        label_name = &label_name[strlen(label_name) + 1];
    }

    *output_label_set = label_set;
    *output_label_set_size = label_count;

    return 0;
}

static int we_expand_perflib_metric_source_labels(
    struct we_perflib_metric_source *source)
{
    source->label_set_size = 0;
    source->label_set = NULL;

    if (source->raw_label_set == NULL) {
        return 0;
    }

    return we_expand_perflib_label_set(source->raw_label_set,
                                       &source->label_set,
                                       &source->label_set_size);
}

static int we_expand_perflib_metric_spec_labels(
    struct we_perflib_metric_spec *spec)
{
    spec->label_set_size = 0;
    spec->label_set = NULL;

    if (spec->raw_label_set == NULL) {
        return 0;
    }

    return we_expand_perflib_label_set(spec->raw_label_set,
                                       &spec->label_set,
                                       &spec->label_set_size);
}

static int we_match_perflib_metric_source_to_parent(
    struct flb_hash_table           *lookup_table,
    struct we_perflib_metric_source *source)
{
    struct we_perflib_metric_spec *spec;

    spec = flb_hash_table_get_ptr(lookup_table,
                                  source->parent_name,
                                  strlen(source->parent_name));

    if (spec == NULL) {
        return -1;
    }

    source->parent = spec;

    return 0;
}

static int we_create_perflib_metric_instance(
    struct cmt                    *context,
    struct flb_hash_table         *lookup_table,
    char                          *namespace,
    char                          *subsystem,
    struct we_perflib_metric_spec *spec)
{
    void *metric_instance;
    int   result;

    if (spec->type == CMT_COUNTER) {
        metric_instance = (void *) cmt_counter_create(context,
                                                      namespace,
                                                      subsystem,
                                                      spec->name,
                                                      spec->description,
                                                      spec->label_set_size,
                                                      spec->label_set);
        if (metric_instance == NULL) {
            return -1;
        }
    }
    else if (spec->type == CMT_GAUGE) {
        metric_instance = (void *) cmt_gauge_create(context,
                                                    namespace,
                                                    subsystem,
                                                    spec->name,
                                                    spec->description,
                                                    spec->label_set_size,
                                                    spec->label_set);

        if (metric_instance == NULL) {
            return -2;
        }
    }
    else {
        return -3;
    }

    result = flb_hash_table_add(lookup_table,
                                spec->name,
                                strlen(spec->name),
                                spec,
                                0);

    if (result < 0) {
        if (spec->type == CMT_COUNTER) {
            cmt_counter_destroy(metric_instance);
        }
        else {
            cmt_gauge_destroy(metric_instance);
        }

        return -4;
    }

    spec->metric_instance = metric_instance;

    return 0;
}

void we_deinitialize_perflib_metric_sources(struct we_perflib_metric_source *sources)
{
    size_t source_index;

    for (source_index = 0 ;
         sources[source_index].name != NULL;
         source_index++) {
        if (sources[source_index].name != NULL) {
            flb_free(sources[source_index].name);
        }

        if (sources[source_index].label_set_size) {
            flb_sds_destroy(sources[source_index].label_set[0]);
            flb_free(sources[source_index].label_set);
        }
    }
}

int we_initialize_perflib_metric_sources(
    struct flb_hash_table            *lookup_table,
    struct we_perflib_metric_source **out_sources,
    struct we_perflib_metric_source  *in_sources)
{
    size_t                           source_array_size;
    struct we_perflib_metric_source *source_array_copy;
    struct we_perflib_metric_source *source_entry;
    size_t                           source_index;
    size_t                           source_count;
    int                              result;
    char                            *flag_ptr;

    if (out_sources == NULL) {
        return -1;
    }

    if (in_sources == NULL) {
        return -2;
    }

    source_count = 0;

    while (in_sources[source_count].name != NULL) {
        source_count++;
    }

    if (source_count == 0) {
        return -3;
    }

    source_array_size  = sizeof(struct we_perflib_metric_source);
    source_array_size *= (source_count + 1);

    source_array_copy = (struct we_perflib_metric_source *) flb_calloc(1, source_array_size);

    if (source_array_copy == NULL) {
        return -4;
    }

    memcpy(source_array_copy, in_sources, source_array_size);

    for (source_index = 0 ; source_index < source_count; source_index++) {
        source_entry = &source_array_copy[source_index];

        source_entry->name = flb_strdup(source_entry->name);
        if (source_entry->name == NULL) {
            /* Handle memory allocation failure */
            we_deinitialize_perflib_metric_sources(source_array_copy);
            flb_free(source_array_copy);
            return -1; /* Or appropriate error code */
        }

        /* Now it is safe to search and modify the writable copy */
        source_entry->use_secondary_value = FLB_FALSE;
        flag_ptr = strstr(source_entry->name, ",secondvalue");

        if (flag_ptr != NULL) {
            source_entry->use_secondary_value = FLB_TRUE;
            *flag_ptr = '\0'; /* This now modifies the heap copy, not read-only memory */
        }

        result = we_expand_perflib_metric_source_labels(source_entry);

        if (result != 0) {
            we_deinitialize_perflib_metric_sources(source_array_copy);
            flb_free(source_array_copy);

            return -5;
        }

        result = we_match_perflib_metric_source_to_parent(lookup_table,
                                                          source_entry);

        if (result != 0) {
            we_deinitialize_perflib_metric_sources(source_array_copy);
            flb_free(source_array_copy);

            return -6;
        }
    }

    *out_sources = source_array_copy;

    return 0;
}

void we_deinitialize_perflib_metric_specs(struct we_perflib_metric_spec *specs)
{
    size_t spec_index;

    for (spec_index = 0 ;
         specs[spec_index].name != NULL;
         spec_index++) {
        if (specs[spec_index].label_set_size) {
            flb_sds_destroy(specs[spec_index].label_set[0]);
            flb_free(specs[spec_index].label_set);
        }
    }
}

int we_initialize_perflib_metric_specs(
    struct cmt                     *context,
    struct flb_hash_table          *lookup_table,
    char                           *namespace,
    char                           *subsystem,
    struct we_perflib_metric_spec **out_specs,
    struct we_perflib_metric_spec  *in_specs)
{
    size_t                         spec_array_size;
    struct we_perflib_metric_spec *spec_array_copy;
    struct we_perflib_metric_spec *spec_entry;
    size_t                         spec_index;
    size_t                         spec_count;
    int                            result;

    if (out_specs == NULL) {
        return -1;
    }

    if (in_specs == NULL) {
        return -2;
    }

    spec_count = 0;

    while (in_specs[spec_count].name != NULL) {
        spec_count++;
    }

    if (spec_count == 0) {
        return -3;
    }

    spec_array_size  = sizeof(struct we_perflib_metric_spec);
    spec_array_size *= spec_count + 1;

    spec_array_copy = (struct we_perflib_metric_spec *) flb_calloc(1, spec_array_size);

    if (spec_array_copy == NULL) {
        return -4;
    }

    memcpy(spec_array_copy, in_specs, spec_array_size);

    for (spec_index = 0 ; spec_index < spec_count; spec_index++) {
        spec_entry = &spec_array_copy[spec_index];

        result = we_expand_perflib_metric_spec_labels(spec_entry);

        if (result) {
            we_deinitialize_perflib_metric_specs(spec_array_copy);
            flb_free(spec_array_copy);

            return -5;
        }

        result = we_create_perflib_metric_instance(context,
                                                   lookup_table,
                                                   namespace,
                                                   subsystem,
                                                   spec_entry);

        if (result) {
            we_deinitialize_perflib_metric_specs(spec_array_copy);
            flb_free(spec_array_copy);

            return -6;
        }
    }

    *out_specs = spec_array_copy;

    return 0;
}

