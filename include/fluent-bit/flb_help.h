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

#ifndef FLB_HELP_H
#define FLB_HELP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_custom.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>

/* JSON Helper version: current '1' */
#define FLB_HELP_SCHEMA_VERSION "1"

enum help_plugin_type {
    FLB_HELP_PLUGIN_CUSTOM = 0,
    FLB_HELP_PLUGIN_INPUT,
    FLB_HELP_PLUGIN_PROCESSOR,
    FLB_HELP_PLUGIN_FILTER,
    FLB_HELP_PLUGIN_OUTPUT,
};

int flb_help_custom(struct flb_custom_instance *ins, void **out_buf, size_t *out_size);
int flb_help_input(struct flb_input_instance *ins, void **out_buf, size_t *out_size);
int flb_help_processor(struct flb_processor_instance *ins, void **out_buf, size_t *out_size);
int flb_help_filter(struct flb_filter_instance *ins, void **out_buf, size_t *out_size);
int flb_help_output(struct flb_output_instance *ins, void **out_buf, size_t *out_size);

flb_sds_t flb_help_build_json_schema(struct flb_config *config);

#endif
