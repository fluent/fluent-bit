/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_api.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_custom.h>

struct flb_api *flb_api_create()
{
    struct flb_api *api;

    api = flb_malloc(sizeof(struct flb_api));
    if (!api) {
        flb_errno();
        return NULL;
    }

    api->output_get_property = flb_output_get_property;
    api->input_get_property = flb_input_get_property;
    api->custom_get_property = flb_custom_get_property;

#ifdef FLB_HAVE_METRICS
    api->output_get_cmt_instance = flb_output_get_cmt_instance;
    api->input_get_cmt_instance = flb_input_get_cmt_instance;
#endif

    api->log_print = flb_log_print;
    api->input_log_check = flb_input_log_check;
    api->output_log_check = flb_output_log_check;
    api->custom_log_check = flb_custom_log_check;

    return api;
}

void flb_api_destroy(struct flb_api *api)
{
    flb_free(api);
}
