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

#ifndef FLB_API_H
#define FLB_API_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_custom.h>

struct flb_api {
    const char *(*output_get_property) (const char *, struct flb_output_instance *);
    const char *(*input_get_property) (const char *, struct flb_input_instance *);

    void *(*output_get_cmt_instance) (struct flb_output_instance *);
    void *(*input_get_cmt_instance) (struct flb_input_instance *);

    void (*log_print) (int, const char*, int, const char*, ...);
    int (*input_log_check) (struct flb_input_instance *, int);
    int (*output_log_check) (struct flb_output_instance *, int);

    /* To preserve ABI, we need to add these APIs after the
     * input/output definitions. */
    const char *(*custom_get_property) (const char *, struct flb_custom_instance *);
    int (*custom_log_check) (struct flb_custom_instance *, int);
};

#ifdef FLB_CORE
struct flb_api *flb_api_create();
void flb_api_destroy(struct flb_api *api);
#endif

#endif
