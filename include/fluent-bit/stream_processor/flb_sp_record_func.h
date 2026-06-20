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

#ifndef FLB_SP_RECORD_FUNC_H
#define FLB_SP_RECORD_FUNC_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

#define RECORD_FUNCTIONS_SIZE 3

typedef struct flb_exp_val *(*record_function_typ) (const char *, int,
                                                    struct flb_time *,
                                                    struct flb_exp_val *);

struct flb_exp_val *cb_contains(const char *tag, int tag_len,
                                struct flb_time *tms,
                                struct flb_exp_val *param)
{
    struct flb_exp_val *result;

    if (param == NULL) {
        return NULL;
    }

    result = flb_calloc(1, sizeof(struct flb_exp_val));
    if (!result) {
       flb_errno();
       return NULL;
    }

    result->type = FLB_EXP_BOOL;
    result->val.boolean = true;

    return result;
}

/* Return the record timestamp */
struct flb_exp_val *cb_time(const char *tag, int tag_len,
                            struct flb_time *tms,
                            struct flb_exp_val *param)
{
    struct flb_exp_val *result;
    (void) param;

    result = flb_calloc(1, sizeof(struct flb_exp_val));
    if (!result) {
        flb_errno();
        return NULL;
    }

    result->type = FLB_EXP_FLOAT;
    result->val.f64 = flb_time_to_double(tms);

    return result;
}

char *record_functions[RECORD_FUNCTIONS_SIZE] = {
                                                 "contains",
                                                 "time"
};

record_function_typ record_functions_ptr[RECORD_FUNCTIONS_SIZE] = {
     cb_contains,
     cb_time
};

#endif
