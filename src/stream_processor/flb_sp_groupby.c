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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/stream_processor/flb_sp.h>

int flb_sp_groupby_compare(const void *lhs, const void *rhs)
{
    int i;
    int strcmp_result;
    struct aggregate_node *left = (struct aggregate_node *) lhs;
    struct aggregate_node *right = (struct aggregate_node *) rhs;
    struct aggregate_num *lval;
    struct aggregate_num *rval;

    for (i = 0; i < left->groupby_keys; i++) {
        lval = &left->groupby_nums[i];
        rval = &right->groupby_nums[i];

        /* Convert integer to double if a float value appears on one side */
        if (lval->type == FLB_SP_NUM_I64 && rval->type == FLB_SP_NUM_F64) {
            lval->type = FLB_SP_NUM_F64;
            lval->f64 = (double) lval->i64;
        }
        else if (lval->type == FLB_SP_NUM_F64 && rval->type == FLB_SP_NUM_I64) {
            rval->type = FLB_SP_NUM_F64;
            rval->f64 = (double) rval->i64;
        }

        /* Comparison */
        if (lval->type == FLB_SP_BOOLEAN && rval->type == FLB_SP_BOOLEAN) {
            if (lval->boolean != rval->boolean) {
                return 1;
            }
        }
        else if (lval->type == FLB_SP_NUM_I64 && rval->type == FLB_SP_NUM_I64) {
            if (lval->i64 > rval->i64) {
                return 1;
            }

            if (lval->i64 < rval->i64) {
                return -1;
            }
        }
        else if (lval->type == FLB_SP_NUM_F64 &&  rval->type == FLB_SP_NUM_F64) {
            if (lval->f64 > rval->f64) {
                return 1;
            }

            if (lval->f64 < rval->f64) {
                return -1;
            }
        }
        else if (lval->type == FLB_SP_STRING && rval->type == FLB_SP_STRING) {
            strcmp_result = strcmp((const char *) lval->string, (const char *) rval->string);
            if (strcmp_result != 0) {
              return strcmp_result;
            }
        }
        else { /* Sides have different types */
            return -1;
        }
    }

    return 0;
}
