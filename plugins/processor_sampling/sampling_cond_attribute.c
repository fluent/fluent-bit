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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_regex.h>

#include "sampling.h"
#include "sampling_cond_attribute.h"

static int cond_attr_check_kvlist(struct cond_attribute *ctx, struct cfl_kvlist *kvlist, int attribute_type)
{
    struct cfl_list *head;
    struct cfl_variant *var;
    struct attribute_value *str_val;

    /* retrieve the value of the key if found */
    var = cfl_kvlist_fetch_s(kvlist, ctx->key, cfl_sds_len(ctx->key));
    if (!var) {
        return FLB_FALSE;
    }

    /* validate the value type */
    if (attribute_type == ATTRIBUTE_TYPE_STRING) {
        if (var->type != CFL_VARIANT_STRING) {
            return FLB_FALSE;
        }
    }
    else if (attribute_type == ATTRIBUTE_TYPE_NUMERIC) {
        if (var->type != CFL_VARIANT_INT && var->type != CFL_VARIANT_DOUBLE && var->type != CFL_VARIANT_UINT) {
            return FLB_FALSE;
        }
    }
    else if (attribute_type == ATTRIBUTE_TYPE_BOOLEAN) {
        if (var->type != CFL_VARIANT_BOOL) {
            return FLB_FALSE;
        }
    }

    /* if the match type is exists, return right away */
    if (ctx->match_type == MATCH_TYPE_EXISTS) {
        return FLB_TRUE;
    }

    /* numeric_attribute */
    if (attribute_type == ATTRIBUTE_TYPE_NUMERIC) {
        if (var->type == CFL_VARIANT_INT) {
            if (var->data.as_int64 >= ctx->min_value && var->data.as_int64 <= ctx->max_value) {
                return FLB_TRUE;
            }
        }
        else if (var->type == CFL_VARIANT_UINT) {
            if (var->data.as_uint64 >= ctx->min_value && var->data.as_uint64 <= ctx->max_value) {
                return FLB_TRUE;
            }
        }
        else if (var->type == CFL_VARIANT_DOUBLE) {
            if (var->data.as_double >= ctx->min_value && var->data.as_double <= ctx->max_value) {
                return FLB_TRUE;
            }
        }

        return FLB_FALSE;
    }

    /* boolean_attribute */
    if (attribute_type == ATTRIBUTE_TYPE_BOOLEAN) {
        if (var->data.as_bool == ctx->boolean_value) {
            return FLB_TRUE;
        }

        return FLB_FALSE;
    }

    /* string_attribute: check if the value matches any of the expected values */
    cfl_list_foreach(head, &ctx->list_values) {
        str_val = cfl_list_entry(head, struct attribute_value, _head);
        if (ctx->match_type == MATCH_TYPE_STRICT) {
            if (attribute_type == ATTRIBUTE_TYPE_STRING) {
                if (cfl_sds_len(var->data.as_string) != cfl_sds_len(str_val->value)) {
                    continue;
                }

                if (strncmp(var->data.as_string, str_val->value, cfl_sds_len(var->data.as_string)) == 0) {
                    return FLB_TRUE;
                }
            }
        }
        else if (ctx->match_type == MATCH_TYPE_REGEX && attribute_type == CFL_VARIANT_STRING) {
            if (flb_regex_match(str_val->regex_value,
                                (unsigned char *) var->data.as_string,
                                cfl_sds_len(var->data.as_string))) {

                                    return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

int cond_attr_check(struct sampling_condition *sampling_condition, struct ctrace_span *span,
                    int attribute_type)
{
    int ret;
    struct cond_attribute *ctx = sampling_condition->type_context;

    if (span->scope_span->resource_span->resource->attr->kv) {
        ret = cond_attr_check_kvlist(ctx,
                                     span->scope_span->resource_span->resource->attr->kv,
                                     attribute_type);
        if (ret == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    if (span->attr) {
        ret = cond_attr_check_kvlist(ctx, span->attr->kv, attribute_type);
        if (ret == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

void cond_attr_destroy(struct sampling_condition *sampling_condition)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct attribute_value *str_val;
    struct cond_attribute *cond = sampling_condition->type_context;

    cfl_sds_destroy(cond->key);

    cfl_list_foreach_safe(head, tmp, &cond->list_values) {
        str_val = cfl_list_entry(head, struct attribute_value, _head);

        if (str_val->value) {
            cfl_sds_destroy(str_val->value);
        }

        if (str_val->regex_value) {
            flb_regex_destroy(str_val->regex_value);
        }

        cfl_list_del(&str_val->_head);
        flb_free(str_val);
    }

    flb_free(cond);
}
