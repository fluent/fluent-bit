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

struct sampling_condition *cond_numeric_attr_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings)
{
    struct cfl_variant *var;
    struct cond_attribute *cond;
    struct sampling_condition *sampling_condition;

    cond = flb_calloc(1, sizeof(struct cond_attribute));
    if (!cond) {
        flb_errno();
        return NULL;
    }
    cond->attribute_type = ATTRIBUTE_TYPE_NUMERIC;
    cond->match_type = MATCH_TYPE_STRICT;
    cfl_list_init(&cond->list_values);

    /* key */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "key");
    if (var) {
        if (var->type != CFL_VARIANT_STRING) {
            flb_plg_error(ctx->ins, "key must be a string");
            flb_free(cond);
            return NULL;
        }
        cond->key = cfl_sds_create_len(var->data.as_string,
                                       cfl_sds_len(var->data.as_string));
        if (!cond->key) {
            flb_free(cond);
            return NULL;
        }
    }
    else {
        flb_plg_error(ctx->ins, "missing 'key' in condition");
        flb_free(cond);
        return NULL;
    }

    /* match_type */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "match_type");
    if (var) {
        if (var->type != CFL_VARIANT_STRING) {
            flb_plg_error(ctx->ins, "match_type must be a string");
            flb_free(cond);
            return NULL;
        }

        if (strcasecmp(var->data.as_string, "strict") == 0) {
            cond->match_type = MATCH_TYPE_STRICT;
        }
        else if (strcasecmp(var->data.as_string, "exists") == 0) {
            cond->match_type = MATCH_TYPE_EXISTS;
        }
        else {
            flb_plg_error(ctx->ins, "invalid match_type '%s'", var->data.as_string);
            flb_free(cond);
            return NULL;
        }
    }

    /* min_value */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "min_value");
    if (var) {
        if (var->type != CFL_VARIANT_INT && var->type != CFL_VARIANT_UINT) {
            flb_plg_error(ctx->ins, "min_value must be an integer");
            flb_free(cond);
            return NULL;
        }

        if (var->type == CFL_VARIANT_INT) {
            cond->min_value = var->data.as_int64;
        }
        else {
            cond->min_value = (int64_t) var->data.as_uint64;
        }
    }
    else {
        flb_plg_error(ctx->ins, "missing 'min_value' in condition");
        flb_free(cond);
        return NULL;
    }

    /* max_value */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "max_value");
    if (var) {
        if (var->type != CFL_VARIANT_INT && var->type != CFL_VARIANT_UINT) {
            flb_plg_error(ctx->ins, "max_value must be an integer");
            flb_free(cond);
            return NULL;
        }

        if (var->type == CFL_VARIANT_INT) {
            cond->max_value = var->data.as_int64;
        }
        else {
            cond->max_value = (int64_t) var->data.as_uint64;
        }
    }
    else {
        flb_plg_error(ctx->ins, "missing 'max_value' in condition");
        flb_free(cond);
        return NULL;
    }

    /* check min_value < max_value */
    if (cond->min_value > cond->max_value) {
        flb_plg_error(ctx->ins, "'min_value' must be less than 'max_value'");
        flb_free(cond);
        return NULL;
    }

    sampling_condition = flb_calloc(1, sizeof(struct sampling_condition));
    if (!sampling_condition) {
        flb_errno();
        flb_free(cond);
        return NULL;
    }
    sampling_condition->type = SAMPLING_COND_NUMERIC_ATTRIBUTE;
    sampling_condition->type_context = cond;
    cfl_list_add(&sampling_condition->_head, &sampling_conditions->list);

    return sampling_condition;

}

void cond_numeric_attr_destroy(struct sampling_condition *sampling_condition)
{
    cond_attr_destroy(sampling_condition);
}
