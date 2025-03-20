/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

int cond_numeric_attr_check(struct sampling_condition *sampling_condition, struct ctrace_span *span,
                            int variant_type)
{
    return cond_attr_check(sampling_condition, span, ATTRIBUTE_TYPE_NUMERIC);
}

struct sampling_condition *cond_numeric_attr_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings)
{
    int i;
    struct cfl_variant *var;
    struct cfl_variant *var_value;
    struct attribute_value *str_val;
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

    /* values */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "values");
    if (var) {
        if (var->type != CFL_VARIANT_ARRAY) {
            flb_plg_error(ctx->ins, "values must be an array");
            flb_free(cond);
            return NULL;
        }

        /* iterate values */
        for (i = 0; i < var->data.as_array->entry_count; i++) {
            var_value = var->data.as_array->entries[i];
            if (var_value->type != CFL_VARIANT_STRING) {
                flb_plg_error(ctx->ins, "value must be an string");
                flb_free(cond);
                return NULL;
            }

            str_val = flb_calloc(1, sizeof(struct attribute_value));
            if (!str_val) {
                flb_errno();
                flb_free(cond);
                return NULL;
            }

            str_val->value = cfl_sds_create_len(var_value->data.as_string,
                                                cfl_sds_len(var_value->data.as_string));
            if (!str_val->value) {
                flb_free(str_val);
                flb_free(cond);
                return NULL;
            }

            cfl_list_add(&str_val->_head, &cond->list_values);
        }
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

        cfl_list_del(&str_val->_head);
        flb_free(str_val);
    }

    flb_free(cond);
}
