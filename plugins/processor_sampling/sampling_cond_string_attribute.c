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
#include "sampling.h"

enum match_type {
    MATCH_TYPE_STRICT = 0,
    MATCH_TYPE_EXISTS
};

struct string_value {
    cfl_sds_t value;
    struct cfl_list _head;
};

struct cond_string_attribute {
    int match_type;
    cfl_sds_t key;
    struct cfl_list list_values;
};

static int cond_string_attr_check_kvlist(struct cond_string_attribute *ctx,
                                         struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_variant *var;
    struct string_value *str_val;

    /* retrieve the value of the key if found */
    var = cfl_kvlist_fetch_s(kvlist, ctx->key, cfl_sds_len(ctx->key));
    if (!var) {
        return FLB_FALSE;
    }

    /* validate the value type */
    if (var->type != CFL_VARIANT_STRING) {
        return FLB_FALSE;
    }

    /* if the match type is exists, return right away */
    if (ctx->match_type == MATCH_TYPE_EXISTS) {
        return FLB_TRUE;
    }

    /* check if the value matches any of the expected values */
    cfl_list_foreach(head, &ctx->list_values) {
        str_val = cfl_list_entry(head, struct string_value, _head);
        if (cfl_sds_len(var->data.as_string) != cfl_sds_len(str_val->value)) {
            continue;
        }

        if (strncmp(var->data.as_string, str_val->value, cfl_sds_len(var->data.as_string)) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int cond_string_attr_check(struct sampling_condition *sampling_condition, struct ctrace_span *span)
{
    int ret;
    struct cond_string_attribute *ctx = sampling_condition->type_context;

    if (span->scope_span->resource_span->resource->attr->kv) {
        ret = cond_string_attr_check_kvlist(ctx, span->scope_span->resource_span->resource->attr->kv);
        if (ret == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    if (span->attr) {
        ret = cond_string_attr_check_kvlist(ctx, span->attr->kv);
        if (ret == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

struct sampling_condition *cond_string_attr_create(struct sampling *ctx,
                                                   struct sampling_conditions *sampling_conditions,
                                                   struct cfl_variant *settings)
{
    int i;
    struct cfl_variant *var;
    struct cfl_variant *var_key;
    struct cfl_variant *var_value;
    struct string_value *str_val;
    struct cond_string_attribute *cond;
    struct sampling_condition *sampling_condition;

    cond = flb_calloc(1, sizeof(struct cond_string_attribute));
    if (!cond) {
        flb_errno();
        return NULL;
    }
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
        var_key = var;
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

    /* values */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "values");
    if (var) {
        if (var->type != CFL_VARIANT_ARRAY) {
            flb_plg_error(ctx->ins, "values must be an array");
            flb_free(cond);
            return NULL;
        }

        cond->key = cfl_sds_create_len(var_key->data.as_string,
                                       cfl_sds_len(var_key->data.as_string));
        if (!cond->key) {
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

            str_val = flb_calloc(1, sizeof(struct string_value));
            if (!str_val) {
                flb_errno();
                flb_free(cond);
                return NULL;
            }

            str_val->value = cfl_sds_create_len(var_value->data.as_string, cfl_sds_len(var_value->data.as_string));
            if (!str_val->value) {
                flb_free(str_val);
                flb_free(cond);
                return NULL;
            }
            cfl_list_add(&str_val->_head, &cond->list_values);
        }
    }
    else {
        if (cond->match_type != MATCH_TYPE_EXISTS) {
            flb_plg_error(ctx->ins, "missing 'values' in condition");
            flb_free(cond);
            return NULL;
        }
    }

    sampling_condition = flb_calloc(1, sizeof(struct sampling_condition));
    if (!sampling_condition) {
        flb_errno();
        flb_free(cond);
        return NULL;
    }
    sampling_condition->type = SAMPLING_COND_STRING_ATTRIBUTE;
    sampling_condition->type_context = cond;
    cfl_list_add(&sampling_condition->_head, &sampling_conditions->list);

    return sampling_condition;

}

void cond_string_attr_destroy(struct sampling_condition *sampling_condition)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct string_value *str_val;
    struct cond_string_attribute *cond = sampling_condition->type_context;

    cfl_sds_destroy(cond->key);

    cfl_list_foreach_safe(head, tmp, &cond->list_values) {
        str_val = cfl_list_entry(head, struct string_value, _head);
        cfl_sds_destroy(str_val->value);
        cfl_list_del(&str_val->_head);
        flb_free(str_val);
    }

    flb_free(cond);
}
