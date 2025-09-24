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
#include "sampling_cond_attribute.h"

struct sampling_condition *cond_status_codes_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings);

static int condition_type_str_to_int(char *type_str)
{
    if (strcasecmp(type_str, "status_code") == 0) {
        return SAMPLING_COND_STATUS_CODE;
    }
    else if (strcasecmp(type_str, "latency") == 0) {
        return SAMPLING_COND_LATENCY;
    }
    else if (strcasecmp(type_str, "string_attribute") == 0) {
        return SAMPLING_COND_STRING_ATTRIBUTE;
    }
    else if (strcasecmp(type_str, "numeric_attribute") == 0) {
        return SAMPLING_COND_NUMERIC_ATTRIBUTE;
    }
    else if (strcasecmp(type_str, "boolean_attribute") == 0) {
        return SAMPLING_COND_BOOLEAN_ATTRIBUTE;
    }
    else if (strcasecmp(type_str, "span_count") == 0) {
        return SAMPLING_COND_SPAN_COUNT;
    }
    else if (strcasecmp(type_str, "trace_state") == 0) {
        return SAMPLING_COND_TRACE_STATE;
    }

    return -1;
}

void sampling_conditions_destroy(struct sampling_conditions *sampling_conditions)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct sampling_condition *sampling_condition;

    if (!sampling_conditions) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, &sampling_conditions->list) {
        sampling_condition = cfl_list_entry(head, struct sampling_condition, _head);
        if (sampling_condition->type == SAMPLING_COND_STATUS_CODE) {
            cond_status_codes_destroy(sampling_condition);
        }
        else if (sampling_condition->type == SAMPLING_COND_LATENCY) {
            cond_latency_destroy(sampling_condition);
        }
        else if (sampling_condition->type == SAMPLING_COND_STRING_ATTRIBUTE) {
            cond_string_attr_destroy(sampling_condition);
        }
        else if (sampling_condition->type == SAMPLING_COND_NUMERIC_ATTRIBUTE) {
            cond_numeric_attr_destroy(sampling_condition);
        }
        else if (sampling_condition->type == SAMPLING_COND_BOOLEAN_ATTRIBUTE) {
            cond_boolean_attr_destroy(sampling_condition);
        }
        else if (sampling_condition->type == SAMPLING_COND_SPAN_COUNT) {
            cond_span_count_destroy(sampling_condition);
        }
        else if (sampling_condition->type == SAMPLING_COND_TRACE_STATE) {
            cond_trace_state_destroy(sampling_condition);
        }

        cfl_list_del(&sampling_condition->_head);
        flb_free(sampling_condition);
    }

    flb_free(sampling_conditions);
}

int sampling_conditions_check(struct sampling *ctx, struct sampling_conditions *sampling_conditions,
                              struct trace_entry *trace_entry, struct ctrace_span *span)
{
    int ret;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct sampling_condition *sampling_condition;

    if (!sampling_conditions) {
        return FLB_TRUE;
    }

    cfl_list_foreach_safe(head, tmp, &sampling_conditions->list) {
        sampling_condition = cfl_list_entry(head, struct sampling_condition, _head);

        ret = FLB_FALSE;

        if (sampling_condition->type == SAMPLING_COND_STATUS_CODE) {
            ret = cond_status_codes_check(sampling_condition, span);
        }
        else if (sampling_condition->type == SAMPLING_COND_LATENCY) {
            ret = cond_latency_check(sampling_condition, span);
        }
        else if (sampling_condition->type == SAMPLING_COND_STRING_ATTRIBUTE) {
            ret = cond_attr_check(sampling_condition, span, ATTRIBUTE_TYPE_STRING);
        }
        else if (sampling_condition->type == SAMPLING_COND_NUMERIC_ATTRIBUTE) {
            ret = cond_attr_check(sampling_condition, span, ATTRIBUTE_TYPE_NUMERIC);
        }
        else if (sampling_condition->type == SAMPLING_COND_BOOLEAN_ATTRIBUTE) {
            ret = cond_attr_check(sampling_condition, span, ATTRIBUTE_TYPE_BOOLEAN);
        }
        else if (sampling_condition->type == SAMPLING_COND_SPAN_COUNT) {
            ret = cond_span_count_check(sampling_condition, trace_entry, span);
        }
        else if (sampling_condition->type == SAMPLING_COND_TRACE_STATE) {
            ret = cond_trace_state_check(sampling_condition, span);
        }

        if (ret == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    /* no matches, trace will be dropped */
    return FLB_FALSE;
}

struct sampling_conditions *sampling_conditions_create(struct sampling *ctx, struct cfl_variant *conditions)
{
    int i;
    int type;
    char *type_str;
    void *cond_ptr = NULL;
    struct sampling_conditions *sampling_cond;
    struct cfl_variant *type_settings;
    struct cfl_variant *condition_settings;

    if (!conditions) {
        return NULL;
    }

    if (conditions->type != CFL_VARIANT_ARRAY) {
        flb_plg_error(ctx->ins, "conditions must be an array");
        return NULL;
    }

    sampling_cond = flb_calloc(1, sizeof(struct sampling_conditions));
    if (!sampling_cond) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&sampling_cond->list);

    /* iterate conditions */
    for (i = 0; i < conditions->data.as_array->entry_count; i++) {
        condition_settings = conditions->data.as_array->entries[i];
        if (condition_settings->type != CFL_VARIANT_KVLIST) {
            flb_plg_error(ctx->ins, "condition must be a map");
            sampling_conditions_destroy(sampling_cond);
            return NULL;
        }

        type_settings = cfl_kvlist_fetch(condition_settings->data.as_kvlist, "type");
        if (!type_settings) {
            flb_plg_error(ctx->ins, "condition must have a 'type' key");
            sampling_conditions_destroy(sampling_cond);
            return NULL;
        }

        if (type_settings->type != CFL_VARIANT_STRING) {
            flb_plg_error(ctx->ins, "condition 'type' must be a string");
            sampling_conditions_destroy(sampling_cond);
            return NULL;
        }

        type_str = type_settings->data.as_string;
        type = condition_type_str_to_int(type_str);
        if (type == -1) {
            flb_plg_error(ctx->ins, "unknown condition type '%s'", type_str);
            sampling_conditions_destroy(sampling_cond);
            return NULL;
        }

        cond_ptr = NULL;
        switch (type) {
        case SAMPLING_COND_STATUS_CODE:
            cond_ptr = cond_status_codes_create(ctx, sampling_cond, condition_settings);
            break;
        case SAMPLING_COND_LATENCY:
            cond_ptr = cond_latency_create(ctx, sampling_cond, condition_settings);
            break;
        case SAMPLING_COND_STRING_ATTRIBUTE:
            cond_ptr = cond_string_attr_create(ctx, sampling_cond, condition_settings);
            break;
        case SAMPLING_COND_NUMERIC_ATTRIBUTE:
            cond_ptr = cond_numeric_attr_create(ctx, sampling_cond, condition_settings);
            break;
        case SAMPLING_COND_BOOLEAN_ATTRIBUTE:
            cond_ptr = cond_boolean_attr_create(ctx, sampling_cond, condition_settings);
            break;
        case SAMPLING_COND_SPAN_COUNT:
            cond_ptr = cond_span_count_create(ctx, sampling_cond, condition_settings);
            break;
        case SAMPLING_COND_TRACE_STATE:
            cond_ptr = cond_trace_state_create(ctx, sampling_cond, condition_settings);
            break;
        default:
            sampling_conditions_destroy(sampling_cond);
            return NULL;
        }

        if (!cond_ptr) {
            flb_plg_error(ctx->ins, "failed to create condition type '%s'", type_str);
            sampling_conditions_destroy(sampling_cond);
            return NULL;
        }
    }

    return sampling_cond;
}

