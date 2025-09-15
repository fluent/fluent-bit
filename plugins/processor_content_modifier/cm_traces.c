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
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_processor.h>
#include <cfl/cfl.h>

#include "cm.h"
#include "cm_utils.h"

typedef int (*attribute_transformer) (void *, struct cfl_variant *value);

static int span_contains_attribute(struct ctrace_span *span,
                                   char *name)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    return cfl_kvlist_contains(span->attr->kv, name);
}

static int span_remove_attribute(struct ctrace_span *span,
                                 char *name)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    return cfl_kvlist_remove(span->attr->kv, name);
}

static int span_update_attribute(struct ctrace_span *span,
                                 char *name,
                                 char *value)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    cfl_kvlist_remove(span->attr->kv, name);

    if (ctr_span_set_attribute_string(span, name, value) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int span_insert_attribute(struct ctrace_span *span,
                                 char *name,
                                 char *value)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    if (ctr_span_set_attribute_string(span, name, value) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int span_transform_attribute(struct ctrace_span *span,
                                    char *name,
                                    attribute_transformer transformer)
{
    struct cfl_variant *attribute;

    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    attribute = cfl_kvlist_fetch(span->attr->kv, name);

    if (attribute == NULL) {
        return FLB_FALSE;
    }

    return transformer(NULL, attribute);
}

static int span_convert_attribute(struct ctrace_span *span,
                                  cfl_sds_t key, int new_type)
{
    int ret;
    struct cfl_variant *attribute;
    struct cfl_variant *converted_attribute;

    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    attribute = cfl_kvlist_fetch(span->attr->kv, key);
    if (attribute == NULL) {
        return FLB_FALSE;
    }

    ret = cm_utils_variant_convert(attribute,
                                   &converted_attribute,
                                   new_type);

    if (ret != FLB_TRUE) {
        return FLB_FALSE;
    }

    ret = cfl_kvlist_remove(span->attr->kv, key);
    if (ret != FLB_TRUE) {
        return FLB_FALSE;
    }


    ret = cfl_kvlist_insert(span->attr->kv, key, converted_attribute);
    if (ret != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int span_rename_attribute(struct ctrace_span *span,
                                  cfl_sds_t key, cfl_sds_t new_name)
{
    cfl_sds_t tmp;
    struct cfl_list *head;
    struct cfl_kvpair *kvpair;

    if (span->attr == NULL) {
        return FLB_FALSE;
    }

   cfl_list_foreach(head, &span->attr->kv->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(key) != cfl_sds_len(kvpair->key)) {
            continue;
        }

        if (strncmp(key, kvpair->key, cfl_sds_len(key)) == 0) {
            break;
        }

        kvpair = NULL;
    }

    if (!kvpair) {
        return FLB_FALSE;
    }

    tmp = kvpair->key;
    kvpair->key = cfl_sds_create_len(new_name, cfl_sds_len(new_name));
    if (!kvpair->key) {
        /* restore previous value */
        kvpair->key = tmp;
        return FLB_FALSE;
    }

    /* destroy previous value */
    cfl_sds_destroy(tmp);

    return FLB_TRUE;
}

static void attribute_match_cb(const char *name,
                               const char *value,
                               size_t value_length,
                               void *context)
{
    cfl_sds_t           temporary_value;
    struct ctrace_span *span;

    temporary_value = cfl_sds_create_len(value, value_length);

    if (temporary_value != NULL) {
        span = (struct ctrace_span *) context;

        if (span_contains_attribute(span, (char *) name) == FLB_TRUE) {
            span_remove_attribute(span, (char *) name);
        }

        ctr_span_set_attribute_string(span, (char *) name, temporary_value);

        cfl_sds_destroy(temporary_value);
    }
}

static int span_extract_attributes(struct ctrace_span *span,
                                   cfl_sds_t key,
                                   struct flb_regex *regex)

{
    ssize_t                  match_count;
    struct flb_regex_search  match_list;
    struct cfl_variant      *attribute;
    int                      result;

    attribute = cfl_kvlist_fetch(span->attr->kv, key);
    if (attribute == NULL) {
        return FLB_FALSE;
    }

    if (attribute->type != CFL_VARIANT_STRING) {
        return FLB_FALSE;
    }

    match_count = flb_regex_do(regex,
                               attribute->data.as_string,
                               cfl_sds_len(attribute->data.as_string),
                               &match_list);

    if (match_count <= 0) {
        return FLB_FALSE;
    }

    result = flb_regex_parse(regex,
                             &match_list,
                             attribute_match_cb,
                             (void *) span);
    if (result == -1) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int context_contains_attribute(struct ctrace *traces_context,
                                             char *name)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int traces_context_hash_attribute(struct ctrace *traces_context,
                                         char *name)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_transform_attribute(span, name, cm_utils_hash_transformer) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_remove_attribute(struct ctrace *traces_context,
                                             char *name)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_remove_attribute(span, name) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_update_attribute(struct ctrace *traces_context,
                                           char *name,
                                           char *value)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_update_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_insert_attribute(struct ctrace *traces_context,
                                           char *name,
                                           char *value)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (!span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_insert_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_upsert_attribute(struct ctrace *traces_context,
                                           char *name,
                                           char *value)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_update_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
        else {
            if (span_insert_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_rename_attributes(struct ctrace *traces_context,
                                            char *name,
                                            char *value)
{
    int ret;
    int renamed = 0;
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            ret = span_rename_attribute(span, name, value);
            if (ret == FLB_FALSE) {
                return FLB_FALSE;
            }
            renamed++;
        }
    }

    if (renamed) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int traces_context_convert_attribute(struct ctrace *traces_context,
                                            char *key, int new_type)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, key) == FLB_TRUE) {
            if (span_convert_attribute(span, key, new_type) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_extract_attribute(struct ctrace *traces_context,
                                            cfl_sds_t key,
                                            struct flb_regex *regex)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, key) == FLB_TRUE) {
            if (span_extract_attributes(span, key, regex) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

int traces_update_attributes(struct ctrace *traces_context, struct cfl_list *attributes)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, attributes) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = traces_context_update_attribute(traces_context,
                                                 pair->key,
                                                 pair->val);

        if (result == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}



static int traces_convert_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context,
                                     cfl_sds_t key, int converted_type)
{
    int ret;

    ret = traces_context_convert_attribute(traces_context, key, converted_type);
    if (ret == FLB_FALSE) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int traces_extract_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context,
                                    cfl_sds_t key, struct flb_regex *regex)
{
    int ret;

    ret = traces_context_extract_attribute(traces_context, key, regex);
    if (ret == FLB_FALSE) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int traces_insert_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context,
                                    cfl_sds_t key, cfl_sds_t value)
{
    int ret;

    ret = traces_context_insert_attribute(traces_context, key, value);
    if (ret == FLB_FALSE) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int traces_rename_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context,
                                    cfl_sds_t key, cfl_sds_t new_name)
{
    int ret;

    ret = traces_context_rename_attributes(traces_context, key, new_name);
    //ret = traces_context_rename_attribute(
    if (ret == FLB_FALSE) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}
static int traces_upsert_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context,
                                    cfl_sds_t key, cfl_sds_t value)
{
    int ret;

    ret = traces_context_upsert_attribute(traces_context, key, value);
    if (ret == FLB_FALSE) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int traces_delete_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context, cfl_sds_t key)
{
    int ret;

    ret = context_contains_attribute(traces_context, key);
    if (ret == FLB_TRUE) {
        ret = traces_context_remove_attribute(traces_context, key);
        if (ret == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}


static int traces_hash_attributes(struct content_modifier_ctx *ctx, struct ctrace *traces_context, cfl_sds_t key)
{
    int ret;

    ret = context_contains_attribute(traces_context, key);
    if (ret == FLB_TRUE) {
        ret = traces_context_hash_attribute(traces_context, key);
        if (ret == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int cm_traces_process(struct flb_processor_instance *ins,
                      struct content_modifier_ctx *ctx,
                      struct ctrace *traces_context,
                      struct ctrace **out_traces_context,
                      const char *tag, int tag_len)
{
    int ret = -1;

    /* process the action */
    if (ctx->action_type == CM_ACTION_INSERT) {
        ret = traces_insert_attributes(ctx, traces_context, ctx->key, ctx->value);
    }
    else if (ctx->action_type == CM_ACTION_UPSERT) {
        ret = traces_upsert_attributes(ctx, traces_context, ctx->key, ctx->value);
    }
    else if (ctx->action_type == CM_ACTION_DELETE) {
        ret = traces_delete_attributes(ctx, traces_context, ctx->key);
    }
    else if (ctx->action_type == CM_ACTION_RENAME) {
        ret = traces_rename_attributes(ctx, traces_context, ctx->key, ctx->value);
    }
    else if (ctx->action_type == CM_ACTION_HASH) {
        ret = traces_hash_attributes(ctx, traces_context, ctx->key);
    }
    else if (ctx->action_type == CM_ACTION_EXTRACT) {
        ret = traces_extract_attributes(ctx, traces_context, ctx->key, ctx->regex);
    }
    else if (ctx->action_type == CM_ACTION_CONVERT) {
        ret = traces_convert_attributes(ctx, traces_context, ctx->key, ctx->converted_type);
    }

    *out_traces_context = traces_context;

    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}
