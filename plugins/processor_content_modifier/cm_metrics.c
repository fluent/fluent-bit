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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <cfl/cfl.h>

#include "cm.h"
#include "cm_utils.h"
#include "cm_opentelemetry.h"


static struct cfl_kvpair *kvlist_get_kvpair(struct cfl_kvlist *kvlist, cfl_sds_t key)
{
    struct cfl_list *head;
    struct cfl_kvpair *kvpair;

    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(key) != cfl_sds_len(kvpair->key)) {
            continue;
        }

        if (strncmp(key, kvpair->key, cfl_sds_len(key)) == 0) {
            return kvpair;
        }
    }

    return NULL;
}

static int run_action_insert(struct content_modifier_ctx *ctx,
                            struct cfl_kvlist *kvlist,
                            const char *tag, int tag_len,
                            cfl_sds_t key, cfl_sds_t value)
{
    int ret;
    struct cfl_kvpair *kvpair;

    /* check that the key don't exists */
    kvpair = kvlist_get_kvpair(kvlist, key);
    if (kvpair) {
        /* Insert requires the key don't exists, we fail silently */
        return 0;
    }

    /* insert the new value */
    ret = cfl_kvlist_insert_string_s(kvlist, key, cfl_sds_len(key), value, cfl_sds_len(value),
                                     CFL_FALSE);
    if (ret != 0) {
        flb_plg_debug(ctx->ins, "[action: insert] failed to insert key: %s", key);
        return -1;
    }
    return 0;
}

static int run_action_upsert(struct content_modifier_ctx *ctx,
                             struct cfl_kvlist *kvlist,
                             const char *tag, int tag_len,
                             cfl_sds_t key, cfl_sds_t value)
{
    int ret;
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = kvlist_get_kvpair(kvlist, key);
    if (kvpair) {
        cfl_kvpair_destroy(kvpair);
    }

    /* insert the key with the updated value */
    ret = cfl_kvlist_insert_string_s(kvlist, key, cfl_sds_len(key), value, cfl_sds_len(value),
                                     CFL_FALSE);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

static int run_action_delete(struct content_modifier_ctx *ctx,
                             struct cfl_kvlist *kvlist,
                             const char *tag, int tag_len,
                             cfl_sds_t key)
{
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = kvlist_get_kvpair(kvlist, key);
    if (kvpair) {
        cfl_kvpair_destroy(kvpair);
        return 0;
    }

    flb_plg_debug(ctx->ins, "[action: delete] key '%s' not found", key);

    /* if the kvpair was not found, it's ok, we return zero */
    return 0;
}

static int run_action_rename(struct content_modifier_ctx *ctx,
                             struct cfl_kvlist *kvlist,
                             const char *tag, int tag_len,
                             cfl_sds_t key, cfl_sds_t value)
{
    cfl_sds_t tmp;
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = kvlist_get_kvpair(kvlist, key);
    if (!kvpair) {
        flb_plg_debug(ctx->ins, "[action: rename] key '%s' not found", key);
        return 0;
    }

    tmp = kvpair->key;

    kvpair->key = cfl_sds_create_len(value, cfl_sds_len(value));
    if (!kvpair->key) {
        /* restore previous value */
        kvpair->key = tmp;
        return -1;
    }

    /* destroy previous value */
    cfl_sds_destroy(tmp);
    return 0;
}

static int run_action_hash(struct content_modifier_ctx *ctx,
                           struct cfl_kvlist *kvlist,
                           const char *tag, int tag_len,
                           cfl_sds_t key)
{
    int ret;
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = kvlist_get_kvpair(kvlist, key);
    if (!kvpair) {
        /* the key was not found, so it's ok */
        return 0;
    }

    ret = cm_utils_hash_transformer(NULL, kvpair->val);
    if (ret == FLB_FALSE) {
        return -1;
    }

    return 0;
}

static void cb_extract_regex(const char *name, const char *value, size_t value_length, void *context)
{

    struct cfl_kvlist *kvlist = (struct cfl_kvlist *) context;

    if (cfl_kvlist_contains(kvlist, (char *) name)) {
        cfl_kvlist_remove(kvlist, (char *) name);
    }

    cfl_kvlist_insert_string_s(kvlist, (char *) name, strlen(name), (char *) value, value_length,
                               CFL_FALSE);
}

static int run_action_extract(struct content_modifier_ctx *ctx,
                              struct cfl_kvlist *kvlist,
                              const char *tag, int tag_len,
                              cfl_sds_t key, struct flb_regex *regex)
{
    int ret;
    int match_count;
    struct flb_regex_search match_list;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *v;

    /* if the kv pair already exists, remove it from the list */
    kvpair = kvlist_get_kvpair(kvlist, key);
    if (!kvpair) {
        return -1;
    }

    v = kvpair->val;
    if (v->type != CFL_VARIANT_STRING) {
        return -1;
    }

    match_count = flb_regex_do(regex,
                               v->data.as_string,
                               cfl_variant_size_get(v), &match_list);
    if (match_count <= 0) {
        return -1;
    }

    ret = flb_regex_parse(regex, &match_list, cb_extract_regex, kvlist);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int run_action_convert(struct content_modifier_ctx *ctx,
                              struct cfl_kvlist *kvlist)
{
    int ret;
    size_t index;
    size_t key_count;
    cfl_sds_t key;
    struct cfl_variant *old_value;
    struct cfl_variant **converted_values;
    struct cfl_kvpair **kvpairs;

    key_count = cm_key_count(ctx);
    converted_values = flb_calloc(key_count, sizeof(struct cfl_variant *));
    kvpairs = flb_calloc(key_count, sizeof(struct cfl_kvpair *));
    if (converted_values == NULL || kvpairs == NULL) {
        flb_free(converted_values);
        flb_free(kvpairs);
        return -1;
    }

    /* Validate and stage every conversion before changing the context. */
    for (index = 0; index < key_count; index++) {
        key = cm_key_at(ctx, index);
        kvpairs[index] = kvlist_get_kvpair(kvlist, key);
        if (kvpairs[index] == NULL) {
            continue;
        }

        ret = cm_utils_variant_convert(kvpairs[index]->val,
                                       &converted_values[index],
                                       ctx->converted_type);
        if (ret != FLB_TRUE) {
            ret = -1;
            goto cleanup;
        }
    }

    for (index = 0; index < key_count; index++) {
        if (kvpairs[index] == NULL) {
            continue;
        }

        old_value = kvpairs[index]->val;
        kvpairs[index]->val = converted_values[index];
        converted_values[index] = NULL;
        cfl_variant_destroy(old_value);
    }
    ret = 0;

cleanup:
    for (index = 0; index < key_count; index++) {
        if (converted_values[index] != NULL) {
            cfl_variant_destroy(converted_values[index]);
        }
    }
    flb_free(converted_values);
    flb_free(kvpairs);

    return ret;
}

int cm_metrics_process(struct flb_processor_instance *ins,
                       struct content_modifier_ctx *ctx,
                       struct cmt *in_cmt,
                       struct cmt **out_cmt,
                       const char *tag, int tag_len)
{
    int ret = -1;
    size_t key_index;
    cfl_sds_t key;
    struct cfl_variant *var = NULL;

    if (ctx->context_type == CM_CONTEXT_OTEL_RESOURCE_ATTR) {
        /* Internal metadata must be valid */
        var = cfl_kvlist_fetch(in_cmt->internal_metadata, "producer");
        if (!var) {
            return FLB_PROCESSOR_FAILURE;
        }

        if (var->type != CFL_VARIANT_STRING) {
            return FLB_PROCESSOR_FAILURE;
        }

        /* validate that the value is 'opentelemetry' */
        if (strcmp(var->data.as_string, "opentelemetry") != 0 &&
            strcmp(var->data.as_string, "fluent-bit") != 0) {
            return FLB_PROCESSOR_FAILURE;
        }

        /* Now check the external metadata */
        if (!in_cmt->external_metadata) {
            return FLB_PROCESSOR_FAILURE;
        }

        var = NULL;

        var = cm_otel_get_attributes(CM_TELEMETRY_METRICS, ctx->context_type, in_cmt->external_metadata);
        if (!var) {
            return FLB_PROCESSOR_FAILURE;
        }
    }
    else if (ctx->context_type == CM_CONTEXT_OTEL_SCOPE_ATTR) {
        var = cm_otel_get_attributes(CM_TELEMETRY_METRICS, ctx->context_type, in_cmt->external_metadata);
    }
    else if ((ctx->context_type == CM_CONTEXT_OTEL_SCOPE_NAME || ctx->context_type == CM_CONTEXT_OTEL_SCOPE_VERSION)) {
        var = cm_otel_get_scope_metadata(CM_TELEMETRY_METRICS, in_cmt->external_metadata);
    }

    if (!var) {
        return FLB_PROCESSOR_FAILURE;
    }

    if (ctx->action_type == CM_ACTION_CONVERT) {
        ret = run_action_convert(ctx, var->data.as_kvlist);
        if (ret != 0) {
            return FLB_PROCESSOR_FAILURE;
        }
        return FLB_PROCESSOR_SUCCESS;
    }

    for (key_index = 0; key_index < cm_key_count(ctx); key_index++) {
        key = cm_key_at(ctx, key_index);

        if (ctx->action_type == CM_ACTION_INSERT) {
            ret = run_action_insert(ctx, var->data.as_kvlist, tag, tag_len, key, ctx->value);
        }
        else if (ctx->action_type == CM_ACTION_UPSERT) {
            ret = run_action_upsert(ctx, var->data.as_kvlist, tag, tag_len, key, ctx->value);
        }
        else if (ctx->action_type == CM_ACTION_DELETE) {
            ret = run_action_delete(ctx, var->data.as_kvlist, tag, tag_len, key);
        }
        else if (ctx->action_type == CM_ACTION_RENAME) {
            ret = run_action_rename(ctx, var->data.as_kvlist, tag, tag_len, key, ctx->value);
        }
        else if (ctx->action_type == CM_ACTION_HASH) {
            ret = run_action_hash(ctx, var->data.as_kvlist, tag, tag_len, key);
        }
        else if (ctx->action_type == CM_ACTION_EXTRACT) {
            ret = run_action_extract(ctx, var->data.as_kvlist, tag, tag_len, key, ctx->regex);
        }
        if (ret != 0) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}
