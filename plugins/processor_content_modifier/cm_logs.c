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


#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "cm.h"
#include "cm_utils.h"
#include "cm_opentelemetry.h"

#include <stdio.h>

static struct cfl_kvpair *cfl_object_kvpair_get(struct cfl_object *obj, cfl_sds_t key)
{
    struct cfl_list *head;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;


    kvlist = obj->variant->data.as_kvlist;
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
                            struct cfl_object *obj,
                            const char *tag, int tag_len,
                            cfl_sds_t key, cfl_sds_t value)
{
    int ret;
    struct cfl_kvlist *kvlist;

    /* check that the key don't exists */
    if (cfl_object_kvpair_get(obj, key)) {
        /* Insert requires the key don't exists, we fail silently */
        return 0;
    }

    /* insert the new value */
    kvlist = obj->variant->data.as_kvlist;
    ret = cfl_kvlist_insert_string_s(kvlist, key, cfl_sds_len(key), value, cfl_sds_len(value),
                                     CFL_FALSE);
    if (ret != 0) {
        flb_plg_debug(ctx->ins, "[action: insert] failed to insert key: %s", key);
        return -1;
    }
    return 0;
}

static int run_action_upsert(struct content_modifier_ctx *ctx,
                            struct cfl_object *obj,
                            const char *tag, int tag_len,
                            cfl_sds_t key, cfl_sds_t value)
{
    int ret;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;

    kvlist = obj->variant->data.as_kvlist;

    /* if the kv pair already exists, remove it from the list */
    kvpair = cfl_object_kvpair_get(obj, key);
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
                            struct cfl_object *obj,
                            const char *tag, int tag_len,
                            cfl_sds_t key)
{
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = cfl_object_kvpair_get(obj, key);
    if (kvpair) {
        cfl_kvpair_destroy(kvpair);
        return 0;
    }

    flb_plg_debug(ctx->ins, "[action: delete] key '%s' not found", key);

    /* if the kvpair was not found, it's ok, we return zero */
    return 0;
}

static int run_action_rename(struct content_modifier_ctx *ctx,
                            struct cfl_object *obj,
                            const char *tag, int tag_len,
                            cfl_sds_t key, cfl_sds_t value)
{
    cfl_sds_t tmp;
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = cfl_object_kvpair_get(obj, key);
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
                           struct cfl_object *obj,
                           const char *tag, int tag_len,
                           cfl_sds_t key)
{
    int ret;
    struct cfl_kvpair *kvpair;

    /* if the kv pair already exists, remove it from the list */
    kvpair = cfl_object_kvpair_get(obj, key);
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

int run_action_extract(struct content_modifier_ctx *ctx,
                       struct cfl_object *obj,
                       const char *tag, int tag_len,
                       cfl_sds_t key, struct flb_regex *regex)
{
    int ret;
    int match_count;
    struct flb_regex_search match_list;
    struct cfl_kvpair *kvpair;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *v;

    kvlist = obj->variant->data.as_kvlist;

    /* if the kv pair already exists, remove it from the list */
    kvpair = cfl_object_kvpair_get(obj, key);
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
                              struct cfl_object *obj,
                              const char *tag, int tag_len,
                              cfl_sds_t key, int converted_type)
{
    int ret;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *v;
    struct cfl_variant *converted;

    /* if the kv pair already exists, remove it from the list */
    kvpair = cfl_object_kvpair_get(obj, key);
    if (!kvpair) {
        return -1;
    }

    /* convert the value */
    v = kvpair->val;
    ret = cm_utils_variant_convert(v, &converted, converted_type);
    if (ret != FLB_TRUE) {
        return -1;
    }

    /* remove the old kvpair */
    cfl_kvpair_destroy(kvpair);

    kvlist = obj->variant->data.as_kvlist;
    ret = cfl_kvlist_insert_s(kvlist, key, cfl_sds_len(key), converted);
    if (ret != 0) {
        cfl_variant_destroy(converted);
        return -1;
    }

    return 0;
}


static struct cfl_variant *otel_get_attributes(int context, struct flb_mp_chunk_record *record)
{
    struct cfl_object *obj = NULL;
    struct cfl_kvlist *kvlist;

    obj = record->cobj_record;
    kvlist = obj->variant->data.as_kvlist;

    return cm_otel_get_attributes(CM_TELEMETRY_LOGS, context, kvlist);
}

static struct cfl_variant *otel_get_scope(struct flb_mp_chunk_record *record)
{
    struct cfl_object *obj;
    struct cfl_kvlist *kvlist;

    obj = record->cobj_record;
    kvlist = obj->variant->data.as_kvlist;

    return cm_otel_get_scope_metadata(CM_TELEMETRY_LOGS, kvlist);
}

int cm_logs_process(struct flb_processor_instance *ins,
                    struct content_modifier_ctx *ctx,
                    struct flb_mp_chunk_cobj *chunk_cobj,
                    const char *tag,
                    int tag_len)
{
    int ret = -1;
    int record_type;
    struct flb_mp_chunk_record *record;
    struct cfl_object *obj = NULL;
    struct cfl_object obj_static;
    struct cfl_variant *var;

    /* Iterate records */
    while ((ret = flb_mp_chunk_cobj_record_next(chunk_cobj, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        obj = NULL;

        /* Retrieve information about the record type */
        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "record has invalid event type");
            continue;
        }

        /* retrieve the target cfl object */
        if (ctx->context_type == CM_CONTEXT_LOG_METADATA) {
            obj = record->cobj_metadata;
        }
        else if (ctx->context_type == CM_CONTEXT_LOG_BODY) {
            obj = record->cobj_record;
        }
        else if (ctx->context_type == CM_CONTEXT_OTEL_RESOURCE_ATTR &&
                 record_type == FLB_LOG_EVENT_GROUP_START) {
            var = otel_get_attributes(CM_CONTEXT_OTEL_RESOURCE_ATTR, record);
            if (!var) {
                continue;
            }

            obj_static.type = CFL_VARIANT_KVLIST;
            obj_static.variant = var;
            obj = &obj_static;
        }
        else if (ctx->context_type == CM_CONTEXT_OTEL_SCOPE_ATTR &&
                 record_type == FLB_LOG_EVENT_GROUP_START) {

            var = otel_get_attributes(CM_CONTEXT_OTEL_SCOPE_ATTR, record);
            if (!var) {
                continue;
            }

            obj_static.type = CFL_VARIANT_KVLIST;
            obj_static.variant = var;
            obj = &obj_static;
        }
        else if ((ctx->context_type == CM_CONTEXT_OTEL_SCOPE_NAME || ctx->context_type == CM_CONTEXT_OTEL_SCOPE_VERSION) &&
                 record_type == FLB_LOG_EVENT_GROUP_START) {

            var = otel_get_scope(record);
            obj_static.type = CFL_VARIANT_KVLIST;
            obj_static.variant = var;
            obj = &obj_static;
        }

        if (!obj) {
            continue;
        }

        /* the operation on top of the data type is unsupported */
        if (obj->variant->type != CFL_VARIANT_KVLIST) {
            flb_plg_error(ctx->ins, "unsupported data type for context");
            return FLB_PROCESSOR_FAILURE;
        }

        /* process the action */
        if (ctx->action_type == CM_ACTION_INSERT) {
            ret = run_action_insert(ctx, obj, tag, tag_len, ctx->key, ctx->value);
        }
        else if (ctx->action_type == CM_ACTION_UPSERT) {
            ret = run_action_upsert(ctx, obj, tag, tag_len, ctx->key, ctx->value);
        }
        else if (ctx->action_type == CM_ACTION_DELETE) {
            ret = run_action_delete(ctx, obj, tag, tag_len, ctx->key);
        }
        else if (ctx->action_type == CM_ACTION_RENAME) {
            ret = run_action_rename(ctx, obj, tag, tag_len, ctx->key, ctx->value);
        }
        else if (ctx->action_type == CM_ACTION_HASH) {
            ret = run_action_hash(ctx, obj, tag, tag_len, ctx->key);
        }
        else if (ctx->action_type == CM_ACTION_EXTRACT) {
            ret = run_action_extract(ctx, obj, tag, tag_len, ctx->key, ctx->regex);
        }
        else if (ctx->action_type == CM_ACTION_CONVERT) {
            ret = run_action_convert(ctx, obj, tag, tag_len, ctx->key, ctx->converted_type);
        }

        if (ret != 0) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}
