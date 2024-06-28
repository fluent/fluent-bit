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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "cm.h"
#include "cm_utils.h"

#include <stdio.h>
#include <math.h>

static int hex_encode(unsigned char *input_buffer,
                      size_t input_length,
                      cfl_sds_t *output_buffer)
{
    const char hex[] = "0123456789abcdef";
    cfl_sds_t  result;
    size_t     index;

    if (cfl_sds_alloc(*output_buffer) <= (input_length * 2)) {
        result = cfl_sds_increase(*output_buffer,
                                  (input_length * 2) -
                                  cfl_sds_alloc(*output_buffer));

        if (result == NULL) {
            return FLB_FALSE;
        }

        *output_buffer = result;
    }

    for (index = 0; index < input_length; index++) {
        (*output_buffer)[index * 2 + 0] = hex[(input_buffer[index] >> 4) & 0xF];
        (*output_buffer)[index * 2 + 1] = hex[(input_buffer[index] >> 0) & 0xF];
    }

    cfl_sds_set_len(*output_buffer, input_length * 2);

    (*output_buffer)[index * 2] = '\0';

    return FLB_TRUE;
}

static int hash_transformer(void *context, struct cfl_variant *value)
{
    unsigned char       digest_buffer[32];
    struct cfl_variant *converted_value;
    cfl_sds_t           encoded_hash;
    int                 result;

    if (value == NULL) {
        return FLB_FALSE;
    }

    result = cfl_variant_convert(value,
                                 &converted_value,
                                 CFL_VARIANT_STRING);

    if (result != FLB_TRUE) {
        return FLB_FALSE;
    }

    if (cfl_variant_size_get(converted_value) == 0) {
        cfl_variant_destroy(converted_value);
        return FLB_TRUE;
    }

    result = flb_hash_simple(FLB_HASH_SHA256,
                             (unsigned char *) converted_value->data.as_string,
                             cfl_sds_len(converted_value->data.as_string),
                             digest_buffer,
                             sizeof(digest_buffer));

    if (result != FLB_CRYPTO_SUCCESS) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    result = hex_encode(digest_buffer,
                        sizeof(digest_buffer),
                        &converted_value->data.as_string);

    if (result != FLB_TRUE) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    encoded_hash = cfl_sds_create(converted_value->data.as_string);
    cfl_variant_destroy(converted_value);
    if (encoded_hash == NULL) {
        return FLB_FALSE;
    }

    /* NOTE: this part does a manual modification of the variant content */
    if (value->type == CFL_VARIANT_STRING ||
        value->type == CFL_VARIANT_BYTES) {
        if (value->referenced == CFL_FALSE) {
            cfl_sds_destroy(value->data.as_string);
        }
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        cfl_array_destroy(value->data.as_array);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        cfl_kvlist_destroy(value->data.as_kvlist);
    }

    value->type = CFL_VARIANT_STRING;
    value->data.as_string = encoded_hash;
    value->referenced = CFL_FALSE;

    cfl_variant_size_set(value, cfl_sds_len(encoded_hash));

    return FLB_TRUE;
}

cfl_sds_t cfl_variant_convert_to_json(struct cfl_variant *value)
{
    cfl_sds_t      json_result;
    mpack_writer_t writer;
    char          *data;
    size_t         size;

    data = NULL;
    size = 0;

    mpack_writer_init_growable(&writer, &data, &size);

    pack_cfl_variant(&writer, value);

    mpack_writer_destroy(&writer);

    json_result = flb_msgpack_raw_to_json_sds(data, size);

    return json_result;
}

int cfl_variant_convert(struct cfl_variant *input_value,
                        struct cfl_variant **output_value,
                        int output_type)
{
    int ret;
    int errno_backup;
    int64_t as_int;
    double as_double;
    char buf[64];
    char *str = NULL;
    char *converstion_canary = NULL;
    struct cfl_variant *tmp = NULL;

    errno_backup = errno;

    /* input: string, bytes or reference */
    if (input_value->type == CFL_VARIANT_STRING || input_value->type == CFL_VARIANT_BYTES ||
        input_value->type == CFL_VARIANT_REFERENCE) {

        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            tmp = cfl_variant_create_from_string_s(input_value->data.as_string,
                                                   cfl_variant_size_get(input_value),
                                                   CFL_FALSE);
            if (!tmp) {
                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;

            if (cfl_variant_size_get(input_value) == 4 &&
                strncasecmp(input_value->data.as_string, "true", 4) == 0) {
                as_int = CFL_TRUE;
            }
            else if (cfl_variant_size_get(input_value) == 5 &&
                strncasecmp(input_value->data.as_string, "false", 5) == 0) {
                as_int = CFL_FALSE;
            }

            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            errno = 0;

            if (input_value->referenced) {
                tmp = cfl_variant_create_from_string_s(input_value->data.as_string,
                                                       cfl_variant_size_get(input_value),
                                                       CFL_FALSE);
                if (!tmp) {
                    return CFL_FALSE;
                }
                str = tmp->data.as_string;
            }
            else {
                str = input_value->data.as_string;
            }

            as_int = strtoimax(str, &converstion_canary, 10);
            if (errno == ERANGE || errno == EINVAL) {
                errno = errno_backup;
                if (tmp) {
                    cfl_variant_destroy(tmp);
                }
                return CFL_FALSE;
            }

            if (tmp) {
                cfl_variant_destroy(tmp);
            }

            tmp = cfl_variant_create_from_int64(as_int);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            errno = 0;
            converstion_canary = NULL;

            if (input_value->referenced) {
                tmp = cfl_variant_create_from_string_s(input_value->data.as_string,
                                                       cfl_variant_size_get(input_value),
                                                       CFL_FALSE);
                if (!tmp) {
                    return CFL_FALSE;
                }
                str = tmp->data.as_string;
            }
            else {
                str = input_value->data.as_string;
            }

            as_double = strtod(str, &converstion_canary);
            if (errno == ERANGE) {
                errno = errno_backup;
                if (tmp) {
                    cfl_variant_destroy(tmp);
                }
                return CFL_FALSE;
            }

            if (tmp) {
                cfl_variant_destroy(tmp);
            }

            if (as_double == 0 && converstion_canary == input_value->data.as_string) {
                errno = errno_backup;
                return CFL_FALSE;
            }

            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    /* input: int */
    else if (input_value->type == CFL_VARIANT_INT) {
        if (output_type == CFL_VARIANT_STRING || output_type == CFL_VARIANT_BYTES) {
            ret = snprintf(buf, sizeof(buf), "%" PRIi64, input_value->data.as_int64);
            if (ret < 0 || ret >= sizeof(buf)) {
                return CFL_FALSE;
            }
            tmp = cfl_variant_create_from_string_s(buf, ret, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;
            if (input_value->data.as_int64 != 0) {
                as_int = CFL_TRUE;
            }

            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            /* same type, do nothing */
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            as_double = (double) input_value->data.as_int64;
            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_DOUBLE) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            ret = snprintf(buf, sizeof(buf), "%.17g", input_value->data.as_double);
            if (ret < 0 || ret >= sizeof(buf)) {
                return CFL_FALSE;
            }
            tmp = cfl_variant_create_from_string_s(buf, ret, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;

            if (input_value->data.as_double != 0) {
                as_int = CFL_TRUE;
            }

            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            as_int = (int64_t) round(input_value->data.as_double);
            tmp = cfl_variant_create_from_int64(as_int);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            as_double = input_value->data.as_int64;
            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_NULL) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            tmp = cfl_variant_create_from_string_s("null", 4, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            tmp = cfl_variant_create_from_bool(CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_INT) {
            tmp = cfl_variant_create_from_int64(0);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            tmp = cfl_variant_create_from_double(0);
        }
        else {
            return CFL_FALSE;
        }
    }
    else {
        return CFL_FALSE;
    }

    *output_value = tmp;
    return FLB_TRUE;
}

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

    ret = hash_transformer(NULL, kvpair->val);
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
    ret = cfl_variant_convert(v, &converted, converted_type);
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

static struct cfl_variant *otel_get_or_create_attributes(struct cfl_kvlist *kvlist)
{
    int ret;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *val;
    struct cfl_kvlist *kvlist_tmp;

    /* iterate resource to find the attributes field */
    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(kvpair->key) != 10) {
            continue;
        }

        if (strncmp(kvpair->key, "attributes", 10) == 0) {
            val = kvpair->val;
            if (val->type != CFL_VARIANT_KVLIST) {
                return NULL;
            }

            return val;
        }
    }

    /* create an empty kvlist as the value of attributes */
    kvlist_tmp = cfl_kvlist_create();
    if (!kvlist_tmp) {
        return NULL;
    }

    /* create the attributes kvpair */
    ret = cfl_kvlist_insert_kvlist_s(kvlist, "attributes", 10, kvlist_tmp);
    if (ret != 0) {
        cfl_kvlist_destroy(kvlist_tmp);
        return NULL;
    }

    /* get the last kvpair from the list */
    kvpair = cfl_list_entry_last(&kvlist->list, struct cfl_kvpair, _head);
    if (!kvpair) {
        return NULL;
    }

    return kvpair->val;
}


static struct cfl_variant *otel_get_attributes(int context, struct flb_mp_chunk_record *record)
{
    int key_len;
    const char *key_buf;
    struct cfl_list *head;
    struct cfl_object *obj = NULL;
    struct cfl_variant *val;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *var_attr;

    if (context == CM_CONTEXT_OTEL_RESOURCE_ATTR) {
        key_buf = "resource";
        key_len = 8;
    }
    else if (context == CM_CONTEXT_OTEL_SCOPE_ATTR) {
        key_buf = "scope";
        key_len = 5;
    }
    else {
        return NULL;
    }

    obj = record->cobj_record;
    kvlist = obj->variant->data.as_kvlist;
    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(kvpair->key) != key_len) {
            continue;
        }

        if (strncmp(kvpair->key, key_buf, key_len) == 0) {
            val = kvpair->val;
            if (val->type != CFL_VARIANT_KVLIST) {
                return NULL;
            }

            var_attr = otel_get_or_create_attributes(val->data.as_kvlist);
            if (!var_attr) {
                return NULL;
            }

            return var_attr;
        }
    }

    return NULL;
}

static struct cfl_variant *otel_get_scope(struct flb_mp_chunk_record *record)
{
    struct cfl_list *head;
    struct cfl_object *obj;
    struct cfl_variant *val;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;

    obj = record->cobj_record;
    kvlist = obj->variant->data.as_kvlist;
    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(kvpair->key) != 5) {
            continue;
        }

        if (strncmp(kvpair->key, "scope", 5) == 0) {
            val = kvpair->val;
            if (val->type != CFL_VARIANT_KVLIST) {
                return NULL;
            }

            return val;
        }
    }

    return NULL;
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
            cfl_object_destroy(obj);
            return -1;
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
