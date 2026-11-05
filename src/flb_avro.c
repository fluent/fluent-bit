/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_avro.h>

static inline int do_avro(int call, const char *msg)
{
    if (call) {
        flb_error("%s:\n  %s\n", msg, avro_strerror());
        return call == ENOMEM ? -1 : FLB_FALSE;
    }
    return FLB_TRUE;
}

static int set_avro_integer(avro_value_t *val, int64_t i64, uint64_t u64, int positive)
{
    avro_type_t type;

    type = avro_value_get_type(val);

    if (type == AVRO_INT64) {
        if (positive && u64 > INT64_MAX) {
            flb_error("positive integer value exceeds Avro long range: %" PRIu64, u64);
            return FLB_FALSE;
        }

        return do_avro(avro_value_set_long(val, positive ? (int64_t) u64 : i64),
                       positive ? "failed on posint" : "failed on negint");
    }

    if (type == AVRO_INT32) {
        if (positive && u64 > INT32_MAX) {
            flb_error("positive integer value exceeds Avro int range: %" PRIu64, u64);
            return FLB_FALSE;
        }
        else if (!positive && (i64 < INT32_MIN || i64 > INT32_MAX)) {
            flb_error("negative integer value exceeds Avro int range: %" PRIi64, i64);
            return FLB_FALSE;
        }

        return do_avro(avro_value_set_int(val, positive ? (int32_t) u64 : (int32_t) i64),
                       positive ? "failed on posint" : "failed on negint");
    }

    flb_error("integer value cannot be assigned to Avro type %d", type);

    return FLB_FALSE;
}

/* Preserve permanent schema failures separately from resource failures. */
static int avro_init_status(avro_value_t *value, const char *json, size_t json_len,
                            avro_schema_t *schema, avro_value_iface_t **iface)
{
    int ret;

    *iface = NULL;
    errno = 0;
    ret = avro_schema_from_json_length(json, json_len, schema);
    if (ret != 0) {
        flb_error("Unable to parse Avro schema");
        return ret == ENOMEM || errno == ENOMEM ? -1 : FLB_FALSE;
    }
    *iface = avro_generic_class_from_schema(*schema);
    if (*iface == NULL) {
        avro_schema_decref(*schema);
        return -1;
    }
    ret = avro_generic_value_new(*iface, value);
    if (ret != 0) {
        avro_value_iface_decref(*iface);
        avro_schema_decref(*schema);
        *iface = NULL;
        return ret == ENOMEM ? -1 : FLB_FALSE;
    }
    return FLB_TRUE;
}

/** Initialize a schema-backed value; return NULL if schema or allocation fails. */
avro_value_iface_t *flb_avro_init(avro_value_t *aobject, char *json, size_t json_len,
                                 avro_schema_t *aschema)
{
    avro_value_iface_t *iface;

    if (avro_init_status(aobject, json, json_len, aschema, &iface) != FLB_TRUE) {
        return NULL;
    }
    return iface;
}

/* Avro field/entry indexes provide constant-time duplicate tracking without
 * rescanning keys. Include existing map entries so repeated conversions into
 * the same value still reject only duplicates in the current input.
 */
static int msgpack_map_to_avro(avro_value_t *val, msgpack_object *o)
{
    int ret;
    size_t i;
    size_t index;
    size_t value_size;
    size_t seen_size;
    avro_type_t type;
    avro_value_t element;
    msgpack_object_kv *pair;
    flb_sds_t key;
    unsigned char *seen;

    type = avro_value_get_type(val);
    if (type != AVRO_MAP && type != AVRO_RECORD) {
        return FLB_FALSE;
    }
    if (avro_value_get_size(val, &value_size) != 0) {
        return FLB_FALSE;
    }
    /* Reader-side defaults do not make writer fields optional. */
    if (type == AVRO_RECORD && value_size != o->via.map.size) {
        flb_error("Avro record must supply exactly the declared fields");
        return FLB_FALSE;
    }
    if (o->via.map.size == 0) {
        return FLB_TRUE;
    }
    seen_size = value_size;
    if (type == AVRO_MAP) {
        if (value_size > SIZE_MAX - o->via.map.size) {
            return -1;
        }
        seen_size += o->via.map.size;
    }
    seen = flb_calloc(seen_size, sizeof(*seen));
    if (seen == NULL) {
        return -1;
    }
    ret = FLB_TRUE;
    for (i = 0; i < o->via.map.size; i++) {
        pair = &o->via.map.ptr[i];
        if (pair->key.type != MSGPACK_OBJECT_STR ||
            memchr(pair->key.via.str.ptr, '\0', pair->key.via.str.size) != NULL) {
            ret = FLB_FALSE;
            break;
        }
        key = flb_sds_create_len(pair->key.via.str.ptr, pair->key.via.str.size);
        if (key == NULL) {
            ret = -1;
            break;
        }
        if (type == AVRO_MAP) {
            ret = avro_value_add(val, key, &element, &index, NULL);
        }
        else {
            ret = avro_value_get_by_name(val, key, &element, &index);
        }
        flb_sds_destroy(key);
        if (ret != 0) {
            flb_error("Avro field lookup or map insertion failed");
            ret = type == AVRO_MAP ? -1 : FLB_FALSE;
            break;
        }
        if (index >= seen_size || seen[index]) {
            flb_error("Avro record or map contains a duplicate field");
            ret = FLB_FALSE;
            break;
        }
        seen[index] = 1;
        ret = flb_msgpack_to_avro(&element, &pair->val);
        if (ret != FLB_TRUE) {
            break;
        }
    }
    flb_free(seen);
    return ret;
}

/* Match the input type before selecting a union branch, without coercing data. */
static int avro_type_matches(avro_type_t type, msgpack_object_type input)
{
    switch (input) {
    case MSGPACK_OBJECT_NIL:
        return type == AVRO_NULL;
    case MSGPACK_OBJECT_BOOLEAN:
        return type == AVRO_BOOLEAN;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        return type == AVRO_INT32 || type == AVRO_INT64;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        return type == AVRO_FLOAT || type == AVRO_DOUBLE;
    case MSGPACK_OBJECT_STR:
        return type == AVRO_STRING;
    case MSGPACK_OBJECT_BIN:
    case MSGPACK_OBJECT_EXT:
        return type == AVRO_BYTES;
    case MSGPACK_OBJECT_ARRAY:
        return type == AVRO_ARRAY;
    case MSGPACK_OBJECT_MAP:
        return type == AVRO_MAP || type == AVRO_RECORD;
    default:
        return FLB_FALSE;
    }
}

/** Convert one value, selecting compatible union branches without coercion.
 * Return FLB_FALSE for invalid data and -1 when conversion needs more resources.
 */
int msgpack2avro(avro_value_t *val, msgpack_object *o)
{
    int ret = FLB_FALSE;
    size_t i;
    avro_value_t element;
    avro_schema_t schema;
    avro_schema_t branch;

    flb_debug("in msgpack2avro\n");

    assert(val != NULL);
    assert(o != NULL);

    if (avro_value_get_type(val) == AVRO_UNION) {
        schema = avro_value_get_schema(val);
        for (i = 0; i < avro_schema_union_size(schema); i++) {
            branch = avro_schema_union_branch(schema, i);
            while (is_avro_link(branch)) {
                branch = avro_schema_link_target(branch);
            }
            if (!avro_type_matches(avro_typeof(branch), o->type)) {
                continue;
            }
            ret = avro_value_set_branch(val, i, &element);
            if (ret != 0) {
                return ret == ENOMEM ? -1 : FLB_FALSE;
            }
            ret = flb_msgpack_to_avro(&element, o);
            if (ret != FLB_FALSE) {
                return ret;
            }
        }
        flb_error("No Avro union branch accepts the input value");
        return FLB_FALSE;
    }

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        flb_debug("got a nil:\n");
        ret = do_avro(avro_value_set_null(val), "failed on nil");
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        flb_debug("got a bool:%s:\n", (o->via.boolean ? "true" : "false"));
        ret = do_avro(avro_value_set_boolean(val, o->via.boolean), "failed on bool");
        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        //  for reference src/objectc.c +/msgpack_pack_object
#if defined(PRIu64)
        // msgpack_pack_fix_uint64
        flb_debug("got a posint: %" PRIu64 "\n", o->via.u64);
#else
        flb_debug("got a posint: %lu\n", (unsigned long) o->via.u64);
#endif
        ret = set_avro_integer(val, 0, o->via.u64, FLB_TRUE);

        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
#if defined(PRIi64)
        flb_debug("got a negint: %" PRIi64 "\n", o->via.i64);
#else
        flb_debug("got a negint: %ld\n", (signed long) o->via.i64);
#endif
        ret = set_avro_integer(val, o->via.i64, 0, FLB_FALSE);
        break;

    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        flb_debug("got a float: %f\n", o->via.f64);
        if (avro_value_get_type(val) == AVRO_DOUBLE) {
            ret = do_avro(avro_value_set_double(val, o->via.f64), "failed on double");
        }
        else {
            ret = do_avro(avro_value_set_float(val, o->via.f64), "failed on float");
        }
        break;

    case MSGPACK_OBJECT_STR: 
        {
            flb_debug("got a string: \"");

            if (flb_log_check(FLB_LOG_DEBUG))
                fwrite(o->via.str.ptr, o->via.str.size, 1, stderr);
            flb_debug("\"\n");

            flb_debug("setting string:%.*s:\n", o->via.str.size, o->via.str.ptr);
            flb_sds_t cstr = flb_sds_create_len(o->via.str.ptr, o->via.str.size);
            if (cstr == NULL) {
                return -1;
            }
            ret = do_avro(avro_value_set_string_len(val, cstr, flb_sds_len(cstr) + 1), "failed on string");
            flb_sds_destroy(cstr);
            flb_debug("set string\n");
        }
        break;

    case MSGPACK_OBJECT_BIN:
        flb_debug("got a binary\n");
        ret = do_avro(avro_value_set_bytes(val, (void *)o->via.bin.ptr, o->via.bin.size), "failed on bin");
        break;

    case MSGPACK_OBJECT_EXT:
#if defined(PRIi8)
        flb_debug("got an ext: %" PRIi8 ")", o->via.ext.type);
#else
        flb_debug("got an ext: %d)", (int)o->via.ext.type);
#endif
        ret = do_avro(avro_value_set_bytes(val, (void *)o->via.bin.ptr, o->via.bin.size), "failed on ext");
        break;

    case MSGPACK_OBJECT_ARRAY:
        if (avro_value_get_type(val) != AVRO_ARRAY) {
            return FLB_FALSE;
        }
        ret = FLB_TRUE;
        for (i = 0; i < o->via.array.size; i++) {
            if (avro_value_append(val, &element, NULL) != 0) {
                return -1;
            }
            ret = flb_msgpack_to_avro(&element, &o->via.array.ptr[i]);
            if (ret != FLB_TRUE) {
                return ret;
            }
        }
        break;

    case MSGPACK_OBJECT_MAP:
        ret = msgpack_map_to_avro(val, o);
        break;

    default:
        // FIXME
#if defined(PRIu64)
        flb_warn(" #<UNKNOWN %i %" PRIu64 ">\n", o->type, o->via.u64);
#else
        if (o.via.u64 > ULONG_MAX)
           flb_warn(" #<UNKNOWN %i over 4294967295>", o->type);
        else
            flb_warn(" #<UNKNOWN %i %lu>", o.type, (unsigned long)o->via.u64);
#endif
        // noop
        break;
    }

    return ret;

}

/**
 *  convert msgpack to an avro object.
 *  it will fill the avro value with whatever comes in from the msgpack
 *  instantiate the avro value properly according to avro-c style
 *    - avro_schema_from_json_literal
 *    - avro_generic_class_from_schema
 *    - avro_generic_value_new 
 * 
 *  or use flb_avro_init for the initialization
 * 
 *  refer to avro docs
 *     http://avro.apache.org/docs/current/api/c/index.html#_avro_values
 *
 *  @param  val       An initialized avro value, an instiatied instance of the class to be unpacked.
 *  @param  data      The msgpack_unpacked data.
 *  @return success   FLB_TRUE on success
 */
int flb_msgpack_to_avro(avro_value_t *val, msgpack_object *o)
{
    int ret = -1;

    if (val == NULL || o == NULL) {
        flb_error("flb_msgpack_to_avro called with NULL\n");
        return ret;
    }

    ret = msgpack2avro(val, o);

    return ret;
}

/* Report exact framed size before writing so callers can grow their buffer. */
int flb_msgpack_raw_to_avro_status(const void *in_buf, size_t in_size,
                                  struct flb_avro_fields *ctx,
                                  char *out_buff, size_t *out_size)
{
    int ret;
    int unpack_errno;
    size_t required_size;
    msgpack_unpack_return unpack_ret;
    msgpack_unpacked result;
    avro_writer_t writer = NULL;
    avro_value_t value;
    avro_value_iface_t *iface;
    avro_schema_t schema;
    unsigned char header[5];

    if (ctx->schema_id <= 0) {
        return FLB_FALSE;
    }
    ret = avro_init_status(&value, ctx->schema_str, flb_sds_len(ctx->schema_str),
                           &schema, &iface);
    if (ret != FLB_TRUE) {
        return ret;
    }
    msgpack_unpacked_init(&result);
    /* The unpacker also uses NOMEM for its fixed nesting limit. Only an
     * allocator failure sets ENOMEM; clear stale errno before decoding.
     */
    errno = 0;
    unpack_ret = msgpack_unpack_next(&result, in_buf, in_size, NULL);
    unpack_errno = errno;
    if (unpack_ret != MSGPACK_UNPACK_SUCCESS) {
        ret = unpack_ret == MSGPACK_UNPACK_NOMEM_ERROR && unpack_errno == ENOMEM ?
              -1 : FLB_FALSE;
        goto cleanup;
    }
    ret = flb_msgpack_to_avro(&value, &result.data);
    if (ret != FLB_TRUE) {
        goto cleanup;
    }
    ret = avro_value_sizeof(&value, &required_size);
    if (ret != 0) {
        ret = ret == ENOMEM ? -1 : FLB_FALSE;
        goto cleanup;
    }
    if (required_size > SIZE_MAX - sizeof(header)) {
        ret = FLB_FALSE;
        goto cleanup;
    }
    required_size += sizeof(header);
    if (*out_size < required_size) {
        *out_size = required_size;
        ret = FLB_AVRO_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    writer = avro_writer_memory(out_buff, *out_size);
    if (writer == NULL) {
        ret = -1;
        goto cleanup;
    }
    header[0] = 0;
    header[1] = (ctx->schema_id >> 24) & 0xff;
    header[2] = (ctx->schema_id >> 16) & 0xff;
    header[3] = (ctx->schema_id >> 8) & 0xff;
    header[4] = ctx->schema_id & 0xff;
    ret = avro_write(writer, header, sizeof(header));
    if (ret == 0) {
        ret = avro_value_write(writer, &value);
    }
    if (ret != 0) {
        ret = ret == ENOMEM ? -1 : FLB_FALSE;
        goto cleanup;
    }
    *out_size = avro_writer_tell(writer);
    ret = FLB_TRUE;
cleanup:
    if (writer != NULL) {
        avro_writer_free(writer);
    }
    msgpack_unpacked_destroy(&result);
    avro_value_decref(&value);
    avro_value_iface_decref(iface);
    avro_schema_decref(schema);
    return ret;
}

/** Compatibility wrapper: only a fully written Avro frame counts as success. */
bool flb_msgpack_raw_to_avro_sds(const void *in_buf, size_t in_size,
                                  struct flb_avro_fields *ctx,
                                  char *out_buff, size_t *out_size)
{
    return flb_msgpack_raw_to_avro_status(in_buf, in_size, ctx, out_buff, out_size) == FLB_TRUE;
}
