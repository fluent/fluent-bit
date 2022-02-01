/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include "avro/legacy.h"
#include "avro/src/avro/basics.h"
#include "avro/src/avro/errors.h"
#include "avro/value.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_avro.h>

avro_value_iface_t  *flb_avro_init(avro_value_t *aobject, char *json, size_t json_len, avro_schema_t *aschema)
{

    flb_debug("in flb_avro_init:before error:%s:json len:%zu:\n", avro_strerror(), json_len);

    if (avro_schema_from_json_length(json, json_len, aschema)) {
        flb_error("Unable to parse aobject schema:%s:error:%s:\n", json, avro_strerror());
        return NULL;
    }

    avro_value_iface_t  *aclass = avro_generic_class_from_schema(*aschema);

    if(aclass == NULL) {
        flb_error("Unable to instantiate class from schema:%s:\n", avro_strerror());
        return NULL;
    }

    if(avro_generic_value_new(aclass, aobject) != 0) {
        flb_error("Unable to allocate new avro value:%s:\n", avro_strerror());
        return NULL;
    }

    return aclass;
}

// Conversion between msgpack numeric types and avro numeric types is tricky:
// There are 3 possible msgpack numeric union fields (f64/i64/u64) and 4 avro
// types.
//
// With avro we have to call the correct `avro_value_set_{type}` function
// based on the schema and pass the correct msgpack union value.
//
// To avoid having to create multiple setters, we use a macro to set any msgpack
// numeric value into the correct avro slot.
#define SET_AVRO_NUMBER(avro_val, msgpack_val, ret)             \
    switch (avro_value_get_type(avro_val)) {                    \
        case AVRO_INT32:                                        \
            ret = avro_value_set_int(avro_val, msgpack_val);    \
            break;                                              \
        case AVRO_INT64:                                        \
            ret = avro_value_set_long(avro_val, msgpack_val);   \
            break;                                              \
        case AVRO_FLOAT:                                        \
            ret = avro_value_set_float(avro_val, msgpack_val);  \
            break;                                              \
        default:                                                \
            ret = avro_value_set_double(avro_val, msgpack_val); \
            break;                                              \
    }

int msgpack2avro(avro_value_t *val, msgpack_object *o)
{
    avro_value_t element;
    avro_type_t type;
    msgpack_object key;
    flb_sds_t cstr;
    int ret;
    int i;

    assert(val != NULL);
    assert(o != NULL);

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        ret = avro_value_set_null(val);
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        ret = avro_value_set_boolean(val, o->via.boolean);
        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        SET_AVRO_NUMBER(val, o->via.u64, ret);
        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        SET_AVRO_NUMBER(val, o->via.i64, ret);
        break;

    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        SET_AVRO_NUMBER(val, o->via.f64, ret);
        break;

    case MSGPACK_OBJECT_STR: 
        cstr = flb_sds_create_len(o->via.str.ptr, o->via.str.size);
        ret = avro_value_set_string_len(val, cstr, o->via.str.size + 1);
        flb_sds_destroy(cstr);
        break;

    case MSGPACK_OBJECT_BIN:
        ret = avro_value_set_bytes(val, (void *)o->via.bin.ptr, o->via.bin.size);
        break;

    case MSGPACK_OBJECT_EXT:
        ret = avro_value_set_bytes(val, (void *)o->via.ext.ptr, o->via.ext.size);
        break;

    case MSGPACK_OBJECT_ARRAY: 
        for (i = 0; i < o->via.array.size; i++) {
            ret = avro_value_append(val, &element, NULL);
            if (ret) {
                flb_error("failed to append to avro array: %s", avro_strerror());
                break;
            }
            ret = msgpack2avro(&element, o->via.array.ptr + i);
            if (ret) {
                break;
            }
        }
        break;

    case MSGPACK_OBJECT_MAP:
        type = avro_value_get_type(val);
        for (i = 0; i < o->via.map.size; i++) {
            key = o->via.map.ptr[i].key;
            if (key.type != MSGPACK_OBJECT_STR) {
                flb_error("the key of in a map must be string for avro");
                ret = -1;
                break;
            }
            cstr = flb_sds_create_len(key.via.str.ptr, key.via.str.size);
            if (type == AVRO_MAP) {
                ret = avro_value_add(val, cstr, &element, NULL, NULL);
            } else if (type == AVRO_RECORD) {
                ret = avro_value_get_by_name(val, cstr, &element, NULL);
            } else {
                ret = -1;
                flb_error("unexpected avro type to convert from msgpack: %d", type);
            }
            if (ret) {
                flb_error("failed to access avro map/record key \"%s\": %s", cstr, avro_strerror());
                flb_sds_destroy(cstr);
                break;
            }
            flb_sds_destroy(cstr);

            ret = msgpack2avro(&element, &o->via.map.ptr[i].val);
        }
        break;

    default:
        flb_error("invalid msgpack type %d", o->type);
        ret = -1;
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

    return msgpack2avro(val, o);
}

bool flb_msgpack_raw_to_avro_sds(const void *in_buf, size_t in_size, struct flb_avro_fields *ctx, char *out_buff, size_t *out_size)
{
    msgpack_unpacked result;
    msgpack_object *root;

    avro_writer_t awriter;
    flb_debug("in flb_msgpack_raw_to_avro_sds\n");
    flb_debug("schemaID:%s:\n", ctx->schema_id);
    flb_debug("schema string:%s:\n", ctx->schema_str);

    size_t schema_json_len = flb_sds_len(ctx->schema_str);

    avro_value_t  aobject;

    assert(in_buf != NULL);

    avro_value_iface_t  *aclass = NULL;
    avro_schema_t aschema;

    aclass = flb_avro_init(&aobject, (char *)ctx->schema_str, schema_json_len, &aschema);

    if (!aclass) {
        flb_error("Failed init avro:%s:n", avro_strerror());
        return false;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, in_buf, in_size, NULL) != MSGPACK_UNPACK_SUCCESS) {
        flb_error("msgpack_unpack problem\n");
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        return false;
    }

    root = &result.data;

    // create the avro object
    // then serialize it into a buffer for the downstream
    flb_debug("calling flb_msgpack_to_avro\n");

    if (flb_msgpack_to_avro(&aobject, root) != FLB_TRUE) {
        flb_errno();
        flb_error("Failed msgpack to avro\n");
        msgpack_unpacked_destroy(&result);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        return false;
    }

    flb_debug("before avro_writer_memory\n");
    awriter = avro_writer_memory(out_buff, *out_size);
    if (awriter == NULL) {
        flb_error("Unable to init avro writer\n");
        msgpack_unpacked_destroy(&result);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        return false;
    }

    // write the magic byte stuff
    //  write one bye of \0
    //  this is followed by
    //  16 bytes of the schemaid where the schemaid is in hex
    //  in this implementation the schemaid is the md5hash of the avro schema
    int rval;
    rval = avro_write(awriter, "\0", 1);
    if (rval != 0) {
        flb_error("Unable to write magic byte\n");
        avro_writer_free(awriter);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&result);
        return false;
    }

    // write the schemaid
    // its md5hash of the avro schema
    // it looks like this c4b52aaf22429c7f9eb8c30270bc1795
    const char *pos = ctx->schema_id;
    unsigned char val[16];
    size_t count;
    for (count = 0; count < sizeof val/sizeof *val; count++) {
            sscanf(pos, "%2hhx", &val[count]);
            pos += 2;
    }
    
    // write it into a buffer which can be passed to librdkafka
    rval = avro_write(awriter, val, 16);
    if (rval != 0) {
        flb_error("Unable to write schemaid\n");
        avro_writer_free(awriter);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&result);
        return false;
    }

    if (avro_value_write(awriter, &aobject)) {
        flb_error("Unable to write avro value to memory buffer\nMessage: %s\n", avro_strerror());
        avro_writer_free(awriter);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&result);
        return false;
    }

    // null terminate it
    avro_write(awriter, "\0", 1);

    flb_debug("before avro_writer_flush\n");

    avro_writer_flush(awriter);

    int64_t bytes_written = avro_writer_tell(awriter);

    // by here the entire object should be fully serialized into the sds buffer
    avro_writer_free(awriter);
    avro_value_decref(&aobject);
    avro_value_iface_decref(aclass);
    avro_schema_decref(aschema);
    msgpack_unpacked_destroy(&result);
 
    flb_debug("after memory free:bytes written:%zu:\n", bytes_written);
    *out_size = bytes_written;

    return true;

}
