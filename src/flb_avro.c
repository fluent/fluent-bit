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
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_avro.h>

static inline int do_avro(bool call, const char *msg) {
    if (call) {
            flb_error("%s:\n  %s\n", msg, avro_strerror());
            return FLB_FALSE;
    }
    return FLB_TRUE;
}

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

int msgpack2avro(avro_value_t *val, msgpack_object *o)
{
    int ret = FLB_FALSE;
    flb_debug("in msgpack2avro\n");

    assert(val != NULL);
    assert(o != NULL);

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
        ret = do_avro(avro_value_set_int(val, o->via.u64), "failed on posint");
#else
        if (o.via.u64 > ULONG_MAX)
            flb_warn("over \"%lu\"", ULONG_MAX);
            ret = do_avro(avro_value_set_int(val, ULONG_MAX), "failed on posint");
        else
            flb_debug("got a posint: %lu\n", (unsigned long)o->via.u64);
            ret = do_avro(avro_value_set_int(val, o->via.u64), "failed on posint");
#endif

        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
#if defined(PRIi64)
        flb_debug("got a negint: %" PRIi64 "\n", o->via.i64);
        ret = do_avro(avro_value_set_int(val, o->via.i64), "failed on negint");
#else
        if (o->via.i64 > LONG_MAX)
            flb_warn("over +\"%ld\"", LONG_MAX);
            ret = do_avro(avro_value_set_int(val, LONG_MAX), "failed on negint");
        else if (o->via.i64 < LONG_MIN)
            flb_warn("under -\"%ld\"", LONG_MIN);
            ret = do_avro(avro_value_set_int(val, LONG_MIN), "failed on negint");
        else
            flb_debug("got a negint: %ld\n", (signed long)o->via.i64);
            ret = do_avro(avro_value_set_int(val, o->via.i64), "failed on negint");
#endif
        break;

    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        flb_debug("got a float: %f\n", o->via.f64);
        ret = do_avro(avro_value_set_float(val, o->via.f64), "failed on float");
        break;

    case MSGPACK_OBJECT_STR: 
        {
            flb_debug("got a string: \"");

            if (flb_log_check(FLB_LOG_DEBUG))
                fwrite(o->via.str.ptr, o->via.str.size, 1, stderr);
            flb_debug("\"\n");

            flb_debug("setting string:%.*s:\n", o->via.str.size, o->via.str.ptr);
            flb_sds_t cstr = flb_sds_create_len(o->via.str.ptr, o->via.str.size);
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
        {

            flb_debug("got a array:size:%u:\n", o->via.array.size);
            if(o->via.array.size != 0) {
                msgpack_object* p = o->via.array.ptr;
                msgpack_object* const pend = o->via.array.ptr + o->via.array.size;
                int i = 0;
                for(; p < pend; ++p) {
                    avro_value_t  element;
                    flb_debug("processing array\n");
                    if (
                        !do_avro(avro_value_append(val, &element, NULL), "Cannot append to array") ||
                        !do_avro(avro_value_get_by_index(val, i++, &element, NULL), "Cannot get element")) {
                        goto msg2avro_end;
                    }
                    ret = flb_msgpack_to_avro(&element, p);
                }
            }
        } 
        break;

    case MSGPACK_OBJECT_MAP:
        flb_debug("got a map\n");
        if(o->via.map.size != 0) {
            msgpack_object_kv* p = o->via.map.ptr;
            msgpack_object_kv* const pend = o->via.map.ptr + o->via.map.size;
            for(; p < pend; ++p) {
                avro_value_t  element;
                if (p->key.type != MSGPACK_OBJECT_STR) {
                    flb_debug("the key of in a map must be string.\n");
                    continue;
                }
                flb_sds_t key = flb_sds_create_len(p->key.via.str.ptr, p->key.via.str.size);
                flb_debug("got key:%s:\n", key);

                if (val == NULL) {
                    flb_debug("got a null val\n");
                    flb_sds_destroy(key);
                    continue;
                }
                // this does not always return 0 for succcess
                if (avro_value_add(val, key, &element, NULL, NULL) != 0) {
                    flb_debug("avro_value_add:key:%s:avro error:%s:\n", key, avro_strerror());
                }
                flb_debug("added\n");

                flb_debug("calling avro_value_get_by_name\n");
                if (!do_avro(avro_value_get_by_name(val, key, &element, NULL), "Cannot get field")) {
                    flb_sds_destroy(key);
                    goto msg2avro_end;
                }
                flb_debug("called avro_value_get_by_index\n");

                ret = flb_msgpack_to_avro(&element, &p->val);

                flb_sds_destroy(key);
            }
        }
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

msg2avro_end:
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

bool flb_msgpack_raw_to_avro_sds(const void *in_buf, size_t in_size, struct flb_avro_fields *ctx, char *out_buff, size_t *out_size)
{
    msgpack_unpacked result;
    msgpack_object *root;

    avro_writer_t awriter;
    flb_debug("in flb_msgpack_raw_to_avro_sds\n");
    flb_debug("schemaID:%d:\n", ctx->schema_id);
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
    unsigned int id = ctx->schema_id;
    unsigned char val[4];
    val[0] = (id >> 24) & 0xFF;
    val[1] = (id >> 16) & 0xFF;
    val[2] = (id >> 8) & 0xFF;
    val[3] = id & 0xFF;
    
    // write it into a buffer which can be passed to librdkafka
    rval = avro_write(awriter, val, 4);
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
