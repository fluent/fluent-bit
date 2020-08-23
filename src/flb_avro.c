/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

// https://stackoverflow.com/questions/11749386/implement-own-memory-pool
// AVRO_POOL * avro_pool_create( size_t size ) {
//     AVRO_POOL * p = (AVRO_POOL*)malloc( size + sizeof(AVRO_POOL) );
//     p->next = (char*)&p[1];
//     p->end = p->next + size;
//     return p;
// }

// void avro_pool_destroy( AVRO_POOL *p ) {
//     free(p);
// }

// size_t avro_pool_available( AVRO_POOL *p ) {
//     return p->end - p->next;
// }

// void * avro_pool_alloc( AVRO_POOL *p, size_t size ) {
//     if( avro_pool_available(p) < size ) return NULL;
//     void *mem = (void*)p->next;
//     p->next += size;
//     return mem;
// }


// https://codereview.stackexchange.com/questions/48919/simple-memory-pool-using-no-extra-memory
int mp_init(Memory_Pool *mp, size_t size, size_t slots)
{
    //allocate memory
    if((mp->memory = malloc(size * slots)) == NULL)
        return MEMORY_POOL_ERROR;

    //initialize
    mp->head = NULL;

    //add every slot to the list
    char *end = (char *)mp->memory + size * slots;
    char *ite = NULL;
    // for(char *ite = mp->memory; ite < end; ite += size)
    for(ite = mp->memory; ite < end; ite += size)
        mp_release(mp, ite);

    return MEMORY_POOL_SUCCESS;
}

void mp_destroy(Memory_Pool *mp)
{
    free(mp->memory);
}

void *mp_get(Memory_Pool *mp)
{
    if(mp->head == NULL)
        return NULL;

    //store first address
    void *temp = mp->head;

    //link one past it
    mp->head = *mp->head;

    //return the first address
    return temp;
}

void mp_release(Memory_Pool *mp, void *mem)
{
    //store first address
    void *temp = mp->head;

    //link new node
    mp->head = mem;

    //link to the list from new node
    *mp->head = temp;
}

static inline int do_avro(bool call, const char *msg) {
    if (call) {
            fprintf(stderr, "%s:\n  %s\n", msg, avro_strerror());
            return FLB_FALSE;
    }
    return FLB_TRUE;
}

/*
 * ud points to a AVRO_POOL
 */
void *
flb_avro_allocatorqqq(void *ud, void *ptr, size_t osize, size_t nsize)
{

    assert(ud != NULL);
    // assert(ptr != NULL);

    // AVRO_POOL *pool = (AVRO_POOL *)ud;

    Memory_Pool * mp = (Memory_Pool *)ud;

    // fprintf(stderr, "alloc(%p, %" PRIsz ", %" PRIsz ") => ", ptr, osize, nsize);
    if (nsize == 0) {
        // fprintf(stderr, "don't free anything. do that later in the caller\n");
        mp_release(mp, ptr);
        return NULL;
    } else {
        // fprintf(stderr, "realloc:ud:%p:\n", ud);
        // return avro_pool_alloc(pool, nsize);
        return mp_get(mp);
    }
}

avro_value_iface_t  *flb_avro_init(avro_value_t *aobject, char *json, size_t json_len, avro_schema_t *aschema)
{

    // fprintf(stderr, "before:error:%s:json len:%zu:\n", avro_strerror(), json_len);

	if (avro_schema_from_json_length(json, json_len, aschema)) {
		fprintf(stderr, "Unable to parse aobject schema:%s:error:%s:\n", json, avro_strerror());
		return NULL;
	}

   avro_value_iface_t  *aclass = avro_generic_class_from_schema(*aschema);

    if(aclass == NULL) {
        fprintf(stderr, "Unable to instantiate class from schema:%s:\n", avro_strerror());
		return NULL;
    }

    if(avro_generic_value_new(aclass, aobject) != 0) {
 		fprintf(stderr, "Unable to allocate new avro value:%s:\n", avro_strerror());
		return NULL;
    }

    return aclass;
}

// /*
//  * void *ud points to a POOL
//  */
// void *
// flb_avro_allocator(void *ud, void *ptr, size_t osize, size_t nsize)
// {
//     // POOL *pool = (POOL *)ud;

//         fprintf(stderr, "alloc(%p, %" PRIsz ", %" PRIsz ") => ", ptr, osize, nsize);
//         if (nsize == 0) {
//             fprintf(stderr, "don't free anything. do that later in the caller\n");
//             flb_free(ptr);
//             return NULL;
//         } else {
//             fprintf(stderr, "realloc:ud:%p:\n", ud);
//             return flb_realloc_z(ptr, osize, nsize);
//         }
// }
// void *
// flb_avro_allocator22(void *ud, void *ptr, size_t osize, size_t nsize)
// {

// #if SHOW_ALLOCATIONS
//         fprintf(stderr, "alloc(%p, %" PRIsz ", %" PRIsz ") => ", ptr, osize, nsize);
// #endif

//         if (nsize == 0) {
//                 size_t  *size = ((size_t *) ptr) - 1;
//                 if (osize != *size) {
//                         fprintf(stderr,
// #if SHOW_ALLOCATIONS
//                                 "ERROR!\n"
// #endif
//                                 "Error freeing %p:\n"
//                                 "Size passed to avro_free (%" PRIsz ") "
//                                 "doesn't match size passed to "
//                                 "avro_malloc (%" PRIsz ")\n",
//                                 ptr, osize, *size);
//                         exit(EXIT_FAILURE);
//                 }
//                 free(size);
// #if SHOW_ALLOCATIONS
//                 fprintf(stderr, "NULL\n");
// #endif
//                 return NULL;
//         } else {
//                 size_t  real_size = nsize + sizeof(size_t);
//                 size_t  *old_size = ptr? ((size_t *) ptr)-1: NULL;
//                 size_t  *size = (size_t *) realloc(old_size, real_size);
//                 *size = nsize;
// #if SHOW_ALLOCATIONS
//                 fprintf(stderr, "%p\n", (size+1));
// #endif
//                 return (size + 1);
//         }
// }

int msgpack2avro(avro_value_t *val, msgpack_object *o)
{
    int ret = FLB_FALSE;
    fprintf(stderr, "DEBUG: in msgpack2avro\n");

    assert(val != NULL);
    assert(o != NULL);

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        fprintf(stderr, "DEBUG: got a nil:\n");
        ret = do_avro(avro_value_set_null(val), "failed on nil");
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        fprintf(stderr, "DEBUG: got a bool:%s:\n", (o->via.boolean ? "true" : "false"));
        ret = do_avro(avro_value_set_boolean(val, o->via.boolean), "failed on bool");
        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        //  for reference src/objectc.c +/msgpack_pack_object
#if defined(PRIu64)
        // msgpack_pack_fix_uint64
        fprintf(stderr, "DEBUG: got a posint: %" PRIu64 "\n", o->via.u64);
        ret = do_avro(avro_value_set_int(val, o->via.u64), "failed on posint");
#else
        if (o.via.u64 > ULONG_MAX)
            fprintf(stderr, "WARNING: over 4294967295");
        else
            fprintf(stderr, "DEBUG: got a posint: %lu\n", (unsigned long)o->via.u64);
            ret = do_avro(avro_value_set_int(val, o->via.u64), "failed on posint");
#endif

        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
#if defined(PRIi64)
        fprintf(stderr, "DEBUG: got a negint: %" PRIi64 "\n", o->via.i64);
        ret = do_avro(avro_value_set_int(val, o->via.i64), "failed on negint");
#else
        if (o->via.i64 > LONG_MAX)
            fprintf(stderr, "WARNING: over +2147483647");
        else if (o->via.i64 < LONG_MIN)
            fprintf(stderr, "WARNING: under -2147483648");
        else
            fprintf(stderr, "DEBUG: got a negint: %ld\n", (signed long)o->via.i64);
            ret = do_avro(avro_value_set_int(val, o->via.i64), "failed on negint");

#endif
        break;

    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        fprintf(stderr, "DEBUG: got a float: %f\n", o->via.f64);
        ret = do_avro(avro_value_set_float(val, o->via.f64), "failed on float");
        break;

    case MSGPACK_OBJECT_STR: 
        {
            fprintf(stderr, "DEBUG: got a string: \"");

            // msgpack_object_print(stdout, *o);

            fwrite(o->via.str.ptr, o->via.str.size, 1, stderr);
            fprintf(stderr, "\"\n");
            // flb_sds_t key = flb_sds_create_len(o->via.str.ptr, o->via.str.size);
            fprintf(stderr, "setting string\n");
            // ret = do_avro(avro_value_set_string(val, key), "failed on string");
            ret = do_avro(avro_value_set_string_len(val, o->via.str.ptr, o->via.str.size), "failed on string");
            fprintf(stderr, "set string\n");

            // flb_sds_destroy(key);
                        // fprintf(stderr, "destroyed string\n");

        }
        break;

    case MSGPACK_OBJECT_BIN:
        fprintf(stderr, "DEBUG: got a binary\n");
        ret = do_avro(avro_value_set_bytes(val, o->via.bin.ptr, o->via.bin.size), "failed on bin");
        break;

    case MSGPACK_OBJECT_EXT:
#if defined(PRIi8)
        fprintf(stderr, "DEBUG: got an ext: %" PRIi8 ")", o->via.ext.type);
#else
        fprintf(stderr, "DEBUG: got an ext: %d)", (int)o->via.ext.type);
#endif
        ret = do_avro(avro_value_set_bytes(val, o->via.bin.ptr, o->via.bin.size), "failed on ext");
        break;

    case MSGPACK_OBJECT_ARRAY: 
        {

            fprintf(stderr, "DEBUG: got a array:size:%u:\n", o->via.array.size);
            if(o->via.array.size != 0) {
                msgpack_object* p = o->via.array.ptr;
                msgpack_object* const pend = o->via.array.ptr + o->via.array.size;
                int i = 0;
                for(; p < pend; ++p) {
                    avro_value_t  element;
                    fprintf(stderr, "DEBUG: processing array\n");
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
        fprintf(stderr, "DEBUG: got a map\n");
        if(o->via.map.size != 0) {
            msgpack_object_kv* p = o->via.map.ptr;
            msgpack_object_kv* const pend = o->via.map.ptr + o->via.map.size;
            size_t i = 0;

            for(; p < pend; ++p) {
                avro_value_t  element;
    			// size_t  new_index;
	    		// int  is_new = 0;

                flb_sds_t key = flb_sds_create_len(p->key.via.str.ptr, p->key.via.str.size);
                fprintf(stderr, "DEBUG: got key:%s:\n", key);

                if (val == NULL) {
                    fprintf(stderr, "got a null val\n");
                    flb_sds_destroy(key);
                    continue;
                }
                    fprintf(stderr, "calling avro_value_add\n");

                // this does not always return 0 for succcess
                // if (avro_value_add(val, key, &element, &new_index, &is_new) != 0) {
                // if (avro_value_add(val, p->key.via.str.ptr, &element, NULL, NULL) != 0) {
                if (avro_value_add(val, key, &element, NULL, NULL) != 0) {
                    fprintf(stderr, "avro_value_add:key:%s:avro error:%s:\n", key, avro_strerror());
                    // fprintf(stderr, "avro_value_add:key:%s:avro error:%s:\n", p->key.via.str.ptr, avro_strerror());
                }
                    fprintf(stderr, "added\n");

                // if (is_new) {
    			// 	fprintf(stderr, "Expected non-new element\n");
		    	// }

                // if (new_index != i) {
    			// 	fprintf(stderr, "Unexpected index:index:%d:new_index:%d:\n", i, new_index);
	    		// }
                    fprintf(stderr, "calling avro_value_get_by_index\n");

                if (!do_avro(avro_value_get_by_index(val, i++, &element, NULL), "Cannot get field")) {
                    flb_sds_destroy(key);
                    goto msg2avro_end;
                    // fprintf(stderr, "ignored error\n");
                }
                                    fprintf(stderr, "called avro_value_get_by_index\n");

                ret = flb_msgpack_to_avro(&element, &p->val);

                flb_sds_destroy(key);

            }
        }
        break;

    default:
        // FIXME
#if defined(PRIu64)
        fprintf(stderr, "WARNING: #<UNKNOWN %i %" PRIu64 ">\n", o->type, o->via.u64);
#else
        if (o.via.u64 > ULONG_MAX)
            fprintf(out, "WARNING: #<UNKNOWN %i over 4294967295>", o->type);
        else
            fprintf(out, "WARNING: #<UNKNOWN %i %lu>", o.type, (unsigned long)o->via.u64);
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
 *  or use flb_avro_init for the so do the initialization
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
        fprintf(stderr, "flb_msgpack_to_avro called with NULL\n");
        return ret;
    }

    ret = msgpack2avro(val, o);

    return ret;
}

flb_sds_t flb_msgpack_raw_to_avro_sds(const void *in_buf, size_t in_size, const char *hexstringxx, char* schema_json)
{
    msgpack_unpacked result;
    msgpack_object *root;

    size_t avro_buffer_size = in_size * 3;
    char *out_buff = flb_malloc(avro_buffer_size);

    avro_writer_t awriter;
    size_t schema_json_len = strlen(schema_json);

    fprintf(stderr,  "DEBUG: in flb_msgpack_raw_to_avro_sds\n");

    avro_value_t  aobject;

    assert(in_buf != NULL);

    avro_value_iface_t  *aclass = NULL;
    avro_schema_t aschema;

    aclass = flb_avro_init(&aobject, (char *)schema_json, schema_json_len, &aschema);

    if (!aclass) {
        fprintf(stderr,  "Failed init avro:%s:n", avro_strerror());
        flb_free(out_buff);
        return NULL;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, in_buf, in_size, NULL) != MSGPACK_UNPACK_SUCCESS) {
        fprintf(stderr,  "msgpack_unpack problem\n");
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        flb_free(out_buff);
        return NULL;
    }

    root = &result.data;

    // create the avro object
    // then serialize it into a buffer for the downstream
    fprintf(stderr,  "calling flb_msgpack_to_avro\n");

    if (flb_msgpack_to_avro(&aobject, root) != FLB_TRUE) {
        flb_errno();
        fprintf(stderr,  "Failed msgpack to avro\n");
        msgpack_unpacked_destroy(&result);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        flb_free(out_buff);
        return NULL;
    }

    fprintf(stderr,  "before avro_writer_memory\n");
    awriter = avro_writer_memory(out_buff, avro_buffer_size);
    if (awriter == NULL) {
        fprintf(stderr,  "Unable to init avro writer\n");
        msgpack_unpacked_destroy(&result);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        flb_free(out_buff);
        return NULL;
    }

    // write the magic byte stuff
    //  write one bye of \0
    //  write 16 bytes schemaid where the schemaid is hex for the written bytes
    int rval;
    rval = avro_write(awriter, "\0", 1);
    if (rval != 0) {
        fprintf(stderr,  "Unable to write magic byte\n");
        avro_writer_free(awriter);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&result);
        flb_free(out_buff);
        return NULL;
    }

    // write the schemaid
    const char *pos = hexstringxx;
    unsigned char val[16];
    size_t count;
    for (count = 0; count < sizeof val/sizeof *val; count++) {
            sscanf(pos, "%2hhx", &val[count]);
            pos += 2;
    }
    
    // write it into a buffer which can be passed to librdkafka
    rval = avro_write(awriter, val, 16);
    if (rval != 0) {
        fprintf(stderr,  "Unable to write schemaid\n");
        avro_writer_free(awriter);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&result);
        flb_free(out_buff);
        return NULL;
    }

	if (avro_value_write(awriter, &aobject)) {
		fprintf(stderr,
			"Unable to write avro value to memory buffer\nMessage: %s\n", avro_strerror());
        avro_writer_free(awriter);
        avro_value_decref(&aobject);
        avro_value_iface_decref(aclass);
        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&result);
        flb_free(out_buff);
		return NULL;
	}

    fprintf(stderr,  "before avro_writer_flush\n");

    avro_writer_flush(awriter);

    int64_t bytes_written = avro_writer_tell(awriter);

    // by here the entire object should be fully serialized into the sds buffer
    avro_writer_free(awriter);
    avro_value_decref(&aobject);
	avro_value_iface_decref(aclass);
    avro_schema_decref(aschema);
    msgpack_unpacked_destroy(&result);
 
    fprintf(stderr,  "after memory free:bytes written:%zu:\n", bytes_written);

    flb_sds_t qqq =  flb_sds_create_len(out_buff, bytes_written + 1);

    flb_free(out_buff);

    fprintf(stderr, "shrunk flb sds:\n");
    fprintf(stderr,  "sds len:%zu:\n", flb_sds_len(qqq));
    fprintf(stderr,  "sds alloc:%zu:\n", flb_sds_alloc(qqq));
    fprintf(stderr,  "sds avail:%zu:\n", flb_sds_avail(qqq));

    return qqq;

}