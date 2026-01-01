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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>

#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_conditionals.h>

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <msgpack.h>
#include <mpack/mpack.h>

/* don't do this at home */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

/* Return the number of msgpack serialized events in the buffer */
int flb_mp_count(const void *data, size_t bytes)
{
    return flb_mp_count_remaining(data, bytes, NULL);
}

int flb_mp_count_remaining(const void *data, size_t bytes, size_t *remaining_bytes)
{
    size_t remaining;
    int count = 0;
    mpack_reader_t reader;

    mpack_reader_init_data(&reader, (const char *) data, bytes);
    for (;;) {
        remaining = mpack_reader_remaining(&reader, NULL);
        if (!remaining) {
            break;
        }
        mpack_discard(&reader);
        if (mpack_reader_error(&reader)) {
            break;
        }
        count++;
    }

    if (remaining_bytes) {
        *remaining_bytes = remaining;
    }
    mpack_reader_destroy(&reader);
    return count;
}

int flb_mp_validate_metric_chunk(const void *data, size_t bytes,
                                 int *out_series, size_t *processed_bytes)
{
    int ret;
    int ok = CMT_DECODE_MSGPACK_SUCCESS;
    int count = 0;
    size_t off = 0;
    size_t pre_off = 0;
    struct cmt *cmt;

    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) data, bytes, &off)) == ok) {
        cmt_destroy(cmt);
        count++;
        pre_off = off;
    }

    switch (ret) {
        case CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR:
        case CMT_DECODE_MSGPACK_CORRUPT_INPUT_DATA_ERROR:
        case CMT_DECODE_MSGPACK_CONSUME_ERROR:
        case CMT_DECODE_MSGPACK_ENGINE_ERROR:
        case CMT_DECODE_MSGPACK_PENDING_MAP_ENTRIES:
        case CMT_DECODE_MSGPACK_PENDING_ARRAY_ENTRIES:
        case CMT_DECODE_MSGPACK_UNEXPECTED_KEY_ERROR:
        case CMT_DECODE_MSGPACK_UNEXPECTED_DATA_TYPE_ERROR:
        case CMT_DECODE_MSGPACK_DICTIONARY_LOOKUP_ERROR:
        case CMT_DECODE_MSGPACK_VERSION_ERROR:
            goto error;
    }

    if (ret == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA && off == bytes) {
        *out_series = count;
        *processed_bytes = pre_off;
        return 0;
    }

error:
    *out_series = count;
    *processed_bytes = pre_off;

    return -1;
}

int flb_mp_validate_log_chunk(const void *data, size_t bytes,
                              int *out_records, size_t *processed_bytes)
{
    int ret;
    int count = 0;
    size_t off = 0;
    size_t pre_off = 0;
    size_t ptr_size;
    unsigned char *ptr;
    msgpack_object array;
    msgpack_object ts;
    msgpack_object header;
    msgpack_object record;
    msgpack_object metadata;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array = result.data;

        if (array.type != MSGPACK_OBJECT_ARRAY) {
            /*
             * Sometimes there is a special case: Chunks might have extra zero
             * bytes at the end of a record, meaning: no more records. This is not
             * an error and actually it happens if a previous run of Fluent Bit
             * was stopped/killed before to adjust the file size.
             *
             * Just validate if all bytes are zero, if so, adjust counters
             * and return zero.
             */
            ptr = (unsigned char *) (data);
            ptr += pre_off;
            if (ptr[0] != 0) {
                goto error;
            }

            ptr_size = bytes - pre_off;
            ret = memcmp(ptr, ptr + 1, ptr_size - 1);
            if (ret == 0) {
                /*
                 * The chunk is valid, just let the caller know the last processed
                 * valid byte.
                 */
                msgpack_unpacked_destroy(&result);
                *out_records = count;
                *processed_bytes = pre_off;
                return 0;
            }
            goto error;
        }

        if (array.via.array.size != 2) {
            goto error;
        }

        header = array.via.array.ptr[0];
        record = array.via.array.ptr[1];

        if (header.type == MSGPACK_OBJECT_ARRAY) {
            if (header.via.array.size != 2) {
                goto error;
            }

            ts = header.via.array.ptr[0];
            metadata = header.via.array.ptr[1];

            if (metadata.type != MSGPACK_OBJECT_MAP) {
                goto error;
            }
        }
        else {
            ts = header;
        }

        if (ts.type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
            ts.type != MSGPACK_OBJECT_FLOAT &&
            ts.type != MSGPACK_OBJECT_EXT) {
            goto error;
        }

        if (record.type != MSGPACK_OBJECT_MAP) {
            goto error;
        }

        count++;
        pre_off = off;
    }

    msgpack_unpacked_destroy(&result);
    *out_records = count;
    *processed_bytes = pre_off;
    return 0;

 error:
    msgpack_unpacked_destroy(&result);
    *out_records = count;
    *processed_bytes = pre_off;

    return -1;
}

/* Adjust a mspack header buffer size */
void flb_mp_set_map_header_size(char *buf, int size)
{
    uint8_t h;
    char *tmp = buf;

    h = tmp[0];
    if (h >> 4 == 0x8) { /* 1000xxxx */
        *tmp = (uint8_t) 0x8 << 4 | ((uint8_t) size);
    }
    else if (h == 0xde) {
        tmp++;
        pack_uint16(tmp, size);
    }
    else if (h == 0xdf) {
        tmp++;
        pack_uint32(tmp, size);
    }
}

void flb_mp_set_array_header_size(char *buf, int size)
{
    uint8_t h;
    char *tmp = buf;

    h = tmp[0];
    if (h >> 4 == 0x9) { /* 1001xxxx */
        *tmp = (uint8_t) 0x9 << 4 | ((uint8_t) size);
    }
    else if (h == 0xdc) {
        tmp++;
        pack_uint16(tmp, size);
    }
    else if (h == 0xdd) {
        tmp++;
        pack_uint32(tmp, size);
    }
}

/*
 * msgpack-c requires to set the number of the entries in a map beforehand. For our
 * use case this adds some complexity, having developers to count all possible
 * entries that might be added.
 *
 * As a workaround and to avoid map's recomposition over and over, this simple API
 * allows to initialize the array header, 'register' new entries (as counters) and
 * finalize, upon finalization the proper array header size is adjusted.
 *
 * To make things easier, we make sure msgpack-c always register an array type of
 * 32 bits (identified by 0xdf, for number of entries >= 65536). Yes, for every
 * array using this API it will use 2 more bytes, not a big ideal. So whoever
 * uses this API, use it only if you don't know the exact number of entries to add.
 *
 * MANDATORY: make sure to always initialize, register every entry and finalize,
 * otherwise you will get a corrupted or incomplete msgpack buffer.
 *
 * Usage example
 * =============
 *
 *  struct flb_mp_map_header mh;
 *
 *  flb_mp_map_header_init(&mh, mp_pck);
 *
 *  -- First key/value entry --
 *  flb_mp_map_header_append(&mh);
 *  msgpack_pack_str(mp_pck, 4);
 *  msgpack_pack_str_body(mp_pck, "cool", 4);
 *  msgpack_pack_true(mp_pck);
 *
 *  -- Second key/value entry --
 *  flb_mp_map_header_append(&mh);
 *  msgpack_pack_str(mp_pck, 4);
 *  msgpack_pack_str_body(mp_pck, "slow", 4);
 *  msgpack_pack_false(mp_pck);
 *
 *  -- Finalize Map --
 *  flb_mp_map_header_end(&mh);
 */

static inline void mp_header_type_init(struct flb_mp_map_header *mh,
                                       msgpack_packer *mp_pck,
                                       int type)
{
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = (msgpack_sbuffer *) mp_pck->data;

    /* map sbuffer */
    mh->data = mp_pck->data;

    /* Reset entries */
    mh->entries = 0;

    /* Store the next byte available */
    mh->offset = mp_sbuf->size;
}

int flb_mp_map_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck)
{
    /* Initialize context for a map */
    mp_header_type_init(mh, mp_pck, FLB_MP_MAP);

    /*
     * Pack a map with size = 65536, so we force the underlaying msgpack-c
     * to use a 32 bit buffer size (0xdf), reference:
     *
     * - https://github.com/msgpack/msgpack/blob/master/spec.md#map-format-family
     */
    return msgpack_pack_map(mp_pck, 65536);
}

int flb_mp_array_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck)
{
    /* Initialize context for a map */
    mp_header_type_init(mh, mp_pck, FLB_MP_ARRAY);

    /*
     * Pack a map with size = 65536, so we force the underlaying msgpack-c
     * to use a 32 bit buffer size (0xdf), reference:
     *
     * - https://github.com/msgpack/msgpack/blob/master/spec.md#map-format-family
     */
    return msgpack_pack_array(mp_pck, 65536);
}


int flb_mp_map_header_append(struct flb_mp_map_header *mh)
{
    mh->entries++;
    return mh->entries;
}

int flb_mp_array_header_append(struct flb_mp_map_header *mh)
{
    mh->entries++;
    return mh->entries;
}

void flb_mp_map_header_end(struct flb_mp_map_header *mh)
{
    char *ptr;
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = mh->data;
    ptr = (char *) mp_sbuf->data + mh->offset;
    flb_mp_set_map_header_size(ptr, mh->entries);
}

void flb_mp_array_header_end(struct flb_mp_map_header *mh)
{
    char *ptr;
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = mh->data;
    ptr = (char *) mp_sbuf->data + mh->offset;
    flb_mp_set_array_header_size(ptr, mh->entries);
}

static int insert_by_subkey_count(struct flb_record_accessor *ra, struct flb_mp_accessor *mpa)
{
    int subkey_count;
    int count;
    struct mk_list *head;
    struct flb_mp_accessor_ra *val_ra;
    struct flb_mp_accessor_ra *mp_ra;

    mp_ra = flb_calloc(1, sizeof(struct flb_mp_accessor_ra));
    if (!mp_ra) {
        flb_errno();
        return -1;
    }
    mp_ra->is_active = FLB_TRUE;
    mp_ra->ra = ra;

    /*
     * sort flb_record_accessor by number of subkey
     *
     *  e.g.
     *    $kubernetes
     *    $kubernetes[2]['a']
     *    $kubernetes[2]['annotations']['fluentbit.io/tag']
     */
    subkey_count = flb_ra_subkey_count(ra);
    mk_list_foreach(head, &mpa->ra_list) {
        val_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);
        count = flb_ra_subkey_count(val_ra->ra);
        if (count >=  subkey_count) {
            mk_list_add_before(&mp_ra->_head, &val_ra->_head, &mpa->ra_list);
            return 0;
        }
    }

    /* add to tail of list */
    mk_list_add(&mp_ra->_head, &mpa->ra_list);
    return 0;
}

/* Set the active status for all record accessor patterns */
void flb_mp_accessor_set_active(struct flb_mp_accessor *mpa, int status)
{
    struct mk_list *head;
    struct flb_mp_accessor_ra *mp_ra;

    mk_list_foreach(head, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);
        mp_ra->is_active = status;
    }
}

/* Set the active status for a specific record accessor pattern */
int flb_mp_accessor_set_active_by_pattern(struct flb_mp_accessor *mpa,
                                          const char *pattern, int status)
{
    int len;
    struct mk_list *head;
    struct flb_mp_accessor_ra *mp_ra;

    len = strlen(pattern);

    mk_list_foreach(head, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);

        if (len != flb_sds_len(mp_ra->ra->pattern)) {
            continue;
        }

        if (strcmp(mp_ra->ra->pattern, pattern) == 0) {
            mp_ra->is_active = status;
            return 0;
        }
    }

    return -1;
}

/*
 * Create an 'mp accessor' context: this context allows to create a list of
 * record accessor patterns based on a 'slist' context, where every slist string
 * buffer represents a key accessor.
 */
struct flb_mp_accessor *flb_mp_accessor_create(struct mk_list *slist_patterns)
{
    size_t size;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct flb_record_accessor *ra;
    struct flb_mp_accessor *mpa;

    /* Allocate context */
    mpa = flb_calloc(1, sizeof(struct flb_mp_accessor));
    if (!mpa) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&mpa->ra_list);

    mk_list_foreach(head, slist_patterns) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* Create the record accessor context */
        ra = flb_ra_create(entry->str, FLB_TRUE);
        if (!ra) {
            flb_error("[mp accessor] could not create entry for pattern '%s'",
                      entry->str);
            flb_mp_accessor_destroy(mpa);
            return NULL;
        }
        insert_by_subkey_count(ra, mpa);
    }

    if (mk_list_size(&mpa->ra_list) == 0) {
        return mpa;
    }

    size = sizeof(struct flb_mp_accessor_match) * mk_list_size(&mpa->ra_list);
    mpa->matches_size = size;
    mpa->matches = flb_calloc(1, size);
    if (!mpa->matches) {
        flb_errno();
        flb_mp_accessor_destroy(mpa);
        return NULL;
    }

    return mpa;
}

/**
 * Finds matches for a given key in the list of record accessor patterns.
 * Stores the indexes of the matches in the provided array.
 *
 * @return The number of matches found.
 */
static inline int accessor_key_find_matches(struct flb_mp_accessor *mpa,
                                            msgpack_object *key,
                                            int* matched_indexes)
{
    int i;
    int count;
    int match_count = 0;
    int out_index = 0;
    struct flb_mp_accessor_match *match;

    count = mk_list_size(&mpa->ra_list);
    for (i = 0; i < count; i++) {
        match = &mpa->matches[i];
        if (match->matched == FLB_FALSE) {
            continue;
        }

        if (match->start_key == key) {
            match_count++;
            matched_indexes[out_index++] = i;
        }
    }

    return match_count;
}

static inline int accessor_sub_pack(struct flb_mp_accessor *mpa,
                                    int* matched_indexes,
                                    int match_count,
                                    msgpack_packer *mp_pck,
                                    msgpack_object *key,
                                    msgpack_object *val)
{
    int i;
    int ret;
    msgpack_object *k;
    msgpack_object *v;
    struct flb_mp_map_header mh;
    struct flb_mp_accessor_match *match;

    for (i = 0; i < match_count; i++) {
        match = &mpa->matches[matched_indexes[i]];
        if (match->key == key || match->key == val) {
            return FLB_FALSE;
        }
    }

    if (key) {
        msgpack_pack_object(mp_pck, *key);
    }

    if (val->type == MSGPACK_OBJECT_MAP) {
        flb_mp_map_header_init(&mh, mp_pck);
        for (i = 0; i < val->via.map.size; i++) {
            k = &val->via.map.ptr[i].key;
            v = &val->via.map.ptr[i].val;

            ret = accessor_sub_pack(mpa, matched_indexes, match_count, mp_pck, k, v);
            if (ret == FLB_TRUE) {
                flb_mp_map_header_append(&mh);
            }
        }
        flb_mp_map_header_end(&mh);
    }
    else if (val->type == MSGPACK_OBJECT_ARRAY) {
        flb_mp_array_header_init(&mh, mp_pck);
        for (i = 0; i < val->via.array.size; i++) {
            v = &val->via.array.ptr[i];
            ret = accessor_sub_pack(mpa, matched_indexes, match_count, mp_pck, NULL, v);
            if (ret == FLB_TRUE) {
                flb_mp_array_header_append(&mh);
            }
        }
        flb_mp_array_header_end(&mh);
    }
    else {
        msgpack_pack_object(mp_pck, *val);
    }

    return FLB_TRUE;
}

/*
 * Remove keys or nested keys from a map. It compose the final result in a
 * new buffer. On error, it returns -1, if the map was modified it returns FLB_TRUE,
 * if no modification was required it returns FLB_FALSE.
 */
int flb_mp_accessor_keys_remove(struct flb_mp_accessor *mpa,
                                msgpack_object *map,
                                void **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int rule_id = 0;
    int matches = 0;
    int* matched_indexes;
    msgpack_object *key;
    msgpack_object *val;
    msgpack_object *s_key;
    msgpack_object *o_key;
    msgpack_object *o_val;
    struct mk_list *head;
    struct flb_mp_accessor_match *match;
    struct flb_mp_accessor_ra *mp_ra;
    struct flb_mp_map_header mh;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    if (map->via.map.size == 0) {
        return FLB_FALSE;
    }

    /* Reset matches cache */
    memset(mpa->matches, '\0', mpa->matches_size);

    mk_list_foreach(head, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);

        if (mp_ra->is_active == FLB_FALSE) {
            rule_id++;
            continue;
        }

        /* Apply the record accessor rule against the map */
        ret = flb_ra_get_kv_pair(mp_ra->ra, *map, &s_key, &o_key, &o_val);
        if (ret == 0) {
            /* There is a match, register in the matches table */
            match = &mpa->matches[rule_id];
            match->matched = FLB_TRUE;
            match->start_key = s_key;        /* Initial key path that matched */
            match->key = o_key;              /* Final key that matched */
            match->val = o_val;              /* Final value */
            match->ra = mp_ra->ra;           /* Record accessor context */
            matches++;
        }
        rule_id++;
    }

    /* If no matches, no modifications were made */
    if (matches == 0) {
        return FLB_FALSE;
    }

    /* Some rules matched, compose a new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Initialize map */
    flb_mp_map_header_init(&mh, &mp_pck);

    /* Initialize array of matching indexes to properly handle sibling keys */
    matched_indexes = flb_malloc(sizeof(int) * matches);
    if (!matched_indexes) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < map->via.map.size; i++) {
        key = &map->via.map.ptr[i].key;
        val = &map->via.map.ptr[i].val;

        /*
         * For every entry on the path, check if we should do a step-by-step
         * repackaging or just pack the whole object.
         *
         * Find all matching rules that match this 'key'. Return the number of matches or 0
         * if no matches were found. Found matches are stored in the 'matched_indexes' array.
         */
        ret = accessor_key_find_matches(mpa, key, matched_indexes);
        if (ret == 0) {
            /* No matches, it's ok to pack the kv pair */
            flb_mp_map_header_append(&mh);
            msgpack_pack_object(&mp_pck, *key);
            msgpack_pack_object(&mp_pck, *val);
        }
        else {
            /* The key has a match. Now we do a step-by-step packaging */

            ret = accessor_sub_pack(mpa, matched_indexes, ret, &mp_pck, key, val);
            if (ret == FLB_TRUE) {
                flb_mp_map_header_append(&mh);
            }
        }
    }
    flb_mp_map_header_end(&mh);

    flb_free(matched_indexes);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return FLB_TRUE;
}

void flb_mp_accessor_destroy(struct flb_mp_accessor *mpa)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_mp_accessor_ra *mp_ra;

    if (!mpa) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);
        mk_list_del(&mp_ra->_head);
        flb_ra_destroy(mp_ra->ra);
        flb_free(mp_ra);
    }

    if (mpa->matches) {
        flb_free(mpa->matches);
    }

    flb_free(mpa);
}


static int mp_object_to_cfl(void **ptr, msgpack_object *o)
{
    int i;
    int ret = -1;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    void *var;
    msgpack_object key;
    msgpack_object val;

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        var = cfl_variant_create_from_null();
        if (!var) {
            return -1;
        }
        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_BOOLEAN:
        var = cfl_variant_create_from_bool(o->via.boolean);
        if (!var) {
            return -1;
        }
        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        var = cfl_variant_create_from_uint64(o->via.u64);
        if (!var) {
            return -1;
        }
        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        var = cfl_variant_create_from_int64(o->via.i64);
        if (!var) {
            return -1;
        }
        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        var = cfl_variant_create_from_double(o->via.f64);
        if (!var) {
            return -1;
        }
        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_STR:
        var = cfl_variant_create_from_string_s((char *) o->via.str.ptr,
                                               o->via.str.size, CFL_TRUE);
        if (!var) {
            return -1;
        }
        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_BIN:
        var = cfl_variant_create_from_bytes((char *) o->via.str.ptr,
                                            o->via.str.size, CFL_TRUE);
        if (!var) {
            return -1;
        }

        *ptr = var;
        ret = CFL_OBJECT_VARIANT;
        break;
    case MSGPACK_OBJECT_EXT:
        /* we do not pack extension type content */
        *ptr = NULL;
        ret = CFL_OBJECT_NONE;
        break;
    case MSGPACK_OBJECT_ARRAY:
        array = cfl_array_create(o->via.map.size);
        if (!array) {
            return -1;
        }
        ret = 0;

        for (i = 0; i < o->via.map.size; i++) {
            ret = mp_object_to_cfl((void *) &var, &o->via.array.ptr[i]);
            if (ret == CFL_OBJECT_KVLIST) {
                ret = cfl_array_append_kvlist(array, var);
            }
            else if (ret == CFL_OBJECT_VARIANT) {
                ret = cfl_array_append(array, var);
            }
            else if (ret == CFL_OBJECT_ARRAY) {
                ret = cfl_array_append_array(array, var);
            }
            else {
                ret = -1;
                break;
            }
        }

        if (ret == -1) {
            cfl_array_destroy(array);
            return -1;
        }

        *ptr = array;
        ret = CFL_OBJECT_ARRAY;
        break;
    case MSGPACK_OBJECT_MAP:
        kvlist = cfl_kvlist_create();
        if (!kvlist) {
            return -1;
        }

        ret = 0;
        for (i = 0; i < o->via.map.size; i++) {
            key = o->via.map.ptr[i].key;
            val = o->via.map.ptr[i].val;

            /* force key type to be strin, otherwise just abort */
            if (key.type != MSGPACK_OBJECT_STR) {
                ret = -1;
                break;
            }

            /* key variant is ready, now we need the value variant */
            ret = mp_object_to_cfl((void *) &var, &val);
            if (ret == -1) {
                 break;
            }

            if (ret == CFL_OBJECT_KVLIST) {
                ret = cfl_kvlist_insert_kvlist_s(kvlist,
                                                 (char *) key.via.str.ptr, key.via.str.size,
                                                 var);
            }
            else if (ret == CFL_OBJECT_VARIANT) {
                ret = cfl_kvlist_insert_s(kvlist,
                                          (char *) key.via.str.ptr, key.via.str.size,
                                          var);
            }
            else if (ret == CFL_OBJECT_ARRAY) {
                ret = cfl_kvlist_insert_array_s(kvlist,
                                                (char *) key.via.str.ptr, key.via.str.size,
                                                var);
            }
            else {
                ret = -1;
                break;
            }
        }

        if (ret == -1) {
            cfl_kvlist_destroy(kvlist);
            return -1;
        }

        *ptr = kvlist;
        ret = CFL_OBJECT_KVLIST;
        break;
    default:
        break;
    }

    return ret;
}


/* Convert a msgpack object to a cfl_object */
struct cfl_object *flb_mp_object_to_cfl(msgpack_object *o)
{
    int ret;
    void *out = NULL;
    struct cfl_object *obj;

    /* For now, only allow to convert to map (kvlist) or array */
    if (o->type != MSGPACK_OBJECT_MAP && o->type != MSGPACK_OBJECT_ARRAY) {
        return NULL;
    }

    obj = cfl_object_create();
    if (!obj) {
        return NULL;
    }

    ret = mp_object_to_cfl(&out, o);
    if (ret < 0) {
        cfl_object_destroy(obj);
        return NULL;
    }

    ret = cfl_object_set(obj, ret, out);
    if (ret == -1) {
        if (ret == CFL_OBJECT_KVLIST) {
            cfl_kvlist_destroy(out);
        }
        else if (ret == CFL_OBJECT_ARRAY) {
            cfl_array_destroy(out);
        }
        cfl_object_destroy(obj);
        return NULL;
    }

    return obj;
}

static int mp_cfl_to_msgpack(struct cfl_variant *var,
                             msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck)
{
    int i;
    int ret;
    struct cfl_list *head;
    struct cfl_kvpair *kv;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;
    struct flb_mp_map_header mh;

    switch (var->type) {
        case CFL_VARIANT_BOOL:
            if (var->data.as_bool) {
                msgpack_pack_true(mp_pck);
            }
            else {
                msgpack_pack_false(mp_pck);
            }
            break;
        case CFL_VARIANT_INT:
            msgpack_pack_int64(mp_pck, var->data.as_int64);
            break;
        case CFL_VARIANT_UINT:
            msgpack_pack_uint64(mp_pck, var->data.as_uint64);
            break;
        case CFL_VARIANT_DOUBLE:
            msgpack_pack_double(mp_pck, var->data.as_double);
            break;
        case CFL_VARIANT_NULL:
            msgpack_pack_nil(mp_pck);
            break;
        case CFL_VARIANT_REFERENCE:
            /* we don't save references */
            break;
        case CFL_VARIANT_STRING:
            msgpack_pack_str(mp_pck, cfl_variant_size_get(var));
            msgpack_pack_str_body(mp_pck,
                                  var->data.as_string, cfl_variant_size_get(var));
            break;
        case CFL_VARIANT_BYTES:
            msgpack_pack_bin(mp_pck, cfl_variant_size_get(var));
            msgpack_pack_bin_body(mp_pck,
                                  var->data.as_bytes, cfl_variant_size_get(var));
            break;
        case CFL_VARIANT_ARRAY:
        msgpack_pack_array(mp_pck, var->data.as_array->entry_count);
            for (i = 0; i < var->data.as_array->entry_count; i++) {
                variant = var->data.as_array->entries[i];
                ret = mp_cfl_to_msgpack(variant, mp_sbuf, mp_pck);
                if (ret == -1) {
                    return -1;
                }
            }
            break;
        case CFL_VARIANT_KVLIST:
            kvlist = var->data.as_kvlist;
            flb_mp_map_header_init(&mh, mp_pck);
            cfl_list_foreach(head, &kvlist->list) {
                kv = cfl_list_entry(head, struct cfl_kvpair, _head);

                flb_mp_map_header_append(&mh);

                /* key */
                msgpack_pack_str(mp_pck, cfl_sds_len(kv->key));
                msgpack_pack_str_body(mp_pck, kv->key, cfl_sds_len(kv->key));

                /* value */
                ret = mp_cfl_to_msgpack(kv->val, mp_sbuf,  mp_pck);
                if (ret == -1) {
                    return -1;
                }
            }
            flb_mp_map_header_end(&mh);
            break;
    }

    return 0;
}

/* Convert a CFL Object and serialize it content in a msgpack buffer */
int flb_mp_cfl_to_msgpack(struct cfl_object *obj, char **out_buf, size_t *out_size)
{
    int ret;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    if (!obj) {
        return -1;
    }

    /* unitialized CFL object ? */
    if (obj->type == CFL_OBJECT_NONE) {
        return -1;
    }

    /* initialize msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    ret = mp_cfl_to_msgpack(obj->variant, &mp_sbuf, &mp_pck);
    if (ret == -1) {
        return -1;
    }

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

struct flb_mp_chunk_record *flb_mp_chunk_record_create(struct flb_mp_chunk_cobj *chunk_cobj)
{
    struct flb_mp_chunk_record *record;

    record = flb_calloc(1, sizeof(struct flb_mp_chunk_record));
    if (!record) {
        flb_errno();
        return NULL;
    }
    record->modified = FLB_FALSE;
    record->cobj_group_metadata = NULL;
    record->cobj_group_attributes = NULL;
    record->owns_group_metadata = FLB_FALSE;
    record->owns_group_attributes = FLB_FALSE;

    return record;
}

struct flb_mp_chunk_cobj *flb_mp_chunk_cobj_create(struct flb_log_event_encoder *log_encoder, struct flb_log_event_decoder *log_decoder)
{
    struct flb_mp_chunk_cobj *chunk_cobj;

    if (!log_encoder || !log_decoder) {
        return NULL;
    }

    chunk_cobj = flb_calloc(1, sizeof(struct flb_mp_chunk_cobj));
    if (!chunk_cobj) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&chunk_cobj->records);
    chunk_cobj->record_pos  = NULL;
    chunk_cobj->log_encoder = log_encoder;
    chunk_cobj->log_decoder = log_decoder;
    chunk_cobj->condition   = NULL;
    chunk_cobj->active_group_metadata = NULL;
    chunk_cobj->active_group_attributes = NULL;

    return chunk_cobj;
}

static int generate_empty_msgpack_map(char **out_buf, size_t *out_size)
{
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* initialize msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 0);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_mp_chunk_cobj_encode(struct flb_mp_chunk_cobj *chunk_cobj, char **out_buf, size_t *out_size)
{
    int ret;
    int record_type;
    char *mp_buf;
    size_t mp_size;
    struct cfl_list *head;
    struct flb_mp_chunk_record *record;

    if (!chunk_cobj) {
        return -1;
    }

    /* Iterate all records */
    cfl_list_foreach(head, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);

        ret = flb_log_event_encoder_begin_record(chunk_cobj->log_encoder);
        if (ret == -1) {
            return -1;
        }

        ret = flb_log_event_encoder_set_timestamp(chunk_cobj->log_encoder, &record->event.timestamp);
        if (ret == -1) {
            return -1;
        }

        /* Determine record type from timestamp */
        if (record->event.timestamp.tm.tv_sec >= 0) {
            record_type = FLB_LOG_EVENT_NORMAL;
        }
        else if (record->event.timestamp.tm.tv_sec == FLB_LOG_EVENT_GROUP_START) {
            record_type = FLB_LOG_EVENT_GROUP_START;
        }
        else if (record->event.timestamp.tm.tv_sec == FLB_LOG_EVENT_GROUP_END) {
            record_type = FLB_LOG_EVENT_GROUP_END;
        }
        else {
            record_type = FLB_LOG_EVENT_NORMAL;
        }


        if (record->cobj_metadata) {
            ret = flb_mp_cfl_to_msgpack(record->cobj_metadata, &mp_buf, &mp_size);
            if (ret == -1) {
                return -1;
            }
        }
        else {
            ret = generate_empty_msgpack_map(&mp_buf, &mp_size);
            if (ret == -1) {
                return -1;
            }
        }

        ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(chunk_cobj->log_encoder, mp_buf, mp_size);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_free(mp_buf);
            return -1;
        }
        flb_free(mp_buf);

        /* For group start records, use group attributes as body if available */
        if (record_type == FLB_LOG_EVENT_GROUP_START && record->cobj_group_attributes) {
            ret = flb_mp_cfl_to_msgpack(record->cobj_group_attributes, &mp_buf, &mp_size);
            if (ret == -1) {
                return -1;
            }
        }
        else if (record->cobj_record) {
            ret = flb_mp_cfl_to_msgpack(record->cobj_record, &mp_buf, &mp_size);
            if (ret == -1) {
                return -1;
            }
        }
        else {
            ret = generate_empty_msgpack_map(&mp_buf, &mp_size);
            if (ret == -1) {
                return -1;
            }
        }

        ret = flb_log_event_encoder_set_body_from_raw_msgpack(chunk_cobj->log_encoder, mp_buf, mp_size);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_free(mp_buf);
            return -1;
        }
        flb_free(mp_buf);

        ret = flb_log_event_encoder_commit_record(chunk_cobj->log_encoder);
        if (ret == -1) {
            return -1;
        }
    }

    /* set new output buffer */
    *out_buf = chunk_cobj->log_encoder->output_buffer;
    *out_size = chunk_cobj->log_encoder->output_length;

    flb_log_event_encoder_claim_internal_buffer_ownership(chunk_cobj->log_encoder);
    return 0;
}

int flb_mp_chunk_cobj_destroy(struct flb_mp_chunk_cobj *chunk_cobj)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct flb_mp_chunk_record *record;

    if (!chunk_cobj) {
        return -1;
    }

    cfl_list_foreach_safe(head, tmp, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (record->cobj_metadata) {
            cfl_object_destroy(record->cobj_metadata);
        }
        if (record->cobj_record) {
            cfl_object_destroy(record->cobj_record);
        }
        if (record->owns_group_metadata && record->cobj_group_metadata &&
            record->cobj_group_metadata != record->cobj_metadata) {
            cfl_object_destroy(record->cobj_group_metadata);
        }
        if (record->owns_group_attributes && record->cobj_group_attributes &&
            record->cobj_group_attributes != record->cobj_record) {
            cfl_object_destroy(record->cobj_group_attributes);
        }
        cfl_list_del(&record->_head);
        flb_free(record);
    }

    flb_free(chunk_cobj);
    return 0;
}

int flb_mp_chunk_cobj_record_next(struct flb_mp_chunk_cobj *chunk_cobj,
                                  struct flb_mp_chunk_record **out_record)
{
    int ret = FLB_MP_CHUNK_RECORD_EOF;
    size_t bytes;
    int record_type = FLB_LOG_EVENT_NORMAL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_condition *condition = NULL;

    *out_record = NULL;
    bytes = chunk_cobj->log_decoder->length - chunk_cobj->log_decoder->offset;

    /* Check if we have a condition */
    condition = chunk_cobj->condition;

    /*
     * if there are remaining decoder bytes, keep iterating msgpack and populate
     * the cobj list. Otherwise it means all the content is ready as a chunk_cobj_record.
     */
    if (bytes > 0) {
        record = flb_mp_chunk_record_create(chunk_cobj);
        if (!record) {
            return FLB_MP_CHUNK_RECORD_ERROR;
        }

        ret = flb_log_event_decoder_next(chunk_cobj->log_decoder, &record->event);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            flb_free(record);
            return -1;
        }

        record->cobj_metadata = flb_mp_object_to_cfl(record->event.metadata);
        if (!record->cobj_metadata) {
            flb_free(record);
            return FLB_MP_CHUNK_RECORD_ERROR;
        }

        record->cobj_record = flb_mp_object_to_cfl(record->event.body);
        if (!record->cobj_record) {
            cfl_object_destroy(record->cobj_metadata);
            flb_free(record);
            return -1;
        }

        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            cfl_object_destroy(record->cobj_record);
            cfl_object_destroy(record->cobj_metadata);
            flb_free(record);
            return FLB_MP_CHUNK_RECORD_ERROR;
        }

        record->owns_group_metadata = FLB_FALSE;
        record->owns_group_attributes = FLB_FALSE;

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            if (record->cobj_metadata) {
                record->cobj_group_metadata = record->cobj_metadata;
                record->owns_group_metadata = FLB_TRUE;
            }
            if (record->cobj_record) {
                record->cobj_group_attributes = record->cobj_record;
                record->owns_group_attributes = FLB_TRUE;
            }

            chunk_cobj->active_group_metadata = record->cobj_group_metadata;
            chunk_cobj->active_group_attributes = record->cobj_group_attributes;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            record->cobj_group_metadata = chunk_cobj->active_group_metadata;
            record->cobj_group_attributes = chunk_cobj->active_group_attributes;

            chunk_cobj->active_group_metadata = NULL;
            chunk_cobj->active_group_attributes = NULL;
        }
        else {
            record->cobj_group_metadata = chunk_cobj->active_group_metadata;
            record->cobj_group_attributes = chunk_cobj->active_group_attributes;
        }

        if (!record->cobj_group_metadata &&
            record->event.group_metadata &&
            (record->event.group_metadata->type == MSGPACK_OBJECT_MAP ||
             record->event.group_metadata->type == MSGPACK_OBJECT_ARRAY)) {
            record->cobj_group_metadata = flb_mp_object_to_cfl(record->event.group_metadata);
            if (!record->cobj_group_metadata) {
                if (record->owns_group_attributes && record->cobj_group_attributes) {
                    cfl_object_destroy(record->cobj_group_attributes);
                }
                cfl_object_destroy(record->cobj_record);
                cfl_object_destroy(record->cobj_metadata);
                flb_free(record);
                return FLB_MP_CHUNK_RECORD_ERROR;
            }
            record->owns_group_metadata = FLB_TRUE;
            if (!chunk_cobj->active_group_metadata) {
                chunk_cobj->active_group_metadata = record->cobj_group_metadata;
            }
        }

        if (!record->cobj_group_attributes &&
            record->event.group_attributes &&
            (record->event.group_attributes->type == MSGPACK_OBJECT_MAP ||
             record->event.group_attributes->type == MSGPACK_OBJECT_ARRAY)) {
            record->cobj_group_attributes = flb_mp_object_to_cfl(record->event.group_attributes);
            if (!record->cobj_group_attributes) {
                if (record->owns_group_metadata && record->cobj_group_metadata) {
                    cfl_object_destroy(record->cobj_group_metadata);
                }
                cfl_object_destroy(record->cobj_record);
                cfl_object_destroy(record->cobj_metadata);
                flb_free(record);
                return FLB_MP_CHUNK_RECORD_ERROR;
            }
            record->owns_group_attributes = FLB_TRUE;
            if (!chunk_cobj->active_group_attributes) {
                chunk_cobj->active_group_attributes = record->cobj_group_attributes;
            }
        }

        cfl_list_add(&record->_head, &chunk_cobj->records);

        /* If there's a condition, check if the record matches */
        if (condition != NULL && record != NULL) {
            flb_trace("[mp] evaluating condition for record");
            ret = flb_condition_evaluate(condition, record);
            flb_trace("[mp] condition evaluation result: %s", ret ? "TRUE" : "FALSE");
            if (ret == FLB_FALSE) {
                flb_trace("[mp] record didn't match condition, skipping");
                /* Record doesn't match the condition, continue to next record */
                return flb_mp_chunk_cobj_record_next(chunk_cobj, out_record);
            }
            flb_trace("[mp] record matched condition, processing");
        }

        ret = FLB_MP_CHUNK_RECORD_OK;
    }
    else if (chunk_cobj->record_pos != NULL) {
        /* is the actual record the last one ? */
        if (chunk_cobj->record_pos == cfl_list_entry_last(&chunk_cobj->records, struct flb_mp_chunk_record, _head)) {
            chunk_cobj->record_pos = NULL;
            return FLB_MP_CHUNK_RECORD_EOF;
        }

        record = cfl_list_entry_next(&chunk_cobj->record_pos->_head, struct flb_mp_chunk_record,
                                    _head, &chunk_cobj->records);

        /* If there's a condition, check if the record matches */
        if (condition != NULL && record != NULL) {
            flb_trace("[mp] evaluating condition for next record");
            ret = flb_condition_evaluate(condition, record);
            flb_trace("[mp] next record condition evaluation result: %s", ret ? "TRUE" : "FALSE");
            if (ret == FLB_FALSE) {
                flb_trace("[mp] next record didn't match condition, skipping");
                /* Record doesn't match the condition, set as current and try again */
                chunk_cobj->record_pos = record;
                return flb_mp_chunk_cobj_record_next(chunk_cobj, out_record);
            }
            flb_trace("[mp] next record matched condition, processing");
        }

        ret = FLB_MP_CHUNK_RECORD_OK;
    }
    else {
        if (cfl_list_size(&chunk_cobj->records) == 0) {
            return FLB_MP_CHUNK_RECORD_EOF;
        }

        /* check if we are the last in the list */
        record = cfl_list_entry_first(&chunk_cobj->records, struct flb_mp_chunk_record, _head);

        /* If there's a condition, check if the record matches */
        if (condition != NULL && record != NULL) {
            flb_trace("[mp] evaluating condition for first record");
            ret = flb_condition_evaluate(condition, record);
            flb_trace("[mp] first record condition evaluation result: %s", ret ? "TRUE" : "FALSE");
            if (ret == FLB_FALSE) {
                flb_trace("[mp] first record didn't match condition, skipping");
                /* Record doesn't match the condition, set as current and try again */
                chunk_cobj->record_pos = record;
                return flb_mp_chunk_cobj_record_next(chunk_cobj, out_record);
            }
            flb_trace("[mp] first record matched condition, processing");
        }

        ret = FLB_MP_CHUNK_RECORD_OK;
    }

    chunk_cobj->record_pos = record;
    *out_record = chunk_cobj->record_pos;

    return ret;
}

int flb_mp_chunk_cobj_record_destroy(struct flb_mp_chunk_cobj *chunk_cobj,
                                     struct flb_mp_chunk_record *record)
{
    struct flb_mp_chunk_record *first;
    struct flb_mp_chunk_record *last;

    if (!record) {
        return -1;
    }

    if (chunk_cobj && chunk_cobj->record_pos) {
        first = cfl_list_entry_first(&chunk_cobj->records, struct flb_mp_chunk_record, _head);
        last = cfl_list_entry_last(&chunk_cobj->records, struct flb_mp_chunk_record, _head);

        if (record == first || record == last) {
            chunk_cobj->record_pos = NULL;
        }
    }

    if (chunk_cobj && record->owns_group_metadata &&
        chunk_cobj->active_group_metadata == record->cobj_group_metadata) {
        chunk_cobj->active_group_metadata = NULL;
    }
    if (chunk_cobj && record->owns_group_attributes &&
        chunk_cobj->active_group_attributes == record->cobj_group_attributes) {
        chunk_cobj->active_group_attributes = NULL;
    }

    if (record->cobj_metadata) {
        cfl_object_destroy(record->cobj_metadata);
    }
    if (record->cobj_record) {
        cfl_object_destroy(record->cobj_record);
    }
    if (record->owns_group_metadata && record->cobj_group_metadata &&
        record->cobj_group_metadata != record->cobj_metadata) {
        cfl_object_destroy(record->cobj_group_metadata);
    }
    if (record->owns_group_attributes && record->cobj_group_attributes &&
        record->cobj_group_attributes != record->cobj_record) {
        cfl_object_destroy(record->cobj_group_attributes);
    }

    cfl_list_del(&record->_head);
    flb_free(record);

    return 0;
}
