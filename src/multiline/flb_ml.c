/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <fluent-bit/multiline/flb_ml_group.h>

#include <math.h>

static inline int match_negate(struct flb_ml_parser *ml_parser, int matched)
{
    int rule_match = matched;

    /* Validate pattern matching against expected 'negate' condition */
    if (matched == FLB_TRUE) {
        if (ml_parser->negate == FLB_FALSE) {
            rule_match = FLB_TRUE;
        }
        else {
            rule_match = FLB_FALSE;
        }
    }
    else {
        if (ml_parser->negate == FLB_TRUE) {
            rule_match = FLB_TRUE;
        }
    }

    return rule_match;
}

static uint64_t time_ms_now()
{
    uint64_t ms;
    struct flb_time tm;

    flb_time_get(&tm);
    ms = (tm.tm.tv_sec * 1000) + lround(tm.tm.tv_nsec/1.0e6);
    return ms;
}

int flb_ml_type_lookup(char *str)
{
    int type = -1;

    if (strcasecmp(str, "regex") == 0) {
        type = FLB_ML_REGEX;
    }
    else if (strcasecmp(str, "endswith") == 0) {
        type = FLB_ML_ENDSWITH;
    }
    else if (strcasecmp(str, "equal") == 0 || strcasecmp(str, "eq") == 0) {
        type = FLB_ML_EQ;
    }

    return type;
}

void flb_ml_flush_parser_instance(struct flb_ml *ml,
                                  struct flb_ml_parser_ins *parser_i,
                                  uint64_t stream_id)
{
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_stream *mst;
    struct flb_ml_stream_group *group;

    mk_list_foreach(head, &parser_i->streams) {
        mst = mk_list_entry(head, struct flb_ml_stream, _head);
        if (stream_id != 0 && mst->id != stream_id) {
            continue;
        }

        /* Iterate stream groups */
        mk_list_foreach(head_group, &mst->groups) {
            group = mk_list_entry(head_group, struct flb_ml_stream_group, _head);
            flb_ml_flush_stream_group(parser_i->ml_parser, mst, group);
        }
    }
}

void flb_ml_flush_pending(struct flb_ml *ml, uint64_t now)
{
    struct mk_list *head;
    struct flb_ml_parser_ins *parser_i;
    struct flb_ml_group *group;

    /* set the last flush time */
    ml->last_flush = now;

    /* flush only the first group of the context */
    group = mk_list_entry_first(&ml->groups, struct flb_ml_group, _head);

    /* iterate group parser instances */
    mk_list_foreach(head, &group->parsers) {
        parser_i = mk_list_entry(head, struct flb_ml_parser_ins, _head);
        flb_ml_flush_parser_instance(ml, parser_i, 0);
    }
}

static void cb_ml_flush_timer(struct flb_config *ctx, void *data)
{
    uint64_t now;
    struct flb_ml *ml = data;

    now = time_ms_now();
    if (ml->last_flush + ml->flush_ms < now) {
        return;
    }

    /*
     * Iterate over all streams and groups and for a flush for expired groups
     * which has not flushed in the last N milliseconds.
     */
    flb_ml_flush_pending(ml, now);
}

int flb_ml_register_context(struct flb_ml_stream_group *group,
                            struct flb_time *tm, msgpack_object *map)
{
    if (tm) {
        flb_time_copy(&group->mp_time, tm);
    }

    if (map) {
        msgpack_pack_object(&group->mp_pck, *map);
    }

    return 0;
}

/*
 * package content into a multiline stream:
 *
 * full_map: if the original content to process comes in msgpack map, this variable
 * reference the map. It's only used in case we will package a first line so we
 * store a copy of the other key values in the map for flush time.
 */
static int package_content(struct flb_ml_stream *mst,
                           msgpack_object *full_map,
                           void *buf, size_t size, struct flb_time *tm,
                           msgpack_object *val_content,
                           msgpack_object *val_pattern,
                           msgpack_object *val_group)
{
    int len;
    int ret;
    int rule_match = FLB_FALSE;
    int processed = FLB_FALSE;
    int type;
    size_t offset = 0;
    msgpack_object *val = val_content;
    struct flb_ml_parser *parser;
    struct flb_ml_parser_ins *parser_i;
    struct flb_ml_stream_group *stream_group;

    parser_i = mst->parser;
    parser = parser_i->ml_parser;

    /* Get stream group */
    stream_group = flb_ml_stream_group_get(mst->parser, mst, val_group);
    if (!mst->last_stream_group) {
        mst->last_stream_group = stream_group;
    }
    else {
        if (mst->last_stream_group != stream_group) {
            flb_ml_flush_stream_group(parser, mst, mst->last_stream_group);
            mst->last_stream_group = stream_group;
        }
    }

    /* Set the parser type */
    type = parser->type;

    if (val_pattern) {
        val = val_pattern;
    }

    if (type == FLB_ML_REGEX) {
        ret = flb_ml_rule_process(parser, mst,
                                  stream_group, full_map, buf, size, tm,
                                  val_content, val_pattern);
        if (ret == -1) {
            processed = FLB_FALSE;
        }
        else {
            processed = FLB_TRUE;
        }
    }
    else if (type == FLB_ML_ENDSWITH) {
        len = flb_sds_len(parser->match_str);
        if (val && len <= val->via.str.size) {
            /* Validate if content ends with expected string */
            offset = val->via.str.size - len;
            ret = memcmp(val->via.str.ptr + offset, parser->match_str, len);
            if (ret == 0) {
                rule_match = match_negate(parser, FLB_TRUE);
            }
            else {
                rule_match = match_negate(parser, FLB_FALSE);
            }

            if (stream_group->mp_sbuf.size == 0) {
                flb_ml_register_context(stream_group, tm, full_map);
            }

            /* Concatenate value */
            flb_sds_cat_safe(&stream_group->buf,
                             val_content->via.str.ptr,
                             val_content->via.str.size);

            /* on ENDSWITH mode, a rule match means flush the content */
            if (rule_match) {
                flb_ml_flush_stream_group(parser, mst, stream_group);
            }
            processed = FLB_TRUE;
        }
    }
    else if (type == FLB_ML_EQ) {
        if (val->via.str.size == flb_sds_len(parser->match_str) &&
            memcmp(val->via.str.ptr, parser->match_str, val->via.str.size) == 0) {
            /* EQ match */
            rule_match = match_negate(parser, FLB_TRUE);
        }
        else {
            rule_match = match_negate(parser, FLB_FALSE);
        }

        if (stream_group->mp_sbuf.size == 0) {
            flb_ml_register_context(stream_group, tm, full_map);
        }

        /* Concatenate value */
        flb_sds_cat_safe(&stream_group->buf,
                         val_content->via.str.ptr,
                         val_content->via.str.size);

        /* on ENDSWITH mode, a rule match means flush the content */
        if (rule_match) {
            flb_ml_flush_stream_group(parser, mst, stream_group);
        }
        processed = FLB_TRUE;
    }

    return processed;

    /*
     * If the incoming buffer could not be processed on any of the rules above,
     * process it as a raw text generating a single record with the given
     * content.
     */
    if (!processed && type == FLB_ML_TYPE_TEXT) {
        flb_ml_flush_stream_group(parser, mst, stream_group);

        /* Concatenate value */
        flb_sds_cat_safe(&stream_group->buf, buf, size);
        flb_ml_flush_stream_group(parser, mst, stream_group);
    }
    else {
        return FLB_FALSE;
    }
}

/*
 * Retrieve the ID of a specific key name in a map. This function might be
 * extended later to use record accessor, since all current cases are solved
 * now quering the first level of keys in the map, we avoid record accessor
 * to avoid extra memory allocations.
 */
static int get_key_id(msgpack_object *map, flb_sds_t key_name)
{
    int i;
    int len;
    int found = FLB_FALSE;
    msgpack_object key;
    msgpack_object val;

    if (!key_name) {
        return -1;
    }

    len = flb_sds_len(key_name);
    for (i = 0; i < map->via.map.size; i++) {
        key = map->via.map.ptr[i].key;
        val = map->via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR || val.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size != len) {
            continue;
        }

        if (strncmp(key.via.str.ptr, key_name, len) == 0) {
            found = FLB_TRUE;
            break;
        }
    }

    if (found) {
        return i;
    }

    return -1;
}

static int process_append(struct flb_ml_parser_ins *parser_i,
                          struct flb_ml_stream *mst,
                          int type,
                          struct flb_time *tm, msgpack_object *obj,
                          void *buf, size_t size)
{
    int ret;
    int id_content = -1;
    int id_pattern = -1;
    int id_group = -1;
    int unpacked = FLB_FALSE;
    size_t off = 0;
    msgpack_object *full_map = NULL;
    msgpack_object *val_content = NULL;
    msgpack_object *val_pattern = NULL;
    msgpack_object *val_group = NULL;
    msgpack_unpacked result;
    struct flb_time tm_record;
    struct flb_ml_parser *parser = parser_i->ml_parser;

    /* Lookup the key */
    if (type == FLB_ML_TYPE_TEXT) {
        ret = package_content(mst, NULL, buf, size, tm, NULL, NULL, NULL);
        if (ret == FLB_FALSE) {
            return -1;
        }
        return 0;
    }
    else if (type == FLB_ML_TYPE_RECORD) {
        off = 0;
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, buf, size, &off);
        if (ret != MSGPACK_UNPACK_SUCCESS) {
            return -1;
        }
        flb_time_pop_from_msgpack(&tm_record, &result, &full_map);
        unpacked = FLB_TRUE;
    }
    else if (type == FLB_ML_TYPE_MAP) {
        full_map = obj;
        if (!full_map) {
            msgpack_unpacked_init(&result);
            off = 0;
            ret = msgpack_unpack_next(&result, buf, size, &off);
            if (ret != MSGPACK_UNPACK_SUCCESS) {
                return -1;
            }
            full_map = &result.data;
            unpacked = FLB_TRUE;
        }
        else if (full_map->type != MSGPACK_OBJECT_MAP) {
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }

    /* Lookup for key_content entry */
    id_content = get_key_id(full_map, parser->key_content);
    if (id_content == -1) {
        if (unpacked) {
            msgpack_unpacked_destroy(&result);
        }
        return -1;
    }
    val_content = &full_map->via.map.ptr[id_content].val;
    if (val_content->type != MSGPACK_OBJECT_STR) {
        val_content = NULL;
    }

    /* Optional: Lookup for key_pattern entry */
    if (parser->key_pattern) {
        id_pattern = get_key_id(full_map, parser->key_pattern);
        if (id_pattern >= 0) {
            val_pattern = &full_map->via.map.ptr[id_pattern].val;
            if (val_pattern->type != MSGPACK_OBJECT_STR) {
                val_pattern = NULL;
            }
        }
    }

    /* Optional: lookup for key_group entry */
    if (parser->key_group) {
        id_group = get_key_id(full_map, parser->key_group);
        if (id_group >= 0) {
            val_group = &full_map->via.map.ptr[id_group].val;
            if (val_group->type != MSGPACK_OBJECT_STR) {
                val_group = NULL;
            }
        }
    }

    /* Package the content */
    ret = package_content(mst, full_map, buf, size, tm,
                          val_content, val_pattern, val_group);
    if (ret == FLB_FALSE) {
        return -1;
    }

    if (unpacked) {
        msgpack_unpacked_destroy(&result);
    }
    return 0;
}


static int ml_append_try_parser(struct flb_ml_parser_ins *parser,
                                uint64_t stream_id,
                                int type,
                                struct flb_time *tm, void *buf, size_t size)
{
    int ret;
    int release = FLB_FALSE;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    struct flb_ml_stream *mst;

    flb_time_zero(&out_time);

    if (parser->ml_parser->parser && type == FLB_ML_TYPE_TEXT) {
        /* Parse incoming content */
        ret = flb_parser_do(parser->ml_parser->parser, (char *) buf, size,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            if (flb_time_to_double(&out_time) == 0.0) {
                flb_time_copy(&out_time, tm);
            }
            release = FLB_TRUE;
            type = FLB_ML_TYPE_MAP;
        }
        else {
            out_buf = buf;
            out_size = size;
            return -1;
        }
    }
    else if (type == FLB_ML_TYPE_TEXT) {
        out_buf = buf;
        out_size = size;
    }

    if (flb_time_to_double(&out_time) == 0.0) {
        if (tm && flb_time_to_double(tm) != 0.0) {
            flb_time_copy(&out_time, tm);
        }
        else {
            flb_time_get(&out_time);
        }
    }

    /* Get the stream */
    mst = flb_ml_stream_get(parser, stream_id);
    if (!mst) {
        flb_error("[multiline] invalid stream_id %" PRIu64 ", could not "
                  "append content to multiline context", stream_id);
        goto exit;
    }

    /* Process the binary record */
    ret = process_append(parser, mst, type, &out_time, NULL, out_buf, out_size);
    if (ret == -1) {
        if (release == FLB_TRUE) {
            flb_free(out_buf);
        }
        return -1;
    }

 exit:
    if (release == FLB_TRUE) {
        flb_free(out_buf);
    }

    return 0;
}

int flb_ml_append(struct flb_ml *ml, uint64_t stream_id,
                  int type,
                  struct flb_time *tm, void *buf, size_t size)
{
    int ret;
    int processed = FLB_FALSE;
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_group *group;
    struct flb_ml_stream *mst;
    struct flb_ml_parser_ins *lru_parser = NULL;
    struct flb_ml_parser_ins *parser_i;
    struct flb_time out_time;
    struct flb_ml_stream_group *st_group;

    flb_time_zero(&out_time);

    mk_list_foreach(head, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);

        /* Check if the incoming data matches the last recently used parser */
        lru_parser = group->lru_parser;

        if (lru_parser && lru_parser->last_stream_id == stream_id) {
            ret = ml_append_try_parser(lru_parser, lru_parser->last_stream_id, type,
                                       tm, buf, size);
            if (ret == 0) {
                processed = FLB_TRUE;
                break;
            }
            else {
                flb_ml_flush_parser_instance(ml,
                                             lru_parser,
                                             lru_parser->last_stream_id);
            }
        }
        else if (lru_parser && lru_parser->last_stream_id > 0) {
            flb_ml_flush_parser_instance(ml,
                                         lru_parser,
                                         lru_parser->last_stream_id);
        }
    }

    mk_list_foreach(head_group, &group->parsers) {
            parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);
            if (lru_parser && parser_i == lru_parser) {
                continue;
            }

            ret = ml_append_try_parser(parser_i, stream_id, type,
                                       tm, buf, size);
            if (ret == 0) {
                group->lru_parser = parser_i;
                group->lru_parser->last_stream_id = stream_id;
                lru_parser = parser_i;
                processed = FLB_TRUE;
                break;
            }
            else {
                parser_i = NULL;
            }

    }

    if (!processed) {
        if (lru_parser) {
            flb_ml_flush_parser_instance(ml, lru_parser, stream_id);
            parser_i = lru_parser;
        }
        else {
            /* get the first parser (just to make use of it buffers) */
            parser_i = mk_list_entry_first(&group->parsers,
                                           struct flb_ml_parser_ins,
                                           _head);
        }

        flb_ml_flush_parser_instance(ml, parser_i, stream_id);
        mst = flb_ml_stream_get(parser_i, stream_id);
        if (!mst) {
            flb_error("[multiline] invalid stream_id %" PRIu64 ", could not "
                       "append content to multiline context", stream_id);
            return -1;
        }

        /* Get stream group */
        st_group = flb_ml_stream_group_get(mst->parser, mst, NULL);
        flb_sds_cat_safe(&st_group->buf, buf, size);
        flb_ml_flush_stream_group(parser_i->ml_parser, mst, st_group);
    }

    return 0;
}

int flb_ml_append_object(struct flb_ml *ml, uint64_t stream_id,
                         struct flb_time *tm, msgpack_object *obj)
{
    int type;
    int ret;
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_group *group;
    struct flb_ml_parser_ins *parser_i;
    struct flb_ml_stream *mst;

    /*
     * As incoming objects, we only accept Fluent Bit array format
     * and Map containing key/value pairs.
     */
    if (obj->type == MSGPACK_OBJECT_ARRAY) {
        if (obj->via.array.size != 2) {
            flb_error("[multiline] appending object with invalid size");
            return -1;
        }
        type = FLB_ML_TYPE_RECORD;
    }
    else if (obj->type != MSGPACK_OBJECT_MAP) {
        flb_error("[multiline] appending object with invalid type, expected "
                  "array or map, received type=%i", obj->type);
        return -1;
    }
    else {
        type = FLB_ML_TYPE_MAP;
    }

    mk_list_foreach(head, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);

        mk_list_foreach(head_group, &group->parsers) {
            parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);

            /* Get the stream */
            mst = flb_ml_stream_get(parser_i, stream_id);
            if (!mst) {
                flb_error("[multiline] invalid stream_id %" PRIu64 ", could not "
                          "append content to multiline context", stream_id);
                return -1;
            }

            ret = process_append(parser_i, mst, type, tm, obj, NULL, 0);
            if (ret == 0) {
                break;
            }
        }
    }

    return 0;
}

struct flb_ml *flb_ml_create(struct flb_config *ctx, char *name)
{
    struct flb_ml *ml;

    ml = flb_calloc(1, sizeof(struct flb_ml));
    if (!ml) {
        flb_errno();
        return NULL;
    }
    ml->name = flb_sds_create(name);
    if (!ml) {
        flb_free(ml);
        return NULL;
    }

    ml->config = ctx;
    ml->last_flush = time_ms_now();
    mk_list_init(&ml->groups);

    return ml;
}

/*
 * Some multiline contexts might define a parser name but not a parser context,
 * for missing contexts, just lookup the parser and perform the assignment.
 *
 * The common use case is when reading config files with [PARSER] and [MULTILINE_PARSER]
 * definitions, so we need to delay the parser loading.
 */
int flb_ml_parsers_init(struct flb_config *ctx)
{
    struct mk_list *head;
    struct flb_parser *p;
    struct flb_ml_parser *ml_parser;

    mk_list_foreach(head, &ctx->multiline_parsers) {
        ml_parser = mk_list_entry(head, struct flb_ml_parser, _head);
        if (ml_parser->parser_name && !ml_parser->parser) {
            p = flb_parser_get(ml_parser->parser_name, ctx);
            if (!p) {
                flb_error("multiline parser '%s' points to an undefined parser '%s'",
                          ml_parser->name, ml_parser->parser_name);
                return -1;
            }
            ml_parser->parser = p;
        }
    }

    return 0;
}

int flb_ml_auto_flush_init(struct flb_ml *ml)
{
    int ret;
    struct flb_config *ctx;

    if (!ml) {
        return -1;
    }

    ctx = ml->config;
    if (!ctx->sched) {
        flb_error("[multiline] scheduler context has not been created");
        return -1;
    }

    if (ml->flush_ms < 500) {
        flb_error("[multiline] flush timeout '%i' is too low", ml->flush_ms);
        return -1;
    }

    /* Create flush timer */
    ret = flb_sched_timer_cb_create(ctx->sched,
                                    FLB_SCHED_TIMER_CB_PERM,
                                    ml->flush_ms,
                                    cb_ml_flush_timer,
                                    ml);
    return ret;
}

int flb_ml_destroy(struct flb_ml *ml)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_ml_group *group;

    if (!ml) {
        return 0;
    }

    if (ml->name) {
        flb_sds_destroy(ml->name);
    }

    /* destroy groups */
    mk_list_foreach_safe(head, tmp, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);
        flb_ml_group_destroy(group);
    }

    flb_free(ml);
    return 0;
}

int flb_ml_flush_stream_group(struct flb_ml_parser *ml_parser,
                              struct flb_ml_stream *mst,
                              struct flb_ml_stream_group *group)
{
    int i;
    int ret;
    int size;
    int len;
    size_t off = 0;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_unpacked result;

    len = flb_sds_len(group->buf);

    /* init msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* compose final record if we have a first line context */
    if (group->mp_sbuf.size > 0) {
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result,
                                  group->mp_sbuf.data, group->mp_sbuf.size,
                                  &off);
        if (ret != MSGPACK_UNPACK_SUCCESS) {
            flb_error("[multiline] could not unpack first line state buffer");
            msgpack_unpacked_destroy(&result);
            group->mp_sbuf.size = 0;
            return -1;
        }
        map = result.data;

        if (map.type != MSGPACK_OBJECT_MAP) {
            flb_error("[multiline] expected MAP type in first line state buffer");
            msgpack_unpacked_destroy(&result);
            group->mp_sbuf.size = 0;
            return -1;
        }

        /* Take the first line keys and repack */
        msgpack_pack_array(&mp_pck, 2);
        flb_time_append_to_msgpack(&group->mp_time, &mp_pck, 0);

        len = flb_sds_len(ml_parser->key_content);
        size = map.via.map.size;
        msgpack_pack_map(&mp_pck, size);

        for (i = 0; i < size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            /*
             * Check if the current key is the key that will contain the
             * concatenated multiline buffer
             */
            if (k.type == MSGPACK_OBJECT_STR &&
                ml_parser->key_content &&
                k.via.str.size == len &&
                strncmp(k.via.str.ptr, ml_parser->key_content, len) == 0) {

                /* key */
                msgpack_pack_object(&mp_pck, k);

                /* value */
                len = flb_sds_len(group->buf);
                msgpack_pack_str(&mp_pck, len);
                msgpack_pack_str_body(&mp_pck, group->buf, len);
            }
            else {
                /* key / val */
                msgpack_pack_object(&mp_pck, k);
                msgpack_pack_object(&mp_pck, v);
            }
        }
        msgpack_unpacked_destroy(&result);
        group->mp_sbuf.size = 0;
    }
    else if (len > 0) {
        /* Pack raw content as Fluent Bit record */
        msgpack_pack_array(&mp_pck, 2);
        flb_time_append_to_msgpack(&group->mp_time, &mp_pck, 0);
        msgpack_pack_map(&mp_pck, 1);

        /* key */
        if (ml_parser->key_content) {
            len = flb_sds_len(ml_parser->key_content);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, ml_parser->key_content, len);
        }
        else {
            msgpack_pack_str(&mp_pck, 3);
            msgpack_pack_str_body(&mp_pck, "log", 3);
        }

        /* val */
        len = flb_sds_len(group->buf);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, group->buf, len);
    }

    if (mp_sbuf.size > 0) {
        mst->cb_flush(ml_parser, mst, mst->cb_data, mp_sbuf.data, mp_sbuf.size);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_sds_len_set(group->buf, 0);

    /* Update last flush time */
    group->last_flush = time_ms_now();

    return 0;
}

/*
 * Initialize multiline global environment.
 *
 * note: function must be invoked before any flb_ml_create() call.
 */
int flb_ml_init(struct flb_config *config)
{
    int ret;

    ret = flb_ml_parser_builtin_create(config);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

int flb_ml_exit(struct flb_config *config)
{
    flb_ml_parser_destroy_all(&config->multiline_parsers);
    return 0;
}
