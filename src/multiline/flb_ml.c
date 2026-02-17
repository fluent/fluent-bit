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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <fluent-bit/multiline/flb_ml_group.h>

#include <stdarg.h>
#include <math.h>
#include <stdint.h>

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


int flb_ml_flush_stdout(struct flb_ml_parser *parser,
                        struct flb_ml_stream *mst,
                        void *data, char *buf_data, size_t buf_size)
{
    fprintf(stdout, "\n%s----- MULTILINE FLUSH (stream_id=%" PRIu64 ") -----%s\n",
            ANSI_GREEN, mst->id, ANSI_RESET);

    /* Print incoming flush buffer */
    flb_pack_print(buf_data, buf_size);

    fprintf(stdout, "%s----------- EOF -----------%s\n",
            ANSI_GREEN, ANSI_RESET);
    return 0;
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
                                  uint64_t stream_id, int forced_flush)
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
            flb_ml_flush_stream_group(parser_i->ml_parser, mst, group, forced_flush);
        }
    }
}

void flb_ml_flush_pending(struct flb_ml *ml, uint64_t now, int forced_flush)
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
        flb_ml_flush_parser_instance(ml, parser_i, 0, forced_flush);
    }
}

void flb_ml_flush_pending_now(struct flb_ml *ml)
{
    uint64_t now;

    now = time_ms_now();
    flb_ml_flush_pending(ml, now, FLB_TRUE);
}

static void cb_ml_flush_timer(struct flb_config *ctx, void *data)
{
    uint64_t now;
    struct flb_ml *ml = data;

    now = time_ms_now();
    if (ml->last_flush + ml->flush_ms > now) {
        return;
    }

    /*
     * Iterate over all streams and groups and for a flush for expired groups
     * which has not flushed in the last N milliseconds.
     */
    flb_ml_flush_pending(ml, now, FLB_TRUE);
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

static inline void breakline_prepare(struct flb_ml_parser_ins *parser_i,
                                     struct flb_ml_stream_group *stream_group)
{
    int len;

    if (parser_i->key_content) {
        return;
    }

    len = flb_sds_len(stream_group->buf);
    if (len <= 0) {
        return;
    }

    if (stream_group->buf[len - 1] != '\n') {
        flb_sds_cat_safe(&stream_group->buf, "\n", 1);
    }
}

/*
 * package content into a multiline stream:
 *
 * full_map: if the original content to process comes in msgpack map, this variable
 * reference the map. It's only used in case we will package a first line so we
 * store a copy of the other key values in the map for flush time.
 */
static int package_content(struct flb_ml_stream *mst,
                           msgpack_object *metadata,
                           msgpack_object *full_map,
                           void *buf, size_t size, struct flb_time *tm,
                           msgpack_object *val_content,
                           msgpack_object *val_pattern,
                           msgpack_object *val_group)
{
    int len;
    int ret;
    int truncated = FLB_FALSE;
    int rule_match = FLB_FALSE;
    int processed = FLB_FALSE;
    int type;
    size_t offset = 0;
    size_t buf_size;
    char *buf_data;
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
            mst->last_stream_group = stream_group;
        }
    }

    /* Set the parser type */
    type = parser->type;

    if (val_pattern) {
        val = val_pattern;
    }

    if (val) {
        buf_data = (char *) val->via.str.ptr;
        buf_size = val->via.str.size;
    }
    else {
        buf_data = buf;
        buf_size = size;

    }
    if (type == FLB_ML_REGEX) {
        ret = flb_ml_rule_process(parser, mst,
                                  stream_group, full_map, buf, size, tm,
                                  val_content, val_pattern);
        if (ret == -1) {
            return -1;
        }

        if (ret == FLB_MULTILINE_TRUNCATED) {
            truncated = FLB_TRUE;
        }

        if (!truncated && stream_group->mp_sbuf.size == 0) {
            flb_ml_register_context(stream_group, tm, full_map);
        }

        processed = FLB_TRUE;
    }
    else if (type == FLB_ML_ENDSWITH) {
        len = flb_sds_len(parser->match_str);
        if (buf_data && len <= buf_size) {
            /* Validate if content ends with expected string */
            offset = buf_size - len;
            ret = memcmp(buf_data + offset, parser->match_str, len);
            if (ret == 0) {
                rule_match = match_negate(parser, FLB_TRUE);
            }
            else {
                rule_match = match_negate(parser, FLB_FALSE);
            }

            if (stream_group->mp_sbuf.size == 0) {
                flb_ml_register_context(stream_group, tm, full_map);
            }

            /* Prepare concatenation */
            breakline_prepare(parser_i, stream_group);

            /* Concatenate value */
            if (val_content) {
                flb_sds_cat_safe(&stream_group->buf,
                                 val_content->via.str.ptr,
                                 val_content->via.str.size);
            }
            else {
                flb_sds_cat_safe(&stream_group->buf, buf_data, buf_size);
            }

            /* on ENDSWITH mode, a rule match means flush the content */
            if (rule_match) {
                flb_ml_flush_stream_group(parser, mst, stream_group, FLB_FALSE);
            }
            processed = FLB_TRUE;
        }
    }
    else if (type == FLB_ML_EQ) {
        if (buf_size == flb_sds_len(parser->match_str) &&
            memcmp(buf_data, parser->match_str, buf_size) == 0) {
            /* EQ match */
            rule_match = match_negate(parser, FLB_TRUE);
        }
        else {
            rule_match = match_negate(parser, FLB_FALSE);
        }

        if (stream_group->mp_sbuf.size == 0) {
            flb_ml_register_context(stream_group, tm, full_map);
        }

        /* Prepare concatenation */
        breakline_prepare(parser_i, stream_group);

        /* Concatenate value */
        if (val_content) {
            flb_sds_cat_safe(&stream_group->buf,
                             val_content->via.str.ptr,
                             val_content->via.str.size);
        }
        else {
            flb_sds_cat_safe(&stream_group->buf, buf_data, buf_size);
        }

        /* on ENDSWITH mode, a rule match means flush the content */
        if (rule_match) {
            flb_ml_flush_stream_group(parser, mst, stream_group, FLB_FALSE);
        }
        processed = FLB_TRUE;
    }

    if (!truncated && processed && metadata != NULL) {
        msgpack_pack_object(&stream_group->mp_md_pck, *metadata);
    }

    if (truncated) {
        return FLB_MULTILINE_TRUNCATED;
    }

    return processed;
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
                          struct flb_time *tm,
                          msgpack_object *metadata,
                          msgpack_object *obj,
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

    /* Lookup the key */
    if (type == FLB_ML_TYPE_TEXT) {
        ret = package_content(mst, NULL, NULL, buf, size, tm, NULL, NULL, NULL);
        /* Return the raw status of text type of result. */
        return ret;
    }
    else if (type == FLB_ML_TYPE_MAP) {
        full_map = obj;
        /*
         * When full_map and buf is not NULL,
         * we use 'buf' since buf is already processed from full_map at
         * ml_append_try_parser_type_map.
         */
        if (!full_map || (buf != NULL && full_map != NULL)) {
            off = 0;
            msgpack_unpacked_init(&result);
            ret = msgpack_unpack_next(&result, buf, size, &off);
            if (ret != MSGPACK_UNPACK_SUCCESS) {
                msgpack_unpacked_destroy(&result);
                return -1;
            }
            full_map = &result.data;
            unpacked = FLB_TRUE;
        }
        else if (full_map->type != MSGPACK_OBJECT_MAP) {
            if (unpacked) {
                msgpack_unpacked_destroy(&result);
            }
            return -1;
        }
    }

    /* Lookup for key_content entry */
    id_content = get_key_id(full_map, parser_i->key_content);
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
    if (parser_i->key_pattern) {
        id_pattern = get_key_id(full_map, parser_i->key_pattern);
        if (id_pattern >= 0) {
            val_pattern = &full_map->via.map.ptr[id_pattern].val;
            if (val_pattern->type != MSGPACK_OBJECT_STR) {
                val_pattern = NULL;
            }
        }
    }

    /* Optional: lookup for key_group entry */
    if (parser_i->key_group) {
        id_group = get_key_id(full_map, parser_i->key_group);
        if (id_group >= 0) {
            val_group = &full_map->via.map.ptr[id_group].val;
            if (val_group->type != MSGPACK_OBJECT_STR) {
                val_group = NULL;
            }
        }
    }

    /* Package the content */
    ret = package_content(mst, metadata, full_map, buf, size, tm,
                          val_content, val_pattern, val_group);
    if (unpacked) {
        msgpack_unpacked_destroy(&result);
    }
    if (ret == FLB_FALSE) {
        return -1;
    }
    return ret;
}

static int ml_append_try_parser_type_text(struct flb_ml_parser_ins *parser,
                                          uint64_t stream_id,
                                          int *type,
                                          struct flb_time *tm, void *buf, size_t size,
                                          msgpack_object *map,
                                          void **out_buf, size_t *out_size, int *out_release,
                                          struct flb_time *out_time)
{
    int ret;

    if (parser->ml_parser->parser) {
        /* Parse incoming content */
        ret = flb_parser_do(parser->ml_parser->parser, (char *) buf, size,
                            out_buf, out_size, out_time);
        if (flb_time_to_nanosec(out_time) == 0L) {
            flb_time_copy(out_time, tm);
        }
        if (ret >= 0) {
            *out_release = FLB_TRUE;
            *type = FLB_ML_TYPE_MAP;
        }
        else {
            *out_buf = buf;
            *out_size = size;
            return -1;
        }
    }
    else {
        *out_buf = buf;
        *out_size = size;
    }
    return 0;
}

static int ml_append_try_parser_type_map(struct flb_ml_parser_ins *parser,
                                         uint64_t stream_id,
                                         int *type,
                                         struct flb_time *tm, void *buf, size_t size,
                                         msgpack_object *map,
                                         void **out_buf, size_t *out_size, int *out_release,
                                         struct flb_time *out_time)
{
    int map_size;
    int i;
    int len;
    msgpack_object key;
    msgpack_object val;

    if (map == NULL || map->type != MSGPACK_OBJECT_MAP) {
        flb_error("%s:invalid map", __FUNCTION__);
        return -1;
    }

    if (parser->ml_parser->parser) {
        /* lookup key_content */

        len = flb_sds_len(parser->key_content);
        map_size = map->via.map.size;
        for(i = 0; i < map_size; i++) {
            key = map->via.map.ptr[i].key;
            val = map->via.map.ptr[i].val;
            if (key.type == MSGPACK_OBJECT_STR &&
                parser->key_content &&
                key.via.str.size == len &&
                strncmp(key.via.str.ptr, parser->key_content, len) == 0) {
                /* key_content found */
                if (val.type == MSGPACK_OBJECT_STR) {
                    /* try parse the value of key_content e*/
                    return ml_append_try_parser_type_text(parser, stream_id, type,
                                                          tm, (void*) val.via.str.ptr,
                                                          val.via.str.size,
                                                          map,
                                                          out_buf, out_size, out_release,
                                                          out_time);
                } else {
                    flb_error("%s: not string", __FUNCTION__);
                    return -1;
                }
            }
        }
    }
    else {
        *out_buf = buf;
        *out_size = size;
    }
    return 0;
}

static int ml_append_try_parser(struct flb_ml_parser_ins *parser,
                                uint64_t stream_id,
                                int type,
                                struct flb_time *tm, void *buf, size_t size,
                                msgpack_object *metadata,
                                msgpack_object *map)
{
    int ret;
    int release = FLB_FALSE;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    struct flb_ml_stream *mst;

    flb_time_zero(&out_time);

    switch (type) {
    case FLB_ML_TYPE_TEXT:
        ret = ml_append_try_parser_type_text(parser, stream_id, &type,
                                             tm, buf, size, map,
                                             &out_buf, &out_size, &release,
                                             &out_time);
        if (ret < 0) {
            /*
             * The underlying parser could not consume the line. Propagate the
             * failure so the caller can try the next multiline parser in the
             * chain (if any) instead of buffering the raw text here.
             */
            return -1;
        }
        break;
    case FLB_ML_TYPE_MAP:
        ret = ml_append_try_parser_type_map(parser, stream_id, &type,
                                            tm, buf, size, map,
                                            &out_buf, &out_size, &release,
                                            &out_time);
        if (ret < 0) {
            return -1;
        }
        break;

    default:
        flb_error("[multiline] unknown type=%d", type);
        return -1;
    }

    if (flb_time_to_nanosec(&out_time) == 0L) {
        if (tm && flb_time_to_nanosec(tm) != 0L) {
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
    ret = process_append(parser, mst, type, &out_time, metadata, map, out_buf, out_size);
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

    return ret;
}

int flb_ml_append_text(struct flb_ml *ml, uint64_t stream_id,
                       struct flb_time *tm, void *buf, size_t size)
{
    int ret;
    int processed = FLB_FALSE;
    int status = FLB_MULTILINE_OK;
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_group *group = NULL;
    struct flb_ml_parser_ins *lru_parser = NULL;
    struct flb_ml_parser_ins *parser_i = NULL;
    struct flb_ml_stream *mst;
    struct flb_ml_stream_group *st_group;
    int type = FLB_ML_TYPE_TEXT;

    mk_list_foreach(head, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);

        lru_parser = group->lru_parser;
        if (lru_parser && lru_parser->last_stream_id == stream_id) {
            ret = ml_append_try_parser(lru_parser, lru_parser->last_stream_id, type,
                                       tm, buf, size, NULL, NULL);
            if (ret >= 0) {
                if (ret == FLB_MULTILINE_TRUNCATED) {
                    status = FLB_MULTILINE_TRUNCATED;
                }
                processed = FLB_TRUE;
                goto done; /* Use goto to break out of nested loops */
            }
        }
    }

    if (!processed) {
        mk_list_foreach(head, &ml->groups) {
            group = mk_list_entry(head, struct flb_ml_group, _head);
            lru_parser = group->lru_parser;

            mk_list_foreach(head_group, &group->parsers) {
                parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);
                if (lru_parser && lru_parser == parser_i &&
                    lru_parser->last_stream_id == stream_id) {
                    continue;
                }

                ret = ml_append_try_parser(parser_i, stream_id, type,
                                           tm, buf, size, NULL, NULL);
                if (ret >= 0) {
                    if (ret == FLB_MULTILINE_TRUNCATED) {
                        status = FLB_MULTILINE_TRUNCATED;
                    }
                    group->lru_parser = parser_i;
                    group->lru_parser->last_stream_id = stream_id;
                    processed = FLB_TRUE;
                    goto done;
                }
            }
        }
    }

done:
    if (!processed) {
        /* A non-matching line breaks any multiline sequence. Flush all pending data. */
        mk_list_foreach(head, &ml->groups) {
            group = mk_list_entry(head, struct flb_ml_group, _head);
            mk_list_foreach(head_group, &group->parsers) {
                parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);
                flb_ml_flush_parser_instance(ml, parser_i, stream_id, FLB_FALSE);
            }
        }

        /* Now process the current line as a standalone message. */
        group = mk_list_entry_first(&ml->groups, struct flb_ml_group, _head);
        parser_i = mk_list_entry_first(&group->parsers,
                                       struct flb_ml_parser_ins,
                                       _head);
        mst = flb_ml_stream_get(parser_i, stream_id);
        if (!mst) {
            return -1;
        }

        st_group = flb_ml_stream_group_get(mst->parser, mst, NULL);
        flb_ml_register_context(st_group, tm, NULL);
        ret = flb_ml_group_cat(st_group, buf, size);
        if (ret == FLB_MULTILINE_TRUNCATED) {
            status = FLB_MULTILINE_TRUNCATED;
        }
        flb_ml_flush_stream_group(parser_i->ml_parser, mst, st_group, FLB_FALSE);
    }

    return status;
}

int flb_ml_append_object(struct flb_ml *ml,
                         uint64_t stream_id,
                         struct flb_time *tm,
                         msgpack_object *metadata,
                         msgpack_object *obj)
{
    int ret;
    int processed = FLB_FALSE;
    int status = FLB_MULTILINE_OK;
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_group *group = NULL;
    struct flb_ml_parser_ins *lru_parser = NULL;
    struct flb_ml_parser_ins *parser_i = NULL;
    struct flb_ml_stream *mst;
    struct flb_ml_stream_group *st_group;
    int type;

    if (metadata == NULL) {
        metadata = ml->log_event_decoder.empty_map;
    }

    if (obj->type != MSGPACK_OBJECT_MAP) {
        flb_error("[multiline] appending object with invalid type, expected "
                  "map, received type=%i", obj->type);
        return -1;
    }
    type = FLB_ML_TYPE_MAP;

    mk_list_foreach(head, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);

        lru_parser = group->lru_parser;
        if (lru_parser && lru_parser->last_stream_id == stream_id) {
            ret = ml_append_try_parser(lru_parser, lru_parser->last_stream_id, type,
                                       tm, NULL, 0, metadata, obj);
            if (ret >= 0) {
                if (ret == FLB_MULTILINE_TRUNCATED) {
                    status = FLB_MULTILINE_TRUNCATED;
                }
                processed = FLB_TRUE;
                goto done;
            }
        }
    }

    if (!processed) {
        mk_list_foreach(head, &ml->groups) {
            group = mk_list_entry(head, struct flb_ml_group, _head);
            lru_parser = group->lru_parser;

            mk_list_foreach(head_group, &group->parsers) {
                parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);
                if (lru_parser && parser_i == lru_parser &&
                    lru_parser->last_stream_id == stream_id) {
                    continue;
                }

                ret = ml_append_try_parser(parser_i, stream_id, type,
                                           tm, NULL, 0, metadata, obj);
                if (ret >= 0) {
                    if (ret == FLB_MULTILINE_TRUNCATED) {
                        status = FLB_MULTILINE_TRUNCATED;
                    }
                    group->lru_parser = parser_i;
                    group->lru_parser->last_stream_id = stream_id;
                    processed = FLB_TRUE;
                    goto done;
                }
            }
        }
    }

done:
    if (!processed) {
        mk_list_foreach(head, &ml->groups) {
            group = mk_list_entry(head, struct flb_ml_group, _head);
            mk_list_foreach(head_group, &group->parsers) {
                parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);
                flb_ml_flush_parser_instance(ml, parser_i, stream_id, FLB_FALSE);
            }
        }

        group = mk_list_entry_first(&ml->groups, struct flb_ml_group, _head);
        parser_i = mk_list_entry_first(&group->parsers,
                                       struct flb_ml_parser_ins,
                                       _head);

        mst = flb_ml_stream_get(parser_i, stream_id);
        if (!mst) {
            return -1;
        }

        st_group = flb_ml_stream_group_get(mst->parser, mst, NULL);
        flb_ml_register_context(st_group, tm, obj);
        flb_ml_flush_stream_group(parser_i->ml_parser, mst, st_group, FLB_FALSE);
    }

    return status;
}

int flb_ml_append_event(struct flb_ml *ml, uint64_t stream_id,
                        struct flb_log_event *event)
{
    return flb_ml_append_object(ml,
                                stream_id,
                                &event->timestamp,
                                event->metadata,
                                event->body);
}


struct flb_ml *flb_ml_create(struct flb_config *ctx, char *name)
{
    int            result;
    int64_t        limit = 0;
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
    limit = flb_utils_size_to_binary_bytes(ml->config->multiline_buffer_limit);
    if (limit >= 0) {
        ml->buffer_limit = (size_t) limit;
    }
    else {
        ml->buffer_limit = FLB_ML_BUFFER_LIMIT_DEFAULT;
    }
    ml->last_flush = time_ms_now();
    mk_list_init(&ml->groups);

    result = flb_log_event_decoder_init(&ml->log_event_decoder,
                                        NULL,
                                        0);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_error("cannot initialize log event decoder");

        flb_ml_destroy(ml);

        return NULL;
    }

    result = flb_log_event_encoder_init(&ml->log_event_encoder,
                                        FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("cannot initialize log event encoder");

        flb_ml_destroy(ml);

        return NULL;
    }

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
    struct flb_sched *scheduler;
    int               ret;

    if (ml == NULL) {
        return -1;
    }

    scheduler = flb_sched_ctx_get();

    if (scheduler == NULL) {
        flb_error("[multiline] scheduler context has not been created");
        return -1;
    }

    if (ml->flush_ms < 500) {
        flb_error("[multiline] flush timeout '%i' is too low", ml->flush_ms);
        return -1;
    }

    /* Create flush timer */
    ret = flb_sched_timer_cb_create(scheduler,
                                    FLB_SCHED_TIMER_CB_PERM,
                                    ml->flush_ms,
                                    cb_ml_flush_timer,
                                    ml, NULL);
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

    flb_log_event_decoder_destroy(&ml->log_event_decoder);
    flb_log_event_encoder_destroy(&ml->log_event_encoder);

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

static int flb_msgpack_object_hash_internal(cfl_hash_state_t *state,
                                            msgpack_object *object)
{
    void *dummy_pointer;
    int   result;
    int   index;

    if (object == NULL) {
        return 0;
    }

    dummy_pointer = NULL;
    result = 0;

    if (object->type == MSGPACK_OBJECT_NIL) {
        cfl_hash_64bits_update(state,
                               &dummy_pointer,
                               sizeof(dummy_pointer));
    }
    else if (object->type == MSGPACK_OBJECT_BOOLEAN) {
        cfl_hash_64bits_update(state,
                               &object->via.boolean,
                               sizeof(object->via.boolean));
    }
    else if (object->type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
             object->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        cfl_hash_64bits_update(state,
                               &object->via.u64,
                               sizeof(object->via.u64));
    }
    else if (object->type == MSGPACK_OBJECT_FLOAT32 ||
             object->type == MSGPACK_OBJECT_FLOAT64 ||
             object->type == MSGPACK_OBJECT_FLOAT) {
        cfl_hash_64bits_update(state,
                               &object->via.f64,
                               sizeof(object->via.f64));
    }
    else if (object->type == MSGPACK_OBJECT_STR) {
        cfl_hash_64bits_update(state,
                               object->via.str.ptr,
                               object->via.str.size);
    }
    else if (object->type == MSGPACK_OBJECT_ARRAY) {
        for (index = 0 ;
             index < object->via.array.size &&
             result == 0;
             index++) {
            result = flb_msgpack_object_hash_internal(
                        state,
                        &object->via.array.ptr[index]);
        }
    }
    else if (object->type == MSGPACK_OBJECT_MAP) {
        for (index = 0 ;
             index < object->via.map.size &&
             result == 0;
             index++) {
            result = flb_msgpack_object_hash_internal(
                        state,
                        &object->via.map.ptr[index].key);

            if (result == 0) {
                result = flb_msgpack_object_hash_internal(
                            state,
                            &object->via.map.ptr[index].val);
            }
        }
    }
    else if (object->type == MSGPACK_OBJECT_BIN) {
        cfl_hash_64bits_update(state,
                               object->via.bin.ptr,
                               object->via.bin.size);
    }
    else if (object->type == MSGPACK_OBJECT_EXT) {
        cfl_hash_64bits_update(state,
                               &object->via.ext.type,
                               sizeof(object->via.ext.type));

        cfl_hash_64bits_update(state,
                               object->via.ext.ptr,
                               object->via.ext.size);
    }

    return result;
}

static int flb_hash_msgpack_object_list(cfl_hash_64bits_t *hash,
                                        size_t entry_count,
                                        ...)
{
    cfl_hash_state_t hash_state;
    va_list          arguments;
    msgpack_object  *object;
    int              result;
    size_t           index;

    cfl_hash_64bits_reset(&hash_state);

    va_start(arguments, entry_count);

    result = 0;

    for (index = 0 ;
         index < entry_count &&
         result == 0 ;
         index++) {
        object = va_arg(arguments, msgpack_object *);

        if (object == NULL) {
            break;
        }

        result = flb_msgpack_object_hash_internal(&hash_state, object);
    }

    va_end(arguments);

    if (result == 0) {
        *hash = cfl_hash_64bits_digest(&hash_state);
    }

    return result;
}

struct flb_deduplication_list_entry {
    cfl_hash_64bits_t hash;
    struct cfl_list   _head;
};

void flb_deduplication_list_init(struct cfl_list *deduplication_list)
{
    cfl_list_init(deduplication_list);
}

int flb_deduplication_list_validate(struct cfl_list *deduplication_list,
                                    cfl_hash_64bits_t hash)
{
    struct cfl_list                     *iterator;
    struct flb_deduplication_list_entry *entry;

    cfl_list_foreach(iterator, deduplication_list) {
        entry = cfl_list_entry(iterator,
                               struct flb_deduplication_list_entry,
                               _head);

        if (entry->hash == hash) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int flb_deduplication_list_add(struct cfl_list *deduplication_list,
                               cfl_hash_64bits_t hash)
{
    struct flb_deduplication_list_entry *entry;

    entry = (struct flb_deduplication_list_entry *)
                flb_calloc(1,
                           sizeof(struct flb_deduplication_list_entry));

    if (entry == NULL) {
        return -1;
    }

    cfl_list_entry_init(&entry->_head);
    entry->hash = hash;

    cfl_list_append(&entry->_head, deduplication_list);

    return 0;
}

void flb_deduplication_list_purge(struct cfl_list *deduplication_list)
{
    struct cfl_list                     *iterator;
    struct cfl_list                     *backup;
    struct flb_deduplication_list_entry *entry;

    cfl_list_foreach_safe(iterator, backup, deduplication_list) {
        entry = cfl_list_entry(iterator,
                               struct flb_deduplication_list_entry,
                               _head);

        cfl_list_del(&entry->_head);

        free(entry);
    }
}

int flb_ml_flush_metadata_buffer(struct flb_ml_stream *mst,
                                 struct flb_ml_stream_group *group,
                                 int deduplicate_metadata)
{
    int               append_metadata_entry;
    cfl_hash_64bits_t metadata_entry_hash;
    struct cfl_list   deduplication_list;
    msgpack_unpacked  metadata_map;
    size_t            offset;
    size_t            index;
    msgpack_object    value;
    msgpack_object    key;
    int               ret;

    ret = FLB_EVENT_ENCODER_SUCCESS;

    if (deduplicate_metadata) {
        flb_deduplication_list_init(&deduplication_list);
    }

    msgpack_unpacked_init(&metadata_map);

    offset = 0;
    while (ret == FLB_EVENT_ENCODER_SUCCESS &&
           msgpack_unpack_next(&metadata_map,
                               group->mp_md_sbuf.data,
                               group->mp_md_sbuf.size,
                               &offset) == MSGPACK_UNPACK_SUCCESS) {

        for (index = 0;
             index < metadata_map.data.via.map.size &&
             ret == FLB_EVENT_ENCODER_SUCCESS;
             index++) {
            key   = metadata_map.data.via.map.ptr[index].key;
            value = metadata_map.data.via.map.ptr[index].val;

            append_metadata_entry = FLB_TRUE;

            if (deduplicate_metadata) {
                ret = flb_hash_msgpack_object_list(&metadata_entry_hash,
                                                   2,
                                                   &key,
                                                   &value);
                if (ret != 0) {
                    ret = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
                }
                else {
                    ret = flb_deduplication_list_validate(
                            &deduplication_list,
                            metadata_entry_hash);

                    if (ret) {
                        append_metadata_entry = FLB_FALSE;

                        ret = FLB_EVENT_ENCODER_SUCCESS;
                    }
                    else {
                        ret = flb_deduplication_list_add(
                                &deduplication_list,
                                metadata_entry_hash);

                        if (ret == 0) {
                            ret = FLB_EVENT_ENCODER_SUCCESS;
                        }
                        else {
                            ret = FLB_EVENT_ENCODER_ERROR_ALLOCATION_ERROR;
                        }
                    }
                }
            }

            if (append_metadata_entry) {
                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_append_metadata_values(
                            &mst->ml->log_event_encoder,
                            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&key),
                            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&value));
                }
            }
        }
    }

    msgpack_unpacked_destroy(&metadata_map);

    if (deduplicate_metadata) {
        flb_deduplication_list_purge(&deduplication_list);
    }

    return ret;
}

int flb_ml_flush_stream_group(struct flb_ml_parser *ml_parser,
                              struct flb_ml_stream *mst,
                              struct flb_ml_stream_group *group,
                              int forced_flush)
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
    struct flb_ml_parser_ins *parser_i = mst->parser;
    struct flb_time *group_time;
    struct flb_time now;

    breakline_prepare(parser_i, group);
    len = flb_sds_len(group->buf);

    /* init msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* if the group don't have a time set, use current time */
    if (flb_time_to_nanosec(&group->mp_time) == 0L) {
        flb_time_get(&now);
        group_time = &now;
    } else {
        group_time = &group->mp_time;
    }

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

        if (flb_sds_len(group->buf) > 0) {
            /* Take the first line keys and repack */
            len = flb_sds_len(parser_i->key_content);
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
                    parser_i->key_content &&
                    k.via.str.size == len &&
                    strncmp(k.via.str.ptr, parser_i->key_content, len) == 0) {

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
        }
        else {
            /* The buffer is empty, so just pack the original map from the context */
            msgpack_pack_object(&mp_pck, map);
        }

        msgpack_unpacked_destroy(&result);
        group->mp_sbuf.size = 0;
        group->mp_md_sbuf.size = 0;
    }
    else if (len > 0) {
        /* Pack raw content as Fluent Bit record */
        msgpack_pack_map(&mp_pck, 1);

        /* key */
        if (parser_i->key_content) {
            len = flb_sds_len(parser_i->key_content);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, parser_i->key_content, len);
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
        /*
         * a 'forced_flush' means to alert the caller that the data 'must be flushed to it destination'. This flag is
         * only enabled when the flush process has been triggered by the multiline timer, e.g:
         *
         * - the message is complete or incomplete and its time to dispatch it.
         */
        if (forced_flush) {
            mst->forced_flush = FLB_TRUE;
        }

        /* encode and invoke the user callback */

        ret = flb_log_event_encoder_begin_record(
                &mst->ml->log_event_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(
                    &mst->ml->log_event_encoder,
                    group_time);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_ml_flush_metadata_buffer(mst,
                                               group,
                                               FLB_TRUE);
        }

        /* If the buffer was truncated, append the marker to the metadata */
        if (ret == FLB_EVENT_ENCODER_SUCCESS && group->truncated) {
            ret = flb_log_event_encoder_append_metadata_values(
                    &mst->ml->log_event_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("multiline_truncated"),
                    FLB_LOG_EVENT_BOOLEAN_VALUE(FLB_TRUE));
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                    &mst->ml->log_event_encoder,
                    mp_sbuf.data,
                    mp_sbuf.size);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(
                    &mst->ml->log_event_encoder);
        }

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_error("[multiline] error packing event");

            return -1;
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            mst->cb_flush(ml_parser,
                          mst,
                          mst->cb_data,
                          mst->ml->log_event_encoder.output_buffer,
                          mst->ml->log_event_encoder.output_length);
        }
        else {
            flb_error("[multiline] log event encoder error : %d", ret);
        }

        flb_log_event_encoder_reset(&mst->ml->log_event_encoder);

        if (forced_flush) {
            mst->forced_flush = FLB_FALSE;
        }
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_sds_len_set(group->buf, 0);
    group->truncated = FLB_FALSE;
    group->mp_md_sbuf.size = 0;

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
