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

#include <math.h>

struct flb_config_map multiline_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "multiline", "true",
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive),
     "Enable or disable Keepalive support"
    },

    /* A pre-defined & built-in mode */
    {
     FLB_CONFIG_MAP_BOOL, "multiline.mode", NULL,
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive),
     "Specify a pre-defined built-in mode to use"
    },

    {
     FLB_CONFIG_MAP_BOOL, "multiline.mode", NULL,
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive),
     "Enable or disable Keepalive support"
    },

};

static int ml_flush_stdout(struct flb_ml *ml,
                           struct flb_ml_stream *mst,
                           void *data, void *buf_data, size_t buf_size)
{
    fprintf(stdout, "\n%s----- MULTILINE FLUSH -----%s\n",
            ANSI_GREEN, ANSI_RESET);

    /* Print incoming flush buffer */
    flb_pack_print(buf_data, buf_size);

    fprintf(stdout, "%s----------- EOF -----------%s\n",
            ANSI_GREEN, ANSI_RESET);
    return 0;
}

static inline int match_negate(struct flb_ml *ml, int matched)
{
    int rule_match = matched;

    /* Validate pattern matching against expected 'negate' condition */
    if (matched == FLB_TRUE) {
        if (ml->negate == FLB_FALSE) {
            rule_match = FLB_TRUE;
        }
        else {
            rule_match = FLB_FALSE;
        }
    }
    else {
        if (ml->negate == FLB_TRUE) {
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

    if (strcasecmp(str, "count") == 0) {
        type = FLB_ML_COUNT;
    }
    else if (strcasecmp(str, "regex") == 0) {
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

void flb_ml_flush_pending(struct flb_ml *ml)
{
    uint64_t time_ms;
    struct mk_list *head;
    struct mk_list *head_group = NULL;
    struct flb_ml_stream *mst;
    struct flb_ml_stream_group *group;

    /* retrieve current time */
    time_ms = time_ms_now();

    /* Iterate streams */
    mk_list_foreach(head, &ml->streams) {
        mst = mk_list_entry(head, struct flb_ml_stream, _head);

        /* Iterate groups */
        mk_list_foreach(head_group, &mst->groups) {
            group = mk_list_entry(head_group, struct flb_ml_stream_group, _head);
            if ((group->last_flush + ml->flush_ms) < time_ms) {
                flb_ml_flush_stream_group(ml, mst, group);
            }
        }
    }
}

static void cb_ml_flush_timer(struct flb_config *ctx, void *data)
{
    struct flb_ml *ml = data;

    /*
     * Iterate over all streams and groups and for a flush for expired groups
     * which has not flushed in the last N milliseconds.
     */
    flb_ml_flush_pending(ml);
}

int flb_ml_register_context(struct flb_ml *ml, struct flb_ml_stream *mst,
                            struct flb_ml_stream_group *group,
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
static int package_content(struct flb_ml *ml,
                           struct flb_ml_stream *mst,
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
    size_t offset = 0;
    msgpack_object *val = val_content;
    struct flb_ml_stream_group *group;

    /* Get stream group */
    group = flb_ml_stream_group_get(ml, mst, val_group);

    if (val_pattern) {
        val = val_pattern;
    }

    if (ml->type == FLB_ML_COUNT) {

    }
    else if (ml->type == FLB_ML_REGEX) {
        ret = flb_ml_rule_process(ml, mst, group, full_map, buf, size, tm,
                                  val_content, val_pattern);
        processed = FLB_TRUE;
    }
    else if (ml->type == FLB_ML_ENDSWITH) {
        len = flb_sds_len(ml->match_str);
        if (val && len <= val->via.str.size) {
            /* Validate if content ends with expected string */
            offset = val->via.str.size - len;
            ret = memcmp(val->via.str.ptr + offset, ml->match_str, len);
            if (ret == 0) {
                rule_match = match_negate(ml, FLB_TRUE);
            }
            else {
                rule_match = match_negate(ml, FLB_FALSE);
            }

            if (group->mp_sbuf.size == 0) {
                flb_ml_register_context(ml, mst, group, tm, full_map);
            }

            /* Concatenate value */
            flb_sds_cat_safe(&group->buf,
                             val_content->via.str.ptr,
                             val_content->via.str.size);

            /* on ENDSWITH mode, a rule match means flush the content */
            if (rule_match) {
                flb_ml_flush_stream_group(ml, mst, group);
            }
            processed = FLB_TRUE;
        }
    }
    else if (ml->type == FLB_ML_EQ) {
        if (val->via.str.size == flb_sds_len(ml->match_str) &&
            memcmp(val->via.str.ptr, ml->match_str, val->via.str.size) == 0) {
            /* EQ match */
            rule_match = match_negate(ml, FLB_TRUE);
        }
        else {
            rule_match = match_negate(ml, FLB_FALSE);
        }

        if (group->mp_sbuf.size == 0) {
            flb_ml_register_context(ml, mst, group, tm, full_map);
        }

        /* Concatenate value */
        flb_sds_cat_safe(&group->buf,
                         val_content->via.str.ptr,
                         val_content->via.str.size);

        /* on ENDSWITH mode, a rule match means flush the content */
        if (rule_match) {
            flb_ml_flush_stream_group(ml, mst, group);
        }
        processed = FLB_TRUE;
    }

    /*
     * If the incoming buffer could not be processed on any of the rules above,
     * process it as a raw text generating a single record with the given
     * content.
     */
    if (!processed) {
        flb_ml_flush_stream_group(ml, mst, group);

        /* Concatenate value */
        flb_sds_cat_safe(&group->buf, buf, size);
        flb_ml_flush_stream_group(ml, mst, group);
    }

    return rule_match;
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

static int process_append(struct flb_ml *ml,
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

    /* Lookup the key */
    if (type == FLB_ML_TYPE_TEXT) {
        package_content(ml, mst, NULL, buf, size, tm, NULL, NULL, NULL);
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
    id_content = get_key_id(full_map, ml->key_content);
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
    if (ml->key_pattern) {
        id_pattern = get_key_id(full_map, ml->key_pattern);
        if (id_pattern >= 0) {
            val_pattern = &full_map->via.map.ptr[id_pattern].val;
            if (val_pattern->type != MSGPACK_OBJECT_STR) {
                val_pattern = NULL;
            }
        }
    }

    /* Optional: lookup for key_group entry */
    if (ml->key_group) {
        id_group = get_key_id(full_map, ml->key_group);
        if (id_group >= 0) {
            val_group = &full_map->via.map.ptr[id_group].val;
            if (val_group->type != MSGPACK_OBJECT_STR) {
                val_group = NULL;
            }
        }
    }

    /* Package the content */
    package_content(ml, mst, full_map, buf, size, tm,
                    val_content, val_pattern, val_group);

    if (unpacked) {
        msgpack_unpacked_destroy(&result);
    }
    return 0;
}

int flb_ml_append(struct flb_ml *ml, struct flb_ml_stream *mst,
                  int type,
                  struct flb_time *tm, void *buf, size_t size)
{
    int ret;
    int release = FLB_FALSE;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    flb_time_zero(&out_time);

    if (ml->parser && type == FLB_ML_TYPE_TEXT) {
        /* Parse incoming content */
        ret = flb_parser_do(ml->parser, (char *) buf, size,
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
            //return -1;
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

    /* Process the binary record */
    process_append(ml, mst, type, &out_time, NULL, out_buf, out_size);

    if (release == FLB_TRUE) {
        flb_free(out_buf);
    }

    return 0;
}

int flb_ml_append_object(struct flb_ml *ml,
                         struct flb_ml_stream *mst,
                         struct flb_time *tm, msgpack_object *obj)
{
    int type;

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

    process_append(ml, mst, type, tm, obj, NULL, 0);
    return 0;
}

struct flb_ml *flb_ml_create(struct flb_config *ctx,
                             char *name,
                             int type, char *match_str, int negate,
                             int flush_ms,
                             char *key_content,
                             char *key_group,
                             char *key_pattern,
                             struct flb_parser *parser_ctx, char *parser_name)
{
    struct flb_ml *ml;

    ml = flb_calloc(1, sizeof(struct flb_ml));
    if (!ml) {
        flb_errno();
        return NULL;
    }
    ml->name = flb_sds_create(name);
    ml->type = type;

    if (match_str) {
        ml->match_str = flb_sds_create(match_str);
        if (!ml->match_str) {
            flb_free(ml);
            return NULL;
        }
    }

    ml->parser = parser_ctx;
    if (parser_name) {
        ml->parser_name = flb_sds_create(parser_name);
    }

    ml->negate = negate;
    mk_list_init(&ml->streams);
    mk_list_init(&ml->regex_rules);
    mk_list_add(&ml->_head, &ctx->multilines);

    if (key_content) {
        ml->key_content = flb_sds_create(key_content);
        if (!ml->key_content) {
            flb_ml_destroy(ml);
            return NULL;
        }
    }

    if (key_group) {
        ml->key_group = flb_sds_create(key_group);
        if (!ml->key_group) {
            flb_ml_destroy(ml);
            return NULL;
        }
    }

    if (key_pattern) {
        ml->key_pattern = flb_sds_create(key_pattern);
        if (!ml->key_pattern) {
            flb_ml_destroy(ml);
            return NULL;
        }
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
    struct flb_ml *ml;
    struct mk_list *head;
    struct flb_parser *p;

    mk_list_foreach(head, &ctx->multilines) {
        ml = mk_list_entry(head, struct flb_ml, _head);
        if (ml->parser_name && !ml->parser) {
            p = flb_parser_get(ml->parser_name, ctx);
            if (!p) {
                flb_error("multiline parser '%s' points to an undefined parser '%s'",
                          ml->name, ml->parser_name);
                return -1;
            }
            ml->parser = p;
        }
    }

    return 0;
}

int flb_ml_auto_flush_start(struct flb_ml *ml)
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
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ml_stream *mst;

    if (!ml) {
        return 0;
    }

    if (ml->name) {
        flb_sds_destroy(ml->name);
    }

    if (ml->match_str) {
        flb_sds_destroy(ml->match_str);
    }
    if (ml->key_content) {
        flb_sds_destroy(ml->key_content);
    }
    if (ml->key_group) {
        flb_sds_destroy(ml->key_group);
    }
    if (ml->key_pattern) {
        flb_sds_destroy(ml->key_pattern);
    }

    /* Destroy streams */
    mk_list_foreach_safe(head, tmp, &ml->streams) {
        mst = mk_list_entry(head, struct flb_ml_stream, _head);
        flb_ml_stream_destroy(mst);
    }

    /* Regex rules */
    flb_ml_rule_destroy_all(ml);

    /* Unlink from struct flb_config->multilines */
    mk_list_del(&ml->_head);

    flb_free(ml);
    return 0;
}

int flb_ml_flush_stream_group(struct flb_ml *ml, struct flb_ml_stream *mst,
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

        len = flb_sds_len(ml->key_content);
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
                ml->key_content &&
                k.via.str.size == len &&
                strncmp(k.via.str.ptr, ml->key_content, len) == 0) {

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
        if (ml->key_content) {
            len = flb_sds_len(ml->key_content);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, ml->key_content, len);
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
        mst->cb_flush(ml, mst, mst->cb_data, mp_sbuf.data, mp_sbuf.size);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_sds_len_set(group->buf, 0);

    /* Update last flush time */
    group->last_flush = time_ms_now();

    return 0;
}

static struct flb_ml_stream_group *stream_group_create(struct flb_ml *ml,
                                                       struct flb_ml_stream *mst,
                                                       char *name, int len)
{
    struct flb_ml_stream_group *group;

    if (!name) {
        name = "_default";
    }

    group = flb_calloc(1, sizeof(struct flb_ml_stream_group));
    if (!group) {
        flb_errno();
        return NULL;
    }
    group->name = flb_sds_create_len(name, len);
    if (!group->name) {
        flb_free(group);
        return NULL;
    }

    /* status */
    group->first_line = FLB_TRUE;

    /* multiline buffer */
    group->buf = flb_sds_create_size(FLB_ML_BUF_SIZE);
    if (!group->buf) {
        flb_error("cannot allocate multiline stream buffer in group %s", name);
        flb_sds_destroy(group->name);
        flb_free(group);
        return NULL;
    }

    /* msgpack buffer */
    msgpack_sbuffer_init(&group->mp_sbuf);
    msgpack_packer_init(&group->mp_pck, &group->mp_sbuf, msgpack_sbuffer_write);

    mk_list_add(&group->_head, &mst->groups);

    return group;
}

struct flb_ml_stream_group *flb_ml_stream_group_get(struct flb_ml *ml,
                                                    struct flb_ml_stream *mst,
                                                    msgpack_object *group_name)
{
    int len;
    char *name;
    struct mk_list *head;
    struct flb_ml_stream_group *group = NULL;

    /* If key_group was not defined, we already have a default group */
    if (!ml->key_group || !group_name) {
        group = mk_list_entry_first(&mst->groups,
                                    struct flb_ml_stream_group,
                                    _head);
        return group;
    }

    /* Lookup for a candidate group */
    len = group_name->via.str.size;
    name = (char *)group_name->via.str.ptr;

    mk_list_foreach(head, &mst->groups) {
        group = mk_list_entry(head, struct flb_ml_stream_group, _head);
        if (flb_sds_cmp(group->name, name, len) == 0) {
            return group;
        }
        else {
            group = NULL;
            continue;
        }
    }

    /* No group has been found, create a new one */
    if (mk_list_size(&mst->groups) >= FLB_ML_MAX_GROUPS) {
        flb_error("[multiline] stream %s exceeded number of allowed groups (%i)",
                  mst->name, FLB_ML_MAX_GROUPS);
        return NULL;
    }

    group = stream_group_create(ml, mst, name, len);
    return group;
}

static void stream_group_destroy(struct flb_ml_stream_group *group)
{
    if (group->name) {
        flb_sds_destroy(group->name);
    }
    if (group->buf) {
        flb_sds_destroy(group->buf);
    }
    msgpack_sbuffer_destroy(&group->mp_sbuf);
    mk_list_del(&group->_head);
    flb_free(group);
}

static void stream_group_destroy_all(struct flb_ml_stream *mst)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ml_stream_group *group;

    mk_list_foreach_safe(head, tmp, &mst->groups) {
        group = mk_list_entry(head, struct flb_ml_stream_group, _head);
        stream_group_destroy(group);
    }
}

static int stream_group_init(struct flb_ml *ml, struct flb_ml_stream *mst)
{
    struct flb_ml_stream_group *group = NULL;

    mk_list_init(&mst->groups);

    /* create a default group */
    group = stream_group_create(ml, mst, NULL, 0);
    if (!group) {
        flb_error("[multiline] error initializing default group for "
                  "stream '%s'", mst->name);
        return -1;
    }

    return 0;
}

struct flb_ml_stream *flb_ml_stream_create(struct flb_ml *ml,
                                           char *name,
                                           int (*cb_flush) (struct flb_ml *,
                                                            struct flb_ml_stream *,
                                                            void *cb_data,
                                                            void *buf_data,
                                                            size_t buf_size),
                                           void *cb_data)
{
    int ret;
    char tmp[64];
    struct flb_ml_stream *mst;

    mst = flb_calloc(1, sizeof(struct flb_ml_stream));
    if (!mst) {
        flb_errno();
        return NULL;
    }

    if (!name) {
        snprintf(tmp, sizeof(tmp) - 1, "stream-%03i", mk_list_size(&ml->streams));
        name = tmp;
    }

    mst->name = flb_sds_create(name);
    if (!mst->name) {
        flb_free(mst);
        return NULL;
    }


    /* Flush Callback and opaque data type */
    if (cb_flush) {
        mst->cb_flush = cb_flush;
    }
    else {
        mst->cb_flush = ml_flush_stdout;
    }
    mst->cb_data = cb_data;

    ret = stream_group_init(ml, mst);
    if (ret != 0) {
        flb_free(mst);
        return NULL;
    }

    mk_list_add(&mst->_head, &ml->streams);
    return mst;
}

int flb_ml_stream_destroy(struct flb_ml_stream *mst)
{
    mk_list_del(&mst->_head);
    if (mst->name) {
        flb_sds_destroy(mst->name);
    }

    /* destroy groups */
    stream_group_destroy_all(mst);

    flb_free(mst);

    return 0;
}

int flb_ml_init(struct flb_ml *ml)
{
    int ret;

    ret = flb_ml_rule_init(ml);
    if (ret == -1) {
        return -1;
    }

    return 0;
}
