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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <cfl/cfl.h>

static int ml_flush_stdout(struct flb_ml_parser *parser,
                           struct flb_ml_stream *mst,
                           void *data, char *buf_data, size_t buf_size)
{
    fprintf(stdout, "\n%s----- MULTILINE FLUSH -----%s\n",
            ANSI_GREEN, ANSI_RESET);

    /* Print incoming flush buffer */
    flb_pack_print(buf_data, buf_size);

    fprintf(stdout, "%s----------- EOF -----------%s\n",
            ANSI_GREEN, ANSI_RESET);
    return 0;
}

static struct flb_ml_stream_group *stream_group_create(struct flb_ml_stream *mst,
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
    msgpack_sbuffer_init(&group->mp_md_sbuf);
    msgpack_packer_init(&group->mp_md_pck, &group->mp_md_sbuf, msgpack_sbuffer_write);

    msgpack_sbuffer_init(&group->mp_sbuf);
    msgpack_packer_init(&group->mp_pck, &group->mp_sbuf, msgpack_sbuffer_write);

    group->truncated = FLB_FALSE;
    /* parent stream reference */
    group->stream = mst;

    mk_list_add(&group->_head, &mst->groups);

    return group;
}

struct flb_ml_stream_group *flb_ml_stream_group_get(struct flb_ml_parser_ins *parser_i,
                                                    struct flb_ml_stream *mst,
                                                    msgpack_object *group_name)
{
    int len;
    char *name;
    struct flb_ml_parser *mlp;
    struct mk_list *head;
    struct flb_ml_stream_group *group = NULL;

    mlp = parser_i->ml_parser;

    /* If key_group was not defined, we already have a default group */
    if (!mlp->key_group || !group_name) {
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

    group = stream_group_create(mst, name, len);
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

    msgpack_sbuffer_destroy(&group->mp_md_sbuf);
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

static int stream_group_init(struct flb_ml_stream *stream)
{
    struct flb_ml_stream_group *group = NULL;

    mk_list_init(&stream->groups);

    /* create a default group */
    group = stream_group_create(stream, NULL, 0);
    if (!group) {
        flb_error("[multiline] error initializing default group for "
                  "stream '%s'", stream->name);
        return -1;
    }

    return 0;
}

static struct flb_ml_stream *stream_create(struct flb_ml *ml,
                                           uint64_t id,
                                           struct flb_ml_parser_ins *parser,
                                           int (*cb_flush) (struct flb_ml_parser *,
                                                            struct flb_ml_stream *,
                                                            void *cb_data,
                                                            char *buf_data,
                                                            size_t buf_size),
                                           void *cb_data)
{
    int ret;
    struct flb_ml_stream *stream;

    stream = flb_calloc(1, sizeof(struct flb_ml_stream));
    if (!stream) {
        flb_errno();
        return NULL;
    }
    stream->ml = ml;
    stream->id = id;
    stream->parser = parser;

    /* Flush Callback and opaque data type */
    if (cb_flush) {
        stream->cb_flush = cb_flush;
    }
    else {
        stream->cb_flush = ml_flush_stdout;
    }
    stream->cb_data = cb_data;

    ret = stream_group_init(stream);
    if (ret != 0) {
        flb_free(stream);
        return NULL;
    }

    mk_list_add(&stream->_head, &parser->streams);
    return stream;
}

int flb_ml_stream_create(struct flb_ml *ml,
                         char *name,
                         int name_len,
                         int (*cb_flush) (struct flb_ml_parser *,
                                          struct flb_ml_stream *,
                                          void *cb_data,
                                          char *buf_data,
                                          size_t buf_size),
                         void *cb_data,
                         uint64_t *stream_id)
{
    uint64_t id;
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_stream *mst;
    struct flb_ml_group *group;
    struct flb_ml_parser_ins *parser;

    if (!name) {
        return -1;
    }

    if (name_len <= 0) {
        name_len = strlen(name);
    }

    /* Set the stream id by creating a hash using the name */
    id = cfl_hash_64bits(name, name_len);

    /* For every group and parser, create a stream for this stream_id/hash */
    mk_list_foreach(head, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);
        mk_list_foreach(head_group, &group->parsers) {
            parser = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);

            /* Check if the stream already exists on the parser */
            if (flb_ml_stream_get(parser, id) != NULL) {
                continue;
            }

            /* Create the stream */
            mst = stream_create(ml, id, parser, cb_flush, cb_data);
            if (!mst) {
                flb_error("[multiline] could not create stream_id=%" PRIu64
                          "for stream '%s' on parser '%s'",
                          *stream_id, name, parser->ml_parser->name);
                return -1;
            }
        }
    }

    *stream_id = id;
    return 0;
}

struct flb_ml_stream *flb_ml_stream_get(struct flb_ml_parser_ins *parser,
                                        uint64_t stream_id)
{
    struct mk_list *head;
    struct flb_ml_stream *mst = NULL;

    mk_list_foreach(head, &parser->streams) {
        mst = mk_list_entry(head, struct flb_ml_stream, _head);
        if (mst->id == stream_id) {
            return mst;
        }
    }

    return NULL;
}

void flb_ml_stream_id_destroy_all(struct flb_ml *ml, uint64_t stream_id)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *head_group;
    struct mk_list *head_stream;
    struct flb_ml_group *group;
    struct flb_ml_stream *mst;
    struct flb_ml_parser_ins *parser_i;

    /* groups */
    mk_list_foreach(head, &ml->groups) {
        group = mk_list_entry(head, struct flb_ml_group, _head);

        /* parser instances */
        mk_list_foreach(head_group, &group->parsers) {
            parser_i = mk_list_entry(head_group, struct flb_ml_parser_ins, _head);

            /* streams */
            mk_list_foreach_safe(head_stream, tmp, &parser_i->streams) {
                mst = mk_list_entry(head_stream, struct flb_ml_stream, _head);
                if (mst->id != stream_id) {
                    continue;
                }

                /* flush any pending data */
                flb_ml_flush_parser_instance(ml, parser_i, stream_id, FLB_TRUE);

                /* destroy internal groups of the stream */
                flb_ml_stream_destroy(mst);
            }
        }
    }
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
