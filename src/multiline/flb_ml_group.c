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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

struct flb_ml_group *flb_ml_group_create(struct flb_ml *ml)
{
    struct flb_ml_group *group;

    group = flb_calloc(1, sizeof(struct flb_ml_group));
    if (!group) {
        flb_errno();
        return NULL;
    }
    group->id = mk_list_size(&ml->groups);
    group->ml = ml;
    group->lru_parser = NULL;
    mk_list_init(&group->parsers);

    mk_list_add(&group->_head, &ml->groups);

    return group;
}

/*
 * Link a parser instance into the active group, if no group exists, a default
 * one is created.
 */
int flb_ml_group_add_parser(struct flb_ml *ctx, struct flb_ml_parser_ins *p)
{
    struct flb_ml_group *group = NULL;

    if (mk_list_size(&ctx->groups) == 0) {
        group = flb_ml_group_create(ctx);
        if (!group) {
            return -1;
        }
    }
    else {
        /* retrieve the latest active group */
        group = mk_list_entry_last(&ctx->groups, struct flb_ml_group, _head);
    }

    if (!group) {
        return -1;
    }

    mk_list_add(&p->_head, &group->parsers);
    return 0;
}

void flb_ml_group_destroy(struct flb_ml_group *group)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_ml_parser_ins *parser_i;

    /* destroy parser instances */
    mk_list_foreach_safe(head, tmp, &group->parsers) {
        parser_i = mk_list_entry(head, struct flb_ml_parser_ins, _head);
        flb_ml_parser_instance_destroy(parser_i);
    }

    mk_list_del(&group->_head);
    flb_free(group);
}

int flb_ml_group_cat(struct flb_ml_stream_group *group,
                     const char *data, size_t len)
{
    size_t avail;
    size_t limit;
    int    ret;
    int    status = FLB_MULTILINE_OK;

    limit = group->stream->ml->buffer_limit;
    if (limit > 0) {
        if (flb_sds_len(group->buf) >= limit) {
            group->truncated = FLB_TRUE;
            return FLB_MULTILINE_TRUNCATED;
        }

        avail = limit - flb_sds_len(group->buf);
        if (len > avail) {
            len = avail;
            group->truncated = FLB_TRUE;
            status = FLB_MULTILINE_TRUNCATED;
        }
    }

    if (len == 0) {
        return status;
    }

    ret = flb_sds_cat_safe(&group->buf, data, len);
    if (ret == -1) {
        return -1;
    }

    return status;
}
