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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_snapshot.h>

static struct flb_sp_snapshot_page *snapshot_page_create()
{
    struct flb_sp_snapshot_page *page;

    page = (struct flb_sp_snapshot_page *)
           flb_calloc(1, sizeof(struct flb_sp_snapshot_page));
    if (!page) {
        flb_errno();
        return NULL;
    }

    page->snapshot_page = (char *) flb_malloc(SNAPSHOT_PAGE_SIZE);
    if (!page->snapshot_page) {
        flb_errno();
        flb_free(page);
        return NULL;
    }

    return page;
}

static int snapshot_cleanup(struct flb_sp_snapshot *snapshot, struct flb_time *tms)
{
    int ok;
    size_t off;
    size_t off_copy;
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_time tms0;
    struct flb_sp_snapshot_page *page;

    ok = MSGPACK_UNPACK_SUCCESS;
    off = 0;

    while (mk_list_is_empty(&snapshot->pages) != 0) {
        page = mk_list_entry_first(&snapshot->pages, struct flb_sp_snapshot_page,
                                   _head);
        off = page->start_pos;
        off_copy = off;

        msgpack_unpacked_init(&result);

        while (msgpack_unpack_next(&result, page->snapshot_page, page->end_pos,
                                   &off) == ok) {

            if (snapshot->record_limit > 0 &&
                snapshot->records > snapshot->record_limit) {
                page->start_pos = off;
                snapshot->records--;
                snapshot->size = snapshot->size - (off - off_copy);
                off_copy = off;

                continue;
            }

            /* extract timestamp */
            flb_time_pop_from_msgpack(&tms0, &result, &obj);

            if (snapshot->time_limit > 0 &&
                tms->tm.tv_sec - tms0.tm.tv_sec > snapshot->time_limit) {
                page->start_pos = off;
                snapshot->records--;
                snapshot->size = snapshot->size - (off - off_copy);
                off_copy = off;

                continue;
            }

            break;
        }

        msgpack_unpacked_destroy(&result);

        /* If page is empty, free the page and move to the next one */
        if (page->start_pos != page->end_pos) {
            break;
        }

        mk_list_del(&page->_head);
        flb_free(page->snapshot_page);
        flb_free(page);
    }

    return 0;
}

static bool snapshot_page_is_full(struct flb_sp_snapshot_page *page, size_t buf_size)
{
    return SNAPSHOT_PAGE_SIZE - page->end_pos < buf_size;
}

char *flb_sp_snapshot_name_from_flush(flb_sds_t name)
{
    return name + sizeof("__flush_") - 1;
}

int flb_sp_snapshot_update(struct flb_sp_task *task, const char *buf_data,
                           size_t buf_size, struct flb_time *tms)
{
    int ok;
    size_t off = 0;
    struct flb_time tm;
    struct flb_sp_snapshot *snapshot;
    struct flb_sp_snapshot_page *page;
    msgpack_unpacked result;
    msgpack_object *obj;

    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);

    if (buf_size <= 0) {
        return -1;
    }

    snapshot = (struct flb_sp_snapshot *) task->snapshot;

    /* Create a snapshot pgae if the list is empty */
    if (mk_list_is_empty(&snapshot->pages) == 0) {
        page = snapshot_page_create();
        if (!page) {
            flb_errno();
            return -1;
        }

        mk_list_add(&page->_head, &snapshot->pages);
    }
    else {
        page = mk_list_entry_last(&snapshot->pages, struct flb_sp_snapshot_page, _head);

        if (snapshot_page_is_full(page, buf_size)) {
            page = snapshot_page_create();
            if (!page) {
                flb_errno();
                return -1;
            }

            mk_list_add(&page->_head, &snapshot->pages);
        }
    }

    memcpy(page->snapshot_page + page->end_pos, buf_data, buf_size);
    page->end_pos = page->end_pos + buf_size;

    /* Get the last timestamp */
    while (msgpack_unpack_next(&result, page->snapshot_page,
                               page->end_pos - page->start_pos, &off) == ok) {
        flb_time_pop_from_msgpack(&tm, &result, &obj);
    }

    msgpack_unpacked_destroy(&result);

    snapshot->records++;
    snapshot->size = snapshot->size + buf_size;

    /* Remove records from snapshot pages based on time/length window */
    snapshot_cleanup(snapshot, tms);

    return 0;
}

int flb_sp_snapshot_flush(struct flb_sp *sp, struct flb_sp_task *task,
                          char **out_buf_data, size_t *out_buf_size)
{
    size_t off;
    size_t page_size;
    char *snapshot_name;
    char *out_buf_data_tmp;
    struct flb_sp_cmd *cmd;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *snapshot_head;
    struct flb_sp_task *snapshot_task;
    struct flb_sp_snapshot *snapshot;
    struct flb_sp_snapshot_page *page;

    off = 0;
    cmd = task->cmd;
    snapshot_name = flb_sp_snapshot_name_from_flush(cmd->stream_name);

    /* Lookup Tasks that matches the incoming instance data */
    mk_list_foreach(head, &sp->tasks) {
        snapshot_task = mk_list_entry(head, struct flb_sp_task, _head);
        cmd = snapshot_task->cmd;

        if (cmd->type == FLB_SP_CREATE_SNAPSHOT &&
            flb_sds_cmp(cmd->stream_name, snapshot_name,
                        strlen(snapshot_name)) == 0) {

            snapshot = (struct flb_sp_snapshot *) snapshot_task->snapshot;

            if (snapshot->size == 0) {
                break;
            }

            if (*out_buf_data == NULL) {
                *out_buf_data = (char *) flb_malloc(snapshot->size);
                if (!*out_buf_data) {
                    flb_errno();
                    return -1;
                }
                *out_buf_size = snapshot->size;
            }
            else {
                out_buf_data_tmp = (char *) flb_realloc(*out_buf_data,
                                                        *out_buf_size + snapshot->size);
                if (!out_buf_data_tmp) {
                    flb_errno();
                    return -1;
                }
                *out_buf_data = out_buf_data_tmp;
                *out_buf_size = *out_buf_size + snapshot->size;
            }

            mk_list_foreach_safe(snapshot_head, tmp, &snapshot->pages) {
                page = mk_list_entry_first(&snapshot->pages,
                                           struct flb_sp_snapshot_page, _head);
                page_size = page->end_pos - page->start_pos;
                memcpy(*out_buf_data + off,
                       page->snapshot_page + page->start_pos, page_size);
                off = off + page_size;

                /* Remove page from list */
                mk_list_del(&page->_head);
                flb_free(page->snapshot_page);
                flb_free(page);
            }

            mk_list_init(&snapshot->pages);

            snapshot->records = 0;
            snapshot->size = 0;
        }
    }

    return 0;
}

void flb_sp_snapshot_destroy(struct flb_sp_snapshot *snapshot)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_sp_snapshot_page *page;

    if (snapshot != NULL) {
        mk_list_foreach_safe(head, tmp, &snapshot->pages) {
            page = mk_list_entry(head, struct flb_sp_snapshot_page, _head);
            mk_list_del(&page->_head);
            flb_free(page->snapshot_page);
            flb_free(page);
        }
        flb_free(snapshot);
    }
}
