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

#define FS_CHUNK_SIZE_DEBUG(op)  {flb_trace("[%d] %s -> fs_chunks_size = %zu", \
	__LINE__, op->name, op->fs_chunks_size);}
#define FS_CHUNK_SIZE_DEBUG_MOD(op, chunk, mod)  {flb_trace( \
	"[%d] %s -> fs_chunks_size = %zu mod=%zd chunk=%s", __LINE__, \
	op->name, op->fs_chunks_size, mod, flb_input_chunk_get_name(chunk));}

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_routes_mask.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <chunkio/chunkio.h>
#include <monkey/mk_core.h>
#include <string.h>
#include <stdint.h>


#ifdef FLB_HAVE_CHUNK_TRACE
#include <fluent-bit/flb_chunk_trace.h>
#endif /* FLB_HAVE_CHUNK_TRACE */


#define BLOCK_UNTIL_KEYPRESS() {char temp_keypress_buffer; read(0, &temp_keypress_buffer, 1);}

#define FLB_INPUT_CHUNK_RELEASE_SCOPE_LOCAL  0
#define FLB_INPUT_CHUNK_RELEASE_SCOPE_GLOBAL 1

struct input_chunk_raw {
    struct flb_input_instance *ins;
    int event_type;
    size_t records;
    flb_sds_t tag;
    void *buf_data;
    size_t buf_size;
};

struct flb_input_chunk_meta_view {
    char *buffer;
    int length;
    const char *tag;
    int tag_length;
    uint8_t flags;
    uint8_t *routing_data;
    uint16_t routing_data_length;
};

static inline int input_chunk_has_magic_bytes(char *buf, int len)
{
    unsigned char *p;

    if (len < FLB_INPUT_CHUNK_META_HEADER) {
        return FLB_FALSE;
    }

    p = (unsigned char *) buf;
    if (p[0] == FLB_INPUT_CHUNK_MAGIC_BYTE_0 &&
        p[1] == FLB_INPUT_CHUNK_MAGIC_BYTE_1) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int input_chunk_metadata_view(struct flb_input_chunk *ic,
                                     struct flb_input_chunk_meta_view *view)
{
    int ret;
    int len;
    int has_magic;
    int payload_length;
    int offset;
    int computed_tag_len;
    uint8_t flags;
    uint16_t routing_length;
    char *buf;
    char *terminator;
    const char *tag_start;

    ret = cio_meta_read(ic->chunk, &buf, &len);
    if (ret == -1) {
        return -1;
    }

    view->buffer = buf;
    view->length = len;
    view->flags = 0;
    view->routing_data = NULL;
    view->routing_data_length = 0;
    view->tag = buf;
    view->tag_length = len;

    has_magic = input_chunk_has_magic_bytes(buf, len);
    if (has_magic == FLB_FALSE) {
        return 0;
    }

    payload_length = len - FLB_INPUT_CHUNK_META_HEADER;
    if (payload_length < 0) {
        payload_length = 0;
    }

    tag_start = buf + FLB_INPUT_CHUNK_META_HEADER;
    view->tag = tag_start;
    view->tag_length = payload_length;
    flags = (uint8_t) buf[3];
    view->flags = flags;

    terminator = memchr(tag_start, '\0', payload_length);
    if (terminator) {
        view->tag_length = (int) (terminator - tag_start);
    }

    if ((flags & FLB_CHUNK_FLAG_DIRECT_ROUTES) == 0) {
        return 0;
    }

    if (payload_length <= 0) {
        return 0;
    }

    if (!terminator) {
        return 1;
    }

    computed_tag_len = view->tag_length;
    offset = computed_tag_len + 1;

    if (payload_length < offset + (int) sizeof(uint16_t)) {
        return 1;
    }

    routing_length = (uint16_t) (((unsigned char) tag_start[offset] << 8) |
                                 (unsigned char) tag_start[offset + 1]);

    if (payload_length < offset + (int) sizeof(uint16_t) + routing_length) {
        return 1;
    }

    view->routing_data_length = routing_length;
    view->routing_data = ((uint8_t *) tag_start) + offset + (int) sizeof(uint16_t);

    return 0;
}

#define ROUTE_PLUGIN_NAME_LEN(route) \
    ((route)->plugin_name_length > 0 ? (int) (route)->plugin_name_length : \
     (route)->plugin_name != NULL ? (int) strlen((route)->plugin_name) : 0)

int flb_chunk_route_plugin_matches(struct flb_output_instance *o_ins,
                                   const struct flb_chunk_direct_route *route)
{
    int stored_length;
    int candidate_length;

    if (!route) {
        return FLB_FALSE;
    }

    if (!route->plugin_name || route->plugin_name[0] == '\0') {
        return FLB_TRUE;
    }

    if (!o_ins || !o_ins->p || !o_ins->p->name) {
        return FLB_FALSE;
    }

    stored_length = ROUTE_PLUGIN_NAME_LEN(route);
    if (stored_length <= 0) {
        return FLB_FALSE;
    }

    candidate_length = (int) strlen(o_ins->p->name);
    if (candidate_length != stored_length) {
        return FLB_FALSE;
    }

    if (strncmp(o_ins->p->name, route->plugin_name, (size_t) stored_length) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

#undef ROUTE_PLUGIN_NAME_LEN

#ifdef FLB_HAVE_IN_STORAGE_BACKLOG

extern ssize_t sb_get_releasable_output_queue_space(struct flb_output_instance *output_plugin,
                                                    size_t                      required_space);

extern int sb_release_output_queue_space(struct flb_output_instance *output_plugin,
                                         ssize_t                    *required_space);


#else

ssize_t sb_get_releasable_output_queue_space(struct flb_output_instance *output_plugin,
                                             size_t                      required_space)
{
    return 0;
}

int sb_release_output_queue_space(struct flb_output_instance *output_plugin,
                                  ssize_t                    *required_space)
{
    return 0;
}

#endif

static int flb_input_chunk_safe_delete(struct flb_input_chunk *ic,
                                       struct flb_input_chunk *old_ic,
                                       uint64_t o_id);

static int flb_input_chunk_is_task_safe_delete(struct flb_task *task);

static int flb_input_chunk_drop_task_route(
                struct flb_task *task,
                struct flb_output_instance *o_ins,
                ssize_t *dropped_record_count);


static ssize_t get_input_chunk_record_count(struct flb_input_chunk *input_chunk)
{
    ssize_t record_count;
    char   *chunk_buffer;
    size_t  chunk_size;
    int     set_down;
    int     ret;

    ret = cio_chunk_is_up(input_chunk->chunk);
    set_down = FLB_FALSE;

    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(input_chunk->chunk);

        if (ret == -1) {
            return -1;
        }

        set_down = FLB_TRUE;
    }

    ret = cio_chunk_get_content(input_chunk->chunk,
                                &chunk_buffer,
                                &chunk_size);

    if (ret == CIO_OK) {
        record_count = flb_mp_count(chunk_buffer, chunk_size);
    }
    else {
        record_count = -1;
    }

    if (set_down) {
        cio_chunk_down(input_chunk->chunk);
    }

    return record_count;
}

static int flb_input_chunk_release_space(
                    struct flb_input_chunk     *new_input_chunk,
                    struct flb_input_instance  *input_plugin,
                    struct flb_output_instance *output_plugin,
                    ssize_t                    *required_space,
                    int                         release_scope)
{
    struct mk_list         *input_chunk_iterator_tmp;
    struct mk_list         *input_chunk_iterator;
    struct flb_router      *router;
    ssize_t                 dropped_record_count;
    int                     chunk_destroy_flag;
    struct flb_input_chunk *old_input_chunk;
    ssize_t                 released_space;
    int                     chunk_released;
    ssize_t                 chunk_size;

    released_space = 0;

    mk_list_foreach_safe(input_chunk_iterator, input_chunk_iterator_tmp,
                         &input_plugin->chunks) {
        old_input_chunk = mk_list_entry(input_chunk_iterator,
                                             struct flb_input_chunk, _head);

        if (!flb_routes_mask_get_bit(old_input_chunk->routes_mask,
                                     output_plugin->id,
                                     input_plugin->config->router)) {
            continue;
        }

        if (flb_input_chunk_safe_delete(new_input_chunk,
                                        old_input_chunk,
                                        output_plugin->id) == FLB_FALSE) {
            continue;
        }

        if (flb_input_chunk_drop_task_route(old_input_chunk->task,
                                            output_plugin,
                                            &dropped_record_count) == FLB_FALSE) {
            continue;
        }

        chunk_size = flb_input_chunk_get_real_size(old_input_chunk);
        chunk_released = FLB_FALSE;
        chunk_destroy_flag = FLB_FALSE;

        if (release_scope == FLB_INPUT_CHUNK_RELEASE_SCOPE_LOCAL) {
            flb_routes_mask_clear_bit(old_input_chunk->routes_mask,
                                      output_plugin->id,
                                      input_plugin->config->router);

            FS_CHUNK_SIZE_DEBUG_MOD(output_plugin, old_input_chunk, chunk_size);
            output_plugin->fs_chunks_size -= chunk_size;

            chunk_destroy_flag = flb_routes_mask_is_empty(
                                                old_input_chunk->routes_mask,
                                                input_plugin->config->router);

            chunk_released = FLB_TRUE;
        }
        else if (release_scope == FLB_INPUT_CHUNK_RELEASE_SCOPE_GLOBAL) {
            chunk_destroy_flag = FLB_TRUE;
        }

#ifdef FLB_HAVE_METRICS
        if (dropped_record_count == 0) {
            dropped_record_count = get_input_chunk_record_count(old_input_chunk);

            if (dropped_record_count == -1) {
                flb_debug("[task] error getting chunk record count : %s",
                          old_input_chunk->in->name);
            }
            else {
                cmt_counter_add(output_plugin->cmt_dropped_records,
                                cfl_time_now(),
                                dropped_record_count,
                                1, (char *[]) {(char *) flb_output_name(output_plugin)});

                if (input_plugin->config && input_plugin->config->router &&
                    old_input_chunk->event_type == FLB_INPUT_LOGS) {
                    router = input_plugin->config->router;

                    cmt_counter_add(router->logs_drop_records_total,
                                    cfl_time_now(),
                                    (double) dropped_record_count,
                                    2,
                                    (char *[]){(char *) flb_input_name(old_input_chunk->in),
                                               (char *) flb_output_name(output_plugin)});

                    cmt_counter_add(router->logs_drop_bytes_total,
                                    cfl_time_now(),
                                    (double) chunk_size,
                                    2,
                                    (char *[]){(char *) flb_input_name(old_input_chunk->in),
                                               (char *) flb_output_name(output_plugin)});
                }

                flb_metrics_sum(FLB_METRIC_OUT_DROPPED_RECORDS,
                                dropped_record_count,
                                output_plugin->metrics);
            }
        }
#endif

        if (chunk_destroy_flag) {
            if (old_input_chunk->task != NULL) {
                /*
                 * If the chunk is referenced by a task and task has no active route,
                 * we need to destroy the task as well.
                 */
                if (old_input_chunk->task->users == 0) {
                    flb_debug("[task] drop task_id %d with no active route from input plugin %s",
                              old_input_chunk->task->id, new_input_chunk->in->name);
                    flb_task_destroy(old_input_chunk->task, FLB_TRUE);

                    chunk_released = FLB_TRUE;
                }
            }
            else {
                flb_debug("[input chunk] drop chunk %s with no output route from input plugin %s",
                          flb_input_chunk_get_name(old_input_chunk), new_input_chunk->in->name);

                flb_input_chunk_destroy(old_input_chunk, FLB_TRUE);

                chunk_released = FLB_TRUE;
            }
        }

        if (chunk_released) {
            released_space += chunk_size;
        }

        if (released_space >= *required_space) {
            break;
        }
    }

    *required_space -= released_space;

    return 0;
}

static void generate_chunk_name(struct flb_input_instance *in,
                                char *out_buf, int buf_size)
{
    struct flb_time tm;
    (void) in;

    flb_time_get(&tm);
    snprintf(out_buf, buf_size - 1,
             "%i-%lu.%4lu.flb",
             getpid(),
             tm.tm.tv_sec, tm.tm.tv_nsec);
}

ssize_t flb_input_chunk_get_size(struct flb_input_chunk *ic)
{
    return cio_chunk_get_content_size(ic->chunk);
}

/*
 * When chunk is set to DOWN from memory, data_size is set to 0 and
 * cio_chunk_get_content_size(1) returns the data_size. fs_chunks_size
 * is used to track the size of chunks in filesystem so we need to call
 * cio_chunk_get_real_size to return the original size in the file system
 */
ssize_t flb_input_chunk_get_real_size(struct flb_input_chunk *ic)
{
    ssize_t meta_size;
    ssize_t size;

    size = cio_chunk_get_real_size(ic->chunk);

    if (size != 0) {
        return size;
    }

    // Real size is not synced to chunk yet
    size = flb_input_chunk_get_size(ic);
    if (size == 0) {
        flb_debug("[input chunk] no data in the chunk %s",
                  flb_input_chunk_get_name(ic));
        return -1;
    }

    meta_size = cio_meta_size(ic->chunk);
    size += meta_size
        /* See https://github.com/edsiper/chunkio#file-layout for more details */
         + 2    /* HEADER BYTES */
         + 4    /* CRC32 */
         + 16   /* PADDING */
         + 2;   /* METADATA LENGTH BYTES */

    return size;
}

int flb_input_chunk_write(void *data, const char *buf, size_t len)
{
    int ret;
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) data;

    ret = cio_chunk_write(ic->chunk, buf, len);
    return ret;
}

int flb_input_chunk_write_at(void *data, off_t offset,
                             const char *buf, size_t len)
{
    int ret;
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) data;

    ret = cio_chunk_write_at(ic->chunk, offset, buf, len);
    return ret;
}

static int flb_input_chunk_drop_task_route(
            struct flb_task *task,
            struct flb_output_instance *output_plugin,
            ssize_t *dropped_record_count)
{
    int route_status;
    int result;

    *dropped_record_count = 0;

    if (task == NULL) {
        return FLB_TRUE;
    }

    result = FLB_TRUE;

    if (task->users != 0) {
        result = FLB_FALSE;

        if (output_plugin != NULL) {
            flb_task_acquire_lock(task);

            route_status = flb_task_get_route_status(task, output_plugin);

            if (route_status == FLB_TASK_ROUTE_INACTIVE) {
                flb_task_set_route_status(task,
                                          output_plugin,
                                          FLB_TASK_ROUTE_DROPPED);

                *dropped_record_count = (ssize_t) task->records;

                result = FLB_TRUE;
            }

            flb_task_release_lock(task);
        }
    }

    return result;
}


/*
 * For input_chunk referenced by an outgoing task, we need to check
 * whether the chunk is in the middle of output flush callback
 */
static int flb_input_chunk_is_task_safe_delete(struct flb_task *task)
{
    if (!task) {
        return FLB_TRUE;
    }

    if (task->users != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int flb_input_chunk_safe_delete(struct flb_input_chunk *ic,
                                       struct flb_input_chunk *old_ic,
                                       uint64_t o_id)
{
    /* The chunk we want to drop should not be the incoming chunk */
    if (ic == old_ic) {
        return FLB_FALSE;
    }

    /*
     * Even if chunks from same input plugin have same routes_mask when created,
     * the routes_mask could be modified when new chunks is ingested. Therefore,
     * we still need to do the validation on the routes_mask with o_id.
     */
    if (flb_routes_mask_get_bit(old_ic->routes_mask,
                                o_id,
                                ic->in->config->router) == 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int flb_input_chunk_release_space_compound(
                        struct flb_input_chunk *new_input_chunk,
                        struct flb_output_instance *output_plugin,
                        size_t *local_release_requirement,
                        int release_local_space)
{
    ssize_t                    required_space_remainder;
    struct flb_input_instance *storage_backlog_instance;
    struct flb_input_instance *input_plugin_instance;
    struct mk_list            *iterator;
    int                        result;

    storage_backlog_instance = output_plugin->config->storage_input_plugin;

    *local_release_requirement = flb_input_chunk_get_real_size(new_input_chunk);
    required_space_remainder = (ssize_t) *local_release_requirement;

    if (required_space_remainder > 0) {
        result = flb_input_chunk_release_space(new_input_chunk,
                                               storage_backlog_instance,
                                               output_plugin,
                                               &required_space_remainder,
                                               FLB_INPUT_CHUNK_RELEASE_SCOPE_GLOBAL);
    }

    if (required_space_remainder > 0) {
        result = sb_release_output_queue_space(output_plugin,
                                               &required_space_remainder);
    }

    if (release_local_space) {
        if (required_space_remainder > 0) {
            result = flb_input_chunk_release_space(new_input_chunk,
                                                   new_input_chunk->in,
                                                   output_plugin,
                                                   &required_space_remainder,
                                                   FLB_INPUT_CHUNK_RELEASE_SCOPE_LOCAL);
        }
    }

    if (required_space_remainder > 0) {
        mk_list_foreach(iterator, &output_plugin->config->inputs) {
            input_plugin_instance = \
                mk_list_entry(iterator, struct flb_input_instance, _head);

            if (input_plugin_instance != new_input_chunk->in) {
                result = flb_input_chunk_release_space(
                            new_input_chunk,
                            input_plugin_instance,
                            output_plugin,
                            &required_space_remainder,
                            FLB_INPUT_CHUNK_RELEASE_SCOPE_LOCAL);
            }

            if (required_space_remainder <= 0) {
                break;
            }
        }
    }

    if (required_space_remainder < 0) {
        required_space_remainder = 0;
    }

    *local_release_requirement = (size_t) required_space_remainder;

    (void) result;

    return 0;
}

/*
 * Find a slot in the output instance to append the new data with size chunk_size, it
 * will drop the the oldest chunks when the limitation on local disk is reached.
 */
int flb_input_chunk_find_space_new_data(struct flb_input_chunk *ic,
                                        size_t chunk_size, int overlimit)
{
    int count;
    int result;
    struct mk_list *head;
    struct flb_output_instance *o_ins;
    size_t local_release_requirement;

    /*
     * For each output instances that will be over the limit after adding the new chunk,
     * we have to determine how many chunks needs to be removed. We will adjust the
     * routes_mask to only route to the output plugin that have enough space after
     * deleting some chunks fome the queue.
     */
    count = 0;

    mk_list_foreach(head, &ic->in->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);

        if ((o_ins->total_limit_size == -1) || ((1 << o_ins->id) & overlimit) == 0 ||
           (flb_routes_mask_get_bit(ic->routes_mask,
                                    o_ins->id,
                                    o_ins->config->router) == 0)) {
            continue;
        }

        local_release_requirement = 0;

        result = flb_input_chunk_release_space_compound(
                                            ic, o_ins,
                                            &local_release_requirement,
                                            FLB_TRUE);

        if (result != 0 ||
            local_release_requirement != 0) {
            count++;
        }
    }

    if (count != 0) {
        flb_error("[input chunk] fail to drop enough chunks in order to place "
                  "new data coming from input plugin %s", flb_input_name(ic->in));
    }

    return count;
}

/*
 * Returns a non-zero result if any output instances will reach the limit
 * after buffering the new data
 */
int flb_input_chunk_has_overlimit_routes(struct flb_input_chunk *ic,
                                         size_t chunk_size)
{
    int overlimit = 0;
    struct mk_list *head;
    struct flb_output_instance *o_ins;

    mk_list_foreach(head, &ic->in->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);

        if ((o_ins->total_limit_size == -1) ||
            (flb_routes_mask_get_bit(ic->routes_mask,
                                     o_ins->id,
                                     o_ins->config->router) == 0)) {
            continue;
        }

        FS_CHUNK_SIZE_DEBUG(o_ins);
        flb_trace("[input chunk] chunk %s required %ld bytes and %ld bytes left "
                  "in plugin %s", flb_input_chunk_get_name(ic), chunk_size,
                  o_ins->total_limit_size -
                  o_ins->fs_backlog_chunks_size -
                  o_ins->fs_chunks_size,
                  o_ins->name);

        if ((o_ins->fs_chunks_size +
             o_ins->fs_backlog_chunks_size +
             chunk_size) > o_ins->total_limit_size) {
            overlimit |= (1 << o_ins->id);
        }
    }

    return overlimit;
}

/* Find a slot for the incoming data to buffer it in local file system
 * returns 0 if none of the routes can be written to
 */
int flb_input_chunk_place_new_chunk(struct flb_input_chunk *ic, size_t chunk_size)
{
    int result;
	int overlimit;
    struct flb_input_instance *i_ins = ic->in;

    if (i_ins->storage_type == CIO_STORE_FS) {
        overlimit = flb_input_chunk_has_overlimit_routes(ic, chunk_size);
        if (overlimit != 0) {
            result = flb_input_chunk_find_space_new_data(ic, chunk_size, overlimit);

            if (result != 0) {
                return 0;
            }
        }
    }
    return !flb_routes_mask_is_empty(ic->routes_mask,
                                     i_ins->config->router);
}

static int input_chunk_collect_output_references(struct flb_config *config,
                                                 const struct flb_chunk_direct_route *route,
                                                 struct flb_output_instance ***out_matches,
                                                 size_t *out_count)
{
    size_t index;
    size_t count;
    int alias_length;
    int label_length;
    int name_length;
    const char *label;
    uint32_t stored_id;
    struct mk_list *head;
    struct flb_output_instance *o_ins;
    struct flb_output_instance **matches;

    if (!config || !route || !out_matches || !out_count) {
        return -1;
    }

    *out_matches = NULL;
    *out_count = 0;

    label = route->label;
    label_length = 0;
    stored_id = route->id;
    if (label != NULL) {
        label_length = route->label_length;
        if (label_length == 0) {
            label_length = (int) strlen(label);
        }
    }

    count = 0;
    if (label != NULL && label_length > 0) {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if (o_ins->alias != NULL) {
                alias_length = (int) strlen(o_ins->alias);
                if (alias_length == label_length &&
                    strncmp(o_ins->alias, label, (size_t) label_length) == 0 &&
                    flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                    count++;
                }
            }
        }

        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            name_length = (int) strlen(o_ins->name);
            if (name_length == label_length &&
                strncmp(o_ins->name, label, (size_t) label_length) == 0 &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                if (o_ins->alias != NULL) {
                    alias_length = (int) strlen(o_ins->alias);
                    if (alias_length == label_length &&
                        strncmp(o_ins->alias, label, (size_t) label_length) == 0) {
                        continue;
                    }
                }
                count++;
            }
        }

        if (count == 0) {
            return 0;
        }
    }
    else {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if ((uint32_t) o_ins->id == stored_id &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                count++;
            }
        }

        if (count == 0) {
            return 0;
        }
    }

    matches = flb_calloc(count, sizeof(struct flb_output_instance *));
    if (!matches) {
        flb_errno();
        return -1;
    }

    index = 0;
    if (label != NULL && label_length > 0) {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if (o_ins->alias != NULL) {
                alias_length = (int) strlen(o_ins->alias);
                if (alias_length == label_length &&
                    strncmp(o_ins->alias, label, (size_t) label_length) == 0 &&
                    flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                    matches[index++] = o_ins;
                }
            }
        }

        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            name_length = (int) strlen(o_ins->name);
            if (name_length == label_length &&
                strncmp(o_ins->name, label, (size_t) label_length) == 0 &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                if (o_ins->alias != NULL) {
                    alias_length = (int) strlen(o_ins->alias);
                    if (alias_length == label_length &&
                        strncmp(o_ins->alias, label, (size_t) label_length) == 0) {
                        continue;
                    }
                }
                matches[index++] = o_ins;
            }
        }
    }
    else {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if ((uint32_t) o_ins->id == stored_id &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                matches[index++] = o_ins;
            }
        }
    }

    *out_matches = matches;
    *out_count = index;

    return 0;
}

/* Create an input chunk using a Chunk I/O */
struct flb_input_chunk *flb_input_chunk_map(struct flb_input_instance *in,
                                            int event_type,
                                            void *chunk)
{
    int records;
    int tag_len;
    int has_routes;
    int ret;
    int direct_status;
    int direct_loaded;
    int direct_index;
    int direct_missing;
    uint32_t missing_id;
    uint16_t missing_label_length;
    struct flb_chunk_direct_route *direct_routes;
    const char *missing_label;
    int direct_count;
    uint64_t ts;
    char *buf_data;
    size_t buf_size;
    size_t offset;
    ssize_t bytes;
    const char *tag_buf;
    struct flb_output_instance **direct_matches;
    size_t direct_match_count;
    size_t direct_match_index;
    struct flb_input_chunk *ic;
    size_t mask_size;

    records = 0;

    /* Create context for the input instance */
    ic = flb_calloc(1, sizeof(struct flb_input_chunk));
    if (!ic) {
        flb_errno();
        return NULL;
    }
    ic->event_type = event_type;
    ic->busy = FLB_FALSE;
    ic->fs_counted = FLB_FALSE;
    ic->fs_backlog = FLB_TRUE;
    ic->chunk = chunk;
    ic->in = in;
    msgpack_packer_init(&ic->mp_pck, ic, flb_input_chunk_write);

    ret = cio_chunk_get_content(ic->chunk, &buf_data, &buf_size);
    if (ret != CIO_OK) {
        flb_error("[input chunk] error retrieving content for metrics");
        flb_free(ic);
        return NULL;
    }

    mask_size = flb_routes_mask_get_size(in->config->router);
    ic->routes_mask = (flb_route_mask_element *)
                            flb_calloc(mask_size,
                                       sizeof(flb_route_mask_element));

    if (ic->routes_mask == NULL) {
        flb_errno();
        cio_chunk_close(chunk, CIO_TRUE);
        flb_free(ic);
        return NULL;
    }

    if (ic->event_type == FLB_INPUT_LOGS) {
        /* Validate records in the chunk */
        ret = flb_mp_validate_log_chunk(buf_data, buf_size, &records, &offset);
        if (ret == -1) {
            /* If there are valid records, truncate the chunk size */
            if (records <= 0) {
                flb_plg_error(in,
                              "chunk validation failed, data might be corrupted. "
                              "No valid records found, the chunk will be discarded.");
                flb_free(ic->routes_mask);
                flb_free(ic);
                return NULL;
            }
            if (records > 0 && offset > 32) {
                flb_plg_warn(in,
                             "chunk validation failed, data might be corrupted. "
                             "Found %d valid records, failed content starts "
                             "right after byte %lu. Recovering valid records.",
                             records, offset);

                /* truncate the chunk to recover valid records */
                cio_chunk_write_at(chunk, offset, NULL, 0);
            }
            else {
                flb_plg_error(in,
                              "chunk validation failed, data might be corrupted. "
                              "Found %d valid records, failed content starts "
                              "right after byte %lu. Cannot recover chunk,",
                              records, offset);
                flb_free(ic->routes_mask);
                flb_free(ic);
                return NULL;
            }
        }
    }
    else if (ic->event_type == FLB_INPUT_METRICS) {
        ret = flb_mp_validate_metric_chunk(buf_data, buf_size, &records, &offset);
        if (ret == -1) {
            if (records <= 0) {
                flb_plg_error(in,
                              "metrics chunk validation failed, data might be corrupted. "
                              "No valid records found, the chunk will be discarded.");
                flb_free(ic->routes_mask);
                flb_free(ic);
                return NULL;
            }
            if (records > 0 && offset > 32) {
                flb_plg_warn(in,
                             "metrics chunk validation failed, data might be corrupted. "
                             "Found %d valid records, failed content starts "
                             "right after byte %lu. Recovering valid records.",
                             records, offset);

                /* truncate the chunk to recover valid records */
                cio_chunk_write_at(chunk, offset, NULL, 0);
            }
            else {
                flb_plg_error(in,
                              "metrics chunk validation failed, data might be corrupted. "
                              "Found %d valid records, failed content starts "
                              "right after byte %lu. Cannot recover chunk,",
                              records, offset);
                flb_free(ic->routes_mask);
                flb_free(ic);
                return NULL;
            }

        }
    }
    else if (ic->event_type == FLB_INPUT_TRACES) {

    }

    /* Skip chunks without content data */
    if (records == 0) {
        flb_plg_error(in,
                      "chunk validation failed, data might be corrupted. "
                      "No valid records found, the chunk will be discarded.");
        flb_free(ic->routes_mask);
        flb_free(ic);
        return NULL;
    }

    /*
     * If the content is valid and the chunk has extra padding zeros, just
     * perform an adjustment.
     */
    bytes = cio_chunk_get_content_size(chunk);
    if (bytes == -1) {
        flb_free(ic->routes_mask);
        flb_free(ic);
        return NULL;
    }
    if (offset < bytes) {
        cio_chunk_write_at(chunk, offset, NULL, 0);
    }

    /* Update metrics */
#ifdef FLB_HAVE_METRICS
    ic->total_records = records;
    if (ic->total_records > 0) {
        /* timestamp */
        ts = cfl_time_now();

        /* fluentbit_input_records_total */
        cmt_counter_add(in->cmt_records, ts, ic->total_records,
                        1, (char *[]) {(char *) flb_input_name(in)});

        /* fluentbit_input_bytes_total */
        cmt_counter_add(in->cmt_bytes, ts, buf_size,
                        1, (char *[]) {(char *) flb_input_name(in)});

        /* OLD metrics */
        flb_metrics_sum(FLB_METRIC_N_RECORDS, ic->total_records, in->metrics);
        flb_metrics_sum(FLB_METRIC_N_BYTES, buf_size, in->metrics);
    }
#endif

    /* Get the the tag reference (chunk metadata) */
    ret = flb_input_chunk_get_tag(ic, &tag_buf, &tag_len);
    if (ret == -1) {
        flb_error("[input chunk] error retrieving tag of input chunk");
        flb_free(ic->routes_mask);
        flb_free(ic);
        return NULL;
    }

    direct_routes = NULL;
    direct_count = 0;
    direct_loaded = FLB_FALSE;
    missing_label = NULL;
    missing_label_length = 0;
    direct_status = flb_input_chunk_get_direct_routes(ic, &direct_routes, &direct_count);
    if (direct_status == 0 && direct_count > 0) {
        direct_missing = FLB_FALSE;
        missing_id = 0;
        for (direct_index = 0; direct_index < direct_count; direct_index++) {
            direct_matches = NULL;
            direct_match_count = 0;
            ret = input_chunk_collect_output_references(in->config,
                                                        &direct_routes[direct_index],
                                                        &direct_matches,
                                                        &direct_match_count);
            if (ret == -1) {
                flb_plg_error(in,
                              "failed collecting restored routes for chunk %s",
                              flb_input_chunk_get_name(ic));
            }

            if (ret != 0 || direct_match_count == 0) {
                direct_missing = FLB_TRUE;
                missing_id = direct_routes[direct_index].id;
                missing_label = direct_routes[direct_index].label;
                missing_label_length = direct_routes[direct_index].label_length;
                if (missing_label_length == 0 && missing_label != NULL) {
                    missing_label_length = (uint16_t) strlen(missing_label);
                }
                if (direct_matches != NULL) {
                    flb_free(direct_matches);
                }
                break;
            }

            if (direct_matches != NULL) {
                flb_free(direct_matches);
            }
        }

        if (direct_missing == FLB_FALSE) {
            memset(ic->routes_mask, 0,
                   sizeof(flb_route_mask_element) * mask_size);
            has_routes = 0;
            for (direct_index = 0; direct_index < direct_count; direct_index++) {
                direct_matches = NULL;
                direct_match_count = 0;
                ret = input_chunk_collect_output_references(in->config,
                                                            &direct_routes[direct_index],
                                                            &direct_matches,
                                                            &direct_match_count);
                if (ret != 0 || direct_match_count == 0 || direct_matches == NULL) {
                    if (direct_matches != NULL) {
                        flb_free(direct_matches);
                    }
                    continue;
                }

                for (direct_match_index = 0;
                     direct_match_index < direct_match_count;
                     direct_match_index++) {
                    flb_routes_mask_set_bit(ic->routes_mask,
                                            direct_matches[direct_match_index]->id,
                                            in->config->router);
                    has_routes++;
                }

                flb_free(direct_matches);
            }
            direct_loaded = FLB_TRUE;
        }
        else {
            flb_plg_warn(in,
                         "direct route output id=%u label=%.*s not found for chunk %s, falling back to tag routing",
                         (unsigned int) missing_id,
                         (int) missing_label_length,
                         missing_label ? missing_label : "",
                         flb_input_chunk_get_name(ic));
        }
    }
    else if (direct_status == -2) {
        flb_plg_warn(in,
                     "invalid direct routing metadata for chunk %s, falling back to tag routing",
                     flb_input_chunk_get_name(ic));
    }

    if (direct_routes) {
        flb_input_chunk_destroy_direct_routes(direct_routes, direct_count);
        direct_routes = NULL;
    }

    bytes = flb_input_chunk_get_real_size(ic);
    if (bytes < 0) {
        flb_warn("[input chunk] could not retrieve chunk real size");
        flb_free(ic->routes_mask);
        flb_free(ic);
        return NULL;
    }

    if (direct_loaded == FLB_FALSE) {
        has_routes = flb_routes_mask_set_by_tag(ic->routes_mask, tag_buf, tag_len, in);
        if (has_routes == 0) {
            flb_warn("[input chunk] no matching route for backoff log chunk %s",
                     flb_input_chunk_get_name(ic));
        }
    }
    else if (has_routes == 0) {
        flb_plg_warn(in,
                     "direct routing metadata for chunk %s produced no routes, falling back to tag routing",
                     flb_input_chunk_get_name(ic));
        has_routes = flb_routes_mask_set_by_tag(ic->routes_mask, tag_buf, tag_len, in);
        if (has_routes == 0) {
            flb_warn("[input chunk] no matching route for backoff log chunk %s",
                     flb_input_chunk_get_name(ic));
        }
    }

    mk_list_add(&ic->_head, &in->chunks);

    flb_input_chunk_update_output_instances(ic, bytes);

    return ic;
}

static int input_chunk_write_header(struct cio_chunk *chunk, int event_type,
                                    char *tag, int tag_len)

{
    int ret;
    int meta_size;
    char *meta;

    /*
     * Prepare the Chunk metadata header
     * ----------------------------------
     * m[0] = FLB_INPUT_CHUNK_MAGIC_BYTE_0
     * m[1] = FLB_INPUT_CHUNK_MAGIC_BYTE_1
     * m[2] = type (FLB_INPUT_CHUNK_TYPE_LOG or FLB_INPUT_CHUNK_TYPE_METRIC or FLB_INPUT_CHUNK_TYPE_TRACE
     * m[3] = 0 (unused for now)
     */

    /* write metadata (tag) */
    if (tag_len > (65535 - FLB_INPUT_CHUNK_META_HEADER)) {
        /* truncate length */
        tag_len = 65535 - FLB_INPUT_CHUNK_META_HEADER;
    }
    meta_size = FLB_INPUT_CHUNK_META_HEADER + tag_len;

    /* Allocate buffer for metadata header */
    meta = flb_calloc(1, meta_size);
    if (!meta) {
        flb_errno();
        return -1;
    }

    /*
     * Write chunk header in a temporary buffer
     * ----------------------------------------
     */

    /* magic bytes */
    meta[0] = FLB_INPUT_CHUNK_MAGIC_BYTE_0;
    meta[1] = FLB_INPUT_CHUNK_MAGIC_BYTE_1;

    /* event type */
    if (event_type == FLB_INPUT_LOGS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_LOGS;
    }
    else if (event_type == FLB_INPUT_METRICS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_METRICS;
    }
    else if (event_type == FLB_INPUT_TRACES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_TRACES;
    }
    else if (event_type == FLB_INPUT_PROFILES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_PROFILES;
    }

    /* unused byte */
    meta[3] = 0;

    /* copy the tag after magic bytes */
    memcpy(meta + FLB_INPUT_CHUNK_META_HEADER, tag, tag_len);

    /* Write tag into metadata section */
    ret = cio_meta_write(chunk, (char *) meta, meta_size);
    if (ret == -1) {
        flb_error("[input chunk] could not write metadata");
        flb_free(meta);
        return -1;
    }
    flb_free(meta);

    return 0;
}

int flb_input_chunk_write_header_v2(struct cio_chunk *chunk,
                                    int event_type,
                                    char *tag, int tag_len,
                                    const struct flb_chunk_direct_route *routes,
                                    int route_count)
{
    int has_labels;
    int has_plugins;
    int wide_ids;
    int index;
    int max_tag_len;
    int meta_size;
    int offset;
    int ret;
    int id_offset;
    int label_offset;
    int plugin_lengths_offset;
    int plugin_data_offset;
    int id_bytes;
    uint16_t label_length;
    uint16_t plugin_length;
    uint16_t routing_length;
    uint16_t stored_count;
    uint16_t *resolved_lengths;
    uint16_t *resolved_plugin_lengths;
    uint16_t stored_label_length;
    size_t labels_total;
    size_t plugins_total;
    size_t routing_payload_bytes;
    size_t computed_length;
    uint8_t flags;
    char *meta;

    has_labels = FLB_FALSE;
    has_plugins = FLB_FALSE;
    wide_ids = FLB_FALSE;
    index = 0;
    max_tag_len = 0;
    meta_size = 0;
    offset = 0;
    ret = 0;
    id_offset = 0;
    label_offset = 0;
    plugin_lengths_offset = 0;
    plugin_data_offset = 0;
    id_bytes = (int) sizeof(uint16_t);
    label_length = 0;
    plugin_length = 0;
    routing_length = 0;
    stored_count = 0;
    resolved_lengths = NULL;
    resolved_plugin_lengths = NULL;
    labels_total = 0;
    plugins_total = 0;
    routing_payload_bytes = 0;
    computed_length = 0;
    flags = 0;
    meta = NULL;

    if (!chunk || !tag || !routes || route_count <= 0) {
        return -1;
    }

    if (route_count > UINT16_MAX) {
        return -1;
    }

    resolved_lengths = flb_calloc((size_t) route_count, sizeof(uint16_t));
    if (!resolved_lengths) {
        flb_errno();
        return -1;
    }

    resolved_plugin_lengths = flb_calloc((size_t) route_count, sizeof(uint16_t));
    if (!resolved_plugin_lengths) {
        flb_errno();
        flb_free(resolved_lengths);
        return -1;
    }

    for (index = 0; index < route_count; index++) {
        if (routes[index].id > UINT16_MAX) {
            wide_ids = FLB_TRUE;
        }
        label_length = routes[index].label_length;
        plugin_length = routes[index].plugin_name_length;
        if (routes[index].label != NULL) {
            if (label_length == 0) {
                computed_length = strlen(routes[index].label);
                if (computed_length > UINT16_MAX) {
                    computed_length = UINT16_MAX;
                }
                label_length = (uint16_t) computed_length;
            }
            else if (label_length > UINT16_MAX) {
                label_length = UINT16_MAX;
            }

            if (routes[index].label_is_alias != 0 &&
                label_length > FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK) {
                label_length = FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK;
            }

            if (label_length > 0) {
                has_labels = FLB_TRUE;
            }
        }
        else {
            label_length = 0;
        }

        resolved_lengths[index] = label_length;
        labels_total += (size_t) label_length;

        if (routes[index].plugin_name != NULL) {
            if (plugin_length == 0) {
                computed_length = strlen(routes[index].plugin_name);
                if (computed_length > UINT16_MAX) {
                    computed_length = UINT16_MAX;
                }
                plugin_length = (uint16_t) computed_length;
            }
            else if (plugin_length > UINT16_MAX) {
                plugin_length = UINT16_MAX;
            }

            if (plugin_length > 0) {
                has_plugins = FLB_TRUE;
            }
        }
        else {
            plugin_length = 0;
        }

        resolved_plugin_lengths[index] = plugin_length;
        plugins_total += (size_t) plugin_length;
    }

    if (wide_ids == FLB_TRUE) {
        id_bytes = (int) sizeof(uint32_t);
    }
    else {
        id_bytes = (int) sizeof(uint16_t);
    }

    routing_payload_bytes = sizeof(uint16_t) +
                            ((size_t) route_count * (size_t) id_bytes);
    if (has_labels == FLB_TRUE) {
        routing_payload_bytes += ((size_t) route_count * sizeof(uint16_t)) +
                                 labels_total;
    }
    if (has_plugins == FLB_TRUE) {
        routing_payload_bytes += ((size_t) route_count * sizeof(uint16_t)) +
                                 plugins_total;
    }

    if (routing_payload_bytes > UINT16_MAX) {
        flb_free(resolved_lengths);
        flb_free(resolved_plugin_lengths);
        return -1;
    }

    routing_length = (uint16_t) routing_payload_bytes;
    max_tag_len = 65535 - (int) (FLB_INPUT_CHUNK_META_HEADER + 1 + sizeof(uint16_t) + routing_length);
    if (max_tag_len < 0) {
        max_tag_len = 0;
    }
    if (tag_len > max_tag_len) {
        tag_len = max_tag_len;
    }

    meta_size = FLB_INPUT_CHUNK_META_HEADER + tag_len + 1 + sizeof(uint16_t) + routing_length;
    meta = flb_calloc(1, meta_size);
    if (!meta) {
        flb_errno();
        flb_free(resolved_lengths);
        flb_free(resolved_plugin_lengths);
        return -1;
    }

    meta[0] = FLB_INPUT_CHUNK_MAGIC_BYTE_0;
    meta[1] = FLB_INPUT_CHUNK_MAGIC_BYTE_1;

    if (event_type == FLB_INPUT_LOGS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_LOGS;
    }
    else if (event_type == FLB_INPUT_METRICS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_METRICS;
    }
    else if (event_type == FLB_INPUT_TRACES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_TRACES;
    }
    else if (event_type == FLB_INPUT_PROFILES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_PROFILES;
    }

    flags = FLB_CHUNK_FLAG_DIRECT_ROUTES;
    if (has_labels == FLB_TRUE) {
        flags |= FLB_CHUNK_FLAG_DIRECT_ROUTE_LABELS;
    }
    if (wide_ids == FLB_TRUE) {
        flags |= FLB_CHUNK_FLAG_DIRECT_ROUTE_WIDE_IDS;
    }
    if (has_plugins == FLB_TRUE) {
        flags |= FLB_CHUNK_FLAG_DIRECT_ROUTE_PLUGIN_IDS;
    }
    meta[3] = (char) flags;

    memcpy(meta + FLB_INPUT_CHUNK_META_HEADER, tag, tag_len);
    meta[FLB_INPUT_CHUNK_META_HEADER + tag_len] = '\0';

    offset = FLB_INPUT_CHUNK_META_HEADER + tag_len + 1;
    meta[offset] = (uint8_t) (routing_length >> 8);
    meta[offset + 1] = (uint8_t) (routing_length & 0xFF);

    stored_count = (uint16_t) route_count;
    meta[offset + 2] = (uint8_t) (stored_count >> 8);
    meta[offset + 3] = (uint8_t) (stored_count & 0xFF);

    id_offset = offset + 4;
    for (index = 0; index < route_count; index++) {
        if (wide_ids == FLB_TRUE) {
            meta[id_offset] = (uint8_t) ((routes[index].id >> 24) & 0xFF);
            meta[id_offset + 1] = (uint8_t) ((routes[index].id >> 16) & 0xFF);
            meta[id_offset + 2] = (uint8_t) ((routes[index].id >> 8) & 0xFF);
            meta[id_offset + 3] = (uint8_t) (routes[index].id & 0xFF);
        }
        else {
            meta[id_offset] = (uint8_t) ((routes[index].id >> 8) & 0xFF);
            meta[id_offset + 1] = (uint8_t) (routes[index].id & 0xFF);
        }
        id_offset += id_bytes;
    }

    label_offset = offset + 4 + (route_count * id_bytes);

    if (has_labels == FLB_TRUE) {
        for (index = 0; index < route_count; index++) {
            stored_label_length = resolved_lengths[index];
            if (routes[index].label_is_alias != 0 && stored_label_length > 0) {
                if (stored_label_length > FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK) {
                    stored_label_length = FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK;
                }
                stored_label_length |= FLB_CHUNK_DIRECT_ROUTE_LABEL_ALIAS_FLAG;
            }
            meta[label_offset] = (uint8_t) (stored_label_length >> 8);
            meta[label_offset + 1] = (uint8_t) (stored_label_length & 0xFF);
            label_offset += sizeof(uint16_t);
        }

        for (index = 0; index < route_count; index++) {
            label_length = resolved_lengths[index];
            if (label_length > 0 && routes[index].label != NULL) {
                memcpy(meta + label_offset, routes[index].label, label_length);
            }
            label_offset += label_length;
        }
    }

    plugin_lengths_offset = label_offset;

    if (has_plugins == FLB_TRUE) {
        for (index = 0; index < route_count; index++) {
            plugin_length = resolved_plugin_lengths[index];
            meta[plugin_lengths_offset] = (uint8_t) (plugin_length >> 8);
            meta[plugin_lengths_offset + 1] = (uint8_t) (plugin_length & 0xFF);
            plugin_lengths_offset += sizeof(uint16_t);
        }

        plugin_data_offset = plugin_lengths_offset;
        for (index = 0; index < route_count; index++) {
            plugin_length = resolved_plugin_lengths[index];
            if (plugin_length > 0 && routes[index].plugin_name != NULL) {
                memcpy(meta + plugin_data_offset,
                       routes[index].plugin_name,
                       plugin_length);
            }
            plugin_data_offset += plugin_length;
        }
    }

    ret = cio_meta_write(chunk, (char *) meta, meta_size);
    if (ret == -1) {
        flb_error("[input chunk] could not write metadata");
        flb_free(resolved_lengths);
        flb_free(resolved_plugin_lengths);
        flb_free(meta);
        return -1;
    }

    flb_free(resolved_lengths);
    flb_free(resolved_plugin_lengths);
    flb_free(meta);

    return 0;
}

int flb_input_chunk_has_direct_routes(struct flb_input_chunk *ic)
{
    int ret;
    struct flb_input_chunk_meta_view view;

    ret = input_chunk_metadata_view(ic, &view);
    if (ret == -1) {
        return FLB_FALSE;
    }

    if ((view.flags & FLB_CHUNK_FLAG_DIRECT_ROUTES) == 0) {
        return FLB_FALSE;
    }

    if (view.routing_data == NULL) {
        return FLB_FALSE;
    }

    if (view.routing_data_length < sizeof(uint16_t)) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int flb_input_chunk_get_direct_routes(struct flb_input_chunk *ic,
                                      struct flb_chunk_direct_route **routes,
                                      int *route_count)
{
    int index;
    int labels_present;
    int plugins_present;
    int wide_ids;
    int ret;
    int id_offset;
    int lengths_offset;
    int label_data_offset;
    int plugin_lengths_offset;
    int plugin_data_offset;
    int id_bytes;
    size_t remaining;
    size_t plugin_remaining;
    uint16_t routing_length;
    uint16_t stored_count;
    uint16_t *label_lengths;
    uint8_t *label_alias_flags;
    uint16_t *plugin_lengths;
    struct flb_chunk_direct_route *result;
    struct flb_input_chunk_meta_view view;
    uint32_t read_id;

    index = 0;
    labels_present = FLB_FALSE;
    plugins_present = FLB_FALSE;
    wide_ids = FLB_FALSE;
    ret = 0;
    id_offset = 0;
    lengths_offset = 0;
    label_data_offset = 0;
    plugin_lengths_offset = 0;
    plugin_data_offset = 0;
    id_bytes = (int) sizeof(uint16_t);
    remaining = 0;
    plugin_remaining = 0;
    routing_length = 0;
    stored_count = 0;
    label_lengths = NULL;
    label_alias_flags = NULL;
    plugin_lengths = NULL;
    result = NULL;
    read_id = 0;

    if (!routes || !route_count) {
        return -1;
    }

    *routes = NULL;
    *route_count = 0;

    ret = input_chunk_metadata_view(ic, &view);
    if (ret == -1) {
        return -1;
    }

    if ((view.flags & FLB_CHUNK_FLAG_DIRECT_ROUTES) == 0) {
        return 0;
    }

    if (view.routing_data == NULL || view.routing_data_length < sizeof(uint16_t)) {
        return -2;
    }

    routing_length = view.routing_data_length;
    stored_count = (uint16_t) (((unsigned char) view.routing_data[0] << 8) |
                               (unsigned char) view.routing_data[1]);

    if (stored_count == 0) {
        return 0;
    }

    wide_ids = ((view.flags & FLB_CHUNK_FLAG_DIRECT_ROUTE_WIDE_IDS) != 0);
    if (wide_ids == FLB_TRUE) {
        id_bytes = (int) sizeof(uint32_t);
    }
    else {
        id_bytes = (int) sizeof(uint16_t);
    }

    if ((size_t) routing_length < (sizeof(uint16_t) +
                                   ((size_t) stored_count * (size_t) id_bytes))) {
        return -2;
    }

    labels_present = ((view.flags & FLB_CHUNK_FLAG_DIRECT_ROUTE_LABELS) != 0);
    plugins_present = ((view.flags & FLB_CHUNK_FLAG_DIRECT_ROUTE_PLUGIN_IDS) != 0);

    result = flb_calloc((size_t) stored_count, sizeof(struct flb_chunk_direct_route));
    if (!result) {
        flb_errno();
        return -1;
    }

    id_offset = sizeof(uint16_t);
    for (index = 0; index < stored_count; index++) {
        if (wide_ids == FLB_TRUE) {
            read_id = ((uint32_t) ((unsigned char) view.routing_data[id_offset]) << 24) |
                      ((uint32_t) ((unsigned char) view.routing_data[id_offset + 1]) << 16) |
                      ((uint32_t) ((unsigned char) view.routing_data[id_offset + 2]) << 8) |
                      (uint32_t) ((unsigned char) view.routing_data[id_offset + 3]);
        }
        else {
            read_id = ((uint32_t) ((unsigned char) view.routing_data[id_offset]) << 8) |
                      (uint32_t) ((unsigned char) view.routing_data[id_offset + 1]);
        }
        result[index].id = read_id;
        result[index].label = NULL;
        result[index].label_length = 0;
        result[index].plugin_name = NULL;
        result[index].plugin_name_length = 0;
        id_offset += id_bytes;
    }

    lengths_offset = sizeof(uint16_t) + (stored_count * id_bytes);
    if ((size_t) lengths_offset > routing_length) {
        flb_input_chunk_destroy_direct_routes(result, stored_count);
        return -2;
    }

    label_data_offset = lengths_offset;

    if (labels_present == FLB_TRUE) {
        label_lengths = flb_calloc((size_t) stored_count, sizeof(uint16_t));
        if (!label_lengths) {
            flb_errno();
            flb_input_chunk_destroy_direct_routes(result, stored_count);
            return -1;
        }

        label_alias_flags = flb_calloc((size_t) stored_count, sizeof(uint8_t));
        if (!label_alias_flags) {
            flb_errno();
            flb_free(label_lengths);
            flb_input_chunk_destroy_direct_routes(result, stored_count);
            return -1;
        }

        for (index = 0; index < stored_count; index++) {
            if ((size_t) (label_data_offset + (int) sizeof(uint16_t)) > routing_length) {
                flb_free(label_alias_flags);
                flb_free(label_lengths);
                flb_input_chunk_destroy_direct_routes(result, stored_count);
                return -2;
            }
            label_lengths[index] = (uint16_t) (((unsigned char) view.routing_data[label_data_offset] << 8) |
                                               (unsigned char) view.routing_data[label_data_offset + 1]);
            if (plugins_present == FLB_TRUE) {
                if ((label_lengths[index] & FLB_CHUNK_DIRECT_ROUTE_LABEL_ALIAS_FLAG) != 0) {
                    label_alias_flags[index] = FLB_TRUE;
                    label_lengths[index] &= FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK;
                }
                else {
                    label_alias_flags[index] = FLB_FALSE;
                }
            }
            else {
                /* Even when plugins_present is FALSE, the alias flag may still be encoded */
                if ((label_lengths[index] & FLB_CHUNK_DIRECT_ROUTE_LABEL_ALIAS_FLAG) != 0) {
                    label_alias_flags[index] = FLB_TRUE;
                    label_lengths[index] &= FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK;
                }
                else {
                    label_alias_flags[index] = FLB_TRUE;
                }
            }
            label_data_offset += sizeof(uint16_t);
        }

        if ((size_t) label_data_offset > routing_length) {
            flb_free(label_alias_flags);
            flb_free(label_lengths);
            flb_input_chunk_destroy_direct_routes(result, stored_count);
            return -2;
        }

        remaining = routing_length - (size_t) label_data_offset;

        for (index = 0; index < stored_count; index++) {
            if (label_lengths[index] == 0) {
                result[index].label = NULL;
                result[index].label_length = 0;
                if (label_alias_flags) {
                    result[index].label_is_alias = label_alias_flags[index];
                }
                else if (plugins_present == FLB_FALSE) {
                    result[index].label_is_alias = FLB_TRUE;
                }
                continue;
            }

            if (label_lengths[index] > remaining) {
                flb_free(label_alias_flags);
                flb_free(label_lengths);
                flb_input_chunk_destroy_direct_routes(result, stored_count);
                return -2;
            }

            result[index].label = flb_malloc((size_t) label_lengths[index] + 1);
            if (!result[index].label) {
                flb_errno();
                flb_free(label_alias_flags);
                flb_free(label_lengths);
                flb_input_chunk_destroy_direct_routes(result, stored_count);
                return -1;
            }

            memcpy((char *) result[index].label,
                   view.routing_data + label_data_offset,
                   label_lengths[index]);
            ((char *) result[index].label)[label_lengths[index]] = '\0';
            result[index].label_length = label_lengths[index];
            if (label_alias_flags) {
                result[index].label_is_alias = label_alias_flags[index];
            }
            else if (plugins_present == FLB_FALSE) {
                result[index].label_is_alias = FLB_TRUE;
            }
            label_data_offset += label_lengths[index];
            remaining -= label_lengths[index];
        }

        flb_free(label_alias_flags);
        flb_free(label_lengths);
    }
    else {
        remaining = routing_length - (size_t) label_data_offset;
    }

    plugin_lengths_offset = label_data_offset;

    if (plugins_present == FLB_TRUE) {
        plugin_lengths = flb_calloc((size_t) stored_count, sizeof(uint16_t));
        if (!plugin_lengths) {
            flb_errno();
            flb_input_chunk_destroy_direct_routes(result, stored_count);
            return -1;
        }

        for (index = 0; index < stored_count; index++) {
            if ((size_t) (plugin_lengths_offset + (int) sizeof(uint16_t)) > routing_length) {
                flb_free(plugin_lengths);
                flb_input_chunk_destroy_direct_routes(result, stored_count);
                return -2;
            }
            plugin_lengths[index] = (uint16_t) (((unsigned char) view.routing_data[plugin_lengths_offset] << 8) |
                                                 (unsigned char) view.routing_data[plugin_lengths_offset + 1]);
            plugin_lengths_offset += sizeof(uint16_t);
        }

        plugin_data_offset = plugin_lengths_offset;
        if ((size_t) plugin_data_offset > routing_length) {
            flb_free(plugin_lengths);
            flb_input_chunk_destroy_direct_routes(result, stored_count);
            return -2;
        }

        plugin_remaining = routing_length - (size_t) plugin_data_offset;

        for (index = 0; index < stored_count; index++) {
            if (plugin_lengths[index] == 0) {
                result[index].plugin_name = NULL;
                result[index].plugin_name_length = 0;
                continue;
            }

            if (plugin_lengths[index] > plugin_remaining) {
                flb_free(plugin_lengths);
                flb_input_chunk_destroy_direct_routes(result, stored_count);
                return -2;
            }

            result[index].plugin_name = flb_malloc((size_t) plugin_lengths[index] + 1);
            if (!result[index].plugin_name) {
                flb_errno();
                flb_free(plugin_lengths);
                flb_input_chunk_destroy_direct_routes(result, stored_count);
                return -1;
            }

            memcpy((char *) result[index].plugin_name,
                   view.routing_data + plugin_data_offset,
                   plugin_lengths[index]);
            ((char *) result[index].plugin_name)[plugin_lengths[index]] = '\0';
            result[index].plugin_name_length = plugin_lengths[index];
            plugin_data_offset += plugin_lengths[index];
            plugin_remaining -= plugin_lengths[index];
        }

        flb_free(plugin_lengths);
    }
    else {
        for (index = 0; index < stored_count; index++) {
            result[index].plugin_name = NULL;
            result[index].plugin_name_length = 0;
        }
    }

    *routes = result;
    *route_count = stored_count;

    return 0;
}

void flb_input_chunk_destroy_direct_routes(struct flb_chunk_direct_route *routes,
                                           int route_count)
{
    int index;

    index = 0;

    if (!routes) {
        return;
    }

    for (index = 0; index < route_count; index++) {
        if (routes[index].label != NULL && routes[index].label_length > 0) {
            flb_free((void *) routes[index].label);
        }
        if (routes[index].plugin_name != NULL) {
            flb_free((void *) routes[index].plugin_name);
        }
    }

    flb_free(routes);
}

struct flb_input_chunk *flb_input_chunk_create(struct flb_input_instance *in, int event_type,
                                               const char *tag, int tag_len)
{
    int ret;
    int err;
    int set_down = FLB_FALSE;
    int has_routes;
    size_t mask_size;
    char name[64];
    struct cio_chunk *chunk;
    struct flb_storage_input *storage;
    struct flb_input_chunk *ic;

    storage = in->storage;

    /* chunk name */
    generate_chunk_name(in, name, sizeof(name) - 1);

    /* open/create target chunk file */
    chunk = cio_chunk_open(storage->cio, storage->stream, name,
                           CIO_OPEN, FLB_INPUT_CHUNK_SIZE, &err);
    if (!chunk) {
        flb_error("[input chunk] could not create chunk file: %s:%s",
                  storage->stream->name, name);
        return NULL;
    }
    /*
     * If the returned chunk at open is 'down', just put it up, write the
     * content and set it down again.
     */
    ret = cio_chunk_is_up(chunk);
    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        if (ret == -1) {
            cio_chunk_close(chunk, CIO_TRUE);
            return NULL;
        }
        set_down = FLB_TRUE;
    }

    /* Write chunk header */
    ret = input_chunk_write_header(chunk, event_type, (char *) tag, tag_len);
    if (ret == -1) {
        cio_chunk_close(chunk, CIO_TRUE);
        return NULL;
    }

    /* Create context for the input instance */
    ic = flb_calloc(1, sizeof(struct flb_input_chunk));
    if (!ic) {
        flb_errno();
        cio_chunk_close(chunk, CIO_TRUE);
        return NULL;
    }

    /*
     * Check chunk content type to be created: depending of the value set by
     * the input plugin, this can be FLB_INPUT_LOGS, FLB_INPUT_METRICS or
     * FLB_INPUT_TRACES.
     */
    ic->event_type = event_type;
    ic->busy = FLB_FALSE;
    ic->fs_counted = FLB_FALSE;
    ic->chunk = chunk;
    ic->fs_backlog = FLB_FALSE;
    ic->in = in;
    ic->stream_off = 0;
    ic->task = NULL;
    ic->create_time = flb_time_now();
#ifdef FLB_HAVE_METRICS
    ic->total_records = 0;
#endif
    mask_size = flb_routes_mask_get_size(in->config->router);
    ic->routes_mask = (flb_route_mask_element *)
                            flb_calloc(mask_size,
                                       sizeof(flb_route_mask_element));

    if (ic->routes_mask == NULL) {
        flb_errno();
        cio_chunk_close(chunk, CIO_TRUE);
        flb_free(ic);
        return NULL;
    }


    /* Calculate the routes_mask for the input chunk */
    has_routes = flb_routes_mask_set_by_tag(ic->routes_mask, tag, tag_len, in);
    if (has_routes == 0) {
        flb_trace("[input chunk] no matching route for input chunk '%s' with tag '%s'",
                  flb_input_chunk_get_name(ic), tag);
    }

    msgpack_packer_init(&ic->mp_pck, ic, flb_input_chunk_write);
    mk_list_add(&ic->_head, &in->chunks);

    if (set_down == FLB_TRUE) {
        cio_chunk_down(chunk);
    }

    if (event_type == FLB_INPUT_LOGS) {
        flb_hash_table_add(in->ht_log_chunks, tag, tag_len, ic, 0);
    }
    else if (event_type == FLB_INPUT_METRICS) {
        flb_hash_table_add(in->ht_metric_chunks, tag, tag_len, ic, 0);
    }
    else if (event_type == FLB_INPUT_TRACES) {
        flb_hash_table_add(in->ht_trace_chunks, tag, tag_len, ic, 0);
    }
    else if (event_type == FLB_INPUT_PROFILES) {
        flb_hash_table_add(in->ht_profile_chunks, tag, tag_len, ic, 0);
    }

    return ic;
}

int flb_input_chunk_destroy_corrupted(struct flb_input_chunk *ic,
                                      const char *tag_buf, int tag_len,
                                      int del)
{
    ssize_t bytes;
    struct mk_list *head;
    struct flb_output_instance *o_ins;

    mk_list_foreach(head, &ic->in->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);

        if (o_ins->total_limit_size == -1) {
            continue;
        }

        bytes = flb_input_chunk_get_real_size(ic);
        if (bytes == -1) {
            // no data in the chunk
            continue;
        }

        if (flb_routes_mask_get_bit(ic->routes_mask,
                                    o_ins->id,
                                    o_ins->config->router) != 0) {
            if (ic->fs_counted == FLB_TRUE) {
                FS_CHUNK_SIZE_DEBUG_MOD(o_ins, ic, -bytes);
                o_ins->fs_chunks_size -= bytes;
                flb_debug("[input chunk] remove chunk %s with %ld bytes from plugin %s, "
                          "the updated fs_chunks_size is %ld bytes", flb_input_chunk_get_name(ic),
                          bytes, o_ins->name, o_ins->fs_chunks_size);
            }
        }
    }

    if (del == CIO_TRUE && tag_buf) {
        /*
         * "TRY" to delete any reference to this chunk ('ic') from the hash
         * table. Note that maybe the value is not longer available in the
         * entries if it was replaced: note that we always keep the last
         * chunk for a specific Tag.
         */
        if (ic->event_type == FLB_INPUT_LOGS) {
            flb_hash_table_del_ptr(ic->in->ht_log_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
        else if (ic->event_type == FLB_INPUT_METRICS) {
            flb_hash_table_del_ptr(ic->in->ht_metric_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
        else if (ic->event_type == FLB_INPUT_TRACES) {
            flb_hash_table_del_ptr(ic->in->ht_trace_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
        else if (ic->event_type == FLB_INPUT_PROFILES) {
            flb_hash_table_del_ptr(ic->in->ht_profile_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ic->trace != NULL) {
        flb_chunk_trace_destroy(ic->trace);
    }
#endif /* FLB_HAVE_CHUNK_TRACE */

    cio_chunk_close(ic->chunk, del);
    mk_list_del(&ic->_head);

    if (ic->routes_mask != NULL) {
        flb_free(ic->routes_mask);
        ic->routes_mask = NULL;
    }

    flb_free(ic);

    return 0;
}


int flb_input_chunk_destroy(struct flb_input_chunk *ic, int del)
{
    int tag_len;
    int ret;
    ssize_t bytes;
    const char *tag_buf = NULL;
    struct mk_list *head;
    struct flb_output_instance *o_ins;

    if (flb_input_chunk_is_up(ic) == FLB_FALSE) {
        flb_input_chunk_set_up(ic);
    }

    mk_list_foreach(head, &ic->in->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);

        if (o_ins->total_limit_size == -1) {
            continue;
        }

        bytes = flb_input_chunk_get_real_size(ic);
        if (bytes == -1) {
            // no data in the chunk
            continue;
        }

        if (flb_routes_mask_get_bit(ic->routes_mask,
                                    o_ins->id,
                                    o_ins->config->router) != 0) {
            if (ic->fs_counted == FLB_TRUE) {
                FS_CHUNK_SIZE_DEBUG_MOD(o_ins, ic, -bytes);
                o_ins->fs_chunks_size -= bytes;
                flb_debug("[input chunk] remove chunk %s with %ld bytes from plugin %s, "
                          "the updated fs_chunks_size is %ld bytes", flb_input_chunk_get_name(ic),
                          bytes, o_ins->name, o_ins->fs_chunks_size);
            }
        }
    }

    /*
     * When a chunk is going to be destroyed, this can be in a down state,
     * since the next step is to retrieve the Tag we need to have the
     * content up.
     */
    ret = flb_input_chunk_is_up(ic);
    if (ret == FLB_FALSE) {
        ret = cio_chunk_up_force(ic->chunk);
        if (ret == -1) {
            flb_error("[input chunk] cannot load chunk: %s",
                      flb_input_chunk_get_name(ic));
        }
    }

    /* Retrieve Tag */
    ret = flb_input_chunk_get_tag(ic, &tag_buf, &tag_len);
    if (ret == -1) {
        flb_trace("[input chunk] could not retrieve chunk tag: %s",
                  flb_input_chunk_get_name(ic));
    }

    if (del == CIO_TRUE && tag_buf) {
        /*
         * "TRY" to delete any reference to this chunk ('ic') from the hash
         * table. Note that maybe the value is not longer available in the
         * entries if it was replaced: note that we always keep the last
         * chunk for a specific Tag.
         */
        if (ic->event_type == FLB_INPUT_LOGS) {
            flb_hash_table_del_ptr(ic->in->ht_log_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
        else if (ic->event_type == FLB_INPUT_METRICS) {
            flb_hash_table_del_ptr(ic->in->ht_metric_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
        else if (ic->event_type == FLB_INPUT_TRACES) {
            flb_hash_table_del_ptr(ic->in->ht_trace_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
        else if (ic->event_type == FLB_INPUT_PROFILES) {
            flb_hash_table_del_ptr(ic->in->ht_profile_chunks,
                                   tag_buf, tag_len, (void *) ic);
        }
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ic->trace != NULL) {
        flb_chunk_trace_destroy(ic->trace);
    }
#endif /* FLB_HAVE_CHUNK_TRACE */

    cio_chunk_close(ic->chunk, del);
    mk_list_del(&ic->_head);

    if (ic->routes_mask != NULL) {
        flb_free(ic->routes_mask);
        ic->routes_mask = NULL;
    }

    flb_free(ic);

    return 0;
}

/* Return or create an available chunk to write data */
static struct flb_input_chunk *input_chunk_get(struct flb_input_instance *in,
                                               int event_type,
                                               const char *tag, int tag_len,
                                               size_t chunk_size, int *set_down)
{
    int id = -1;
    int ret;
    int new_chunk = FLB_FALSE;
    size_t out_size;
    struct flb_input_chunk *ic = NULL;

    if (tag_len > FLB_INPUT_CHUNK_TAG_MAX) {
        flb_plg_warn(in,
                     "Tag set exceeds limit, truncating from %i to %i bytes",
                     tag_len, FLB_INPUT_CHUNK_TAG_MAX);
        tag_len = FLB_INPUT_CHUNK_TAG_MAX;
    }

    if (event_type == FLB_INPUT_LOGS) {
        id = flb_hash_table_get(in->ht_log_chunks, tag, tag_len,
                                (void *) &ic, &out_size);
    }
    else if (event_type == FLB_INPUT_METRICS) {
        id = flb_hash_table_get(in->ht_metric_chunks, tag, tag_len,
                                (void *) &ic, &out_size);
    }
    else if (event_type == FLB_INPUT_TRACES) {
        id = flb_hash_table_get(in->ht_trace_chunks, tag, tag_len,
                                (void *) &ic, &out_size);
    }
    else if (event_type == FLB_INPUT_PROFILES) {
        id = flb_hash_table_get(in->ht_profile_chunks, tag, tag_len,
                                (void *) &ic, &out_size);
    }

    if (id >= 0) {
        if (ic->busy == FLB_TRUE || cio_chunk_is_locked(ic->chunk)) {
            ic = NULL;
        }
        else if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
            ret = cio_chunk_up_force(ic->chunk);

            if (ret == CIO_CORRUPTED) {
                if (in->config->storage_del_bad_chunks) {
                    /* If the chunk is corrupted we need to discard it and
                     * set ic to NULL so the system tries to allocate a new
                     * chunk.
                     */

                    flb_error("[input chunk] discarding corrupted chunk");
                }

                flb_input_chunk_destroy_corrupted(ic,
                                                  tag, tag_len,
                                                  in->config->storage_del_bad_chunks);

                ic = NULL;
            }
            else if (ret != CIO_OK) {
                ic = NULL;
            }

            *set_down = FLB_TRUE;
        }
    }

    /* No chunk was found, we need to create a new one */
    if (!ic) {
        ic = flb_input_chunk_create(in, event_type, (char *) tag, tag_len);
        new_chunk = FLB_TRUE;
        if (!ic) {
            return NULL;
        }
        ic->event_type = event_type;
    }

    /*
     * If buffering this block of data will exceed one of the limit among all output instances
     * that the chunk will flush to, we need to modify the routes_mask of the oldest chunks
     * (based in creation time) to get enough space for the incoming chunk.
     */
    if (!flb_routes_mask_is_empty(ic->routes_mask, ic->in->config->router)
        && flb_input_chunk_place_new_chunk(ic, chunk_size) == 0) {
        /*
         * If the chunk is not newly created, the chunk might already have logs inside.
         * We cannot delete (reused) chunks here.
         * If the routes_mask is cleared after trying to append new data, we destroy
         * the chunk.
         */
        if (new_chunk ||
            flb_routes_mask_is_empty(ic->routes_mask, ic->in->config->router) == FLB_TRUE) {
            flb_input_chunk_destroy(ic, FLB_TRUE);
        }
        return NULL;
    }

    return ic;
}

static inline int flb_input_chunk_is_mem_overlimit(struct flb_input_instance *i)
{
    if (i->mem_buf_limit <= 0) {
        return FLB_FALSE;
    }

    if (i->mem_chunks_size >= i->mem_buf_limit) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static inline int flb_input_chunk_is_storage_overlimit(struct flb_input_instance *i)
{
    struct flb_storage_input *storage = (struct flb_storage_input *)i->storage;

    if (storage->type == FLB_STORAGE_FS) {
        if (i->storage_pause_on_chunks_overlimit == FLB_TRUE) {
            if (storage->cio->total_chunks_up >= storage->cio->max_chunks_up) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

/*
 * Check all chunks associated to the input instance and summarize
 * the number of bytes in use.
 */
size_t flb_input_chunk_total_size(struct flb_input_instance *in)
{
    size_t total = 0;
    struct flb_storage_input *storage;

    storage = (struct flb_storage_input *) in->storage;
    total = cio_stream_size_chunks_up(storage->stream);
    return total;
}

/*
 * Count and update the number of bytes being used by the instance. Also
 * check if the instance is paused, if so, check if it can be resumed if
 * is not longer over the limits.
 *
 * It always returns the number of bytes in use.
 */
size_t flb_input_chunk_set_limits(struct flb_input_instance *in)
{
    size_t total;

    /* Gather total number of enqueued bytes */
    total = flb_input_chunk_total_size(in);

    /* Register the total into the context variable */
    in->mem_chunks_size = total;

    /*
     * After the adjustments, validate if the plugin is overlimit or paused
     * and perform further adjustments.
     */
    if (flb_input_chunk_is_mem_overlimit(in) == FLB_FALSE &&
        in->config->is_running == FLB_TRUE &&
        in->config->is_ingestion_active == FLB_TRUE &&
        in->mem_buf_status == FLB_INPUT_PAUSED) {
        in->mem_buf_status = FLB_INPUT_RUNNING;
        if (in->p->cb_resume) {
            flb_input_resume(in);
            flb_info("[input] %s resume (mem buf overlimit - buf size %zuB now below limit %zuB)",
                      flb_input_name(in),
                      in->mem_chunks_size,
                      in->mem_buf_limit);
        }
    }
    if (flb_input_chunk_is_storage_overlimit(in) == FLB_FALSE &&
        in->config->is_running == FLB_TRUE &&
        in->config->is_ingestion_active == FLB_TRUE &&
        in->storage_buf_status == FLB_INPUT_PAUSED) {
        in->storage_buf_status = FLB_INPUT_RUNNING;
        if (in->p->cb_resume) {
            flb_input_resume(in);
            flb_info("[input] %s resume (storage buf overlimit %zu/%zu)",
                      flb_input_name(in),
                      ((struct flb_storage_input *)in->storage)->cio->total_chunks_up,
                      ((struct flb_storage_input *)in->storage)->cio->max_chunks_up);
        }
    }

    return total;
}

/*
 * If the number of bytes in use by the chunks are over the imposed limit
 * by configuration, pause the instance.
 */
static inline int flb_input_chunk_protect(struct flb_input_instance *i, size_t just_written_size)
{
    struct flb_storage_input *storage = i->storage;

    if (flb_input_chunk_is_storage_overlimit(i) == FLB_TRUE) {
        flb_warn("[input] %s paused (storage buf overlimit %zu/%zu)",
                 flb_input_name(i),
                 storage->cio->total_chunks_up,
                 storage->cio->max_chunks_up);
        flb_input_pause(i);
        i->storage_buf_status = FLB_INPUT_PAUSED;
        return FLB_TRUE;
    }

    if (storage->type == FLB_STORAGE_FS) {
        return FLB_FALSE;
    }

    if (flb_input_chunk_is_mem_overlimit(i) == FLB_TRUE) {
        /*
         * if the plugin is already overlimit and the strategy is based on
         * a memory-ring-buffer logic, do not pause the plugin, upon next
         * try of ingestion 'memrb' will make sure to release some bytes.
         */
        if (i->storage_type == FLB_STORAGE_MEMRB) {
            return FLB_FALSE;
        }

        /*
         * The plugin is using 'memory' buffering only and already reached
         * it limit, just pause the ingestion.
         */
        flb_warn("[input] %s paused (mem buf overlimit - event of size %zuB exceeded limit %zu to %zuB)",
                 flb_input_name(i),
                 just_written_size,
                 i->mem_buf_limit,
                 i->mem_chunks_size
                );
        flb_input_pause(i);
        i->mem_buf_status = FLB_INPUT_PAUSED;
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Validate if the chunk coming from the input plugin based on config and
 * resources usage must be 'up' or 'down' (applicable for filesystem storage
 * type).
 *
 * FIXME: can we find a better name for this function ?
 */
int flb_input_chunk_set_up_down(struct flb_input_chunk *ic)
{
    size_t total;
    struct flb_input_instance *in;

    in = ic->in;

    /* Gather total number of enqueued bytes */
    total = flb_input_chunk_total_size(in);

    /* Register the total into the context variable */
    in->mem_chunks_size = total;

    if (flb_input_chunk_is_mem_overlimit(in) == FLB_TRUE) {
        if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
            cio_chunk_down(ic->chunk);

            /* Adjust new counters */
            total = flb_input_chunk_total_size(ic->in);
            in->mem_chunks_size = total;

            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

int flb_input_chunk_is_up(struct flb_input_chunk *ic)
{
    return cio_chunk_is_up(ic->chunk);
}

int flb_input_chunk_down(struct flb_input_chunk *ic)
{
    if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
        return cio_chunk_down(ic->chunk);
    }

    return 0;
}

int flb_input_chunk_set_up(struct flb_input_chunk *ic)
{
    if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
        return cio_chunk_up(ic->chunk);
    }

    return 0;
}

static int memrb_input_chunk_release_space(struct flb_input_instance *ins,
                                           size_t required_space,
                                           size_t *dropped_chunks, size_t *dropped_bytes)
{
    int ret;
    int released;
    size_t removed_chunks = 0;
    ssize_t chunk_size;
    ssize_t released_space = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;

    mk_list_foreach_safe(head, tmp, &ins->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);

        /* check if is there any task or no users associated */
        ret = flb_input_chunk_is_task_safe_delete(ic->task);
        if (ret == FLB_FALSE) {
            continue;
        }

        /* get chunk size */
        chunk_size = flb_input_chunk_get_real_size(ic);

        released = FLB_FALSE;
        if (ic->task != NULL) {
            if (ic->task->users == 0) {
                flb_task_destroy(ic->task, FLB_TRUE);
                released = FLB_TRUE;
            }
        }
        else {
            flb_input_chunk_destroy(ic, FLB_TRUE);
            released = FLB_TRUE;
        }

        if (released) {
            released_space += chunk_size;
            removed_chunks++;
        }

        if (released_space >= required_space) {
            break;
        }
    }

    /* no matter if we succeeded or not, set the counters */
    *dropped_bytes = released_space;
    *dropped_chunks = removed_chunks;

    /* set the final status of the operation */
    if (released_space >= required_space) {
        return 0;
    }

    return -1;
}

/* Append a RAW MessagPack buffer to the input instance */
static int input_chunk_append_raw(struct flb_input_instance *in,
                                  int event_type,
                                  size_t n_records,
                                  const char *tag, size_t tag_len,
                                  const void *buf, size_t buf_size)
{
    int ret, total_records_start;
    int set_down = FLB_FALSE;
    int min;
    int new_chunk = FLB_FALSE;
    uint64_t ts;
    char *name;
    size_t dropped_chunks;
    size_t dropped_bytes;
    size_t content_size;
    size_t real_diff;
    size_t real_size;
    size_t pre_real_size;
    struct flb_input_chunk *ic;
    struct flb_storage_input *si;
    void  *filtered_data_buffer;
    size_t filtered_data_size;
    void  *final_data_buffer;
    size_t final_data_size;

    /* memory ring-buffer checker */
    if (in->storage_type == FLB_STORAGE_MEMRB) {
        /* check if we are overlimit */
        ret = flb_input_chunk_is_mem_overlimit(in);
        if (ret) {
            /* reset counters */
            dropped_chunks = 0;
            dropped_bytes = 0;

            /* try to release 'buf_size' */
            ret = memrb_input_chunk_release_space(in, buf_size,
                                                  &dropped_chunks, &dropped_bytes);

            /* update metrics if required */
            if (dropped_chunks > 0 || dropped_bytes > 0) {
                /* timestamp and input plugin name for label */
                ts = cfl_time_now();
                name = (char *) flb_input_name(in);

                /* update counters */
                cmt_counter_add(in->cmt_memrb_dropped_chunks, ts,
                                dropped_chunks, 1, (char *[]) {name});

                cmt_counter_add(in->cmt_memrb_dropped_bytes, ts,
                                dropped_bytes, 1, (char *[]) {name});
            }

            if (ret != 0) {
                /* we could not allocate the required space, just return */
                return -1;
            }
        }
    }

    /* Check if the input plugin has been paused */
    if (flb_input_buf_paused(in) == FLB_TRUE) {
        flb_debug("[input chunk] %s is paused, cannot append records",
                  flb_input_name(in));
        return -1;
    }

    if (buf_size == 0) {
        flb_debug("[input chunk] skip ingesting data with 0 bytes");
        return -1;
    }

    /*
     * Some callers might not set a custom tag, on that case just inherit
     * the fixed instance tag or instance name.
     */
    if (!tag) {
        if (in->tag && in->tag_len > 0) {
            tag = in->tag;
            tag_len = in->tag_len;
        }
        else {
            tag = in->name;
            tag_len = strlen(in->name);
        }
    }

    /*
     * Get a target input chunk, can be one with remaining space available
     * or a new one.
     */
    ic = input_chunk_get(in, event_type, tag, tag_len, buf_size, &set_down);
    if (!ic) {
        flb_error("[input chunk] no available chunk");
        return -1;
    }

    /* newly created chunk */
    if (flb_input_chunk_get_size(ic) == 0) {
        new_chunk = FLB_TRUE;
    }

    /* We got the chunk, validate if is 'up' or 'down' */
    ret = flb_input_chunk_is_up(ic);
    if (ret == FLB_FALSE) {
        ret = cio_chunk_up_force(ic->chunk);
        if (ret == -1) {
            flb_error("[input chunk] cannot retrieve temporary chunk");
            return -1;
        }
        set_down = FLB_TRUE;
    }

    /*
     * Keep the previous real size to calculate the real size
     * difference for flb_input_chunk_update_output_instances(),
     * use 0 when the chunk is new since it's size will never
     * have been calculated before.
     */
    if (new_chunk == FLB_TRUE) {
        pre_real_size = 0;
    }
    else {
        pre_real_size = flb_input_chunk_get_real_size(ic);
    }

    /*
     * Set the total_records based on the records that n_records
     * says we should be writing. These values may be overwritten
     * flb_filter_do, where a filter may add/remove records.
     */
    total_records_start = ic->total_records;
    ic->added_records =  n_records;
    ic->total_records += n_records;

#ifdef FLB_HAVE_CHUNK_TRACE
    flb_chunk_trace_do_input(ic);
#endif /* FLB_HAVE_CHUNK_TRACE */

    /* Update 'input' metrics */
#ifdef FLB_HAVE_METRICS
    if (ic->total_records > 0) {
        /* timestamp */
        ts = cfl_time_now();

        /* fluentbit_input_records_total */
        cmt_counter_add(in->cmt_records, ts, ic->added_records,
                        1, (char *[]) {(char *) flb_input_name(in)});

        /* fluentbit_input_bytes_total */
        cmt_counter_add(in->cmt_bytes, ts, buf_size,
                        1, (char *[]) {(char *) flb_input_name(in)});

        /* OLD api */
        flb_metrics_sum(FLB_METRIC_N_RECORDS, ic->added_records, in->metrics);
        flb_metrics_sum(FLB_METRIC_N_BYTES, buf_size, in->metrics);
    }
#endif

    filtered_data_buffer = NULL;
    final_data_buffer = (char *) buf;
    final_data_size = buf_size;

    /* Apply filters */
    if (event_type == FLB_INPUT_LOGS) {
        flb_filter_do(ic,
                      buf, buf_size,
                      &filtered_data_buffer,
                      &filtered_data_size,
                      tag, tag_len,
                      in->config);

        final_data_buffer = filtered_data_buffer;
        final_data_size = filtered_data_size;
    }

    if (final_data_size > 0){
        ret = flb_input_chunk_write(ic,
                                    final_data_buffer,
                                    final_data_size);
    }
    else {
        ret = 0;
    }

    if (filtered_data_buffer != NULL &&
        filtered_data_buffer != buf) {
        flb_free(filtered_data_buffer);
    }

    /*
     * If the write failed, then we did not add any records. Reset
     * the record counters to reflect this.
     */
    if (ret != CIO_OK) {
        ic->added_records = 0;
        ic->total_records = total_records_start;
    }

    if (ret == -1) {
        flb_error("[input chunk] error writing data from %s instance",
                  flb_input_name(in));
        cio_chunk_tx_rollback(ic->chunk);

        return -1;
    }

    /* get the chunks content size */
    content_size = cio_chunk_get_content_size(ic->chunk);

    /*
     * There is a case that rewrite_tag will modify the tag and keep rule is set
     * to drop the original record. The original record will still go through the
     * flb_input_chunk_update_output_instances(2) to update the fs_chunks_size by
     * metadata bytes (consisted by metadata bytes of the file chunk). This condition
     * sets the diff to 0 in order to not update the fs_chunks_size.
     */
    if (flb_input_chunk_get_size(ic) == 0) {
        real_diff = 0;
    }

    /* Lock buffers where size > 2MB */
    if (content_size > FLB_INPUT_CHUNK_FS_MAX_SIZE) {
        cio_chunk_lock(ic->chunk);
    }

    /* Make sure the data was not filtered out and the buffer size is zero */
    if (content_size == 0) {
        flb_input_chunk_destroy(ic, FLB_TRUE);
        flb_input_chunk_set_limits(in);
        return 0;
    }
#ifdef FLB_HAVE_STREAM_PROCESSOR
    else if (in->config->stream_processor_ctx &&
             ic->event_type == FLB_INPUT_LOGS) {
        char *c_data;
        size_t c_size;

        /* Retrieve chunk (filtered) output content */
        cio_chunk_get_content(ic->chunk, &c_data, &c_size);

        /* Invoke stream processor */
        flb_sp_do(in->config->stream_processor_ctx,
                  in,
                  tag, tag_len,
                  c_data + ic->stream_off, c_size - ic->stream_off);
        ic->stream_off += (c_size - ic->stream_off);
    }
#endif

    if (set_down == FLB_TRUE) {
        cio_chunk_down(ic->chunk);
    }

    /*
     * If the instance is not routable, there is no need to keep the
     * content in the storage engine, just get rid of it.
     */
    if (in->routable == FLB_FALSE) {
        flb_input_chunk_destroy(ic, FLB_TRUE);
        return 0;
    }

    /* Update memory counters and adjust limits if any */
    flb_input_chunk_set_limits(in);

    /*
     * Check if we are overlimit and validate if is there any filesystem
     * storage type asociated to this input instance, if so, unload the
     * chunk content from memory to respect imposed limits.
     *
     * Calling cio_chunk_down() the memory map associated and the file
     * descriptor will be released. At any later time, it must be bring up
     * for I/O operations.
     */
    si = (struct flb_storage_input *) in->storage;
    if (flb_input_chunk_is_mem_overlimit(in) == FLB_TRUE &&
        si->type == FLB_STORAGE_FS) {
        if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
            /*
             * If we are already over limit, a sub-sequent data ingestion
             * might need a Chunk to write data in. As an optimization we
             * will put this Chunk down ONLY IF it has less than 1% of
             * it capacity as available space, otherwise keep it 'up' so
             * it available space can be used.
             */
            content_size = cio_chunk_get_content_size(ic->chunk);

            /* Do we have less than 1% available ? */
            min = (FLB_INPUT_CHUNK_FS_MAX_SIZE * 0.01);
            if (FLB_INPUT_CHUNK_FS_MAX_SIZE - content_size < min) {
                cio_chunk_down(ic->chunk);
            }
        }
    }

    real_size = flb_input_chunk_get_real_size(ic);
    real_diff = real_size - pre_real_size;
    if (real_diff != 0) {
        flb_trace("[input chunk] update output instances with new chunk size diff=%zd, records=%zu, input=%s",
                  real_diff, n_records, flb_input_name(in));
        flb_input_chunk_update_output_instances(ic, real_diff);
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ic->trace) {
        flb_chunk_trace_pre_output(ic->trace);
    }
#endif /* FLB_HAVE_CHUNK_TRACE */

    flb_input_chunk_protect(in, final_data_size);
    return 0;
}

static void destroy_chunk_raw(struct input_chunk_raw *cr)
{
    if (cr->buf_data) {
        flb_free(cr->buf_data);
    }

    if (cr->tag) {
        flb_sds_destroy(cr->tag);
    }

    flb_free(cr);
}

static int append_to_ring_buffer(struct flb_input_instance *ins,
                                 int event_type,
                                 size_t records,
                                 const char *tag,
                                 size_t tag_len,
                                 const void *buf,
                                 size_t buf_size)

{
    int ret;
    int retries = 0;
    int retry_limit = 10;
    struct input_chunk_raw *cr;

    if (buf_size == 0) {
        flb_plg_debug(ins, "skip ingesting data with 0 bytes");
        return -1;
    }

    cr = flb_calloc(1, sizeof(struct input_chunk_raw));
    if (!cr) {
        flb_errno();
        return -1;
    }
    cr->ins = ins;
    cr->event_type = event_type;

    if (tag && tag_len > 0) {
        cr->tag = flb_sds_create_len(tag, tag_len);
        if (!cr->tag) {
            flb_free(cr);
            return -1;
        }
    }
    else {
        cr->tag = NULL;
    }

    cr->records = records;
    cr->buf_data = flb_malloc(buf_size);
    if (!cr->buf_data) {
        flb_errno();
        destroy_chunk_raw(cr);
        return -1;
    }

    /*
     * this memory copy is just a simple overhead, the problem we have is that
     * input instances always assume that they have to release their buffer since
     * the append raw operation already did a copy. Not a big issue but maybe this
     * is a tradeoff...
     */
    memcpy(cr->buf_data, buf, buf_size);
    cr->buf_size = buf_size;



retry:
    /*
     * There is a little chance that the ring buffer is full or due to saturation
     * from the main thread the data is not being consumed. On this scenario we
     * retry up to 'retry_limit' times with a little wait time.
     */
    if (retries >= retry_limit) {
        flb_plg_error(ins, "could not enqueue records into the ring buffer");
        destroy_chunk_raw(cr);

        /* update failed retries counter */
        cmt_counter_add(ins->cmt_ring_buffer_retry_failures, cfl_time_now(),
                        1, 1, (char *[]) {(char *) flb_input_name(ins)});
        return -1;
    }

    /* append chunk raw context to the ring buffer */
    ret = flb_ring_buffer_write(ins->rb, (void *) &cr, sizeof(cr));
    if (ret == -1) {
        flb_plg_debug(ins, "failed buffer write, retries=%i\n",
                      retries);

        /* if the ring buffer is full, we need to retry, update the counters */
        cmt_counter_add(ins->cmt_ring_buffer_retries, cfl_time_now(),
                        1, 1, (char *[]) {(char *) flb_input_name(ins)});


        /* sleep for 100000 microseconds (100 milliseconds) */
        usleep(100000);
        retries++;

        goto retry;
    }

    /* update successful writes */
    cmt_counter_add(ins->cmt_ring_buffer_writes, cfl_time_now(),
                    1, 1, (char *[]) {(char *) flb_input_name(ins)});

    return 0;
}

/* iterate input instance ring buffer and remove any enqueued input_chunk_raw */
void flb_input_chunk_ring_buffer_cleanup(struct flb_input_instance *ins)
{
    int ret;
    struct input_chunk_raw *cr;

    if (!ins->rb) {
        return;
    }

    while ((ret = flb_ring_buffer_read(ins->rb, (void *) &cr, sizeof(cr))) == 0) {
        if (cr) {
            destroy_chunk_raw(cr);
            cr = NULL;
        }
    }
}

void flb_input_chunk_ring_buffer_collector(struct flb_config *ctx, void *data)
{
    int ret;
    int tag_len = 0;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct input_chunk_raw *cr;

    mk_list_foreach(head, &ctx->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        cr = NULL;

        while (1) {
            if (flb_input_buf_paused(ins) == FLB_TRUE) {
                break;
            }

            ret = flb_ring_buffer_read(ins->rb,
                                       (void *) &cr,
                                       sizeof(cr));
            if (ret != 0) {
                break;
            }

            if (cr) {
                if (cr->tag) {
                    tag_len = flb_sds_len(cr->tag);
                }
                else {
                    tag_len = 0;
                }

                input_chunk_append_raw(cr->ins, cr->event_type, cr->records,
                                       cr->tag, tag_len,
                                       cr->buf_data, cr->buf_size);
                destroy_chunk_raw(cr);
            }
            cr = NULL;
        }

        ins->rb->flush_pending = FLB_FALSE;
    }
}

int flb_input_chunk_append_raw(struct flb_input_instance *in,
                               int event_type,
                               size_t records,
                               const char *tag, size_t tag_len,
                               const void *buf, size_t buf_size)
{
    int ret;

    /*
     * If the plugin instance registering the data runs in a separate thread, we must
     * add the data reference to the ring buffer.
     */
    if (flb_input_is_threaded(in)) {
        ret = append_to_ring_buffer(in, event_type, records,
                                    tag, tag_len,
                                    buf, buf_size);
    }
    else {
        ret = input_chunk_append_raw(in, event_type, records,
                                     tag, tag_len, buf, buf_size);
    }

    return ret;
}

/* Retrieve a raw buffer from a dyntag node */
const void *flb_input_chunk_flush(struct flb_input_chunk *ic, size_t *size)
{
    int ret;
    size_t pre_size;
    size_t post_size;
    ssize_t diff_size;
    char *buf = NULL;

    pre_size = flb_input_chunk_get_real_size(ic);

    if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
        ret = cio_chunk_up(ic->chunk);
        if (ret == -1) {
            return NULL;
        }
    }

    /* Lock the internal chunk
     *
     * This operation has to be performed before getting the chunk data
     * pointer because in certain situations it could cause the chunk
     * mapping to be relocated (ie. macos / windows on trim)
     */
    cio_chunk_lock(ic->chunk);

    /*
     * msgpack-c internal use a raw buffer for it operations, since we
     * already appended data we just can take out the references to avoid
     * a new memory allocation and skip a copy operation.
     */
    ret = cio_chunk_get_content(ic->chunk, &buf, size);

    if (ret == -1) {
        flb_error("[input chunk] error retrieving chunk content");
        return NULL;
    }

    if (!buf) {
        *size = 0;
        return NULL;
    }

    /* Set it busy as it likely it's a reference for an outgoing task */
    ic->busy = FLB_TRUE;

    post_size = flb_input_chunk_get_real_size(ic);
    if (post_size != pre_size) {
        diff_size = post_size - pre_size;
        flb_input_chunk_update_output_instances(ic, diff_size);
    }
    return buf;
}

int flb_input_chunk_release_lock(struct flb_input_chunk *ic)
{
    if (ic->busy == FLB_FALSE) {
        return -1;
    }

    ic->busy = FLB_FALSE;
    return 0;
}

flb_sds_t flb_input_chunk_get_name(struct flb_input_chunk *ic)
{
    struct cio_chunk *ch;

    ch = (struct cio_chunk *) ic->chunk;
    return ch->name;
}

/*
 * Get the event type by retrieving metadata header. NOTE: this function only event type discovery by looking at the
 * headers bytes of a chunk that exists on disk.
 */
int flb_input_chunk_get_event_type(struct flb_input_chunk *ic)
{
    int len;
    int ret;
    int type = -1;
    char *buf = NULL;

    ret = cio_meta_read(ic->chunk, &buf, &len);
    if (ret == -1) {
        return -1;
    }

    /* Check metadata header / magic bytes */
    if (input_chunk_has_magic_bytes(buf, len)) {
        if (buf[2] == FLB_INPUT_CHUNK_TYPE_LOGS) {
            type = FLB_INPUT_LOGS;
        }
        else if (buf[2] == FLB_INPUT_CHUNK_TYPE_METRICS) {
            type = FLB_INPUT_METRICS;
        }
        else if (buf[2] == FLB_INPUT_CHUNK_TYPE_TRACES) {
            type = FLB_INPUT_TRACES;
        }
        else if (buf[2] == FLB_INPUT_CHUNK_TYPE_PROFILES) {
            type = FLB_INPUT_PROFILES;
        }
        else if (buf[2] == FLB_INPUT_CHUNK_TYPE_BLOBS) {
            type = FLB_INPUT_BLOBS;
        }
    }
    else {
        type = FLB_INPUT_LOGS;
    }


    return type;
}

int flb_input_chunk_get_tag(struct flb_input_chunk *ic,
                            const char **tag_buf, int *tag_len)
{
    int ret;
    struct flb_input_chunk_meta_view view;

    ret = input_chunk_metadata_view(ic, &view);
    if (ret == -1) {
        *tag_len = -1;
        *tag_buf = NULL;
        return -1;
    }

    *tag_buf = view.tag;
    *tag_len = view.tag_length;

    return 0;
}

/*
 * Iterates all output instances that the chunk will be flushing to and summarize
 * the total number of bytes in use after ingesting the new data.
 */
void flb_input_chunk_update_output_instances(struct flb_input_chunk *ic,
                                             size_t chunk_size)
{
    struct mk_list *head;
    struct flb_output_instance *o_ins;

    /* for each output plugin, we update the fs_chunks_size */
    mk_list_foreach(head, &ic->in->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (o_ins->total_limit_size == -1) {
            continue;
        }

        if (flb_routes_mask_get_bit(ic->routes_mask,
                                    o_ins->id,
                                    o_ins->config->router) != 0) {
            /*
             * if there is match on any index of 1's in the binary, it indicates
             * that the input chunk will flush to this output instance
             */
            FS_CHUNK_SIZE_DEBUG_MOD(o_ins, ic, chunk_size);
            o_ins->fs_chunks_size += chunk_size;
            ic->fs_counted = FLB_TRUE;

            flb_trace("[input chunk] chunk %s update plugin %s fs_chunks_size by %ld bytes, "
                      "the current fs_chunks_size is %ld bytes", flb_input_chunk_get_name(ic),
                      o_ins->name, chunk_size, o_ins->fs_chunks_size);
        }
    }
}
