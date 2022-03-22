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

#include <monkey/mk_http_status.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_stream.h>
#include <fluent-bit/stream_processor/flb_sp_snapshot.h>

#define HTTP_CONTENT_JSON  0

static void send_response(mk_request_t *request, int code, char *message, size_t size)
{
    mk_http_status(request, code);
    mk_http_send(request, message, size, NULL);
    mk_http_done(request);
}

static void create_stream(mk_request_t *request, void *data)
{
    flb_sds_t task_name;
    flb_sds_t query;
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;
    struct flb_sp_task *task = NULL;
    struct flb_sp *sp;
    struct mk_list *head;

    /* Context Type */
    int type = -1;
    struct mk_http_header *header;

    header = &request->session->parser.headers[MK_HEADER_CONTENT_TYPE];

    if (header->val.len == 16 &&
        strncasecmp(header->val.data, "application/json", 16) == 0) {
        type = HTTP_CONTENT_JSON;
    }

    if (type == -1) {
        send_response(request, MK_CLIENT_BAD_REQUEST, "error: invalid 'Content-Type'\n", 30);
        return;
    }

    if (request->data.len <= 0) {
        send_response(request, MK_CLIENT_BAD_REQUEST, "error: no payload found\n", 24);
        return;
    }

    if (type == HTTP_CONTENT_JSON) {
        task_name = flb_json_get_val(request->data.data, request->data.len, "task");
        if (!task_name) {
            send_response(request, MK_CLIENT_BAD_REQUEST, "error: task name not found\n", 27);
            return;
        }
        query = flb_json_get_val(request->data.data, request->data.len, "query");
        if (!query) {
            send_response(request, MK_CLIENT_BAD_REQUEST, "error: query not found\n", 23);
            flb_sds_destroy(task_name);
            return;
        }
    }

    /* check if task name exists */
    // traverse stream processor tasks
    sp = (struct flb_sp *) config->stream_processor_ctx;

    mk_list_foreach(head, &sp->tasks) {
        task = mk_list_entry(head, struct flb_sp_task, _head);

        if (flb_sds_cmp(task->name, task_name, flb_sds_len(task_name)) != 0) {
            continue;
        }

        /* task name exists */
        send_response(request, MK_CLIENT_CONFLICT, "error: task name exists\n", 24);

        // cleanup strings
        flb_sds_destroy(task_name);
        flb_sds_destroy(query);

        return;
    }

    task = flb_sp_task_create(config->stream_processor_ctx, task_name, query);

    // cleanup strings
    flb_sds_destroy(task_name);
    flb_sds_destroy(query);

    if (!task) {
        /* TODO: better to return 400 for invalid queries */
        send_response(request, MK_SERVER_INTERNAL_ERROR, NULL, 0);
        return;
    }

    send_response(request, MK_HTTP_CREATED, NULL, 0);
    return;
}

static void delete_stream(mk_request_t *request, void *data)
{
    int i;
    int task_index;
    /* config */
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    struct flb_sp *sp;
    struct flb_sp_task *task;
    struct mk_list *head;

    task_index = request->uri_processed.len;
    for (i = request->uri_processed.len - 1; i > 0; i--) {
        if (request->uri_processed.data[i] == '/') {
            task_index = i + 1;
            break;
        }
    }

    if (config->stream_processor_ctx) {
        // traverse stream processor tasks
        sp = (struct flb_sp *) config->stream_processor_ctx;

        mk_list_foreach(head, &sp->tasks) {
            task = mk_list_entry(head, struct flb_sp_task, _head);

            if (flb_sds_cmp(task->name, request->uri_processed.data + task_index,
                            request->uri_processed.len - task_index) != 0) {
              continue;
            }

            // shall we only allow to destroy dynamic tasks?
            flb_sp_task_destroy(task);
            send_response(request, MK_HTTP_OK, NULL, 0);
            break;
        }
    }

    send_response(request, MK_CLIENT_NOT_FOUND, NULL, 0);
}

static void cb_sp_create_task(mk_request_t *request, void *data)
{
    if (request->method != MK_METHOD_POST) {
        send_response(request, MK_CLIENT_BAD_REQUEST, NULL, 0);
        return;
    }

    create_stream(request, data);
}

static void cb_sp_delete_task(mk_request_t *request, void *data)
{
    if (request->method != MK_METHOD_DELETE) {
        send_response(request, MK_CLIENT_BAD_REQUEST, NULL, 0);
        return;
    }

    delete_stream(request, data);
}

// GET the list of all the stream processor tasks running
static void cb_sp_list_tasks(mk_request_t *request, void *data)
{
    /* output buffers */
    flb_sds_t out_buf = NULL;
    size_t out_size = 0;
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    struct mk_list *head;
    struct flb_sp *sp;
    struct flb_sp_task *task;
    /* msgpack */
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    if (request->method != MK_METHOD_GET) {
        send_response(request, MK_CLIENT_BAD_REQUEST, NULL, 0);
        return;
    }

    if (config->stream_processor_ctx) {
        // traverse strea, processor tasks
        sp = (struct flb_sp *) config->stream_processor_ctx;

        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        msgpack_pack_array(&mp_pck, mk_list_size(&sp->tasks));
        mk_list_foreach(head, &sp->tasks) {
            task = mk_list_entry(head, struct flb_sp_task, _head);

            msgpack_pack_map(&mp_pck, 2);

            msgpack_pack_str(&mp_pck, 4);
            msgpack_pack_str_body(&mp_pck, "name", 4);
            msgpack_pack_str(&mp_pck, flb_sds_len(task->name));
            msgpack_pack_str_body(&mp_pck, task->name, flb_sds_len(task->name));

            msgpack_pack_str(&mp_pck, 5);
            msgpack_pack_str_body(&mp_pck, "query", 5);
            msgpack_pack_str(&mp_pck, flb_sds_len(task->query));
            msgpack_pack_str_body(&mp_pck, task->query, flb_sds_len(task->query));
        }

        /* Export to JSON */
        out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
        if (!out_buf) {
            return;
        }
        out_size = flb_sds_len(out_buf);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);

    send_response(request, MK_HTTP_OK, out_buf, out_size);
    if (out_buf) {
        flb_sds_destroy(out_buf);
    }
}

flb_sds_t snapshot_reformat_and_jsonify(char **data_buf, size_t *data_size, int records)
{
    /* unpacker variables */
    int ok;
    size_t off = 0;
    msgpack_object root;
    msgpack_object map;
    msgpack_unpacked result;
    struct flb_time tm;
    msgpack_object *obj;
    flb_sds_t out_buf;

    /* packer variables */
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, records);
    /* Iterate over incoming records */
    while (msgpack_unpack_next(&result, *data_buf, *data_size, &off) == ok) {
        root = result.data;

        /* extract timestamp */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        map = root.via.array.ptr[1];

        msgpack_pack_map(&mp_pck, 2);

        msgpack_pack_str(&mp_pck, 17);
        msgpack_pack_str_body(&mp_pck, "__flb_record_time", 17);
        msgpack_pack_double(&mp_pck, flb_time_to_double(&tm));

        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "record", 6);
        msgpack_pack_object(&mp_pck, map);
    }

    msgpack_unpacked_destroy(&result);
    flb_free(*data_buf);

    /* for test */
    /* flb_pack_print(*data_buf, *data_size); */

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);

    return out_buf;
}

static void cb_sp_flush_snapshot(mk_request_t *request, void *data)
{
    int i;
    int task_index;
    /* output buffers */
    flb_sds_t out_buf = NULL;
    size_t out_size = 0;
    /* config */
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    size_t snapshot_out_size = 0;
    char *snapshot_out_buffer = NULL;
    struct flb_sp *sp;
    struct flb_sp_task *task;
    struct mk_list *head;

    if (request->method != MK_METHOD_GET) {
        send_response(request, MK_CLIENT_BAD_REQUEST, NULL, 0);
        return;
    }

    task_index = request->uri_processed.len;
    for (i = request->uri_processed.len - 1; i > 0; i--) {
        if (request->uri_processed.data[i] == '/') {
            task_index = i + 1;
            break;
        }
    }

    if (config->stream_processor_ctx) {
        // traverse strea, processor tasks
        sp = (struct flb_sp *) config->stream_processor_ctx;

        mk_list_foreach(head, &sp->tasks) {
            task = mk_list_entry(head, struct flb_sp_task, _head);

            if (flb_sds_cmp(task->name, request->uri_processed.data + task_index,
                            request->uri_processed.len - task_index) != 0) {
              continue;
            }

            int records = ((struct flb_sp_snapshot *) task->snapshot)->records;
            if (flb_sp_snapshot_flush(sp, task, &snapshot_out_buffer,
                                      &snapshot_out_size, true) == -1) {
                flb_error("Error flushing snapshot %s!", request->uri_processed.data + task_index);
                send_response(request, MK_SERVER_INTERNAL_ERROR, NULL, 0);
                return;
            }
            else {
                if (records > 0) {
                    /* this structural conversion (adding time as key/value)
                       imposes additional computation, hence, we keep it for the
                       sake of PoC.
                    */
                    out_buf = snapshot_reformat_and_jsonify(&snapshot_out_buffer, &snapshot_out_size, records);
                    if (!out_buf) {
                        send_response(request, MK_SERVER_INTERNAL_ERROR, NULL, 0);
                        return;
                    }
                    out_size = flb_sds_len(out_buf);

                    send_response(request, MK_HTTP_OK, out_buf, out_size);
                    if (out_buf) {
                        flb_sds_destroy(out_buf);
                    }
                    return;
                }
                else {
                    send_response(request, MK_HTTP_OK, "[]", 2);
                    return;
                }
            }
        }
    }

    send_response(request, MK_CLIENT_NOT_FOUND, NULL, 0);
    return;
}

/* Perform registration */
int api_v1_sp_query(struct flb_hs *hs)
{
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/stream_processor/task/[A-Za-z_][0-9A-Za-z_\\-]*", cb_sp_delete_task, hs);
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/stream_processor/task", cb_sp_create_task, hs);
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/stream_processor/list", cb_sp_list_tasks, hs);
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/stream_processor/flush/[A-Za-z_][0-9A-Za-z_\\-]*", cb_sp_flush_snapshot, hs);
    return 0;
}