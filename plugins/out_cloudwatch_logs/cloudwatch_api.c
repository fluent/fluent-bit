/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_output_plugin.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>

#include <monkey/mk_core.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "cloudwatch_api.h"

#define ERR_CODE_ALREADY_EXISTS         "ResourceAlreadyExistsException"
#define ERR_CODE_INVALID_SEQUENCE_TOKEN "InvalidSequenceTokenException"

#define ONE_DAY_IN_MILLISECONDS          86400000
#define FOUR_HOURS_IN_SECONDS            14400

static struct flb_aws_header create_group_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.CreateLogGroup",
    .val_len = 28,
};

static struct flb_aws_header create_stream_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Logs_20140328.CreateLogStream",
    .val_len = 29,
};

static struct flb_aws_header put_log_events_header[] = {
    {
        .key = "X-Amz-Target",
        .key_len = 12,
        .val = "Logs_20140328.PutLogEvents",
        .val_len = 26,
    },
    {
        .key = "x-amzn-logs-format",
        .key_len = 18,
        .val = "",
        .val_len = 0,
    },
};

int plugin_under_test()
{
    if (getenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

char *mock_error_response(char *error_env_var)
{
    char *err_val = NULL;
    char *error = NULL;
    int len = 0;

    err_val = getenv(error_env_var);
    if (err_val != NULL && strlen(err_val) > 0) {
        error = flb_malloc(strlen(err_val) + sizeof(char));
        if (error == NULL) {
            flb_errno();
            return NULL;
        }

        len = strlen(err_val);
        memcpy(error, err_val, len);
        error[len] = '\0';
        return error;
    }

    return NULL;
}

struct flb_http_client *mock_http_call(char *error_env_var, char *api)
{
    /* create an http client so that we can set the response */
    struct flb_http_client *c = NULL;
    char *error = mock_error_response(error_env_var);

    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        flb_free(error);
        return NULL;
    }
    mk_list_init(&c->headers);

    if (error != NULL) {
        c->resp.status = 400;
        /* resp.data is freed on destroy, payload is supposed to reference it */
        c->resp.data = error;
        c->resp.payload = c->resp.data;
        c->resp.payload_size = strlen(error);
    }
    else {
        c->resp.status = 200;
        c->resp.payload = "";
        c->resp.payload_size = 0;
        if (strcmp(api, "PutLogEvents") == 0) {
            /* mocked success response */
            c->resp.payload = "{\"nextSequenceToken\": \""
                  "49536701251539826331025683274032969384950891766572122113\"}";
            c->resp.payload_size = strlen(c->resp.payload);
        }
        else {
            c->resp.payload = "";
            c->resp.payload_size = 0;
        }
    }

    return c;
}

int compare_events(const void *a_arg, const void *b_arg)
{
    struct cw_event *r_a = (struct cw_event *) a_arg;
    struct cw_event *r_b = (struct cw_event *) b_arg;

    if (r_a->timestamp < r_b->timestamp) {
        return -1;
    }
    else if (r_a->timestamp == r_b->timestamp) {
        return 0;
    }
    else {
        return 1;
    }
}

static inline int try_to_write(char *buf, int *off, size_t left,
                               const char *str, size_t str_len)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        return FLB_FALSE;
    }
    memcpy(buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}

/*
 * Writes the "header" for a put log events payload
 */
static int init_put_payload(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                            struct log_stream *stream, int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"logGroupName\":\"", 17)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ctx->log_group, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",\"logStreamName\":\"", 19)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      stream->name, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",", 2)) {
        goto error;
    }

    if (stream->sequence_token) {
        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          "\"sequenceToken\":\"", 17)) {
            goto error;
        }

        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          stream->sequence_token, 0)) {
            goto error;
        }

        if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                          "\",", 2)) {
            goto error;
        }
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"logEvents\":[", 13)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/*
 * Writes a log event to the output buffer
 */
static int write_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                       struct cw_event *event, int *offset)
{
    char ts[50];

    if (!snprintf(ts, 50, "%llu", event->timestamp)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"timestamp\":", 13)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ts, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ",\"message\":\"", 12)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      event->json, event->len)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\"}", 2)) {
        goto error;
    }

    return 0;

error:
    return -1;
}

/* Terminates a PutLogEvents payload */
static int end_put_payload(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                           int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "]}", 2)) {
        return -1;
    }
    buf->out_buf[*offset] = '\0';

    return 0;
}

static unsigned long long stream_time_span(struct log_stream *stream,
                                           struct cw_event *event)
{
    if (stream->oldest_event == 0 || stream->newest_event == 0) {
        return 0;
    }

    if (stream->oldest_event > event->timestamp) {
        return stream->newest_event - event->timestamp;
    }
    else if (stream->newest_event < event->timestamp) {
        return event->timestamp - stream->oldest_event;
    }

    return stream->newest_event - stream->oldest_event;
}

/* returns FLB_TRUE if time span is less than 24 hours, FLB_FALSE if greater */
static int check_stream_time_span(struct log_stream *stream,
                                  struct cw_event *event)
{
    unsigned long long span = stream_time_span(stream, event);

    if (span < ONE_DAY_IN_MILLISECONDS) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* sets the oldest_event and newest_event fields */
static void set_stream_time_span(struct log_stream *stream, struct cw_event *event)
{
    if (stream->oldest_event == 0 || stream->oldest_event > event->timestamp) {
        stream->oldest_event = event->timestamp;
    }

    if (stream->newest_event == 0 || stream->newest_event < event->timestamp) {
        stream->newest_event = event->timestamp;
    }
}


/*
 * Processes the msgpack object
 * -1 = failure, record not added
 * 0 = success, record added
 * 1 = we ran out of space, send and retry
 * 2 = record could not be processed, discard it
 * Returns 0 on success, -1 on general errors,
 * and 1 if we ran out of space to write the event
 * which means a send must occur
 */
int process_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                  const msgpack_object *obj, struct flb_time *tms)
{
    size_t written;
    int ret;
    size_t size;
    int offset = 0;
    struct cw_event *event;
    char *tmp_buf_ptr;

    tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
    ret = flb_msgpack_to_json(tmp_buf_ptr,
                                  buf->tmp_buf_size - buf->tmp_buf_offset,
                                  obj);
    if (ret < 0) {
        /*
         * negative value means failure to write to buffer,
         * which means we ran out of space, and must send the logs
         */
        return 1;
    }
    written = (size_t) ret;
    /* Discard empty messages (written == 2 means '""') */
    if (written <= 2) {
        flb_plg_debug(ctx->ins, "Found empty log message");
        return 2;
    }

    /* the json string must be escaped, unless the log_key option is used */
    if (ctx->log_key == NULL) {
        /*
         * check if event_buf is initialized and big enough
         * If all chars need to be hex encoded (impossible), 6x space would be
         * needed
         */
        size = written * 6;
        if (buf->event_buf == NULL || buf->event_buf_size < size) {
            flb_free(buf->event_buf);
            buf->event_buf = flb_malloc(size);
            buf->event_buf_size = size;
            if (buf->event_buf == NULL) {
                flb_errno();
                return -1;
            }
        }
        offset = 0;
        if (!flb_utils_write_str(buf->event_buf, &offset, size,
                                 tmp_buf_ptr, written)) {
            return -1;
        }
        written = offset;

        tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
        if ((buf->tmp_buf_size - buf->tmp_buf_offset) < written) {
            /* not enough space, send logs */
            return 1;
        }

        if (written > MAX_EVENT_LEN) {
            flb_plg_warn(ctx->ins, "[size=%zu] Truncating event which is larger than "
                         "max size allowed by CloudWatch", written);
            written = MAX_EVENT_LEN;
        }

        /* copy serialized json to tmp_buf */
        if (!strncpy(tmp_buf_ptr, buf->event_buf, written)) {
            return -1;
        }

        buf->tmp_buf_offset += written;
        event = &buf->events[buf->event_index];
        event->json = tmp_buf_ptr;
        event->len = written;
        event->timestamp = (unsigned long long) (tms->tm.tv_sec * 1000 +
                                                 tms->tm.tv_nsec/1000000);

    }
    else {
        /*
         * flb_msgpack_to_json will encase the value in quotes
         * We don't want that for log_key, so we ignore the first
         * and last character
         */
        written -= 2;

        if (written > MAX_EVENT_LEN) {
            flb_plg_warn(ctx->ins, "[size=%zu] Truncating event which is larger than "
                         "max size allowed by CloudWatch", written);
            written = MAX_EVENT_LEN;
        }

        tmp_buf_ptr++; /* pass over the opening quote */
        buf->tmp_buf_offset += (written + 1);
        event = &buf->events[buf->event_index];
        event->json = tmp_buf_ptr;
        event->len = written;
        event->timestamp = (unsigned long long) (tms->tm.tv_sec * 1000 +
                                                 tms->tm.tv_nsec/1000000);
    }

    return 0;
}

/* Resets or inits a cw_flush struct */
void reset_flush_buf(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                    struct log_stream *stream) {
    buf->event_index = 0;
    buf->tmp_buf_offset = 0;
    buf->event_index = 0;
    buf->data_size = PUT_LOG_EVENTS_HEADER_LEN + PUT_LOG_EVENTS_FOOTER_LEN;
    buf->data_size += strlen(stream->name);
    buf->data_size += strlen(ctx->log_group);
    if (stream->sequence_token) {
        buf->data_size += strlen(stream->sequence_token);
    }
}

/* sorts events, constructs a put payload, and then sends */
int send_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                    struct log_stream *stream) {
    int ret;
    int offset;
    int i;
    struct cw_event *event;

    if (buf->event_index <= 0) {
        return 0;
    }

    /* events must be sorted by timestamp in a put payload */
    qsort(buf->events, buf->event_index, sizeof(struct cw_event), compare_events);

retry:
    stream->newest_event = 0;
    stream->oldest_event = 0;

    offset = 0;
    ret = init_put_payload(ctx, buf, stream, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to initialize PutLogEvents payload");
        return -1;
    }

    for (i = 0; i < buf->event_index; i++) {
        event = &buf->events[i];
        ret = write_event(ctx, buf, event, &offset);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write log event %d to "
                          "payload buffer", i);
            return -1;
        }
        if (i != (buf->event_index - 1)) {
            if (!try_to_write(buf->out_buf, &offset, buf->out_buf_size,
                              ",", 1)) {
                flb_plg_error(ctx->ins, "Could not terminate log event with ','");
                return -1;
            }
        }
    }

    ret = end_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not complete PutLogEvents payload");
        return -1;
    }

    flb_plg_debug(ctx->ins, "Sending %d events", i);
    ret = put_log_events(ctx, buf, stream, (size_t) offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to send log events");
        return -1;
    }
    else if (ret > 0) {
        goto retry;
    }

    return 0;
}

/*
 * Processes the msgpack object, sends the current batch if needed
 */
int add_event(struct flb_cloudwatch *ctx, struct cw_flush *buf,
              struct log_stream *stream,
              const msgpack_object *obj, struct flb_time *tms)
{
    int ret;
    struct cw_event *event;
    int retry_add = FLB_FALSE;
    int event_bytes = 0;

    if (buf->event_index == 0) {
        /* init */
        reset_flush_buf(ctx, buf, stream);
    }

retry_add_event:
    retry_add = FLB_FALSE;
    ret = process_event(ctx, buf, obj, tms);
    if (ret < 0) {
        return -1;
    }
    else if (ret == 1) {
        if (buf->event_index <= 0) {
            /* somehow the record was larger than our entire request buffer */
            flb_plg_warn(ctx->ins, "Discarding massive log record");
            return 0; /* discard this record and return to caller */
        }
        /* send logs and then retry the add */
        retry_add = FLB_TRUE;
        goto send;
    } else if (ret == 2) {
        /*
         * discard this record and return to caller
         * only happens for empty records in this plugin
         */
        return 0;
    }

    event = &buf->events[buf->event_index];
    event_bytes = event->len + PUT_LOG_EVENTS_PER_EVENT_LEN;

    if (check_stream_time_span(stream, event) == FLB_FALSE) {
        /* do not send this event */
        retry_add = FLB_TRUE;
        goto send;
    }

    if ((buf->data_size + event_bytes) > PUT_LOG_EVENTS_PAYLOAD_SIZE) {
        if (buf->event_index <= 0) {
            /* somehow the record was larger than our entire request buffer */
            flb_plg_warn(ctx->ins, "Discarding massive log record");
            return 0; /* discard this record and return to caller */
        }
        /* do not send this event */
        retry_add = FLB_TRUE;
        goto send;
    }

    buf->data_size += event_bytes;
    set_stream_time_span(stream, event);
    buf->event_index++;

    if (buf->event_index == MAX_EVENTS_PER_PUT) {
        goto send;
    }

    /* send is not needed yet, return to caller */
    return 0;

send:
    ret = send_log_events(ctx, buf, stream);
    reset_flush_buf(ctx, buf, stream);
    if (ret < 0) {
        return -1;
    }

    if (retry_add == FLB_TRUE) {
        goto retry_add_event;
    }

    return 0;
}

/*
 * Main routine- processes msgpack and sends in batches
 * return value is the number of events processed
 */
int process_and_send(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                     struct log_stream *stream,
                     const char *data, size_t bytes)
{
    size_t off = 0;
    int i = 0;
    size_t map_size;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object  map;
    msgpack_object root;
    msgpack_object_kv *kv;
    msgpack_object  key;
    msgpack_object  val;
    char *key_str = NULL;
    size_t key_str_size = 0;
    int j;
    int ret;
    int check = FLB_FALSE;
    int found = FLB_FALSE;
    struct flb_time tms;

    /* unpack msgpack */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map.
         */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* Get the record/map */
        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        if (ctx->log_key) {
            key_str = NULL;
            key_str_size = 0;
            check = FLB_FALSE;
            found = FLB_FALSE;

            kv = map.via.map.ptr;

            for(j=0; j < map_size; j++) {
                key = (kv+j)->key;
                if (key.type == MSGPACK_OBJECT_BIN) {
                    key_str  = (char *) key.via.bin.ptr;
                    key_str_size = key.via.bin.size;
                    check = FLB_TRUE;
                }
                if (key.type == MSGPACK_OBJECT_STR) {
                    key_str  = (char *) key.via.str.ptr;
                    key_str_size = key.via.str.size;
                    check = FLB_TRUE;
                }

                if (check == FLB_TRUE) {
                    if (strncmp(ctx->log_key, key_str, key_str_size) == 0) {
                        found = FLB_TRUE;
                        val = (kv+j)->val;
                        ret = add_event(ctx, buf, stream, &val, &tms);
                        if (ret < 0 ) {
                            goto error;
                        }
                    }
                }

            }
            if (found == FLB_FALSE) {
                flb_plg_error(ctx->ins, "Could not find log_key '%s' in record",
                              ctx->log_key);
            }
            else {
                i++;
            }
            continue;
        }

        ret = add_event(ctx, buf, stream, &map, &tms);
        if (ret < 0 ) {
            goto error;
        }
        i++;
    }
    msgpack_unpacked_destroy(&result);

    /* send any remaining events */
    ret = send_log_events(ctx, buf, stream);
    reset_flush_buf(ctx, buf, stream);
    if (ret < 0) {
        return -1;
    }

    /* return number of events */
    return i;

error:
    msgpack_unpacked_destroy(&result);
    return -1;
}


struct log_stream *get_dynamic_log_stream(struct flb_cloudwatch *ctx,
                                          const char *tag, int tag_len)
{
    struct log_stream *new_stream;
    struct log_stream *stream;
    struct mk_list *tmp;
    struct mk_list *head;
    flb_sds_t name = NULL;
    flb_sds_t tmp_s = NULL;
    time_t now;
    int ret;

    name = flb_sds_create(ctx->log_stream_prefix);
    if (!name) {
        flb_errno();
        return NULL;
    }

    tmp_s = flb_sds_cat(name, tag, tag_len);
    if (!tmp_s) {
        flb_errno();
        flb_sds_destroy(name);
        return NULL;
    }
    name = tmp_s;

    /* check if the stream already exists */
    now = time(NULL);
    mk_list_foreach_safe(head, tmp, &ctx->streams) {
        stream = mk_list_entry(head, struct log_stream, _head);
        if (strcmp(name, stream->name) == 0) {
            flb_sds_destroy(name);
            return stream;
        }
        else {
            /* check if stream is expired, if so, clean it up */
            if (stream->expiration < now) {
                mk_list_del(&stream->_head);
                log_stream_destroy(stream);
            }
        }
    }

    /* create the new stream */
    new_stream = flb_calloc(1, sizeof(struct log_stream));
    if (!new_stream) {
        flb_errno();
        flb_sds_destroy(name);
        return NULL;
    }
    new_stream->name = name;

    ret = create_log_stream(ctx, new_stream);
    if (ret < 0) {
        log_stream_destroy(new_stream);
        return NULL;
    }
    new_stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;

    mk_list_add(&new_stream->_head, &ctx->streams);
    return new_stream;
}

struct log_stream *get_log_stream(struct flb_cloudwatch *ctx,
                                  const char *tag, int tag_len)
{
    struct log_stream *stream;
    int ret;

    if (ctx->log_stream_name) {
        stream = &ctx->stream;
        if (ctx->stream_created == FLB_FALSE) {
            ret = create_log_stream(ctx, stream);
            if (ret < 0) {
                return NULL;
            }
            stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;
            ctx->stream_created = FLB_TRUE;
        }
        return stream;
    }

     return get_dynamic_log_stream(ctx, tag, tag_len);
}

int create_log_group(struct flb_cloudwatch *ctx)
{
    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;

    flb_plg_info(ctx->ins, "Creating log group %s", ctx->log_group);

    body = flb_sds_create_size(25 + strlen(ctx->log_group));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogGroup request body */
    tmp = flb_sds_printf(&body, "{\"logGroupName\":\"%s\"}", ctx->log_group);
    if (!tmp) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }
    body = tmp;

    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_CREATE_LOG_GROUP_ERROR", "CreateLogGroup");
    }
    else {
        cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body),
                                              &create_group_header, 1);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "CreateLogGroup http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Created log group %s", ctx->log_group);
            ctx->group_created = FLB_TRUE;
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_ALREADY_EXISTS) == 0) {
                    flb_plg_info(ctx->ins, "Log Group %s already exists",
                                  ctx->log_group);
                    ctx->group_created = FLB_TRUE;
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    return 0;
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                        "CreateLogGroup", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error can not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to create log group");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

int create_log_stream(struct flb_cloudwatch *ctx, struct log_stream *stream)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t body;
    flb_sds_t tmp;
    flb_sds_t error;

    flb_plg_info(ctx->ins, "Creating log stream %s in log group %s",
                 stream->name, ctx->log_group);

    body = flb_sds_create_size(50 + strlen(ctx->log_group) +
                               strlen(stream->name));
    if (!body) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }

    /* construct CreateLogStream request body */
    tmp = flb_sds_printf(&body,
                         "{\"logGroupName\":\"%s\",\"logStreamName\":\"%s\"}",
                         ctx->log_group,
                         stream->name);
    if (!tmp) {
        flb_sds_destroy(body);
        flb_errno();
        return -1;
    }
    body = tmp;

    cw_client = ctx->cw_client;
    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_CREATE_LOG_STREAM_ERROR", "CreateLogStream");
    }
    else {
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", body, strlen(body),
                                              &create_stream_header, 1);
    }

    if (c) {
        flb_plg_debug(ctx->ins,"CreateLogStream http status=%d",
                      c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_info(ctx->ins, "Created log stream %s", stream->name);
            flb_sds_destroy(body);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_ALREADY_EXISTS) == 0) {
                    flb_plg_info(ctx->ins, "Log Stream %s already exists",
                                 stream->name);
                    flb_sds_destroy(body);
                    flb_sds_destroy(error);
                    flb_http_client_destroy(c);
                    return 0;
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "CreateLogStream", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error can not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to create log stream");
    if (c) {
        flb_http_client_destroy(c);
    }
    flb_sds_destroy(body);
    return -1;
}

/*
 * Returns -1 on failure, 0 on success, and 1 for a sequence token error,
 * which means the caller can retry.
 */
int put_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                   struct log_stream *stream, size_t payload_size)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *cw_client;
    flb_sds_t tmp;
    flb_sds_t error;
    int num_headers = 1;

    buf->put_events_calls++;

    if (buf->put_events_calls >= 4) {
        /*
         * In normal execution, even under high throughput, 4+ calls per flush
         * should be extremely rare. This is needed for edge cases basically.
         */
        flb_plg_debug(ctx->ins, "Too many calls this flush, sleeping for 250 ms");
        usleep(250000);
    }

    flb_plg_debug(ctx->ins, "Sending log events to log stream %s", stream->name);

    /* stream is being used, update expiration */
    stream->expiration = time(NULL) + FOUR_HOURS_IN_SECONDS;

    if (ctx->log_format != NULL) {
        put_log_events_header[1].val = (char *) ctx->log_format;
        put_log_events_header[1].val_len = strlen(ctx->log_format);
        num_headers = 2;
    }

    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_PUT_LOG_EVENTS_ERROR", "PutLogEvents");
    }
    else {
        cw_client = ctx->cw_client;
        c = cw_client->client_vtable->request(cw_client, FLB_HTTP_POST,
                                              "/", buf->out_buf, payload_size,
                                              put_log_events_header, num_headers);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "PutLogEvents http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* success */
            flb_plg_debug(ctx->ins, "Sent events to %s", stream->name);
            if (c->resp.payload_size > 0) {
                tmp = flb_json_get_val(c->resp.payload, c->resp.payload_size,
                                       "nextSequenceToken");
                if (tmp) {
                    if (stream->sequence_token != NULL) {
                        flb_sds_destroy(stream->sequence_token);
                    }
                    stream->sequence_token = tmp;
                }
                else {
                    flb_plg_error(ctx->ins, "Could not find sequence token in "
                                  "response: %s", c->resp.payload);
                }
            }
            else {
                flb_plg_error(ctx->ins, "Could not find sequence token in "
                              "response: response body is empty");
            }
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_INVALID_SEQUENCE_TOKEN) == 0) {
                    /*
                     * This case will happen when we do not know the correct
                     * sequence token; we can find it in the error response
                     * and retry.
                     */
                    flb_plg_debug(ctx->ins, "Sequence token was invalid, "
                                  "will retry");
                    tmp = flb_json_get_val(c->resp.payload, c->resp.payload_size,
                                           "expectedSequenceToken");
                    if (tmp) {
                        if (stream->sequence_token != NULL) {
                            flb_sds_destroy(stream->sequence_token);
                        }
                        stream->sequence_token = tmp;
                        flb_sds_destroy(error);
                        flb_http_client_destroy(c);
                        /* tell the caller to retry */
                        return 1;
                    }
                }
                /* some other error occurred; notify user */
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "PutLogEvents", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error could not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to send log events");
    if (c) {
        flb_http_client_destroy(c);
    }
    return -1;
}


void cw_flush_destroy(struct cw_flush *buf)
{
    if (buf) {
        flb_free(buf->tmp_buf);
        flb_free(buf->out_buf);
        flb_free(buf->events);
        flb_free(buf->event_buf);
        flb_free(buf);
    }
}
