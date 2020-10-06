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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>

#include <monkey/mk_core.h>
#include <mbedtls/base64.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "firehose_api.h"

#define ERR_CODE_SERVICE_UNAVAILABLE "ServiceUnavailableException"

static struct flb_aws_header put_record_batch_header = {
    .key = "X-Amz-Target",
    .key_len = 12,
    .val = "Firehose_20150804.PutRecordBatch",
    .val_len = 32,
};

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
 * Writes the "header" for a put_record_batch payload
 */
static int init_put_payload(struct flb_firehose *ctx, struct flush *buf,
                            int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"DeliveryStreamName\":\"", 23)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      ctx->delivery_stream, 0)) {
        goto error;
    }

    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "\",\"Records\":[", 13)) {
        goto error;
    }
    return 0;

error:
    return -1;
}

/*
 * Writes a log event to the output buffer
 */
static int write_event(struct flb_firehose *ctx, struct flush *buf,
                       struct event *event, int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "{\"Data\":\"", 9)) {
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

/* Terminates a PutRecordBatch payload */
static int end_put_payload(struct flb_firehose *ctx, struct flush *buf,
                           int *offset)
{
    if (!try_to_write(buf->out_buf, offset, buf->out_buf_size,
                      "]}", 2)) {
        return -1;
    }
    buf->out_buf[*offset] = '\0';

    return 0;
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
static int process_event(struct flb_firehose *ctx, struct flush *buf,
                         const msgpack_object *obj, struct flb_time *tms)
{
    size_t written = 0;
    int ret;
    size_t size;
    size_t b64_len;
    struct event *event;
    char *tmp_buf_ptr;
    char *time_key_ptr;
    struct tm time_stamp;
    struct tm *tmp;
    size_t len;
    size_t tmp_size;

    tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
    ret = flb_msgpack_to_json(tmp_buf_ptr,
                                  buf->tmp_buf_size - buf->tmp_buf_offset,
                                  obj);
    if (ret <= 0) {
        /*
         * negative value means failure to write to buffer,
         * which means we ran out of space, and must send the logs
         *
         * TODO: This could also incorrectly be triggered if the record
         * is larger than MAX_EVENT_SIZE
         */
        return 1;
    }
    written = (size_t) ret;

    /* Discard empty messages (written == 2 means '""') */
    if (written <= 2) {
        flb_plg_debug(ctx->ins, "Found empty log message, %s", ctx->delivery_stream);
        return 2;
    }

    if (ctx->log_key) {
        /*
         * flb_msgpack_to_json will encase the value in quotes
         * We don't want that for log_key, so we ignore the first
         * and last character
         */
        written -= 2;
        tmp_buf_ptr++; /* pass over the opening quote */
        buf->tmp_buf_offset++;
    }

    /* is (written + 1) because we still have to append newline */
    if ((written + 1) >= MAX_EVENT_SIZE) {
        flb_plg_warn(ctx->ins, "[size=%zu] Discarding record which is larger than "
                     "max size allowed by Firehose, %s", written + 1,
                     ctx->delivery_stream);
        return 2;
    }

    if (ctx->time_key) {
        /* append time_key to end of json string */
        tmp = gmtime_r(&tms->tm.tv_sec, &time_stamp);
        if (!tmp) {
            flb_plg_error(ctx->ins, "Could not create time stamp for %lu unix "
                         "seconds, discarding record, %s", tms->tm.tv_sec,
                         ctx->delivery_stream);
            return 2;
        }
        /* guess space needed to write time_key */
        len = 6 + strlen(ctx->time_key) + 6 * strlen(ctx->time_key_format);
        /* how much space do we have left */
        tmp_size = (buf->tmp_buf_size - buf->tmp_buf_offset) - written;
        if (len > tmp_size) {
            /* not enough space- tell caller to retry */
            return 1;
        }
        time_key_ptr = tmp_buf_ptr + written - 1;
        memcpy(time_key_ptr, ",", 1);
        time_key_ptr++;
        memcpy(time_key_ptr, "\"", 1);
        time_key_ptr++;
        memcpy(time_key_ptr, ctx->time_key, strlen(ctx->time_key));
        time_key_ptr += strlen(ctx->time_key);
        memcpy(time_key_ptr, "\":\"", 3);
        time_key_ptr += 3;
        tmp_size = buf->tmp_buf_size - buf->tmp_buf_offset;
        tmp_size -= (time_key_ptr - tmp_buf_ptr);
        len = strftime(time_key_ptr, tmp_size, ctx->time_key_format, &time_stamp);
        if (len <= 0) {
            /* ran out of space - should not happen because of check above */
            return 1;
        }
        time_key_ptr += len;
        memcpy(time_key_ptr, "\"}", 2);
        time_key_ptr += 2;
        written = (time_key_ptr - tmp_buf_ptr);
    }

    /* is (written + 1) because we still have to append newline */
    if ((written + 1) >= MAX_EVENT_SIZE) {
        flb_plg_warn(ctx->ins, "[size=%zu] Discarding record which is larger than "
                     "max size allowed by Firehose, %s", written + 1,
                     ctx->delivery_stream);
        return 2;
    }

    /* append newline to record */

    tmp_size = (buf->tmp_buf_size - buf->tmp_buf_offset) - written;
    if (tmp_size <= 1) {
        /* no space left- tell caller to retry */
        return 1;
    }

    memcpy(tmp_buf_ptr + written, "\n", 1);
    written++;

    /*
     * check if event_buf is initialized and big enough
     * Base64 encoding will increase size by ~4/3
     */
    size = (written * 1.5) + 4;
    if (buf->event_buf == NULL || buf->event_buf_size < size) {
        flb_free(buf->event_buf);
        buf->event_buf = flb_malloc(size);
        buf->event_buf_size = size;
        if (buf->event_buf == NULL) {
            flb_errno();
            return -1;
        }
    }

    tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
    ret = mbedtls_base64_encode((unsigned char *) buf->event_buf, size, &b64_len,
                                (unsigned char *) tmp_buf_ptr, written);
    if (ret != 0) {
        flb_errno();
        return -1;
    }
    written = b64_len;

    tmp_buf_ptr = buf->tmp_buf + buf->tmp_buf_offset;
    if ((buf->tmp_buf_size - buf->tmp_buf_offset) < written) {
        /* not enough space, send logs */
        return 1;
    }

    /* copy serialized json to tmp_buf */
    memcpy(tmp_buf_ptr, buf->event_buf, written);

    buf->tmp_buf_offset += written;
    event = &buf->events[buf->event_index];
    event->json = tmp_buf_ptr;
    event->len = written;
    event->timestamp.tv_sec = tms->tm.tv_sec;
    event->timestamp.tv_nsec = tms->tm.tv_nsec;

    return 0;
}

/* Resets or inits a flush struct */
static void reset_flush_buf(struct flb_firehose *ctx, struct flush *buf) {
    buf->event_index = 0;
    buf->tmp_buf_offset = 0;
    buf->data_size = PUT_RECORD_BATCH_HEADER_LEN + PUT_RECORD_BATCH_FOOTER_LEN;
    buf->data_size += strlen(ctx->delivery_stream);
}

/* constructs a put payload, and then sends */
static int send_log_events(struct flb_firehose *ctx, struct flush *buf) {
    int ret;
    int offset;
    int i;
    struct event *event;

    if (buf->event_index <= 0) {
        /*
         * event_index should always be 1 more than the actual last event index
         * when this function is called.
         * Except in the case where send_log_events() is called at the end of
         * process_and_send. If all records were already sent, event_index
         * will be 0. Hence this check.
         */
        return 0;
    }

    /* alloc out_buf if needed */
    if (buf->out_buf == NULL || buf->out_buf_size < buf->data_size) {
        if (buf->out_buf != NULL) {
            flb_free(buf->out_buf);
        }
        buf->out_buf = flb_malloc(buf->data_size + 1);
        if (!buf->out_buf) {
            flb_errno();
            return -1;
        }
        buf->out_buf_size = buf->data_size;
    }

    offset = 0;
    ret = init_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to initialize PutRecordBatch payload, %s",
                      ctx->delivery_stream);
        return -1;
    }

    for (i = 0; i < buf->event_index; i++) {
        event = &buf->events[i];
        ret = write_event(ctx, buf, event, &offset);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write log record %d to "
                          "payload buffer, %s", i, ctx->delivery_stream);
            return -1;
        }
        if (i != (buf->event_index -1)) {
            if (!try_to_write(buf->out_buf, &offset, buf->out_buf_size,
                              ",", 1)) {
                flb_plg_error(ctx->ins, "Could not terminate record with ','");
                return -1;
            }
        }
    }

    ret = end_put_payload(ctx, buf, &offset);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not complete PutRecordBatch payload");
        return -1;
    }
    flb_plg_debug(ctx->ins, "Sending %d records", i);
    ret = put_record_batch(ctx, buf, (size_t) offset, i);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to send log records");
        return -1;
    }
    buf->records_sent += i;

    return 0;
}

/*
 * Processes the msgpack object, sends the current batch if needed
 */
static int add_event(struct flb_firehose *ctx, struct flush *buf,
                     const msgpack_object *obj, struct flb_time *tms)
{
    int ret;
    struct event *event;
    int retry_add = FLB_FALSE;
    size_t event_bytes = 0;

    if (buf->event_index == 0) {
        /* init */
        reset_flush_buf(ctx, buf);
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
            flb_plg_warn(ctx->ins, "Discarding massive log record, %s",
                         ctx->delivery_stream);
            return 0; /* discard this record and return to caller */
        }
        /* send logs and then retry the add */
        retry_add = FLB_TRUE;
        goto send;
    } else if (ret == 2) {
        /* discard this record and return to caller */
        flb_plg_warn(ctx->ins, "Discarding large or unprocessable record, %s",
                     ctx->delivery_stream);
        return 0;
    }

    event = &buf->events[buf->event_index];
    event_bytes = event->len + PUT_RECORD_BATCH_PER_RECORD_LEN;

    if ((buf->data_size + event_bytes) > PUT_RECORD_BATCH_PAYLOAD_SIZE) {
        if (buf->event_index <= 0) {
            /* somehow the record was larger than our entire request buffer */
            flb_plg_warn(ctx->ins, "[size=%zu] Discarding massive log record, %s",
                         event_bytes, ctx->delivery_stream);
            return 0; /* discard this record and return to caller */
        }
        /* do not send this event */
        retry_add = FLB_TRUE;
        goto send;
    }

    /* send is not needed yet, return to caller */
    buf->data_size += event_bytes;
    buf->event_index++;

    if (buf->event_index == MAX_EVENTS_PER_PUT) {
        goto send;
    }

    return 0;

send:
    ret = send_log_events(ctx, buf);
    reset_flush_buf(ctx, buf);
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
 * return value is the number of events processed (number sent is stored in buf)
 */
int process_and_send_records(struct flb_firehose *ctx, struct flush *buf,
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
                        ret = add_event(ctx, buf, &val, &tms);
                        if (ret < 0 ) {
                            goto error;
                        }
                    }
                }

            }
            if (found == FLB_FALSE) {
                flb_plg_error(ctx->ins, "Could not find log_key '%s' in record, %s",
                              ctx->log_key, ctx->delivery_stream);
            }
            else {
                i++;
            }
            continue;
        }

        ret = add_event(ctx, buf, &map, &tms);
        if (ret < 0 ) {
            goto error;
        }
        i++;
    }
    msgpack_unpacked_destroy(&result);

    /* send any remaining events */
    ret = send_log_events(ctx, buf);
    reset_flush_buf(ctx, buf);
    if (ret < 0) {
        return -1;
    }

    /* return number of events processed */
    buf->records_processed = i;
    return i;

error:
    msgpack_unpacked_destroy(&result);
    return -1;
}

/*
 * Returns number of failed records on success, -1 on failure
 */
static int process_api_response(struct flb_firehose *ctx,
                                struct flb_http_client *c)
{
    int i;
    int k;
    int w;
    int ret;
    int failed_records = -1;
    int root_type;
    char *out_buf;
    int throughput_exceeded = FLB_FALSE;
    size_t off = 0;
    size_t out_size;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;
    msgpack_object response;
    msgpack_object response_key;
    msgpack_object response_val;

    if (strstr(c->resp.payload, "\"FailedPutCount\":0")) {
        return 0;
    }

    /* Convert JSON payload to msgpack */
    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &out_buf, &out_size, &root_type);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not pack/validate JSON API response\n%s",
                      c->resp.payload);
        return -1;
    }

    /* Lookup error field */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack response to find error\n%s",
                      c->resp.payload);
        failed_records = -1;
        goto done;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected payload type=%i",
                      root.type);
        failed_records = -1;
        goto done;
    }

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "unexpected key type=%i",
                          key.type);
            failed_records = -1;
            goto done;
        }

        if (key.via.str.size >= 14 &&
            strncmp(key.via.str.ptr, "FailedPutCount", 14) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
                flb_plg_error(ctx->ins, "unexpected 'FailedPutCount' value type=%i",
                              val.type);
                failed_records = -1;
                goto done;
            }

            failed_records = val.via.u64;
            if (failed_records == 0) {
                /* no need to check RequestResponses field */
                goto done;
            }
        }

        if (key.via.str.size >= 14 &&
            strncmp(key.via.str.ptr, "RequestResponses", 16) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_ARRAY) {
                flb_plg_error(ctx->ins, "unexpected 'RequestResponses' value type=%i",
                              val.type);
                failed_records = -1;
                goto done;
            }

            if (val.via.array.size == 0) {
                flb_plg_error(ctx->ins, "'RequestResponses' field in response is empty");
                failed_records = -1;
                goto done;
            }

            for (k = 0; k < val.via.array.size; k++) {
                /* iterate through the responses */
                response = val.via.array.ptr[k];
                if (response.type != MSGPACK_OBJECT_MAP) {
                    flb_plg_error(ctx->ins, "unexpected 'RequestResponses[%d]' value type=%i",
                                  k, response.type);
                    failed_records = -1;
                    goto done;
                }
                for (w = 0; w < response.via.map.size; w++) {
                    /* iterate through the response's keys */
                    response_key = response.via.map.ptr[w].key;
                    if (response_key.type != MSGPACK_OBJECT_STR) {
                        flb_plg_error(ctx->ins, "unexpected key type=%i",
                                      response_key.type);
                        failed_records = -1;
                        goto done;
                    }
                    if (response_key.via.str.size >= 9 &&
                        strncmp(response_key.via.str.ptr, "ErrorCode", 9) == 0) {
                        response_val = response.via.map.ptr[w].val;
                        if (!throughput_exceeded &&
                            response_val.via.str.size >= 27 &&
                            (strncmp(response_val.via.str.ptr,
                                    ERR_CODE_SERVICE_UNAVAILABLE, 27) == 0)) {
                                        throughput_exceeded = FLB_TRUE;
                                        flb_plg_error(ctx->ins, "Thoughput limits may have been exceeded, %s",
                                                      ctx->delivery_stream);
                        }
                        flb_plg_debug(ctx->ins, "Record %i failed with err_code=%.*s",
                                      k, response_val.via.str.size,
                                      response_val.via.str.ptr);
                    }
                    if (response_key.via.str.size >= 12 &&
                        strncmp(response_key.via.str.ptr, "ErrorMessage", 12) == 0) {
                        response_val = response.via.map.ptr[w].val;
                        flb_plg_debug(ctx->ins, "Record %i failed with err_msg=%.*s",
                                      k, response_val.via.str.size,
                                      response_val.via.str.ptr);
                    }
                }
            }
        }
    }

 done:
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
    return failed_records;
}

static int plugin_under_test()
{
    if (getenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static char *mock_error_response(char *error_env_var)
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

int partial_success()
{
    char *err_val = NULL;

    err_val = getenv("PARTIAL_SUCCESS_CASE");
    if (err_val != NULL && strlen(err_val) > 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static struct flb_http_client *mock_http_call(char *error_env_var)
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
        if (partial_success() == FLB_TRUE) {
            /* mocked partial failure response */
            c->resp.payload = "{\"Encrypted\": false,\"FailedPutCount\": 1,\"RequestResponses\":[{\"RecordId\": \"Me0CqhxK3BK3MiBWgy/AydQrVUg7vbc40Z4zNds3jiiJDscqGtWFz9bJugbrAoN70YCaxpXgmyR9R+LFxS2rleDepqFljYArBtXnRmVzSMOAzTJZlwsO84+757kBvA5RUycF3wC3XZjFtUFP0Q4QTdhuD8HMJBvKGiBY9Yy5jBUmZuKhXxCLQ/YTwKQaQKn4fnc5iISxaErPXsWMI7OApHZ1eFGvcHVZ\"},{\"RecordId\": \"NRAZVkblYgWWDSvTAF/9jBR4MlciEUFV+QIjb1D8uar7YbC3wqeLQuSZ0GEopGlE/8JAK9h9aAyTub5lH5V+bZuR3SeKKABWoJ788/tI455Kup9oRzmXTKWiXeklxmAe9MtsSz0y4t3oIrSLq8e3QVH9DJKWdhDkIXd8lXK1wuJi8tKmnNgxFob/Cz398kQFXPc4JwKj3Dv3Ou0qibZiusko6f7yBUve\",\"ErrorCode\":\"ServiceUnavailableException\",\"ErrorMessage\": \"Catsssss\"},{\"RecordId\": \"InFGTFvML/MGCLtnC3moI/zCISrKSScu/D8oCGmeIIeVaYUfywHpr2NmsQiZsxUL9+4ThOm2ypxqFGudZvgXQ45gUWMG+R4Y5xzS03N+vQ71+UaL392jY6HUs2SxYkZQe6vpdK+xHaJJ1b8uE++Laxg9rmsXtNt193WjmH3FhU1veu9pnSiGZgqC7czpyVgvZBNeWc+hTjEVicj3VAHBg/9yRN0sC30C\",\"ErrorCode\":\"ServiceUnavailableException\",\"ErrorMessage\": \"Catsssss 2\"},{\"RecordId\":\"KufmrRJ2z8zAgYAYGz6rm4BQC8SA7g87lQJQl2DQ+Be5EiEpr5bG33ilnQVvo1Q05BJuQBnjbw2cm919Ya72awapxfOBdZcPPKJN7KDZV/n1DFCDDrJ2vgyNK4qhKdo3Mr7nyrBpkLIs93PdxOdrTh11Y9HHEaFtim0cHJYpKCSZBjNObfWjfjHx5TuB7L3PHQqMKMu0MT5L9gPgVXHElGalqKZGTcfB\"}]}";
            c->resp.payload_size = strlen(c->resp.payload);
        }
        else {
            /* mocked success response */
            c->resp.payload = "{\"Encrypted\": false,\"FailedPutCount\": 0,\"RequestResponses\":[{\"RecordId\": \"Me0CqhxK3BK3MiBWgy/AydQrVUg7vbc40Z4zNds3jiiJDscqGtWFz9bJugbrAoN70YCaxpXgmyR9R+LFxS2rleDepqFljYArBtXnRmVzSMOAzTJZlwsO84+757kBvA5RUycF3wC3XZjFtUFP0Q4QTdhuD8HMJBvKGiBY9Yy5jBUmZuKhXxCLQ/YTwKQaQKn4fnc5iISxaErPXsWMI7OApHZ1eFGvcHVZ\"},{\"RecordId\": \"NRAZVkblYgWWDSvTAF/9jBR4MlciEUFV+QIjb1D8uar7YbC3wqeLQuSZ0GEopGlE/8JAK9h9aAyTub5lH5V+bZuR3SeKKABWoJ788/tI455Kup9oRzmXTKWiXeklxmAe9MtsSz0y4t3oIrSLq8e3QVH9DJKWdhDkIXd8lXK1wuJi8tKmnNgxFob/Cz398kQFXPc4JwKj3Dv3Ou0qibZiusko6f7yBUve\"},{\"RecordId\": \"InFGTFvML/MGCLtnC3moI/zCISrKSScu/D8oCGmeIIeVaYUfywHpr2NmsQiZsxUL9+4ThOm2ypxqFGudZvgXQ45gUWMG+R4Y5xzS03N+vQ71+UaL392jY6HUs2SxYkZQe6vpdK+xHaJJ1b8uE++Laxg9rmsXtNt193WjmH3FhU1veu9pnSiGZgqC7czpyVgvZBNeWc+hTjEVicj3VAHBg/9yRN0sC30C\"},{\"RecordId\": \"KufmrRJ2z8zAgYAYGz6rm4BQC8SA7g87lQJQl2DQ+Be5EiEpr5bG33ilnQVvo1Q05BJuQBnjbw2cm919Ya72awapxfOBdZcPPKJN7KDZV/n1DFCDDrJ2vgyNK4qhKdo3Mr7nyrBpkLIs93PdxOdrTh11Y9HHEaFtim0cHJYpKCSZBjNObfWjfjHx5TuB7L3PHQqMKMu0MT5L9gPgVXHElGalqKZGTcfB\"}]}";
            c->resp.payload_size = strlen(c->resp.payload);
        }
    }

    return c;
}


/*
 * Returns -1 on failure, 0 on success
 */
int put_record_batch(struct flb_firehose *ctx, struct flush *buf,
                     size_t payload_size, int num_records)
{

    struct flb_http_client *c = NULL;
    struct flb_aws_client *firehose_client;
    flb_sds_t error;
    int failed_records = 0;

    flb_plg_debug(ctx->ins, "Sending log records to delivery stream %s",
                  ctx->delivery_stream);

    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_PUT_RECORD_BATCH_ERROR");
    }
    else {
        firehose_client = ctx->firehose_client;
        c = firehose_client->client_vtable->request(firehose_client, FLB_HTTP_POST,
                                                    "/", buf->out_buf, payload_size,
                                                    &put_record_batch_header, 1);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "PutRecordBatch http status=%d", c->resp.status);

        if (c->resp.status == 200) {
            /* Firehose API can return partial success- check response */
            if (c->resp.payload_size > 0) {
                failed_records = process_api_response(ctx, c);
                if (failed_records < 0) {
                    flb_plg_error(ctx->ins, "PutRecordBatch response "
                                  "could not be parsed, %s",
                                  c->resp.payload);
                    flb_http_client_destroy(c);
                    return -1;
                }
                if (failed_records == num_records) {
                    flb_plg_error(ctx->ins, "PutRecordBatch request returned "
                                  "with no records successfully recieved, %s",
                                  ctx->delivery_stream);
                    flb_http_client_destroy(c);
                    return -1;
                }
                if (failed_records > 0) {
                    flb_plg_error(ctx->ins, "%d out of %d records failed to be "
                                  "delivered, will retry this batch, %s",
                                  failed_records, num_records,
                                  ctx->delivery_stream);
                    flb_http_client_destroy(c);
                    return -1;
                }
            }
            flb_plg_debug(ctx->ins, "Sent events to %s", ctx->delivery_stream);
            flb_http_client_destroy(c);
            return 0;
        }

        /* Check error */
        if (c->resp.payload_size > 0) {
            error = flb_aws_error(c->resp.payload, c->resp.payload_size);
            if (error != NULL) {
                if (strcmp(error, ERR_CODE_SERVICE_UNAVAILABLE) == 0) {
                    flb_plg_error(ctx->ins, "Throughput limits for %s "
                                  "may have been exceeded.",
                                  ctx->delivery_stream);
                }
                if (strncmp(error, "SerializationException", 22) == 0) {
                    /*
                     * If this happens, we habe a bug in the code
                     * User should send us the output to debug
                     */
                    flb_plg_error(ctx->ins, "<<------Bug in Code------>>");
                    printf("Malformed request: %s", buf->out_buf);
                }
                flb_aws_print_error(c->resp.payload, c->resp.payload_size,
                                    "PutRecordBatch", ctx->ins);
                flb_sds_destroy(error);
            }
            else {
                /* error could not be parsed, print raw response to debug */
                flb_plg_debug(ctx->ins, "Raw response: %s", c->resp.payload);
            }
        }
    }

    flb_plg_error(ctx->ins, "Failed to send log records to %s", ctx->delivery_stream);
    if (c) {
        flb_http_client_destroy(c);
    }
    return -1;
}


void flush_destroy(struct flush *buf)
{
    if (buf) {
        flb_free(buf->tmp_buf);
        flb_free(buf->out_buf);
        flb_free(buf->events);
        flb_free(buf->event_buf);
        flb_free(buf);
    }
}
