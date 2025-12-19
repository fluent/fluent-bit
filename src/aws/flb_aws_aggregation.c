/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/aws/flb_aws_aggregation.h>

#include <string.h>
#include <time.h>

int flb_aws_aggregation_init(struct flb_aws_agg_buffer *buf, size_t max_record_size)
{
    if (!buf) {
        return -1;
    }

    buf->agg_buf = flb_malloc(max_record_size);
    if (!buf->agg_buf) {
        flb_errno();
        return -1;
    }

    buf->agg_buf_size = max_record_size;
    buf->agg_buf_offset = 0;

    return 0;
}

void flb_aws_aggregation_destroy(struct flb_aws_agg_buffer *buf)
{
    if (buf && buf->agg_buf) {
        flb_free(buf->agg_buf);
        buf->agg_buf = NULL;
        buf->agg_buf_size = 0;
        buf->agg_buf_offset = 0;
    }
}

int flb_aws_aggregation_add(struct flb_aws_agg_buffer *buf,
                            const char *data, size_t data_len,
                            size_t max_record_size)
{
    if (!buf || !data || data_len == 0) {
        return -1;
    }

    /* Check if adding this data would exceed the max record size */
    if (buf->agg_buf_offset + data_len > max_record_size) {
        /* Buffer full, caller should finalize and retry */
        return 1;
    }

    /* Add data to aggregation buffer */
    memcpy(buf->agg_buf + buf->agg_buf_offset, data, data_len);
    buf->agg_buf_offset += data_len;

    return 0;
}

int flb_aws_aggregation_finalize(struct flb_aws_agg_buffer *buf,
                                 int add_final_newline,
                                 size_t *out_size)
{
    if (!buf || !out_size) {
        return -1;
    }

    /* Check if there's any data to finalize */
    if (buf->agg_buf_offset == 0) {
        return -1;
    }

    /* Add final newline if requested (for Firehose) */
    if (add_final_newline && buf->agg_buf_offset < buf->agg_buf_size) {
        buf->agg_buf[buf->agg_buf_offset] = '\n';
        buf->agg_buf_offset++;
    }

    *out_size = buf->agg_buf_offset;
    return 0;
}

void flb_aws_aggregation_reset(struct flb_aws_agg_buffer *buf)
{
    if (buf) {
        buf->agg_buf_offset = 0;
    }
}

/*
 * Process event with simple aggregation
 * Shared implementation for Kinesis Streams and Firehose
 */
int flb_aws_aggregation_process_event(struct flb_aws_agg_buffer *agg_buf,
                                      char *tmp_buf,
                                      size_t tmp_buf_size,
                                      size_t *tmp_buf_offset,
                                      const msgpack_object *obj,
                                      struct flb_time *tms,
                                      struct flb_config *config,
                                      struct flb_output_instance *ins,
                                      const char *stream_name,
                                      const char *log_key,
                                      const char *time_key,
                                      const char *time_key_format,
                                      size_t max_event_size)
{
    size_t written = 0;
    int ret;
    char *tmp_buf_ptr;
    char *time_key_ptr;
    struct tm time_stamp;
    struct tm *tmp;
    size_t len;
    size_t tmp_size;
    char *out_buf;

    tmp_buf_ptr = tmp_buf + *tmp_buf_offset;
    ret = flb_msgpack_to_json(tmp_buf_ptr,
                              tmp_buf_size - *tmp_buf_offset,
                              obj, config->json_escape_unicode);
    if (ret <= 0) {
        return 1;
    }
    written = (size_t) ret;

    /* Discard empty messages */
    if (written <= 2) {
        flb_plg_debug(ins, "Found empty log message, %s", stream_name);
        return 2;
    }

    if (log_key) {
        written -= 2;
        tmp_buf_ptr++;
        (*tmp_buf_offset)++;
    }

    if ((written + 1) >= max_event_size) {
        flb_plg_warn(ins, "[size=%zu] Discarding record which is larger than "
                     "max size allowed, %s", written + 1, stream_name);
        return 2;
    }

    if (time_key) {
        tmp = gmtime_r(&tms->tm.tv_sec, &time_stamp);
        if (!tmp) {
            flb_plg_error(ins, "Could not create time stamp for %lu unix "
                         "seconds, discarding record, %s", tms->tm.tv_sec, stream_name);
            return 2;
        }

        len = flb_aws_strftime_precision(&out_buf, time_key_format, tms);
        tmp_size = (tmp_buf_size - *tmp_buf_offset) - written;
        if (len > tmp_size) {
            flb_free(out_buf);
            return 1;
        }

        if (len == 0) {
            flb_plg_error(ins, "Failed to add time_key %s to record, %s",
                          time_key, stream_name);
            flb_free(out_buf);
            return 2;
        }
        else {
            time_key_ptr = tmp_buf_ptr + written - 1;
            memcpy(time_key_ptr, ",", 1);
            time_key_ptr++;
            memcpy(time_key_ptr, "\"", 1);
            time_key_ptr++;
            memcpy(time_key_ptr, time_key, strlen(time_key));
            time_key_ptr += strlen(time_key);
            memcpy(time_key_ptr, "\":\"", 3);
            time_key_ptr += 3;

            memcpy(time_key_ptr, out_buf, len);
            flb_free(out_buf);
            time_key_ptr += len;
            memcpy(time_key_ptr, "\"}", 2);
            time_key_ptr += 2;
            written = (time_key_ptr - tmp_buf_ptr);
        }
    }

    if ((written + 1) >= max_event_size) {
        flb_plg_warn(ins, "[size=%zu] Discarding record which is larger than "
                     "max size allowed, %s", written + 1, stream_name);
        return 2;
    }

    /* Append newline */
    tmp_size = (tmp_buf_size - *tmp_buf_offset) - written;
    if (tmp_size <= 1) {
        return 1;
    }

    memcpy(tmp_buf_ptr + written, "\n", 1);
    written++;

    /* Try to add to aggregation buffer */
    tmp_buf_ptr = tmp_buf + *tmp_buf_offset;
    ret = flb_aws_aggregation_add(agg_buf, tmp_buf_ptr, written, max_event_size);

    if (ret == 1) {
        return 1;
    }
    else if (ret < 0) {
        flb_plg_error(ins, "Failed to add record to aggregation buffer");
        return -1;
    }

    *tmp_buf_offset += written;
    return 0;
}
