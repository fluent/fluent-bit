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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#ifdef FLB_SYSTEM_FREEBSD
#include <sys/user.h>
#include <libutil.h>
#endif

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_parser.h>
#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash_table.h>
#endif
#include <fluent-bit/flb_simd.h>

#include "tail.h"
#include "tail_file.h"
#include "tail_config.h"
#include "tail_db.h"
#include "tail_signal.h"
#include "tail_dockermode.h"
#include "tail_multiline.h"
#include "tail_scan.h"

#ifdef FLB_SYSTEM_WINDOWS
#include "win32.h"
#endif

#include <fluent-bit/flb_unicode.h>

#include <cfl/cfl.h>

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static uint64_t stat_get_st_dev(struct stat *st)
{
#ifdef FLB_SYSTEM_WINDOWS
    /* do you want to contribute with a way to extract volume serial number ? */
    return 0;
#else
    return st->st_dev;
#endif
}

static int stat_to_hash_bits(struct flb_tail_config *ctx, struct stat *st,
                             uint64_t *out_hash)
{
    int len;
    uint64_t st_dev;
    char tmp[64];

    st_dev = stat_get_st_dev(st);

    len = snprintf(tmp, sizeof(tmp) - 1, "%" PRIu64 ":%" PRIu64,
                   st_dev, (uint64_t)st->st_ino);

    *out_hash = cfl_hash_64bits(tmp, len);
    return 0;
}

static int stat_to_hash_key(struct flb_tail_config *ctx, struct stat *st,
                            flb_sds_t *key)
{
    uint64_t st_dev;
    flb_sds_t tmp;
    flb_sds_t buf;

    buf = flb_sds_create_size(64);
    if (!buf) {
        return -1;
    }

    st_dev = stat_get_st_dev(st);
    tmp = flb_sds_printf(&buf, "%" PRIu64 ":%" PRIu64,
                         st_dev, (uint64_t)st->st_ino);
    if (!tmp) {
        flb_sds_destroy(buf);
        return -1;
    }

    *key = buf;
    return 0;
}

/* Append custom keys and report the number of records processed */
static int record_append_custom_keys(struct flb_tail_file *file,
                                     char *in_data, size_t in_size,
                                     char **out_data, size_t *out_size)
{
    int i;
    int ret;
    int records = 0;
    msgpack_object k;
    msgpack_object v;
    struct flb_log_event event;
    struct flb_tail_config *ctx;
    struct flb_log_event_encoder encoder;
    struct flb_log_event_decoder decoder;

    ctx = (struct flb_tail_config *) file->config;

    ret = flb_log_event_decoder_init(&decoder, in_data, in_size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_decoder_destroy(&decoder);

        return -2;
    }

    while (flb_log_event_decoder_next(&decoder, &event) ==
            FLB_EVENT_DECODER_SUCCESS) {

        ret = flb_log_event_encoder_begin_record(&encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(&encoder, &event.timestamp);
        }

        /* append previous map keys */
        for (i = 0; i < event.body->via.map.size; i++) {
            k = event.body->via.map.ptr[i].key;
            v = event.body->via.map.ptr[i].val;

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_msgpack_object(
                        &encoder,
                        &k);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_msgpack_object(
                        &encoder,
                        &v);
            }
        }

        /* path_key */
        if (ctx->path_key != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_cstring(
                        &encoder,
                        file->config->path_key);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_cstring(
                        &encoder,
                        file->orig_name);
            }
        }

        /* offset_key */
        if (ctx->offset_key != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_cstring(
                        &encoder,
                        file->config->offset_key);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_uint64(
                        &encoder,
                        file->stream_offset +
                        file->last_processed_bytes);
            }
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(&encoder);
        }
        else {
            flb_plg_error(file->config->ins, "error packing event : %d", ret);

            flb_log_event_encoder_rollback_record(&encoder);
        }

        /* counter */
        records++;
    }

    *out_data = encoder.output_buffer;
    *out_size = encoder.output_length;

    /* This function transfers ownership of the internal memory allocated by
     * sbuffer using msgpack_sbuffer_release which means the caller is
     * responsible for releasing the memory.
     */
    flb_log_event_encoder_claim_internal_buffer_ownership(&encoder);

    flb_log_event_decoder_destroy(&decoder);
    flb_log_event_encoder_destroy(&encoder);

    return records;
}

static int flb_tail_repack_map(struct flb_log_event_encoder *encoder,
                               char *data,
                               size_t data_size)
{
    msgpack_unpacked source_map;
    size_t           offset;
    int              result;
    size_t           index;
    msgpack_object   value;
    msgpack_object   key;

    result = FLB_EVENT_ENCODER_SUCCESS;

    if (data_size > 0) {
        msgpack_unpacked_init(&source_map);

        offset = 0;
        result = msgpack_unpack_next(&source_map,
                                     data,
                                     data_size,
                                     &offset);

        if (result == MSGPACK_UNPACK_SUCCESS) {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
        else {
            result = FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE;
        }

        for (index = 0;
             index < source_map.data.via.map.size &&
             result == FLB_EVENT_ENCODER_SUCCESS;
             index++) {
            key   = source_map.data.via.map.ptr[index].key;
            value = source_map.data.via.map.ptr[index].val;

            result = flb_log_event_encoder_append_body_msgpack_object(
                        encoder,
                        &key);

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_append_body_msgpack_object(
                            encoder,
                            &value);
            }
        }

        msgpack_unpacked_destroy(&source_map);
    }

    return result;
}

int flb_tail_pack_line_map(struct flb_time *time, char **data,
                           size_t *data_size, struct flb_tail_file *file,
                           size_t processed_bytes)
{
    int result;

    result = flb_log_event_encoder_begin_record(file->sl_log_event_encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(
                    file->sl_log_event_encoder, time);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_tail_repack_map(file->sl_log_event_encoder,
                                     *data,
                                     *data_size);
    }

    /* path_key */
    if (file->config->path_key != NULL) {
        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_append_body_values(
                        file->sl_log_event_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE(file->config->path_key),
                        FLB_LOG_EVENT_STRING_VALUE(file->orig_name,
                                                   file->orig_name_len));
        }
    }

    /* offset_key */
    if (file->config->offset_key != NULL) {
        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_append_body_values(
                        file->sl_log_event_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE(file->config->offset_key),
                        FLB_LOG_EVENT_UINT64_VALUE(file->stream_offset +
                                                   processed_bytes));
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(file->sl_log_event_encoder);
    }
    else {
        flb_log_event_encoder_rollback_record(file->sl_log_event_encoder);
    }

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(file->config->ins, "error packing event");

        return -1;
    }

    return 0;
}

int flb_tail_file_pack_line(struct flb_time *time, char *data, size_t data_size,
                            struct flb_tail_file *file, size_t processed_bytes)
{
    int result;

    result = flb_log_event_encoder_begin_record(file->sl_log_event_encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(
                    file->sl_log_event_encoder, time);
    }

    /* path_key */
    if (file->config->path_key != NULL) {
        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_append_body_values(
                        file->sl_log_event_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE(file->config->path_key),
                        FLB_LOG_EVENT_STRING_VALUE(file->orig_name,
                                                   file->orig_name_len));
        }
    }

    /* offset_key */
    if (file->config->offset_key != NULL) {
        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_append_body_values(
                        file->sl_log_event_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE(file->config->offset_key),
                        FLB_LOG_EVENT_UINT64_VALUE(file->stream_offset +
                                                   processed_bytes));
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_body_values(
                    file->sl_log_event_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(file->config->key),
                    FLB_LOG_EVENT_STRING_VALUE(data,
                                               data_size));
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(file->sl_log_event_encoder);
    }

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(file->config->ins, "error packing event : %d", result);

        return -1;
    }

    return 0;
}

static int ml_stream_buffer_append(struct flb_tail_file *file, char *buf_data, size_t buf_size)
{
    int result;

    result = flb_log_event_encoder_emit_raw_record(
                 file->ml_log_event_encoder,
                 buf_data, buf_size);

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(file->config->ins,
                      "log event raw append error : %d",
                      result);

        return -1;
    }

    return 0;
}

static int ml_stream_buffer_flush(struct flb_tail_config *ctx, struct flb_tail_file *file)
{
    if (file->ml_log_event_encoder->output_length > 0) {
        flb_input_log_append(ctx->ins,
                             file->tag_buf,
                             file->tag_len,
                             file->ml_log_event_encoder->output_buffer,
                             file->ml_log_event_encoder->output_length);

        flb_log_event_encoder_reset(file->ml_log_event_encoder);
    }

    return 0;
}

/* Skip leading '\0' quickly. Returns new data pointer and bumps processed_bytes. */
static FLB_INLINE const char *flb_skip_leading_zeros_simd(const char *data, const char *end, size_t *processed_bytes)
{
#ifdef FLB_HAVE_SIMD
    const size_t vlen = FLB_SIMD_VEC8_INST_LEN;

    while ((size_t)(end - data) >= vlen) {
        size_t i;
        flb_vector8 v;
        flb_vector8_load(&v, (const uint8_t *)data);

        if (!flb_vector8_has(v, (uint8_t)'\0')) {
            return data;
        }

        for (i = 0; i < vlen; i++) {
            if (data[i] != '\0') {
                *processed_bytes += i;
                return data + i;
            }
        }

        data += vlen;
        *processed_bytes += vlen;
    }
#endif
    while (data < end && *data == '\0') {
        data++;
        (*processed_bytes)++;
    }
    return data;
}

static int process_content(struct flb_tail_file *file, size_t *bytes)
{
    size_t len;
    int lines = 0;
    int ret;
    size_t processed_bytes = 0;
    char *data;
    char *end;
    char *p;
    void *out_buf;
    size_t out_size;
    int crlf;
    char *line;
    size_t line_len;
    char *repl_line;
    size_t repl_line_len;
    size_t original_len = 0;
    time_t now = time(NULL);
    struct flb_time out_time = {0};
    struct flb_tail_config *ctx;
    char *decoded = NULL;
#ifdef FLB_HAVE_UNICODE_ENCODER
    size_t decoded_len;
#endif
#ifdef FLB_HAVE_METRICS
    uint64_t ts;
    char *name;
#endif


    ctx = (struct flb_tail_config *) file->config;

    /* Parse the data content */
    data = file->buf_data;
    end = data + file->buf_len;

    /* reset last processed bytes */
    file->last_processed_bytes = 0;

#ifdef FLB_HAVE_UNICODE_ENCODER
    if (ctx->preferred_input_encoding != FLB_UNICODE_ENCODING_UNSPECIFIED) {
        original_len = end - data;
        decoded = NULL;
        ret = flb_unicode_convert(ctx->preferred_input_encoding,
                                  data, end - data, &decoded, &decoded_len);
        if (ret == FLB_SIMDUTF_CONNECTOR_CONVERT_OK) {
            data = decoded;
            end  = data + decoded_len;
        }
        else if (ret == FLB_UNICODE_CONVERT_NOP) {
            flb_plg_debug(ctx->ins, "nothing to convert encoding '%.*s'", end - data, data);
            /* Skip the UTF-8 BOM */
            if (file->buf_len >= 3 &&
                data[0] == '\xEF' &&
                data[1] == '\xBB' &&
                data[2] == '\xBF') {
                data += 3;
                processed_bytes += 3;
            }
        }
        else {
            flb_plg_error(ctx->ins, "encoding failed '%.*s'", end - data, data);
        }
    }
#endif
    if (ctx->generic_input_encoding_type != FLB_GENERIC_UNSPECIFIED) {
        original_len = end - data;
        decoded = NULL;
        ret = flb_unicode_generic_convert_to_utf8(ctx->generic_input_encoding_name,
                                                  (unsigned char*)data, (unsigned char**)&decoded,
                                                  end - data);
        if (ret > 0) {
            data = decoded;
            end  = data + strlen(decoded);
        }
        else {
            flb_plg_error(ctx->ins, "encoding failed '%.*s' with status %d", end - data, data, ret);
        }
    }

    /* Skip null characters from the head (sometimes introduced by copy-truncate log rotation) */
    if (data < end) {
        data = (char *)flb_skip_leading_zeros_simd(data, end, &processed_bytes);
    }

    while (data < end && (p = memchr(data, '\n', end - data))) {
        len = (p - data);
        crlf = 0;
        if (file->skip_next == FLB_TRUE) {
            data += len + 1;
            processed_bytes += len + 1;
            file->skip_next = FLB_FALSE;
            continue;
        }

        /*
         * Empty line (just breakline)
         * ---------------------------
         * [NOTE] with the new Multiline core feature and Multiline Filter on
         * Fluent Bit v1.8.2, there are a couple of cases where stack traces
         * or multi line patterns expects an empty line (meaning only the
         * breakline), skipping empty lines on this plugin will break that
         * functionality.
         *
         * We are introducing 'skip_empty_lines=off' configuration
         * property to revert this behavior if some user is affected by
         * this change.
         */
        if (ctx->skip_empty_lines) {
            if (len == 0) { /* LF */
                data++;
                processed_bytes++;
                continue;
            }
            else if (len == 1 && data[0] == '\r')  { /* CR LF */
                data += 2;
                processed_bytes += 2;
                continue;
            }
        }

        /* Process '\r\n' */
        if (len >= 2) {
            crlf = (data[len-1] == '\r');
            if (len == 1 && crlf) {
                data += 2;
                processed_bytes += 2;
                continue;
            }
        }

        /* Reset time for each line */
        flb_time_zero(&out_time);

        line = data;
        line_len = len - crlf;
        repl_line = NULL;

        if (ctx->ml_ctx) {
            ret = flb_ml_append_text(ctx->ml_ctx,
                                     file->ml_stream_id,
                                     &out_time,
                                     line,
                                     line_len);
            if (ret == FLB_MULTILINE_TRUNCATED) {
                flb_plg_warn(ctx->ins, "multiline message truncated due to buffer limit");
#ifdef FLB_HAVE_METRICS
                name = (char *) flb_input_name(ctx->ins);
                ts = cfl_time_now();
                cmt_counter_inc(ctx->cmt_multiline_truncated, ts, 1, (char *[]) {name});

                /* Old api */
                flb_metrics_sum(FLB_TAIL_METRIC_M_TRUNCATED, 1, ctx->ins->metrics);
#endif
            }
            goto go_next;
        }
        else if (ctx->docker_mode) {
            ret = flb_tail_dmode_process_content(now, line, line_len,
                                                 &repl_line, &repl_line_len,
                                                 file, ctx);
            if (ret >= 0) {
                if (repl_line == line) {
                    repl_line = NULL;
                }
                else {
                    line = repl_line;
                    line_len = repl_line_len;
                }
                /* Skip normal parsers flow */
                goto go_next;
            }
            else {
                flb_tail_dmode_flush(file, ctx);
            }
        }

#ifdef FLB_HAVE_PARSER
        if (ctx->parser) {
            /* Common parser (non-multiline) */
            ret = flb_parser_do(ctx->parser, line, line_len,
                                &out_buf, &out_size, &out_time);
            if (ret >= 0) {
                if (flb_time_to_nanosec(&out_time) == 0L) {
                    flb_time_get(&out_time);
                }

                /* If multiline is enabled, flush any buffered data */
                if (ctx->multiline == FLB_TRUE) {
                    flb_tail_mult_flush(file, ctx);
                }

                flb_tail_pack_line_map(&out_time,
                                       (char**) &out_buf, &out_size, file,
                                       processed_bytes);

                flb_free(out_buf);
            }
            else {
                /* Parser failed, pack raw text */
                flb_tail_file_pack_line(NULL, data, len, file, processed_bytes);
            }
        }
        else if (ctx->multiline == FLB_TRUE) {
            ret = flb_tail_mult_process_content(now,
                                                line, line_len,
                                                file, ctx, processed_bytes);

            /* No multiline */
            if (ret == FLB_TAIL_MULT_NA) {
                flb_tail_mult_flush(file, ctx);

                flb_tail_file_pack_line(NULL,
                                        line, line_len, file, processed_bytes);
            }
            else if (ret == FLB_TAIL_MULT_MORE) {
                /* we need more data, do nothing */
                goto go_next;
            }
            else if (ret == FLB_TAIL_MULT_DONE) {
                /* Finalized */
            }
        }
        else {
            flb_tail_file_pack_line(NULL,
                                    line, line_len, file, processed_bytes);
        }
#else
        flb_tail_file_pack_line(NULL,
                                line, line_len, file, processed_bytes);
#endif

    go_next:
        flb_free(repl_line);
        repl_line = NULL;
        /* Adjust counters */
        data += len + 1;
        processed_bytes += len + 1;
        lines++;
        file->parsed = 0;
        file->last_processed_bytes += processed_bytes;
    }

    if (decoded) {
        flb_free(decoded);
        decoded = NULL;
    }

    file->parsed = file->buf_len;

    if (lines > 0) {
        /* Append buffer content to a chunk */
        if (original_len > 0) {
            *bytes = original_len;
        } else {
            *bytes = processed_bytes;
        }

        if (file->sl_log_event_encoder->output_length > 0) {
            flb_input_log_append_records(ctx->ins,
                                         lines,
                                         file->tag_buf,
                                         file->tag_len,
                                         file->sl_log_event_encoder->output_buffer,
                                         file->sl_log_event_encoder->output_length);

            flb_log_event_encoder_reset(file->sl_log_event_encoder);
        }
    }
    else if (file->skip_next) {
        *bytes = file->buf_len;
    }
    else {
        if (original_len > 0) {
            *bytes = original_len;
        } else {
            *bytes = processed_bytes;
        }
    }

    if (ctx->ml_ctx) {
        ml_stream_buffer_flush(ctx, file);
    }

    return lines;
}

static inline void drop_bytes(char *buf, size_t len, int pos, int bytes)
{
    memmove(buf + pos,
            buf + pos + bytes,
            len - pos - bytes);
}

#ifdef FLB_HAVE_REGEX
static void cb_results(const char *name, const char *value,
                       size_t vlen, void *data)
{
    struct flb_hash_table *ht = data;

    if (vlen == 0) {
        return;
    }

    flb_hash_table_add(ht, name, strlen(name), (void *) value, vlen);
}
#endif

#ifdef FLB_HAVE_REGEX
static int tag_compose(char *tag, struct flb_regex *tag_regex, char *fname,
                       char *out_buf, size_t *out_size,
                       struct flb_tail_config *ctx)
#else
static int tag_compose(char *tag, char *fname, char *out_buf, size_t *out_size,
                       struct flb_tail_config *ctx)
#endif
{
    int i;
    size_t len;
    char *p;
    size_t buf_s = 0;
#ifdef FLB_HAVE_REGEX
    ssize_t n;
    struct flb_regex_search result;
    struct flb_hash_table *ht;
    char *beg;
    char *end;
    int ret;
    const char *tmp;
    size_t tmp_s;
#endif

#ifdef FLB_HAVE_REGEX
    if (tag_regex) {
        n = flb_regex_do(tag_regex, fname, strlen(fname), &result);
        if (n <= 0) {
            flb_plg_error(ctx->ins, "invalid tag_regex pattern for file %s",
                          fname);
            return -1;
        }
        else {
            ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                       FLB_HASH_TABLE_SIZE, FLB_HASH_TABLE_SIZE);
            flb_regex_parse(tag_regex, &result, cb_results, ht);

            for (p = tag, beg = p; (beg = strchr(p, '<')); p = end + 2) {
                if (beg != p) {
                    len = (beg - p);
                    memcpy(out_buf + buf_s, p, len);
                    buf_s += len;
                }

                beg++;

                end = strchr(beg, '>');
                if (end && !memchr(beg, '<', end - beg)) {
                    end--;

                    len = end - beg + 1;
                    ret = flb_hash_table_get(ht, beg, len, (void *) &tmp, &tmp_s);
                    if (ret != -1) {
                        memcpy(out_buf + buf_s, tmp, tmp_s);
                        buf_s += tmp_s;
                    }
                    else {
                        memcpy(out_buf + buf_s, "_", 1);
                        buf_s++;
                    }
                }
                else {
                    flb_plg_error(ctx->ins,
                                  "missing closing angle bracket in tag %s "
                                  "at position %lu", tag, beg - tag);
                    flb_hash_table_destroy(ht);
                    return -1;
                }
            }

            flb_hash_table_destroy(ht);
            if (*p) {
                len = strlen(p);
                memcpy(out_buf + buf_s, p, len);
                buf_s += len;
            }
        }
    }
    else {
#endif
        p = strchr(tag, '*');
        if (!p) {
            return -1;
        }

        /* Copy tag prefix if any */
        len = (p - tag);
        if (len > 0) {
            memcpy(out_buf, tag, len);
            buf_s += len;
        }

        /* Append file name */
        len = strlen(fname);
        memcpy(out_buf + buf_s, fname, len);
        buf_s += len;

        /* Tag suffix (if any) */
        p++;
        if (*p) {
            len = strlen(tag);
            memcpy(out_buf + buf_s, p, (len - (p - tag)));
            buf_s += (len - (p - tag));
        }

        /* Sanitize buffer */
        for (i = 0; i < buf_s; i++) {
            if (out_buf[i] == '/' || out_buf[i] == '\\' || out_buf[i] == ':') {
                if (i > 0) {
                    out_buf[i] = '.';
                }
                else {
                    drop_bytes(out_buf, buf_s, i, 1);
                    buf_s--;
                    i--;
                }
            }

            if (i > 0 && out_buf[i] == '.') {
                if (out_buf[i - 1] == '.') {
                    drop_bytes(out_buf, buf_s, i, 1);
                    buf_s--;
                    i--;
                }
            }
            else if (out_buf[i] == '*') {
                    drop_bytes(out_buf, buf_s, i, 1);
                    buf_s--;
                    i--;
            }
        }

        /* Check for an ending '.' */
        if (out_buf[buf_s - 1] == '.') {
            drop_bytes(out_buf, buf_s, buf_s - 1, 1);
            buf_s--;
        }
#ifdef FLB_HAVE_REGEX
    }
#endif

    out_buf[buf_s] = '\0';
    *out_size = buf_s;

    return 0;
}

static inline int flb_tail_file_exists(struct stat *st,
                                       struct flb_tail_config *ctx)
{
    int ret;
    uint64_t hash;

    ret = stat_to_hash_bits(ctx, st, &hash);
    if (ret != 0) {
        return -1;
    }

    /* static hash */
    if (flb_hash_table_exists(ctx->static_hash, hash)) {
        return FLB_TRUE;
    }

    /* event hash */
    if (flb_hash_table_exists(ctx->event_hash, hash)) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Based in the configuration or database offset, set the proper 'offset' for the
 * file in question.
 */
static int set_file_position(struct flb_tail_config *ctx,
                             struct flb_tail_file *file)
{
    int64_t ret;

#ifdef FLB_HAVE_SQLDB
    /*
     * If the database option is enabled, try to gather the file position. The
     * database function updates the file->offset entry.
     */
    if (ctx->db) {
        ret = flb_tail_db_file_set(file, ctx);
        if (ret == 0) {
            if (file->offset > 0) {
                ret = lseek(file->fd, file->offset, SEEK_SET);
                if (ret == -1) {
                    flb_errno();
                    return -1;
                }
            }
            else if (ctx->read_from_head == FLB_FALSE) {
                ret = lseek(file->fd, 0, SEEK_END);
                if (ret == -1) {
                    flb_errno();
                    return -1;
                }
                file->offset = ret;
                flb_tail_db_file_offset(file, ctx);
            }
            return 0;
        }
    }
#endif

    if (ctx->read_from_head == FLB_TRUE) {
        /* no need to seek, offset position is already zero */
        return 0;
    }

    if (file->offset > 0) {
        ret = lseek(file->fd, file->offset, SEEK_SET);

        if (ret == -1) {
            flb_errno();
            return -1;
        }
    }
    else {
        ret = lseek(file->fd, 0, SEEK_END);

        if (ret == -1) {
            flb_errno();
            return -1;
        }

        file->offset = ret;
    }

    if (file->decompression_context == NULL) {
        file->stream_offset = ret;
    }

    return 0;
}

/* Multiline flush callback: invoked every time some content is complete */
static int ml_flush_callback(struct flb_ml_parser *parser,
                             struct flb_ml_stream *mst,
                             void *data, char *buf_data, size_t buf_size)
{
    int result;
    size_t mult_size = 0;
    char *mult_buf = NULL;
    struct flb_tail_file *file = data;
    struct flb_tail_config *ctx = file->config;

    if (ctx->path_key == NULL && ctx->offset_key == NULL) {
        ml_stream_buffer_append(file, buf_data, buf_size);
    }
    else {
        /* adjust the records in a new buffer */
        result = record_append_custom_keys(file,
                                           buf_data,
                                           buf_size,
                                           &mult_buf,
                                           &mult_size);

        if (result < 0) {
            ml_stream_buffer_append(file, buf_data, buf_size);
        }
        else {
            ml_stream_buffer_append(file, mult_buf, mult_size);

            flb_free(mult_buf);
        }
    }

    if (mst->forced_flush) {
        ml_stream_buffer_flush(ctx, file);
    }

    return 0;
}

int flb_tail_file_append(char *path, struct stat *st, int mode,
                         ssize_t offset,
                         struct flb_tail_config *ctx)
{
    int fd;
    int ret;
    uint64_t stream_id;
    uint64_t ts;
    uint64_t hash_bits;
    flb_sds_t hash_key;
    size_t len;
    char *tag;
    char *name;
    size_t tag_len;
    struct flb_tail_file *file;
    struct stat lst;
    flb_sds_t inode_str;

    if (!S_ISREG(st->st_mode)) {
        return -1;
    }

    if (flb_tail_file_exists(st, ctx) == FLB_TRUE) {
        return -1;
    }

    #ifdef __linux__
    if (ctx->file_cache_advise) {
        flb_plg_debug(ctx->ins, "file will be read in POSIX_FADV_DONTNEED mode %s", path);
    }
    #endif

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open %s", path);
        return -1;
    }

    file = flb_calloc(1, sizeof(struct flb_tail_file));
    if (!file) {
        flb_errno();
        goto error;
    }

    /* Initialize */
    file->watch_fd  = -1;
    file->fd        = fd;

    /* On non-windows environments check if the original path is a link */
    ret = lstat(path, &lst);
    if (ret == 0) {
        if (S_ISLNK(lst.st_mode)) {
            file->is_link = FLB_TRUE;
            file->link_inode = lst.st_ino;
        }
    }

    /* get unique hash for this file */
    ret = stat_to_hash_bits(ctx, st, &hash_bits);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error procesisng hash bits for file %s", path);
        goto error;
    }
    file->hash_bits = hash_bits;

    /* store the hash key used for hash_bits */
    ret = stat_to_hash_key(ctx, st, &hash_key);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error procesisng hash key for file %s", path);
        goto error;
    }
    file->hash_key = hash_key;

    file->inode     = st->st_ino;
    file->offset    = 0;
    file->size      = st->st_size;
    file->buf_len   = 0;
    file->parsed    = 0;
    file->config    = ctx;
    file->tail_mode = mode;
    file->tag_len   = 0;
    file->tag_buf   = NULL;
    file->rotated   = 0;
    file->pending_bytes = 0;
    file->stream_offset = 0;
    file->mult_firstline = FLB_FALSE;
    file->mult_keys = 0;
    file->mult_flush_timeout = 0;
    file->mult_skipping = FLB_FALSE;

    if (offset != -1) {
        file->offset = offset;
    }

    if (strlen(path) >= 3 &&
        strcasecmp(&path[strlen(path) - 3], ".gz") == 0) {
        file->decompression_context =
            flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP,
                                             ctx->buf_max_size);

        if (file->decompression_context == NULL) {
            goto error;
        }
    }

    /*
     * Duplicate string into 'file' structure, the called function
     * take cares to resolve real-name of the file in case we are
     * running in a non-Linux system.
     *
     * Depending of the operating system, the way to obtain the file
     * name associated to it file descriptor can have different behaviors
     * specifically if it root path it's under a symbolic link. On Linux
     * we can trust the file name but in others it's better to solve it
     * with some extra calls.
     */
    ret = flb_tail_file_name_dup(path, file);
    if (!file->name) {
        flb_errno();
        goto error;
    }

    /* We keep a copy of the initial filename in orig_name. This is required
     * for path_key to continue working after rotation. */
    file->orig_name = flb_strdup(file->name);
    if (!file->orig_name) {
        flb_errno();
        flb_free(file->name);
        file->name = NULL;
        goto error;
    }
    file->orig_name_len = file->name_len;

    /* multiline msgpack buffers */
    file->mult_records = 0;
    msgpack_sbuffer_init(&file->mult_sbuf);
    msgpack_packer_init(&file->mult_pck, &file->mult_sbuf,
                        msgpack_sbuffer_write);

    /* docker mode */
    file->dmode_flush_timeout = 0;
    file->dmode_complete = true;
    file->dmode_buf = flb_sds_create_size(ctx->docker_mode == FLB_TRUE ? 65536 : 0);
    file->dmode_lastline = flb_sds_create_size(ctx->docker_mode == FLB_TRUE ? 20000 : 0);
    file->dmode_firstline = false;
#ifdef FLB_HAVE_SQLDB
    file->db_id     = 0;
#endif
    file->skip_next = FLB_FALSE;
    file->skip_warn = FLB_FALSE;

    /* Multiline core mode */
    if (ctx->ml_ctx) {
        /*
         * Create inode str to get stream_id.
         *
         * If stream_id is created by filename,
         * it will be same after file rotation and it causes invalid destruction:
         *
         *  - https://github.com/fluent/fluent-bit/issues/4190
         */
        inode_str = flb_sds_create_size(64);
        flb_sds_printf(&inode_str, "%"PRIu64, file->inode);

        /* Create a stream for this file */
        ret = flb_ml_stream_create(ctx->ml_ctx,
                                   inode_str, flb_sds_len(inode_str),
                                   ml_flush_callback, file,
                                   &stream_id);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not create multiline stream for file: %s",
                          inode_str);
            flb_sds_destroy(inode_str);
            goto error;
        }
        file->ml_stream_id = stream_id;
        flb_sds_destroy(inode_str);

        /*
         * Multiline core file buffer: the multiline core functionality invokes a callback everytime a message is ready
         * to be processed by the caller, this can be a multiline message or a message that is considered 'complete'. In
         * the previous version of Tail, when it received a message this message was automatically ingested into the pipeline
         * without any previous buffering which leads to performance degradation.
         *
         * The msgpack buffer 'ml_sbuf' keeps all ML provided records and it's flushed just when the file processor finish
         * processing the "read() bytes".
         */
    }

    /* Local buffer */
    file->buf_size = ctx->buf_chunk_size;
    file->buf_data = flb_malloc(file->buf_size);
    if (!file->buf_data) {
        flb_errno();
        goto error;
    }

    /* Initialize (optional) dynamic tag */
    if (ctx->dynamic_tag == FLB_TRUE) {
        len = ctx->ins->tag_len + strlen(path) + 1;
        tag = flb_malloc(len);
        if (!tag) {
            flb_errno();
            flb_plg_error(ctx->ins, "failed to allocate tag buffer");
            goto error;
        }
#ifdef FLB_HAVE_REGEX
        ret = tag_compose(ctx->ins->tag, ctx->tag_regex, path, tag, &tag_len, ctx);
#else
        ret = tag_compose(ctx->ins->tag, path, tag, &tag_len, ctx);
#endif
        if (ret == 0) {
            file->tag_len = tag_len;
            file->tag_buf = flb_strdup(tag);
        }
        flb_free(tag);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to compose tag for file: %s", path);
            goto error;
        }
    }
    else {
        file->tag_len = strlen(ctx->ins->tag);
        file->tag_buf = flb_strdup(ctx->ins->tag);
    }
    if (!file->tag_buf) {
        flb_plg_error(ctx->ins, "failed to set tag for file: %s", path);
        flb_errno();
        goto error;
    }

    if (mode == FLB_TAIL_STATIC) {
        mk_list_add(&file->_head, &ctx->files_static);
        ctx->files_static_count++;
        flb_hash_table_add(ctx->static_hash, file->hash_key, flb_sds_len(file->hash_key),
                           file, sizeof(file));
        tail_signal_manager(file->config);
    }
    else if (mode == FLB_TAIL_EVENT) {
        mk_list_add(&file->_head, &ctx->files_event);
        flb_hash_table_add(ctx->event_hash, file->hash_key, flb_sds_len(file->hash_key),
                           file, sizeof(file));

        /* Register this file into the fs_event monitoring */
        ret = flb_tail_fs_add(ctx, file);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not register file into fs_events");
            goto error;
        }
    }

    /* Set the file position (database offset, head or tail) */
    ret = set_file_position(ctx, file);
    if (ret == -1) {
        flb_tail_file_remove(file);
        goto error;
    }

    /* Remaining bytes to read */
    file->pending_bytes = file->size - file->offset;

#ifdef FLB_HAVE_METRICS
    name = (char *) flb_input_name(ctx->ins);
    ts = cfl_time_now();
    cmt_counter_inc(ctx->cmt_files_opened, ts, 1, (char *[]) {name});

    /* Old api */
    flb_metrics_sum(FLB_TAIL_METRIC_F_OPENED, 1, ctx->ins->metrics);
#endif

    file->sl_log_event_encoder = flb_log_event_encoder_create(
                                    FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (file->sl_log_event_encoder == NULL) {
        flb_tail_file_remove(file);

        goto error;
    }

    file->ml_log_event_encoder = flb_log_event_encoder_create(
                                    FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (file->ml_log_event_encoder == NULL) {
        flb_tail_file_remove(file);

        goto error;
    }

    flb_plg_debug(ctx->ins,
                  "inode=%"PRIu64" with offset=%"PRId64" appended as %s",
                  file->inode, file->offset, path);
    return 0;

error:
    if (file) {
        if (file->buf_data) {
            flb_free(file->buf_data);
        }
        if (file->name) {
            flb_free(file->name);
        }
        flb_free(file);
    }
    close(fd);

    return -1;
}

void flb_tail_file_remove(struct flb_tail_file *file)
{
    uint64_t ts;
    char *name;
    struct flb_tail_config *ctx;

    ctx = file->config;

    flb_plg_debug(ctx->ins, "inode=%"PRIu64" removing file name %s",
                  file->inode, file->name);

    if (file->decompression_context != NULL) {
        flb_decompression_context_destroy(file->decompression_context);
    }

    if (file->sl_log_event_encoder != NULL) {
        flb_log_event_encoder_destroy(file->sl_log_event_encoder);
    }

    /* remove the multiline.core stream */
    if (ctx->ml_ctx && file->ml_stream_id > 0) {
        flb_ml_stream_id_destroy_all(ctx->ml_ctx, file->ml_stream_id);
    }

    if (file->ml_log_event_encoder != NULL) {
        flb_log_event_encoder_destroy(file->ml_log_event_encoder);
    }

    if (file->rotated > 0) {
#ifdef FLB_HAVE_SQLDB
        /*
         * Make sure to remove a the file entry from the database if the file
         * was rotated and it's not longer being monitored.
         */
        if (ctx->db) {
            flb_tail_db_file_delete(file, file->config);
        }
#endif
        mk_list_del(&file->_rotate_head);
    }

    msgpack_sbuffer_destroy(&file->mult_sbuf);

    flb_sds_destroy(file->dmode_buf);
    flb_sds_destroy(file->dmode_lastline);
    mk_list_del(&file->_head);
    flb_tail_fs_remove(ctx, file);

    /* avoid deleting file with -1 fd */
    if (file->fd != -1) {
        close(file->fd);
    }
    if (file->tag_buf) {
        flb_free(file->tag_buf);
    }

    /* remove any potential entry from the hash tables */
    flb_hash_table_del(ctx->static_hash, file->hash_key);
    flb_hash_table_del(ctx->event_hash, file->hash_key);

    flb_free(file->buf_data);
    flb_free(file->name);
    flb_free(file->orig_name);
    flb_free(file->real_name);
    flb_sds_destroy(file->hash_key);

#ifdef FLB_HAVE_METRICS
    name = (char *) flb_input_name(ctx->ins);
    ts = cfl_time_now();
    cmt_counter_inc(ctx->cmt_files_closed, ts, 1, (char *[]) {name});

    /* old api */
    flb_metrics_sum(FLB_TAIL_METRIC_F_CLOSED, 1, ctx->ins->metrics);
#endif

    flb_free(file);
}

int flb_tail_file_remove_all(struct flb_tail_config *ctx)
{
    int count = 0;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_file *file;

    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        flb_tail_file_remove(file);
        count++;
    }

    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        flb_tail_file_remove(file);
        count++;
    }

    return count;
}

static int adjust_counters(struct flb_tail_config *ctx, struct flb_tail_file *file)
{
    int ret;
    int64_t offset;
    struct stat st;

    ret = fstat(file->fd, &st);
    if (ret == -1) {
        flb_errno();
        return FLB_TAIL_ERROR;
    }

    int64_t size_delta = st.st_size - file->size;
    if (size_delta != 0) {
        file->size = st.st_size;
    }

    /* Check if the file was truncated by comparing current size with previous size */
    if (size_delta < 0) {
        offset = lseek(file->fd, 0, SEEK_SET);
        if (offset == -1) {
            flb_errno();
            return FLB_TAIL_ERROR;
        }

        flb_plg_debug(ctx->ins, "adjust_counters: inode=%"PRIu64" file truncated %s (diff: %"PRId64" bytes)",
                      file->inode, file->name, size_delta);
        file->offset = offset;
        file->buf_len = 0;

        /* Update offset in the database file */
#ifdef FLB_HAVE_SQLDB
        if (ctx->db) {
            flb_tail_db_file_offset(file, ctx);
        }
#endif
    }
    else {
        // Avoid negative pending_bytes when fstat() has stale data and size < offset
        file->pending_bytes = (st.st_size > file->offset) ? (st.st_size - file->offset) : 0;
    }

    return FLB_TAIL_OK;
}

int flb_tail_file_chunk(struct flb_tail_file *file)
{
    size_t                  decompression_buffer_capacity;
    size_t                  decompressed_data_length;
    size_t                  file_buffer_capacity;
    size_t                  stream_data_length;
    ssize_t                 raw_data_length;
    size_t                  processed_bytes;
    uint8_t                *read_buffer;
    size_t                  read_size;
    size_t                  size;
    char                   *tmp;
    int                     ret;
    struct flb_tail_config *ctx;

    /* Check if we the engine issued a pause */
    ctx = file->config;

    if (flb_input_buf_paused(ctx->ins) == FLB_TRUE) {
        return FLB_TAIL_BUSY;
    }

    file_buffer_capacity = (file->buf_size - file->buf_len) - 1;
    stream_data_length = 0;

    if (file_buffer_capacity < 1) {
        /*
         * If there is no more room for more data, try to increase the
         * buffer under the limit of buffer_max_size.
         */
        if (file->buf_size >= ctx->buf_max_size) {
            if (ctx->skip_long_lines == FLB_FALSE) {
                flb_plg_error(ctx->ins, "file=%s requires a larger buffer size, "
                          "lines are too long. Skipping file.", file->name);
                return FLB_TAIL_ERROR;
            }

            /* Warn the user */
            if (file->skip_warn == FLB_FALSE) {
                flb_plg_warn(ctx->ins, "file=%s have long lines. "
                             "Skipping long lines.", file->name);
                file->skip_warn = FLB_TRUE;
            }

            /* Do buffer adjustments */
            file->buf_len = 0;
            file->skip_next = FLB_TRUE;
        }
        else {
            size = file->buf_size + ctx->buf_chunk_size;
            if (size > ctx->buf_max_size) {
                size = ctx->buf_max_size;
            }

            /* Increase the buffer size */
            tmp = flb_realloc(file->buf_data, size);
            if (tmp) {
                flb_plg_trace(ctx->ins, "file=%s increase buffer size "
                              "%lu => %lu bytes",
                              file->name, file->buf_size, size);
                file->buf_data = tmp;
                file->buf_size = size;
            }
            else {
                flb_errno();
                flb_plg_error(ctx->ins, "cannot increase buffer size for %s, "
                          "skipping file.", file->name);
                return FLB_TAIL_ERROR;
            }
        }

        file_buffer_capacity = (file->buf_size - file->buf_len) - 1;
    }

    #ifdef __linux__
    if (ctx->file_cache_advise) {
        if (posix_fadvise(file->fd, 0, 0, POSIX_FADV_DONTNEED) == -1) {
            flb_errno();
            flb_plg_error(ctx->ins, "error during posix_fadvise");
        }
    }
    #endif

    read_size = file_buffer_capacity;

    if (file->decompression_context != NULL) {
        /* This call looks useless but is not, we
         * will remove this as soon as this fork
         * is updated with the latest code from master
         * which makes flb_decompression_context_get_available_space
         * perform the internal buffer rewind as needed.
         */
        flb_decompression_context_get_append_buffer(
            file->decompression_context);

        decompression_buffer_capacity =
            flb_decompression_context_get_available_space(
                file->decompression_context);

        if (decompression_buffer_capacity == 0) {
            if (file->decompression_context->input_buffer_size <
                ctx->buf_max_size) {
                decompression_buffer_capacity += ctx->buf_chunk_size;

                if (decompression_buffer_capacity > ctx->buf_max_size) {
                    decompression_buffer_capacity = ctx->buf_max_size;
                }

                ret = flb_decompression_context_resize_buffer(
                        file->decompression_context,
                        decompression_buffer_capacity);

                if (ret != FLB_DECOMPRESSOR_SUCCESS) {
                    flb_plg_error(ctx->ins,
                                  "decompression buffer resize failed for %s.",
                                  file->name);

                    return FLB_TAIL_ERROR;
                }

                decompression_buffer_capacity = \
                    flb_decompression_context_get_available_space(
                        file->decompression_context);
            }
        }

        if (decompression_buffer_capacity > 0) {
            if (read_size > decompression_buffer_capacity) {
                read_size = decompression_buffer_capacity;
            }

            read_buffer = flb_decompression_context_get_append_buffer(
                            file->decompression_context);

            raw_data_length = read(file->fd, read_buffer, read_size);
        }
        else {
            raw_data_length = 0;
        }

        if (raw_data_length >= 0) {
            file->decompression_context->input_buffer_length += \
                (size_t) raw_data_length;

            if (file->decompression_context->input_buffer_length > 0) {
                decompressed_data_length = file_buffer_capacity;

                ret = flb_decompress(file->decompression_context,
                                     &file->buf_data[file->buf_len],
                                     &decompressed_data_length);

                if (ret != 0) {
                    flb_plg_error(ctx->ins,
                                  "decompression failed for %s.",
                                  file->name);

                    return FLB_TAIL_ERROR;
                }

                stream_data_length = decompressed_data_length;
            }
        }
    }
    else {
        raw_data_length = read(file->fd,
                               &file->buf_data[file->buf_len],
                               read_size);

        stream_data_length = (size_t) raw_data_length;
    }

    if (stream_data_length > 0 || raw_data_length > 0) {
        /* we read some data, let the content processor take care of it */
        file->offset += raw_data_length;
        file->buf_len += stream_data_length;
        file->buf_data[file->buf_len] = '\0';

        /* Now that we have some data in the buffer, call the data processor
         * which aims to cut lines and register the entries into the engine.
         *
         * The returned value is the absolute offset the file must be seek
         * now. It may need to get back a few bytes at the beginning of a new
         * line.
         */
        ret = process_content(file, &processed_bytes);
        if (ret < 0) {
            flb_plg_debug(ctx->ins, "inode=%"PRIu64" file=%s process content ERROR",
                          file->inode, file->name);
            return FLB_TAIL_ERROR;
        }

        /* Adjust the file offset and buffer */
        file->stream_offset += processed_bytes;
        consume_bytes(file->buf_data, processed_bytes, file->buf_len);
        file->buf_len -= processed_bytes;
        file->buf_data[file->buf_len] = '\0';

#ifdef FLB_HAVE_SQLDB
        if (file->config->db) {
            flb_tail_db_file_offset(file, file->config);
        }
#endif

        /* adjust file counters, returns FLB_TAIL_OK or FLB_TAIL_ERROR */
        ret = adjust_counters(ctx, file);

        /* Data was consumed but likely some bytes still remain */
        return ret;
    }
    else if (raw_data_length == 0) {
        /* We reached the end of file, let's wait for some incoming data */
        ret = adjust_counters(ctx, file);
        if (ret == FLB_TAIL_OK) {
            return FLB_TAIL_WAIT;
        }
        else {
            return FLB_TAIL_ERROR;
        }
    }
    else {
        /* error */
        flb_errno();
        flb_plg_error(ctx->ins, "error reading %s", file->name);
        return FLB_TAIL_ERROR;
    }

    return FLB_TAIL_ERROR;
}

/* Returns FLB_TRUE if a file has been rotated, otherwise FLB_FALSE */
int flb_tail_file_is_rotated(struct flb_tail_config *ctx,
                             struct flb_tail_file *file)
{
    int ret;
    char *name;
    struct stat st;

    /*
     * Do not double-check already rotated files since the caller of this
     * function will trigger a rotation.
     */
    if (file->rotated != 0) {
        return FLB_FALSE;
    }

    /* Check if the 'original monitored file' is a link and rotated */
    if (file->is_link == FLB_TRUE) {
        ret = lstat(file->name, &st);
        if (ret == -1) {
            /* Broken link or missing file */
            if (errno == ENOENT) {
                flb_plg_info(ctx->ins, "inode=%"PRIu64" link_rotated: %s",
                             file->link_inode, file->name);
                return FLB_TRUE;
            }
            else {
                flb_errno();
                flb_plg_error(ctx->ins,
                              "link_inode=%"PRIu64" cannot detect if file: %s",
                              file->link_inode, file->name);
                return -1;
            }
        }
        else {
            /* The file name is there, check if the same that we have */
            if (st.st_ino != file->link_inode) {
                return FLB_TRUE;
            }
        }
    }

    /* Retrieve the real file name, operating system lookup */
    name = flb_tail_file_name(file);
    if (!name) {
        flb_plg_error(ctx->ins,
                      "inode=%"PRIu64" cannot detect if file was rotated: %s",
                      file->inode, file->name);
        return -1;
    }


    /* Get stats from the file name */
    ret = stat(name, &st);
    if (ret == -1) {
        flb_errno();
        flb_free(name);
        return -1;
    }

    /* Compare inodes and names */
    if (file->inode == st.st_ino &&
        flb_tail_target_file_name_cmp(name, file) == 0) {
        flb_free(name);
        return FLB_FALSE;
    }

    flb_plg_debug(ctx->ins, "inode=%"PRIu64" rotated: %s => %s",
                  file->inode, file->name, name);

    flb_free(name);
    return FLB_TRUE;
}

/* Promote a event in the static list to the dynamic 'events' interface */
int flb_tail_file_to_event(struct flb_tail_file *file)
{
    int ret;
    struct stat st;
    struct flb_tail_config *ctx = file->config;

    /* Check if the file promoted have pending bytes */
    ret = fstat(file->fd, &st);
    if (ret != 0) {
        flb_errno();
        return -1;
    }

    if (file->offset < st.st_size) {
        file->pending_bytes = (st.st_size - file->offset);
        tail_signal_pending(file->config);
    }
    else {
        file->pending_bytes = 0;
    }

    /* Check if the file has been rotated */
    ret = flb_tail_file_is_rotated(ctx, file);
    if (ret == FLB_TRUE) {
        flb_tail_file_rotated(file);
    }

    /* Notify the fs-event handler that we will start monitoring this 'file' */
    ret = flb_tail_fs_add(ctx, file);
    if (ret == -1) {
        return -1;
    }

    /* List swap: change from 'static' to 'event' list */
    mk_list_del(&file->_head);
    ctx->files_static_count--;
    flb_hash_table_del(ctx->static_hash, file->hash_key);

    mk_list_add(&file->_head, &file->config->files_event);
    flb_hash_table_add(ctx->event_hash, file->hash_key, flb_sds_len(file->hash_key),
                       file, sizeof(file));

    file->tail_mode = FLB_TAIL_EVENT;

    return 0;
}

/*
 * Given an open file descriptor, return the filename. This function is a
 * bit slow and it aims to be used only when a file is rotated.
 */
char *flb_tail_file_name(struct flb_tail_file *file)
{
    int ret;
    char *buf;
#ifdef __linux__
    ssize_t s;
    char tmp[128];
#elif defined(__APPLE__)
    char path[PATH_MAX];
#elif defined(FLB_SYSTEM_WINDOWS)
    HANDLE h;
#elif defined(FLB_SYSTEM_FREEBSD)
    struct kinfo_file *file_entries;
    int file_count;
    int file_index;
#endif

    buf = flb_malloc(PATH_MAX);
    if (!buf) {
        flb_errno();
        return NULL;
    }

#ifdef __linux__
    ret = snprintf(tmp, sizeof(tmp) - 1, "/proc/%i/fd/%i", getpid(), file->fd);
    if (ret == -1) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    s = readlink(tmp, buf, PATH_MAX);
    if (s == -1) {
        flb_free(buf);
        flb_errno();
        return NULL;
    }
    buf[s] = '\0';

#elif __APPLE__
    int len;

    ret = fcntl(file->fd, F_GETPATH, path);
    if (ret == -1) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    len = strlen(path);
    memcpy(buf, path, len);
    buf[len] = '\0';

#elif defined(FLB_SYSTEM_WINDOWS)
    int len;

    h = (HANDLE) _get_osfhandle(file->fd);
    if (h == INVALID_HANDLE_VALUE) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    /* This function returns the length of the string excluding "\0"
     * and the resulting path has a "\\?\" prefix.
     */
    len = GetFinalPathNameByHandleA(h, buf, PATH_MAX, FILE_NAME_NORMALIZED);
    if (len == 0 || len >= PATH_MAX) {
        flb_free(buf);
        return NULL;
    }

    if (strstr(buf, "\\\\?\\")) {
        memmove(buf, buf + 4, len + 1);
    }
#elif defined(FLB_SYSTEM_FREEBSD)
    if ((file_entries = kinfo_getfile(getpid(), &file_count)) == NULL) {
        flb_free(buf);
        return NULL;
    }

    for (file_index=0; file_index < file_count; file_index++) {
        if (file_entries[file_index].kf_fd == file->fd) {
            strncpy(buf, file_entries[file_index].kf_path, PATH_MAX - 1);
            buf[PATH_MAX - 1] = 0;
            break;
        }
    }
    free(file_entries);
#endif
    return buf;
}

int flb_tail_file_name_dup(char *path, struct flb_tail_file *file)
{
    file->name = flb_strdup(path);
    if (!file->name) {
        flb_errno();
        return -1;
    }
    file->name_len = strlen(file->name);

    if (file->real_name) {
        flb_free(file->real_name);
    }

    file->real_name = flb_tail_file_name(file);
    if (!file->real_name) {
        flb_errno();
        flb_free(file->name);
        file->name = NULL;
        return -1;
    }

    return 0;
}

/* Invoked every time a file was rotated */
int flb_tail_file_rotated(struct flb_tail_file *file)
{
    int ret;
    uint64_t ts;
    char *name;
    char *i_name;
    char *tmp;
    struct stat st;
    struct flb_tail_config *ctx = file->config;

    /* Get the new file name */
    name = flb_tail_file_name(file);
    if (!name) {
        return -1;
    }

    flb_plg_debug(ctx->ins, "inode=%"PRIu64" rotated %s -> %s",
                  file->inode, file->name, name);

    /* Update local file entry */
    tmp = file->name;
    flb_tail_file_name_dup(name, file);
    flb_plg_info(ctx->ins, "inode=%"PRIu64" handle rotation(): %s => %s",
                 file->inode, tmp, file->name);
    if (file->rotated == 0) {
        file->rotated = time(NULL);
        mk_list_add(&file->_rotate_head, &file->config->files_rotated);

    /* Rotate the file in the database */
#ifdef FLB_HAVE_SQLDB
        if (file->config->db) {
            ret = flb_tail_db_file_rotate(name, file, file->config);
            if (ret == -1) {
                flb_plg_error(ctx->ins, "could not rotate file %s->%s in database",
                              file->name, name);
            }
        }
#endif

#ifdef FLB_HAVE_METRICS
        i_name = (char *) flb_input_name(ctx->ins);
        ts = cfl_time_now();
        cmt_counter_inc(ctx->cmt_files_rotated, ts, 1, (char *[]) {i_name});

        /* OLD api */
        flb_metrics_sum(FLB_TAIL_METRIC_F_ROTATED,
                        1, file->config->ins->metrics);
#endif

        /* Check if a new file has been created */
        ret = stat(tmp, &st);
        if (ret == 0 && st.st_ino != file->inode) {
            if (flb_tail_file_exists(&st, ctx) == FLB_FALSE) {
                ret = flb_tail_file_append(tmp, &st, FLB_TAIL_STATIC, -1, ctx);
                if (ret == -1) {
                    flb_tail_scan(ctx->path_list, ctx);
                }
                else {
                    tail_signal_manager(file->config);
                }
            }
        }
    }
    flb_free(tmp);
    flb_free(name);

    return 0;
}

static int check_purge_deleted_file(struct flb_tail_config *ctx,
                                    struct flb_tail_file *file, time_t ts)
{
    int ret;
    int64_t mtime;
    struct stat st;

    ret = fstat(file->fd, &st);
    if (ret == -1) {
        flb_plg_debug(ctx->ins, "error stat(2) %s, removing", file->name);
        flb_tail_file_remove(file);
        return FLB_TRUE;
    }

    if (st.st_nlink == 0) {
        flb_plg_debug(ctx->ins, "purge: monitored file has been deleted: %s",
                      file->name);
#ifdef FLB_HAVE_SQLDB
        if (ctx->db) {
            /* Remove file entry from the database */
            flb_tail_db_file_delete(file, file->config);
        }
#endif
        /* Remove file from the monitored list */
        flb_tail_file_remove(file);
        return FLB_TRUE;
    }

    if (ctx->ignore_older > 0 && ctx->ignore_active_older_files) {
        mtime = flb_tail_stat_mtime(&st);
        if (mtime > 0) {
            if ((ts - ctx->ignore_older) > mtime) {
                flb_plg_debug(ctx->ins, "purge: monitored file (ignore older): %s",
                              file->name);
                flb_tail_file_remove(file);
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

/* Purge rotated and deleted files */
int flb_tail_file_purge(struct flb_input_instance *ins,
                        struct flb_config *config, void *context)
{
    int ret;
    int count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_file *file;
    struct flb_tail_config *ctx = context;
    time_t now;
    struct stat st;

    /* Rotated files */
    now = time(NULL);
    mk_list_foreach_safe(head, tmp, &ctx->files_rotated) {
        file = mk_list_entry(head, struct flb_tail_file, _rotate_head);
        if ((file->rotated + ctx->rotate_wait) <= now) {
            ret = fstat(file->fd, &st);
            if (ret == 0) {
                flb_plg_debug(ctx->ins,
                              "inode=%"PRIu64" purge rotated file %s " \
                              "(offset=%"PRId64" / size = %"PRIu64")",
                              file->inode, file->name, file->offset, (uint64_t)st.st_size);
                if (file->pending_bytes > 0 && flb_input_buf_paused(ins)) {
                    flb_plg_warn(ctx->ins, "purged rotated file while data "
                                 "ingestion is paused, consider increasing "
                                 "rotate_wait");
                }
            }
            else {
                flb_plg_debug(ctx->ins,
                              "inode=%"PRIu64" purge rotated file %s (offset=%"PRId64")",
                              file->inode, file->name, file->offset);
            }

            flb_tail_file_remove(file);
            count++;
        }
    }

    /*
     * Deleted files: under high load scenarios, exists the chances that in
     * our event loop we miss some notifications about a file. In order to
     * sanitize our list of monitored files we will iterate all of them and check
     * if they have been deleted or not.
     */
    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        check_purge_deleted_file(ctx, file, now);
    }
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        check_purge_deleted_file(ctx, file, now);
    }

    return count;
}
