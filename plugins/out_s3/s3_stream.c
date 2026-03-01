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

#include "s3.h"
#include "s3_store.h"
#include "s3_stream.h"
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <msgpack.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <process.h>
#define s3_fdopen(fd, mode) _fdopen(fd, mode)
#else
#include <unistd.h>
#include <fcntl.h>
#define s3_fdopen(fd, mode) fdopen(fd, mode)
#endif

#define S3_STREAM_COMPRESS_BUFFER_SIZE  (1024 * 1024)
#define S3_STREAM_READ_BUFFER_SIZE      (1024 * 1024)

/*
 * Compress file using streaming approach
 *
 * All compression formats now support streaming/concatenation:
 * - GZIP: native frame concatenation support
 * - ZSTD: native frame concatenation support
 * - Snappy: uses snappy framing format (Google Snappy framing_format.txt)
 *
 * This allows memory-efficient chunk-by-chunk compression for all formats.
 */
static int stream_compress_file_chunked(struct flb_s3 *ctx,
                                         FILE *in_fp,
                                         FILE *out_fp,
                                         off_t offset_start,
                                         off_t offset_end)
{
    char *read_buffer = NULL;
    void *compressed_chunk = NULL;
    size_t compressed_chunk_size;
    size_t bytes_to_read;
    size_t bytes_read;
    off_t current_offset;
    off_t remaining;
    int ret = -1;

    read_buffer = flb_malloc(S3_STREAM_COMPRESS_BUFFER_SIZE);
    if (!read_buffer) {
        flb_errno();
        return -1;
    }

    current_offset = offset_start;
    remaining = (offset_end > 0) ? (offset_end - offset_start) : -1;

    while (1) {
        if (remaining > 0) {
            bytes_to_read = (remaining < S3_STREAM_COMPRESS_BUFFER_SIZE) ?
                           (size_t)remaining : S3_STREAM_COMPRESS_BUFFER_SIZE;
        }
        else {
            bytes_to_read = S3_STREAM_COMPRESS_BUFFER_SIZE;
        }

        bytes_read = fread(read_buffer, 1, bytes_to_read, in_fp);
        if (bytes_read == 0) {
            break;
        }

        ret = flb_aws_compression_compress(ctx->compression, read_buffer, bytes_read,
                                          &compressed_chunk, &compressed_chunk_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to compress chunk");
            goto cleanup;
        }

        if (fwrite(compressed_chunk, 1, compressed_chunk_size, out_fp) != compressed_chunk_size) {
            flb_errno();
            flb_plg_error(ctx->ins, "Failed to write compressed data");
            flb_free(compressed_chunk);
            compressed_chunk = NULL;
            ret = -1;
            goto cleanup;
        }

        flb_free(compressed_chunk);
        compressed_chunk = NULL;

        if (remaining > 0) {
            remaining -= bytes_read;
            current_offset += bytes_read;
            if (remaining <= 0 || current_offset >= offset_end) {
                break;
            }
        }
    }

    if (ferror(in_fp)) {
        flb_errno();
        flb_plg_error(ctx->ins, "Error reading file during compression");
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (read_buffer) {
        flb_free(read_buffer);
    }
    if (compressed_chunk) {
        flb_free(compressed_chunk);
    }

    return ret;
}

int stream_compress_file(struct flb_s3 *ctx,
                         const char *input_path,
                         const char *output_path,
                         off_t offset_start,
                         off_t offset_end)
{
    FILE *in_fp = NULL;
    FILE *out_fp = NULL;
    int ret = -1;

    flb_plg_debug(ctx->ins, "Compressing file with %s: %s",
                 ctx->compression == FLB_AWS_COMPRESS_GZIP ? "gzip" :
                 ctx->compression == FLB_AWS_COMPRESS_ZSTD ? "zstd" :
                 ctx->compression == FLB_AWS_COMPRESS_SNAPPY ? "snappy" : "unknown",
                 input_path);

    in_fp = fopen(input_path, "rb");
    if (!in_fp) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to open file for compression: %s", input_path);
        goto cleanup;
    }

    /* Validate offset parameters */
    if (offset_start < 0) {
        flb_plg_error(ctx->ins, "Invalid offset_start: %lld", (long long)offset_start);
        goto cleanup;
    }

    if (offset_end > 0 && offset_end <= offset_start) {
        flb_plg_error(ctx->ins, "Invalid compression range: start=%lld, end=%lld",
                      (long long)offset_start, (long long)offset_end);
        goto cleanup;
    }

    if (offset_start > 0 && fseek(in_fp, offset_start, SEEK_SET) != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to seek in file");
        goto cleanup;
    }

    out_fp = fopen(output_path, "wb");
    if (!out_fp) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to create compressed file: %s", output_path);
        goto cleanup;
    }

    /*
     * All compression formats now support streaming/concatenation:
     * - GZIP: native frame concatenation support
     * - ZSTD: native frame concatenation support
     * - Snappy: Snappy framing format (Google Snappy framing_format.txt)
     *
     * This unified approach simplifies the code and ensures consistent behavior.
     */
    ret = stream_compress_file_chunked(ctx, in_fp, out_fp, offset_start, offset_end);

cleanup:
    if (out_fp) {
        fclose(out_fp);
    }
    if (in_fp) {
        fclose(in_fp);
    }

    if (ret == -1 && output_path) {
        flb_s3_unlink(output_path);
    }

    return ret;
}

struct stream_context {
    FILE *msgpack_fp;
    FILE *temp_fp;
    flb_sds_t temp_path;
    char *read_buffer;
    msgpack_unpacker unpacker;
    msgpack_unpacked result;
    int unpacker_initialized;
    int result_initialized;
};

static void stream_context_init(struct stream_context *ctx)
{
    memset(ctx, 0, sizeof(struct stream_context));
}

static void stream_context_destroy(struct stream_context *ctx, int keep_temp_file)
{
    if (!ctx) {
        return;
    }

    if (ctx->result_initialized) {
        msgpack_unpacked_destroy(&ctx->result);
    }
    if (ctx->unpacker_initialized) {
        msgpack_unpacker_destroy(&ctx->unpacker);
    }
    if (ctx->read_buffer) {
        flb_free(ctx->read_buffer);
    }
    if (ctx->msgpack_fp) {
        fclose(ctx->msgpack_fp);
    }
    if (ctx->temp_fp) {
        fclose(ctx->temp_fp);
    }
    if (ctx->temp_path) {
        if (!keep_temp_file) {
            flb_s3_unlink(ctx->temp_path);
        }
        flb_sds_destroy(ctx->temp_path);
    }
}

static int stream_context_setup(struct flb_s3 *s3_ctx,
                                 const char *input_path,
                                 const char *output_suffix,
                                 struct stream_context *ctx)
{
    char *temp_template = NULL;
    size_t template_len;
    int fd = -1;
    flb_sds_t final_path = NULL;

    stream_context_init(ctx);

    ctx->msgpack_fp = flb_chunk_file_open(input_path);
    if (!ctx->msgpack_fp) {
        flb_plg_error(s3_ctx->ins, "Failed to open msgpack file: %s", input_path);
        return -1;
    }

    /*
     * Use secure temporary file creation to avoid TOCTOU race conditions.
     *
     * Strategy:
     * 1. Create temp file atomically with unique name
     * 2. After successful creation, rename to final name with proper suffix
     *
     * Platform-specific implementations:
     * - POSIX: mkstemp() atomically creates and opens the file
     * - Windows: GetTempFileName() + _sopen_s() with _O_CREAT|_O_EXCL
     */
    template_len = strlen(s3_ctx->buffer_dir) + strlen("/stream_XXXXXX.tmp") + 1;
    temp_template = flb_malloc(template_len);
    if (!temp_template) {
        flb_errno();
        flb_plg_error(s3_ctx->ins, "Failed to allocate temp template buffer");
        return -1;
    }

#ifdef _WIN32
    {
        char temp_filename[MAX_PATH];
        UINT unique_result;
        errno_t err;

        /*
         * GetTempFileName generates a unique filename based on:
         * - Directory path
         * - Prefix (up to 3 chars used)
         * - Unique number (0 = system generates)
         *
         * It also creates the file, avoiding race conditions.
         */
        unique_result = GetTempFileName(s3_ctx->buffer_dir, "stm", 0, temp_filename);
        if (unique_result == 0) {
            flb_plg_error(s3_ctx->ins, "GetTempFileName failed in: %s (error: %lu)",
                          s3_ctx->buffer_dir, GetLastError());
            flb_free(temp_template);
            return -1;
        }

        /*
         * GetTempFileName already created the file, but we need to open it
         * with proper sharing/access modes. Delete and recreate with _sopen_s
         * using _O_CREAT | _O_EXCL for atomicity.
         *
         * Note: There's a small race window here, but GetTempFileName's
         * unique naming makes collision extremely unlikely.
         */
        DeleteFile(temp_filename);

        err = _sopen_s(&fd, temp_filename,
                       _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
                       _SH_DENYNO, _S_IREAD | _S_IWRITE);
        if (err != 0 || fd < 0) {
            flb_plg_error(s3_ctx->ins, "Failed to create temp file: %s (errno: %d)",
                          temp_filename, err);
            flb_free(temp_template);
            return -1;
        }

        /* Resize buffer to fit the actual path returned by GetTempFileName */
        flb_free(temp_template);
        template_len = strlen(temp_filename) + 1;
        temp_template = flb_malloc(template_len);
        if (!temp_template) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to allocate temp template buffer");
            flb_s3_close(fd);
            flb_s3_unlink(temp_filename);
            return -1;
        }
        memcpy(temp_template, temp_filename, template_len);

        /* Convert file descriptor to FILE* for streaming operations */
        ctx->temp_fp = s3_fdopen(fd, "wb");
        if (!ctx->temp_fp) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to fdopen temp file: %s", temp_template);
            flb_s3_close(fd);
            flb_s3_unlink(temp_template);
            flb_free(temp_template);
            return -1;
        }
    }
#else
    /* Create temp file without suffix - will rename later if needed */
    snprintf(temp_template, template_len, "%s/stream_XXXXXX", s3_ctx->buffer_dir);

    fd = mkstemp(temp_template);
    if (fd < 0) {
        flb_errno();
        flb_plg_error(s3_ctx->ins, "Failed to create temp file in: %s",
                      s3_ctx->buffer_dir);
        flb_free(temp_template);
        return -1;
    }

    /* Convert file descriptor to FILE* for streaming operations */
    ctx->temp_fp = s3_fdopen(fd, "wb");
    if (!ctx->temp_fp) {
        flb_errno();
        flb_plg_error(s3_ctx->ins, "Failed to fdopen temp file: %s", temp_template);
        flb_s3_close(fd);
        flb_s3_unlink(temp_template);
        flb_free(temp_template);
        return -1;
    }
#endif

    /*
     * If output_suffix differs from .tmp, rename the file.
     * Otherwise, keep the mkstemp-generated name.
     */
    if (output_suffix && strcmp(output_suffix, ".tmp") != 0) {
        /* Create final path by detecting and replacing actual suffix */
        size_t temp_len = strlen(temp_template);
        size_t base_len;
        const char *dot_pos;

        /* Check if temp_template ends with ".tmp" */
        dot_pos = strrchr(temp_template, '.');
        if (dot_pos && strcmp(dot_pos, ".tmp") == 0) {
            /* Has .tmp suffix - remove it */
            base_len = (size_t)(dot_pos - temp_template);
        }
        else {
            /* No .tmp suffix - use full path as base */
            base_len = temp_len;
        }

        final_path = flb_sds_create_size(base_len + strlen(output_suffix) + 1);
        if (!final_path) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to allocate final path buffer");
            fclose(ctx->temp_fp);
            ctx->temp_fp = NULL;
            flb_s3_unlink(temp_template);
            flb_free(temp_template);
            return -1;
        }

        /* Copy base path (without suffix if present) and append desired suffix */
        memcpy(final_path, temp_template, base_len);
        final_path[base_len] = '\0';
        flb_sds_len_set(final_path, base_len);
        final_path = flb_sds_cat(final_path, output_suffix, strlen(output_suffix));
        if (!final_path) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to create final path");
            fclose(ctx->temp_fp);
            ctx->temp_fp = NULL;
            flb_s3_unlink(temp_template);
            flb_free(temp_template);
            return -1;
        }

        /*
         * Close the file before rename() to support Windows.
         * On Windows, rename() fails if the file is still open.
         */
        fclose(ctx->temp_fp);
        ctx->temp_fp = NULL;

        /* Rename the file to have the correct suffix */
        if (rename(temp_template, final_path) != 0) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to rename temp file from %s to %s",
                          temp_template, final_path);
            flb_s3_unlink(temp_template);
            flb_free(temp_template);
            flb_sds_destroy(final_path);
            return -1;
        }

        /* Set temp_path after successful rename */
        ctx->temp_path = final_path;

        /* Reopen the renamed file for further writes */
        ctx->temp_fp = fopen(final_path, "ab");
        if (!ctx->temp_fp) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to reopen renamed file: %s", final_path);
            flb_s3_unlink(final_path);
            flb_free(temp_template);
            return -1;
        }
    }
    else {
        /* Keep the mkstemp-generated name */
        ctx->temp_path = flb_sds_create(temp_template);
        if (!ctx->temp_path) {
            flb_errno();
            flb_plg_error(s3_ctx->ins, "Failed to copy temp path");
            fclose(ctx->temp_fp);
            ctx->temp_fp = NULL;
            flb_s3_unlink(temp_template);
            flb_free(temp_template);
            return -1;
        }
    }

    flb_free(temp_template);

    ctx->read_buffer = flb_malloc(S3_STREAM_READ_BUFFER_SIZE);
    if (!ctx->read_buffer) {
        flb_errno();
        flb_plg_error(s3_ctx->ins, "Failed to allocate read buffer");
        stream_context_destroy(ctx, FLB_FALSE);
        return -1;
    }

    if (!msgpack_unpacker_init(&ctx->unpacker, S3_STREAM_READ_BUFFER_SIZE)) {
        flb_plg_error(s3_ctx->ins, "Failed to initialize msgpack unpacker");
        stream_context_destroy(ctx, FLB_FALSE);
        return -1;
    }
    ctx->unpacker_initialized = FLB_TRUE;

    msgpack_unpacked_init(&ctx->result);
    ctx->result_initialized = FLB_TRUE;

    return 0;
}

static int process_unpacked_records(struct flb_s3 *ctx,
                                     struct stream_context *stream_ctx,
                                     record_processor_fn processor,
                                     struct stream_processor_context *proc_ctx)
{
    msgpack_unpack_return ret;
    const msgpack_object *record;

    while ((ret = msgpack_unpacker_next(&stream_ctx->unpacker,
                                        &stream_ctx->result)) != MSGPACK_UNPACK_CONTINUE) {
        if (ret == MSGPACK_UNPACK_SUCCESS || ret == MSGPACK_UNPACK_EXTRA_BYTES) {
            /*
             * Both SUCCESS and EXTRA_BYTES indicate a complete message was unpacked.
             * EXTRA_BYTES additionally signals more bytes remain in the buffer,
             * which will be processed in subsequent loop iterations.
             */
            record = &stream_ctx->result.data;
            if (record->type == MSGPACK_OBJECT_ARRAY && record->via.array.size == 2) {
                if (processor(ctx, record, stream_ctx->temp_fp, proc_ctx) < 0) {
                    return -1;
                }
                proc_ctx->records_processed++;
            }
            
            /* Free the unpacked zone to prevent memory accumulation */
            msgpack_unpacked_destroy(&stream_ctx->result);
            msgpack_unpacked_init(&stream_ctx->result);
        }
        else if (ret == MSGPACK_UNPACK_NOMEM_ERROR) {
            flb_plg_error(ctx->ins, "Msgpack unpacker out of memory");
            return -1;
        }
        else if (ret == MSGPACK_UNPACK_PARSE_ERROR) {
            flb_plg_error(ctx->ins, "Msgpack parse error");
            return -1;
        }
    }

    return 0;
}

static int process_msgpack_stream(struct flb_s3 *ctx,
                                   struct stream_context *stream_ctx,
                                   record_processor_fn processor,
                                   struct stream_processor_context *proc_ctx)
{
    size_t bytes_read;

    while ((bytes_read = fread(stream_ctx->read_buffer, 1,
                               S3_STREAM_READ_BUFFER_SIZE,
                               stream_ctx->msgpack_fp)) > 0) {

        if (!msgpack_unpacker_reserve_buffer(&stream_ctx->unpacker, bytes_read)) {
            flb_plg_error(ctx->ins, "msgpack unpacker buffer reserve failed");
            return -1;
        }

        memcpy(msgpack_unpacker_buffer(&stream_ctx->unpacker),
               stream_ctx->read_buffer, bytes_read);
        msgpack_unpacker_buffer_consumed(&stream_ctx->unpacker, bytes_read);

        if (process_unpacked_records(ctx, stream_ctx, processor, proc_ctx) < 0) {
            return -1;
        }
    }

    if (ferror(stream_ctx->msgpack_fp)) {
        flb_errno();
        flb_plg_error(ctx->ins, "Error reading msgpack file");
        return -1;
    }

    return 0;
}

static int create_output_file_marker(struct flb_s3 *ctx,
                                      const char *temp_path,
                                      size_t file_size,
                                      flb_sds_t *out_buf,
                                      size_t *out_size)
{
    flb_sds_t marker;

    marker = flb_sds_create(temp_path);
    if (!marker) {
        flb_plg_error(ctx->ins, "Failed to create path marker");
        return -1;
    }

    *out_buf = marker;
    *out_size = file_size;

    return 0;
}

int stream_process_msgpack_file(struct flb_s3 *ctx,
                                 const char *input_path,
                                 size_t input_size,
                                 const char *output_suffix,
                                 record_processor_fn processor,
                                 void *processor_ctx,
                                 flb_sds_t *out_buf,
                                 size_t *out_size)
{
    struct stream_context stream_ctx;
    struct stream_processor_context proc_ctx = {
        .processor = processor,
        .user_data = processor_ctx,
        .records_processed = 0,
        .bytes_written = 0
    };
    struct stat temp_stat;
    int ret;

    if (input_size == 0) {
        flb_plg_debug(ctx->ins, "Empty input file, skipping: %s", input_path);
        *out_buf = NULL;
        *out_size = 0;
        return 0;
    }

    ret = stream_context_setup(ctx, input_path, output_suffix, &stream_ctx);
    if (ret < 0) {
        stream_context_destroy(&stream_ctx, FLB_FALSE);
        return -1;
    }

    ret = process_msgpack_stream(ctx, &stream_ctx, processor, &proc_ctx);
    if (ret < 0) {
        stream_context_destroy(&stream_ctx, FLB_FALSE);
        return -1;
    }

    fclose(stream_ctx.temp_fp);
    stream_ctx.temp_fp = NULL;

    if (stat(stream_ctx.temp_path, &temp_stat) != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to stat temp file: %s", stream_ctx.temp_path);
        stream_context_destroy(&stream_ctx, FLB_FALSE);
        return -1;
    }

    if (temp_stat.st_size == 0) {
        flb_plg_debug(ctx->ins, "No data generated by processor");
        stream_context_destroy(&stream_ctx, FLB_FALSE);
        *out_buf = NULL;
        *out_size = 0;
        return 0;
    }

    ret = create_output_file_marker(ctx, stream_ctx.temp_path,
                                    temp_stat.st_size, out_buf, out_size);
    if (ret < 0) {
        stream_context_destroy(&stream_ctx, FLB_FALSE);
        return -1;
    }

    flb_plg_debug(ctx->ins, "Stream processing: %zu records, %zu bytes → %lld bytes",
                  proc_ctx.records_processed, input_size, (long long)temp_stat.st_size);

    stream_context_destroy(&stream_ctx, FLB_TRUE);
    return 0;
}

int stream_json_processor(struct flb_s3 *ctx,
                          const msgpack_object *record,
                          FILE *output_file,
                          void *proc_ctx_ptr)
{
    struct stream_processor_context *proc_ctx = proc_ctx_ptr;
    const msgpack_object *body = &record->via.array.ptr[1];
    char *json_str;
    size_t json_len;

    json_str = flb_msgpack_to_json_str(1024, body,
                                       ctx->ins->config->json_escape_unicode);
    if (!json_str) {
        flb_plg_error(ctx->ins, "Failed to convert record to JSON");
        return -1;
    }

    json_len = strlen(json_str);

    if (fwrite(json_str, 1, json_len, output_file) != json_len ||
        fputc('\n', output_file) == EOF) {
        flb_free(json_str);
        return -1;
    }

    proc_ctx->bytes_written += json_len + 1;
    flb_free(json_str);
    return 0;
}

static const msgpack_object *find_log_key_in_map(struct flb_s3 *ctx,
                                                  const msgpack_object *map_obj)
{
    const char *key_str;
    size_t key_str_size;
    uint32_t i;

    if (map_obj->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (i = 0; i < map_obj->via.map.size; i++) {
        const msgpack_object *key = &map_obj->via.map.ptr[i].key;
        const msgpack_object *val = &map_obj->via.map.ptr[i].val;

        if (key->type == MSGPACK_OBJECT_STR) {
            key_str = key->via.str.ptr;
            key_str_size = key->via.str.size;
        }
        else if (key->type == MSGPACK_OBJECT_BIN) {
            key_str = key->via.bin.ptr;
            key_str_size = key->via.bin.size;
        }
        else {
            continue;
        }

        if (key_str_size == strlen(ctx->log_key) &&
            strncmp(ctx->log_key, key_str, key_str_size) == 0) {
            return val;
        }
    }

    return NULL;
}

static int write_string_value(FILE *output_file,
                               const void *data,
                               size_t data_size,
                               struct stream_processor_context *proc_ctx)
{
    if (fwrite(data, 1, data_size, output_file) != data_size ||
        fputc('\n', output_file) == EOF) {
        return -1;
    }

    proc_ctx->bytes_written += data_size + 1;
    return 0;
}

static int write_json_value(struct flb_s3 *ctx,
                             FILE *output_file,
                             const msgpack_object *val,
                             struct stream_processor_context *proc_ctx)
{
    char *json_str;
    size_t json_len;
    int ret;

    json_str = flb_msgpack_to_json_str(1024, val,
                                       ctx->ins->config->json_escape_unicode);
    if (!json_str) {
        flb_plg_error(ctx->ins, "Failed to convert log_key value to JSON");
        return -1;
    }

    json_len = strlen(json_str);
    ret = write_string_value(output_file, json_str, json_len, proc_ctx);
    flb_free(json_str);

    return ret;
}

int stream_log_key_processor(struct flb_s3 *ctx,
                              const msgpack_object *record,
                              FILE *output_file,
                              void *proc_ctx_ptr)
{
    struct stream_processor_context *proc_ctx = proc_ctx_ptr;
    const msgpack_object *map_obj = &record->via.array.ptr[1];
    const msgpack_object *val;
    const void *data;
    size_t data_size;

    val = find_log_key_in_map(ctx, map_obj);
    if (!val) {
        return 0;
    }

    if (val->type == MSGPACK_OBJECT_STR) {
        data = val->via.str.ptr;
        data_size = val->via.str.size;
        return write_string_value(output_file, data, data_size, proc_ctx);
    }
    else if (val->type == MSGPACK_OBJECT_BIN) {
        data = val->via.bin.ptr;
        data_size = val->via.bin.size;
        return write_string_value(output_file, data, data_size, proc_ctx);
    }
    else {
        return write_json_value(ctx, output_file, val, proc_ctx);
    }
}