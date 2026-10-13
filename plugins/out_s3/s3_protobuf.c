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

#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_crypto_constants.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output_plugin.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <msgpack.h>

#include "s3_protobuf.h"

#define S3_PROTOBUF_ERROR_SIZE 512
#define S3_PROTOBUF_SHA256_SIZE 32

static int s3_format_is_columnar(int format)
{
    return format == FLB_S3_FORMAT_PARQUET ||
           format == FLB_S3_FORMAT_ARROW;
}

static int option_is_set(const char *value)
{
    return value != NULL && value[0] != '\0';
}

#if defined(FLB_HAVE_ARROW) && defined(FLB_HAVE_PROTOBUF)
static int create_buffer_id(struct flb_s3 *ctx)
{
    static unsigned char version[] = "s3-protobuf-v1";
    int result;
    size_t index;
    size_t message_type_size;
    const char *message_type;
    unsigned char digest[S3_PROTOBUF_SHA256_SIZE];
    unsigned char *entries[2];
    size_t lengths[2];

    message_type = ctx->protobuf_message_type;
    if (message_type[0] == '.') {
        message_type++;
    }
    message_type_size = strlen(message_type);
    entries[0] = version;
    entries[1] = (unsigned char *) message_type;
    lengths[0] = sizeof(version) - 1;
    lengths[1] = message_type_size;

    result = flb_hash_simple_batch(FLB_HASH_SHA256,
                                   2, entries, lengths,
                                   digest, sizeof(digest));
    if (result != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "could not create Protobuf schema identifier");
        return -1;
    }

    for (index = 0; index < sizeof(digest); index++) {
        snprintf(&ctx->protobuf_buffer_id[index * 2], 3,
                 "%02x", digest[index]);
    }
    ctx->protobuf_buffer_id[sizeof(digest) * 2] = '\0';

    return 0;
}
#endif

int s3_protobuf_configure(struct flb_s3 *ctx)
{
    int has_protobuf_options;
#if defined(FLB_HAVE_ARROW) && defined(FLB_HAVE_PROTOBUF)
    char *descriptor = NULL;
    size_t descriptor_size = 0;
    char error[S3_PROTOBUF_ERROR_SIZE];
#endif

    ctx->columnar_input_format = FLB_S3_COLUMNAR_INPUT_JSON;

    has_protobuf_options =
        option_is_set(ctx->protobuf_data_key) ||
        option_is_set(ctx->protobuf_descriptor_file) ||
        option_is_set(ctx->protobuf_message_type);

    if (ctx->columnar_input_format_str == NULL ||
        strcasecmp(ctx->columnar_input_format_str, "json") == 0) {
        if (has_protobuf_options) {
            flb_plg_error(ctx->ins,
                          "Protobuf options require "
                          "'columnar_input_format protobuf'");
            return -1;
        }
        return 0;
    }

    if (strcasecmp(ctx->columnar_input_format_str, "protobuf") != 0) {
        flb_plg_error(ctx->ins,
                      "unsupported columnar_input_format '%s'",
                      ctx->columnar_input_format_str);
        return -1;
    }

    if (!s3_format_is_columnar(ctx->s3_format)) {
        flb_plg_error(ctx->ins,
                      "'columnar_input_format protobuf' requires "
                      "'format parquet' or 'format arrow'");
        return -1;
    }
    if (ctx->log_key != NULL) {
        flb_plg_error(ctx->ins,
                      "'log_key' cannot be combined with "
                      "'columnar_input_format protobuf'; use "
                      "'protobuf_data_key'");
        return -1;
    }
    if (!option_is_set(ctx->protobuf_data_key) ||
        !option_is_set(ctx->protobuf_descriptor_file) ||
        !option_is_set(ctx->protobuf_message_type)) {
        flb_plg_error(ctx->ins,
                      "Protobuf columnar input requires "
                      "'protobuf_data_key', 'protobuf_descriptor_file', "
                      "and 'protobuf_message_type'");
        return -1;
    }

#if defined(FLB_HAVE_ARROW) && defined(FLB_HAVE_PROTOBUF)
    if (flb_read_file(ctx->protobuf_descriptor_file,
                      &descriptor, &descriptor_size) < 0) {
        flb_plg_error(ctx->ins,
                      "could not read Protobuf descriptor file '%s'",
                      ctx->protobuf_descriptor_file);
        return -1;
    }

    ctx->protobuf_schema = flb_aws_protobuf_schema_create(
                                descriptor, descriptor_size,
                                ctx->protobuf_message_type,
                                error, sizeof(error));
    if (ctx->protobuf_schema == NULL) {
        flb_plg_error(ctx->ins,
                      "could not load Protobuf schema: %s", error);
        flb_free(descriptor);
        return -1;
    }

    if (create_buffer_id(ctx) != 0) {
        flb_aws_protobuf_schema_destroy(ctx->protobuf_schema);
        ctx->protobuf_schema = NULL;
        flb_free(descriptor);
        return -1;
    }

    flb_free(descriptor);
    ctx->columnar_input_format = FLB_S3_COLUMNAR_INPUT_PROTOBUF;
    return 0;
#else
    flb_plg_error(ctx->ins,
                  "Protobuf columnar input requires Fluent Bit to be built "
                  "with Arrow and Protobuf support");
    return -1;
#endif
}

void s3_protobuf_destroy(struct flb_s3 *ctx)
{
#if defined(FLB_HAVE_ARROW) && defined(FLB_HAVE_PROTOBUF)
    if (ctx->protobuf_schema != NULL) {
        flb_aws_protobuf_schema_destroy(ctx->protobuf_schema);
        ctx->protobuf_schema = NULL;
    }
#else
    (void) ctx;
#endif
}

static int object_key_matches(const msgpack_object *key, const char *name)
{
    const char *key_value;
    size_t key_size;
    size_t name_size;

    if (key->type == MSGPACK_OBJECT_STR) {
        key_value = key->via.str.ptr;
        key_size = key->via.str.size;
    }
    else if (key->type == MSGPACK_OBJECT_BIN) {
        key_value = key->via.bin.ptr;
        key_size = key->via.bin.size;
    }
    else {
        return FLB_FALSE;
    }

    name_size = strlen(name);
    return name_size == key_size &&
           memcmp(name, key_value, key_size) == 0;
}

flb_sds_t s3_protobuf_format_event_chunk(
                                struct flb_s3 *ctx,
                                struct flb_event_chunk *event_chunk)
{
    int result;
    int found;
    size_t record_count = 0;
    size_t index;
    flb_sds_t output = NULL;
    msgpack_object *body;
    msgpack_object *value;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;

    if (event_chunk->type != FLB_EVENT_TYPE_LOGS) {
        flb_plg_error(ctx->ins,
                      "Protobuf columnar input only accepts log events");
        return NULL;
    }

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    result = flb_log_event_decoder_init(
                    &decoder,
                    (char *) event_chunk->data,
                    event_chunk->size);
    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "could not initialize log event decoder: %s",
                      flb_log_event_decoder_get_error_description(result));
        msgpack_sbuffer_destroy(&buffer);
        return NULL;
    }

    while (flb_log_event_decoder_next(
                &decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        body = event.body;
        if (body == NULL || body->type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins,
                          "Protobuf data key '%s' requires a map log body",
                          ctx->protobuf_data_key);
            goto done;
        }

        found = FLB_FALSE;
        value = NULL;
        for (index = 0; index < body->via.map.size; index++) {
            if (!object_key_matches(&body->via.map.ptr[index].key,
                                    ctx->protobuf_data_key)) {
                continue;
            }
            if (found == FLB_TRUE) {
                flb_plg_error(ctx->ins,
                              "Protobuf data key '%s' appears more than once "
                              "in a log record",
                              ctx->protobuf_data_key);
                goto done;
            }
            found = FLB_TRUE;
            value = &body->via.map.ptr[index].val;
        }

        if (found == FLB_FALSE) {
            flb_plg_error(ctx->ins,
                          "could not find Protobuf data key '%s' in a log "
                          "record",
                          ctx->protobuf_data_key);
            goto done;
        }
        if (value->type != MSGPACK_OBJECT_BIN) {
            flb_plg_error(ctx->ins,
                          "Protobuf data key '%s' must contain a MessagePack "
                          "binary value",
                          ctx->protobuf_data_key);
            goto done;
        }
        if (value->via.bin.size > UINT32_MAX) {
            flb_plg_error(ctx->ins,
                          "Protobuf record in key '%s' exceeds the "
                          "MessagePack binary size limit",
                          ctx->protobuf_data_key);
            goto done;
        }
        if (msgpack_pack_bin(&packer, value->via.bin.size) != 0 ||
            msgpack_pack_bin_body(&packer,
                                  value->via.bin.ptr,
                                  value->via.bin.size) != 0) {
            flb_plg_error(ctx->ins,
                          "could not frame Protobuf record for local storage");
            goto done;
        }
        record_count++;
    }

    result = flb_log_event_decoder_get_last_result(&decoder);
    if (result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "could not decode complete log event chunk: %s",
                      flb_log_event_decoder_get_error_description(result));
        goto done;
    }
    if (record_count == 0) {
        flb_plg_error(ctx->ins,
                      "log event chunk did not contain Protobuf records");
        goto done;
    }
    if (buffer.size > INT_MAX) {
        flb_plg_error(ctx->ins,
                      "framed Protobuf event chunk is too large");
        goto done;
    }

    output = flb_sds_create_len(buffer.data, (int) buffer.size);
    if (output == NULL) {
        flb_errno();
    }

done:
    flb_log_event_decoder_destroy(&decoder);
    msgpack_sbuffer_destroy(&buffer);
    return output;
}

#if defined(FLB_HAVE_ARROW) && defined(FLB_HAVE_PROTOBUF)
static int read_binary_frame(const unsigned char *buffer, size_t buffer_size,
                             size_t *offset, const void **data,
                             size_t *data_size)
{
    unsigned char marker;
    uint32_t value_size;
    size_t header_size;
    size_t current;

    current = *offset;
    if (current >= buffer_size) {
        return 1;
    }

    marker = buffer[current];
    if (marker == 0xc4) {
        header_size = 2;
        if (buffer_size - current < header_size) {
            return -1;
        }
        value_size = buffer[current + 1];
    }
    else if (marker == 0xc5) {
        header_size = 3;
        if (buffer_size - current < header_size) {
            return -1;
        }
        value_size = ((uint32_t) buffer[current + 1] << 8) |
                     (uint32_t) buffer[current + 2];
    }
    else if (marker == 0xc6) {
        header_size = 5;
        if (buffer_size - current < header_size) {
            return -1;
        }
        value_size = ((uint32_t) buffer[current + 1] << 24) |
                     ((uint32_t) buffer[current + 2] << 16) |
                     ((uint32_t) buffer[current + 3] << 8) |
                     (uint32_t) buffer[current + 4];
    }
    else {
        return -1;
    }

    current += header_size;
    if (value_size > buffer_size - current) {
        return -1;
    }

    *data = &buffer[current];
    *data_size = value_size;
    *offset = current + value_size;
    return 0;
}

static int create_record_view(const void *buffer, size_t buffer_size,
                              struct flb_aws_protobuf_record **out_records,
                              size_t *out_record_count)
{
    int result;
    size_t count = 0;
    size_t index;
    size_t offset = 0;
    size_t data_size;
    const void *data;
    struct flb_aws_protobuf_record *records;
    const unsigned char *bytes = buffer;

    if (buffer == NULL || buffer_size == 0) {
        return -1;
    }

    while (offset < buffer_size) {
        result = read_binary_frame(bytes, buffer_size, &offset,
                                   &data, &data_size);
        if (result != 0 || count == SIZE_MAX) {
            return -1;
        }
        count++;
    }
    if (count == 0 ||
        count > SIZE_MAX / sizeof(struct flb_aws_protobuf_record)) {
        return -1;
    }

    records = flb_calloc(count, sizeof(struct flb_aws_protobuf_record));
    if (records == NULL) {
        flb_errno();
        return -1;
    }

    offset = 0;
    for (index = 0; index < count; index++) {
        result = read_binary_frame(bytes, buffer_size, &offset,
                                   &records[index].data,
                                   &records[index].size);
        if (result != 0) {
            flb_free(records);
            return -1;
        }
    }

    *out_records = records;
    *out_record_count = count;
    return 0;
}
#endif

int s3_protobuf_compress_columnar(struct flb_s3 *ctx,
                                  int columnar_format,
                                  const void *buffer, size_t buffer_size,
                                  void **out_buffer, size_t *out_size,
                                  int compression_type,
                                  char *error, size_t error_size)
{
#if defined(FLB_HAVE_ARROW) && defined(FLB_HAVE_PROTOBUF)
    int result;
    size_t record_count;
    struct flb_aws_protobuf_record *records = NULL;

    if (create_record_view(buffer, buffer_size,
                           &records, &record_count) != 0) {
        if (error != NULL && error_size > 0) {
            snprintf(error, error_size,
                     "buffer does not contain a complete sequence of "
                     "MessagePack binary Protobuf records");
        }
        return -1;
    }

    result = flb_aws_compression_compress_protobuf_columnar(
                        columnar_format,
                        ctx->protobuf_schema,
                        records, record_count,
                        out_buffer, out_size,
                        compression_type,
                        error, error_size);
    flb_free(records);
    return result;
#else
    (void) ctx;
    (void) columnar_format;
    (void) buffer;
    (void) buffer_size;
    (void) out_buffer;
    (void) out_size;
    (void) compression_type;

    if (error != NULL && error_size > 0) {
        snprintf(error, error_size,
                 "Protobuf columnar support is not available");
    }
    return -1;
#endif
}
