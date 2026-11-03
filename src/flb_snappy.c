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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <cfl/cfl.h>
#include <cfl/cfl_list.h>
#include <cfl/cfl_checksum.h>

#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_compression.h>

#include <snappy.h>

int flb_snappy_compress(char *in_data, size_t in_len,
                        char **out_data, size_t *out_len)
{
    struct snappy_env snappy_env;
    char             *tmp_data;
    size_t            tmp_len;
    int               result;

    tmp_len = snappy_max_compressed_length(in_len);

    tmp_data = flb_malloc(tmp_len);

    if (tmp_data == NULL) {
        flb_errno();

        return -1;
    }

    result = snappy_init_env(&snappy_env);

    if (result != 0) {
        flb_free(tmp_data);

        return -2;
    }

    result = snappy_compress(&snappy_env, in_data, in_len, tmp_data, &tmp_len);

    if (result != 0) {
        flb_free(tmp_data);

        return -3;
    }

    snappy_free_env(&snappy_env);

    *out_data = tmp_data;
    *out_len = tmp_len;

    return 0;
}

int flb_snappy_uncompress(char *in_data, size_t in_len,
                          char **out_data, size_t *out_len)
{
    char             *tmp_data;
    size_t            tmp_len;
    int               result;

    result = snappy_uncompressed_length(in_data, in_len, &tmp_len);

    if (result == 0) {
        return -1;
    }

    tmp_data = flb_malloc(tmp_len);

    if (tmp_data == NULL) {
        flb_errno();

        return -2;
    }

    result = snappy_uncompress(in_data, in_len, tmp_data);

    if (result != 0) {
        flb_free(tmp_data);

        return -3;
    }

    *out_data = tmp_data;
    *out_len = tmp_len;

    return 0;
}

static uint32_t snappy_read_le32(const unsigned char *buffer)
{
    /* Framed checksums are little-endian and may start at any byte alignment. */
    return ((uint32_t) buffer[0]) | ((uint32_t) buffer[1] << 8) |
           ((uint32_t) buffer[2] << 16) | ((uint32_t) buffer[3] << 24);
}

int flb_snappy_uncompress_bounded(char **output_buffer, size_t *output_size,
                                    char *input_buffer, size_t input_size, size_t limit)
{
    size_t offset;
    size_t length;
    size_t expanded;
    size_t total = 0;
    size_t output_offset = 0;
    int pass;
    unsigned char type;
    unsigned char *frame;
    uint32_t checksum;
    char *buffer = NULL;

    if (output_buffer == NULL || output_size == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    *output_buffer = NULL;
    *output_size = 0;
    if (input_buffer == NULL || input_size == 0) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (input_size < 10 ||
        (unsigned char) input_buffer[0] != FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER ||
        input_buffer[1] != 6 || input_buffer[2] != 0 || input_buffer[3] != 0 ||
        memcmp(input_buffer + 4, FLB_SNAPPY_STREAM_IDENTIFIER_STRING, 6) != 0) {
        if (!snappy_uncompressed_length(input_buffer, input_size, &expanded)) {
            return FLB_DECOMPRESSOR_FAILURE;
        }
        if (expanded > limit) {
            return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
        }
        return flb_snappy_uncompress(input_buffer, input_size, output_buffer, output_size) == 0 ?
               0 : FLB_DECOMPRESSOR_FAILURE;
    }

    /* Inspect every framed chunk before allocating a single bounded output. */
    for (pass = 0; pass < 2; pass++) {
        offset = 0;
        while (offset < input_size) {
            if (input_size - offset < 4) {
                goto invalid;
            }
            frame = (unsigned char *) input_buffer + offset;
            type = frame[0];
            length = ((size_t) frame[1]) | ((size_t) frame[2] << 8) |
                     ((size_t) frame[3] << 16);
            if (length > input_size - offset - 4) {
                goto invalid;
            }
            frame += 4;
            if (type == FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER) {
                if (length != 6 || memcmp(frame, FLB_SNAPPY_STREAM_IDENTIFIER_STRING, 6) != 0) {
                    goto invalid;
                }
            }
            else if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA ||
                     type == FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA) {
                if (length < 4 || length > FLB_SNAPPY_FRAME_SIZE_LIMIT) {
                    goto invalid;
                }
                expanded = length - 4;
                if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA &&
                    !snappy_uncompressed_length((char *) frame + 4, length - 4, &expanded)) {
                    goto invalid;
                }
                if (pass == 0) {
                    if (expanded > limit - total) {
                        return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
                    }
                    total += expanded;
                }
                else {
                    if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA) {
                        if (snappy_uncompress((char *) frame + 4, length - 4,
                                              buffer + output_offset) != 0) {
                            goto invalid;
                        }
                    }
                    else {
                        memcpy(buffer + output_offset, frame + 4, expanded);
                    }
                    checksum = cfl_checksum_crc32c((unsigned char *) buffer + output_offset,
                                                   expanded);
                    checksum = ((checksum >> 15) | (checksum << 17)) + 0xa282ead8;
                    if (checksum != snappy_read_le32(frame)) {
                        goto invalid;
                    }
                    output_offset += expanded;
                }
            }
            else if (type < FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_BASE) {
                goto invalid;
            }
            offset += 4 + length;
        }
        if (pass == 0) {
            buffer = flb_malloc(total == 0 ? 1 : total);
            if (buffer == NULL) {
                return FLB_DECOMPRESSOR_FAILURE;
            }
        }
    }
    *output_buffer = buffer;
    *output_size = total;
    return 0;

invalid:
    flb_free(buffer);
    return FLB_DECOMPRESSOR_FAILURE;
}

int flb_snappy_uncompress_framed_data(char *in_data, size_t in_len,
                                      char **out_data, size_t *out_len)
{
    return flb_snappy_uncompress_bounded(out_data, out_len, in_data, in_len, SIZE_MAX);
}
