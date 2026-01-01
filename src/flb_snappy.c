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

static uint32_t calculate_checksum(char *buffer, size_t length)
{
    uint32_t checksum;

    checksum = cfl_checksum_crc32c((unsigned char *) buffer, length);

    return ((checksum >> 15)  |
            (checksum << 17)) + 0xa282ead8;
}

int flb_snappy_uncompress_framed_data(char *in_data, size_t in_len,
                                      char **out_data, size_t *out_len)
{
    uint32_t                      decompressed_data_checksum;
    size_t                        stream_identifier_length;
    size_t                        uncompressed_chunk_count;
    int                           stream_identifier_found;
    char                         *aggregated_data_buffer;
    size_t                        aggregated_data_length = 0;
    size_t                        aggregated_data_offset;
    size_t                        compressed_chunk_count;
    struct cfl_list              *iterator_backup;
    uint32_t                      frame_checksum;
    char                         *frame_buffer;
    size_t                        frame_length;
    char                         *frame_body;
    unsigned char                 frame_type;
    struct cfl_list              *iterator;
    int                           result;
    size_t                        offset;
    struct cfl_list               chunks;
    struct flb_snappy_data_chunk *chunk;

    if (*((uint8_t *) in_data) != FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER) {
        return flb_snappy_uncompress(in_data, in_len, out_data, out_len);
    }

    if (out_data == NULL) {
        return -1;
    }

    if (out_len == NULL) {
        return -1;
    }

    *out_data = NULL;
    *out_len = 0;

    cfl_list_init(&chunks);

    compressed_chunk_count = 0;
    uncompressed_chunk_count = 0;

    stream_identifier_found = FLB_FALSE;
    stream_identifier_length = strlen(FLB_SNAPPY_STREAM_IDENTIFIER_STRING);

    result = 0;
    offset = 0;

    while (offset < in_len && result == 0) {
        frame_buffer = &in_data[offset];

        frame_type    = *((uint8_t *) &frame_buffer[0]);

        frame_length  = *((uint32_t *) &frame_buffer[1]);
        frame_length &= 0x00FFFFFF;

        frame_body    = &frame_buffer[4];

        if (frame_length > FLB_SNAPPY_FRAME_SIZE_LIMIT) {
            result = -2;
        }
        else if (frame_type == FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER) {
            if (!stream_identifier_found) {
                if (frame_length == stream_identifier_length) {
                    result = strncmp(frame_body,
                                     FLB_SNAPPY_STREAM_IDENTIFIER_STRING,
                                     stream_identifier_length);

                    if (result == 0) {
                        stream_identifier_found = FLB_TRUE;
                    }
                }
            }
        }
        else if (frame_type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA) {
            chunk = (struct flb_snappy_data_chunk * ) \
                        flb_calloc(1, sizeof(struct flb_snappy_data_chunk));

            if (chunk != NULL) {
                /* We add the chunk to the list now because that way
                 * even if the process fails we can clean up in a single
                 * place.
                 */
                compressed_chunk_count++;

                chunk->dynamically_allocated_buffer = FLB_TRUE;

                cfl_list_add(&chunk->_head, &chunks);

                frame_checksum = *((uint32_t *) &frame_body[0]);
                frame_body = &frame_body[4];

                result = flb_snappy_uncompress(
                            frame_body,
                            frame_length - sizeof(uint32_t),
                            &chunk->buffer,
                            &chunk->length);

                /* decompressed data */
                if (result == 0) {
                    decompressed_data_checksum = calculate_checksum(
                                                    chunk->buffer,
                                                    chunk->length);

                    if (decompressed_data_checksum != frame_checksum) {
                        result = -3;
                    }
                    else {
                        aggregated_data_length += chunk->length;
                    }
                }
                else {
                    result = -4;
                }
            }
        }
        else if (frame_type == FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA) {
            chunk = (struct flb_snappy_data_chunk *) \
                        flb_calloc(1, sizeof(struct flb_snappy_data_chunk));

            if (chunk != NULL) {
                /* We add the chunk to the list now because that way
                 * even if the process fails we can clean up in a single
                 * place.
                 */
                uncompressed_chunk_count++;

                chunk->dynamically_allocated_buffer = FLB_FALSE;

                cfl_list_add(&chunk->_head, &chunks);

                frame_checksum = *((uint32_t *) &frame_body[0]);
                frame_body = &frame_body[4];

                chunk->buffer = frame_body;
                chunk->length = frame_length - sizeof(uint32_t);

                decompressed_data_checksum = calculate_checksum(
                                                chunk->buffer,
                                                chunk->length);

                if (decompressed_data_checksum != frame_checksum) {
                    result = -3;
                }
                else {
                    aggregated_data_length += chunk->length;
                }
            }
        }
        else if (frame_type == FLB_SNAPPY_FRAME_TYPE_PADDING) {
            /* We just need to skip these frames */
        }
        else if (frame_type >= FLB_SNAPPY_FRAME_TYPE_RESERVED_UNSKIPPABLE_BASE &&
                 frame_type <= FLB_SNAPPY_FRAME_TYPE_RESERVED_UNSKIPPABLE_TOP) {
            result = -5;
        }
        else if (frame_type >= FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_BASE &&
                 frame_type <= FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_TOP) {
            /* We just need to skip these frames */
        }

        offset += frame_length + 4;
    }

    aggregated_data_buffer = NULL;
    aggregated_data_length = 0;

    if (compressed_chunk_count == 1 &&
        uncompressed_chunk_count == 0 &&
        result == 0) {
        /* This is a "past path" to avoid unnecessarily copying
         * data whene the input is only comprised of a single
         * compressed chunk.
         */

        chunk = cfl_list_entry_first(&chunks,
                                     struct flb_snappy_data_chunk, _head);

        aggregated_data_buffer = chunk->buffer;
        aggregated_data_length = chunk->length;
        aggregated_data_offset = aggregated_data_length;

        flb_free(chunk);
    }
    else {
        if (aggregated_data_length > 0) {
            aggregated_data_buffer = flb_calloc(aggregated_data_length,
                                                sizeof(char));

            if (aggregated_data_buffer == NULL) {
                result = -6;
            }
        }

        aggregated_data_offset = 0;
        cfl_list_foreach_safe(iterator, iterator_backup, &chunks) {
            chunk = cfl_list_entry(iterator,
                                   struct flb_snappy_data_chunk, _head);

            if (chunk->buffer != NULL) {
                if (aggregated_data_buffer != NULL &&
                    result == 0) {
                    memcpy(&aggregated_data_buffer[aggregated_data_offset],
                           chunk->buffer,
                           chunk->length);

                    aggregated_data_offset += chunk->length;
                }

                if (chunk->dynamically_allocated_buffer) {
                    flb_free(chunk->buffer);
                }
            }

            cfl_list_del(&chunk->_head);

            flb_free(chunk);
        }
    }

    *out_data = (char *) aggregated_data_buffer;
    *out_len = aggregated_data_offset;

    return result;
}
