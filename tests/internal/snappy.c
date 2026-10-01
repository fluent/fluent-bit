/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_snappy.h>
#include <cfl/cfl_checksum.h>

#include "flb_tests_internal.h"

static uint32_t calculate_snappy_checksum(char *buffer, size_t length)
{
    uint32_t checksum;

    checksum = cfl_checksum_crc32c((unsigned char *) buffer, length);

    return ((checksum >> 15) |
            (checksum << 17)) + 0xa282ead8;
}

static void write_frame_header(char *buffer, size_t *offset,
                               unsigned char frame_type, size_t frame_length)
{
    buffer[*offset] = frame_type;
    buffer[*offset + 1] = (char) (frame_length & 0xff);
    buffer[*offset + 2] = (char) ((frame_length >> 8) & 0xff);
    buffer[*offset + 3] = (char) ((frame_length >> 16) & 0xff);

    *offset += 4;
}

static void write_uint32_le(char *buffer, size_t *offset, uint32_t value)
{
    buffer[*offset] = (char) (value & 0xff);
    buffer[*offset + 1] = (char) ((value >> 8) & 0xff);
    buffer[*offset + 2] = (char) ((value >> 16) & 0xff);
    buffer[*offset + 3] = (char) ((value >> 24) & 0xff);

    *offset += 4;
}

static void write_uncompressed_frame(char *buffer, size_t *offset,
                                     char *data, size_t data_length)
{
    uint32_t checksum;

    checksum = calculate_snappy_checksum(data, data_length);

    write_frame_header(buffer, offset,
                       FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA,
                       data_length + sizeof(uint32_t));
    write_uint32_le(buffer, offset, checksum);
    memcpy(&buffer[*offset], data, data_length);

    *offset += data_length;
}

void test_raw_block_data_with_stream_identifier_byte(void)
{
    int ret;
    char raw_data[255];
    char *compressed_data;
    char *uncompressed_data;
    size_t compressed_length;
    size_t uncompressed_length;
    size_t index;

    for (index = 0; index < sizeof(raw_data); index++) {
        raw_data[index] = (char) index;
    }

    compressed_data = NULL;
    compressed_length = 0;
    ret = flb_snappy_compress(raw_data, sizeof(raw_data),
                              &compressed_data, &compressed_length);
    TEST_CHECK(ret == 0);
    TEST_CHECK(compressed_data != NULL);
    TEST_CHECK(compressed_length > 0);
    TEST_CHECK((unsigned char) compressed_data[0] ==
               FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER);

    uncompressed_data = NULL;
    uncompressed_length = 0;
    ret = flb_snappy_uncompress_framed_data(compressed_data, compressed_length,
                                            &uncompressed_data,
                                            &uncompressed_length);
    TEST_CHECK(ret == 0);
    TEST_CHECK(uncompressed_data != NULL);
    TEST_CHECK(uncompressed_length == sizeof(raw_data));

    if (ret != 0 || uncompressed_data == NULL ||
        uncompressed_length != sizeof(raw_data)) {
        flb_free(compressed_data);
        flb_free(uncompressed_data);
        return;
    }

    TEST_CHECK(memcmp(raw_data, uncompressed_data, sizeof(raw_data)) == 0);

    flb_free(compressed_data);
    flb_free(uncompressed_data);
}

void test_framed_data_with_multiple_chunks(void)
{
    int ret;
    char *first_chunk;
    char *second_chunk;
    char *expected_data;
    char framed_data[128];
    char *uncompressed_data;
    size_t first_length;
    size_t second_length;
    size_t expected_length;
    size_t framed_length;
    size_t uncompressed_length;

    first_chunk = "first framed chunk";
    second_chunk = "second framed chunk";
    first_length = strlen(first_chunk);
    second_length = strlen(second_chunk);
    expected_length = first_length + second_length;

    framed_length = 0;
    write_frame_header(framed_data, &framed_length,
                       FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER,
                       strlen(FLB_SNAPPY_STREAM_IDENTIFIER_STRING));
    memcpy(&framed_data[framed_length],
           FLB_SNAPPY_STREAM_IDENTIFIER_STRING,
           strlen(FLB_SNAPPY_STREAM_IDENTIFIER_STRING));
    framed_length += strlen(FLB_SNAPPY_STREAM_IDENTIFIER_STRING);

    write_uncompressed_frame(framed_data, &framed_length,
                             first_chunk, first_length);
    write_uncompressed_frame(framed_data, &framed_length,
                             second_chunk, second_length);

    uncompressed_data = NULL;
    uncompressed_length = 0;
    ret = flb_snappy_uncompress_framed_data(framed_data, framed_length,
                                            &uncompressed_data,
                                            &uncompressed_length);
    TEST_CHECK(ret == 0);
    TEST_CHECK(uncompressed_data != NULL);
    TEST_CHECK(uncompressed_length == expected_length);

    if (ret != 0 || uncompressed_data == NULL ||
        uncompressed_length != expected_length) {
        flb_free(uncompressed_data);
        return;
    }

    expected_data = flb_malloc(expected_length);
    TEST_CHECK(expected_data != NULL);
    memcpy(expected_data, first_chunk, first_length);
    memcpy(expected_data + first_length, second_chunk, second_length);
    TEST_CHECK(memcmp(expected_data, uncompressed_data, expected_length) == 0);

    flb_free(expected_data);
    flb_free(uncompressed_data);
}

TEST_LIST = {
    { "raw_block_data_with_stream_identifier_byte",
      test_raw_block_data_with_stream_identifier_byte },
    { "framed_data_with_multiple_chunks",
      test_framed_data_with_multiple_chunks },
    { 0 }
};
