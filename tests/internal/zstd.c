/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_zstd.h>
#include "flb_tests_internal.h"

/* try a small string */
static void test_compress_small_string()
{
    int len;
    int ret;
    const char *input = "Hello world";
    void *compressed_data = NULL;
    size_t compressed_len = 0;

    len = strlen(input);
    ret = flb_zstd_compress((void *) input, len, &compressed_data, &compressed_len);

    TEST_CHECK(ret == 0);
    TEST_CHECK(compressed_data != NULL);
    TEST_CHECK(compressed_len > 0);

    if (compressed_data) {
        flb_free(compressed_data);
    }
}

/* compress and decompress string */
static void test_decompress_small_string()
{
    int len;
    int ret;
    void *compressed_data = NULL;
    void *decompressed_data = NULL;
    size_t compressed_len = 0;
    size_t decompressed_len = 0;
    const char *input = "Hello world";

    /* compress */
    len = strlen(input);
    ret = flb_zstd_compress((void *) input, len, &compressed_data, &compressed_len);
    TEST_CHECK(ret == 0);

    /* decompress */
    ret = flb_zstd_uncompress(compressed_data, compressed_len, &decompressed_data, &decompressed_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(decompressed_data != NULL);
    TEST_CHECK(decompressed_len == len);
    TEST_CHECK(memcmp(decompressed_data, input, len) == 0);

    flb_free(compressed_data);
    flb_free(decompressed_data);
}

/* empty buffer */
static void test_compress_empty_input()
{
    void *compressed_data = NULL;
    size_t compressed_len = 0;

    int ret = flb_zstd_compress((void *) "", 0 , &compressed_data, &compressed_len);

    TEST_CHECK(ret == 0);
    TEST_CHECK(compressed_data != NULL);
    TEST_CHECK(compressed_len > 0);

    flb_free(compressed_data);
}


static void test_decompress_invalid_data()
{
    int len;
    int ret;
    const char *invalid_data = "an invalid compressed data";
    void *decompressed_data = NULL;
    size_t decompressed_len;

    len = strlen(invalid_data);
    ret = flb_zstd_uncompress((void *) invalid_data, len, &decompressed_data, &decompressed_len);

    /* check the error */
    TEST_CHECK(ret != 0);
    TEST_CHECK(decompressed_data == NULL);
}

/* large data test compression/decompression */
static void test_compress_decompress_large_data() {
    int ret;
    char *input;
    void *compressed_data = NULL;
    size_t compressed_len = 0;
    size_t input_len = 1024 * 1024;  /* 1MB */
    void *decompressed_data;
    size_t decompressed_len;

    /* input buffer */
    input = malloc(input_len);
    TEST_CHECK(input != NULL);
    memset(input, 'A', input_len);

    /* compress */
    ret = flb_zstd_compress((void *) input, input_len, &compressed_data, &compressed_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(compressed_data != NULL);
    TEST_CHECK(compressed_len > 0);


    /* decompress */
    ret = flb_zstd_uncompress(compressed_data, compressed_len, &decompressed_data, &decompressed_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(decompressed_data != NULL);
    TEST_CHECK(decompressed_len == input_len);
    TEST_CHECK(memcmp(decompressed_data, input, input_len) == 0);

    free(input);
    flb_free(compressed_data);
    flb_free(decompressed_data);
}

/*
 * zstd can contain a payload with an unknown registered size, as an example we have this payload
 * that can be generated from the command line:
 *
 *   $ echo -n '{"hello":"world"}' | zstd > data.json.stream.zstd
 *
 *   $zstd -l data.json.stream.zstd
 *
 *   Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename
 *        1      0      31   B                       XXH64  data.json.streamed.zstd
 *
 * note: to regenerate the payload in the compressed_data buffer, you can use the following command:
 *
 *   $ xxd -i data.json.stream.zstd
 */
static void test_decompress_unknown_size()
{
    int ret;
    int input_len = 0;
    int compressed_len;
    char *input = "{\"hello\":\"world\"}";
    void *decompressed_data;
    size_t decompressed_len;

    /* this is data.json.stream.zstd in a buffer representation (hexdump data.json.streamed.zstd )*/
     unsigned char compressed_data[30] = {
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x89, 0x00, 0x00, 0x7b, 0x22, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x22, 0x3a, 0x22, 0x77, 0x6f, 0x72, 0x6c, 0x64,
        0x22, 0x7d, 0x8e, 0x23, 0xa6, 0x52
    };

    compressed_len = sizeof(compressed_data);
    input_len = strlen(input);

    /* decompress */
    ret = flb_zstd_uncompress(compressed_data, compressed_len, &decompressed_data, &decompressed_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(decompressed_data != NULL);
    TEST_CHECK(decompressed_len == input_len);
    TEST_CHECK(memcmp(decompressed_data, input, input_len) == 0);

    flb_free(decompressed_data);
}

TEST_LIST = {
    { "compress_small_string",          test_compress_small_string },
    { "decompress_small_string",        test_decompress_small_string },
    { "compress_empty_input",           test_compress_empty_input },
    { "decompress_invalid_data",        test_decompress_invalid_data },
    { "compress_decompress_large_data", test_compress_decompress_large_data },
    { "decompress_unknown_size",        test_decompress_unknown_size },
    { NULL, NULL }
};
