/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_compression.h>
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

static void append_to_context(struct flb_decompression_context *ctx, const void *data, size_t size)
{
    uint8_t *append_ptr;
    size_t available_space;

    available_space = flb_decompression_context_get_available_space(ctx);

    if (size > available_space) {
        size_t required_size = ctx->input_buffer_length + size;
        flb_decompression_context_resize_buffer(ctx, required_size);
    }

    /* Get pointer to the write location */
    append_ptr = flb_decompression_context_get_append_buffer(ctx);
    TEST_CHECK(append_ptr != NULL);

    /* Copy the data */
    memcpy(append_ptr, data, size);

    ctx->input_buffer_length += size;
}

static void *compress_with_checksum(const void *original_data, size_t original_len,
                                    size_t *compressed_len)
{
    ZSTD_CCtx* cctx;
    void *compressed_buffer;
    size_t bound;
    size_t ret;

    /* Create a compression context */
    cctx = ZSTD_createCCtx();
    TEST_CHECK(cctx != NULL);

    /*
     * THIS IS THE KEY: Explicitly enable content checksums in the frame.
     */
    ret = ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
    TEST_CHECK(!ZSTD_isError(ret));

    /* Compress the data */
    bound = ZSTD_compressBound(original_len);
    compressed_buffer = flb_malloc(bound);
    TEST_CHECK(compressed_buffer != NULL);

    *compressed_len = ZSTD_compress2(cctx,
                                     compressed_buffer, bound,
                                     original_data, original_len);

    TEST_CHECK(!ZSTD_isError(*compressed_len));

    ZSTD_freeCCtx(cctx);

    return compressed_buffer;
}

/*
 * This test validates that the flb_decompress API can seamlessly handle
 * three or more independent Zstd frames concatenated into a single buffer.
 */
void test_zstd_streaming_decompress_multi_chunk(void)
{
    int ret = 0;
    const char *original1 = "This is the first payload.";
    const char *original2 = "This is the second, slightly longer payload.";
    const char *original3 = "And this is the final, third payload.";
    size_t original1_len = strlen(original1);
    size_t original2_len = strlen(original2);
    size_t original3_len = strlen(original3);
    size_t max_original_len;

    void *compressed1 = NULL, *compressed2 = NULL, *compressed3 = NULL;
    size_t compressed1_len = 0, compressed2_len = 0, compressed3_len = 0;

    char *concatenated_buffer = NULL;
    size_t concatenated_len = 0;

    char *output_buffer = NULL;
    size_t output_len;

    struct flb_decompression_context *ctx;

    flb_zstd_compress((void *)original1, original1_len, &compressed1, &compressed1_len);
    TEST_CHECK(compressed1 != NULL);

    flb_zstd_compress((void *)original2, original2_len, &compressed2, &compressed2_len);
    TEST_CHECK(compressed2 != NULL);

    flb_zstd_compress((void *)original3, original3_len, &compressed3, &compressed3_len);
    TEST_CHECK(compressed3 != NULL);

    concatenated_len = compressed1_len + compressed2_len + compressed3_len;
    concatenated_buffer = flb_malloc(concatenated_len);
    TEST_CHECK(concatenated_buffer != NULL);

    memcpy(concatenated_buffer, compressed1, compressed1_len);
    memcpy(concatenated_buffer + compressed1_len, compressed2, compressed2_len);
    memcpy(concatenated_buffer + compressed1_len + compressed2_len, compressed3, compressed3_len);

    flb_free(compressed1);
    flb_free(compressed2);
    flb_free(compressed3);

    /* Create context and append the entire concatenated buffer */
    ctx = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_ZSTD, 0);
    TEST_CHECK(ctx != NULL);

    append_to_context(ctx, concatenated_buffer, concatenated_len);

    /* Allocate an output buffer large enough for the biggest payload */
    max_original_len = original1_len;
    if (original2_len > max_original_len) max_original_len = original2_len;
    if (original3_len > max_original_len) max_original_len = original3_len;
    output_buffer = flb_malloc(max_original_len);
    TEST_CHECK(output_buffer != NULL);

    output_len = original1_len;
    ret = flb_decompress(ctx, output_buffer, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output_len == original1_len);
    TEST_CHECK(memcmp(original1, output_buffer, original1_len) == 0);

    output_len = original2_len;
    ret = flb_decompress(ctx, output_buffer, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output_len == original2_len);
    TEST_CHECK(memcmp(original2, output_buffer, original2_len) == 0);

    output_len = original3_len;
    ret = flb_decompress(ctx, output_buffer, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output_len == original3_len);
    TEST_CHECK(memcmp(original3, output_buffer, original3_len) == 0);

    output_len = 1; /* Ask for one byte */
    ret = flb_decompress(ctx, output_buffer, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output_len == 0); /* Should produce 0 bytes */

    flb_free(concatenated_buffer);
    flb_free(output_buffer);
    flb_decompression_context_destroy(ctx);
}

/* In tests/internal/zstd.c */

void test_zstd_streaming_decompress_corrupted_data(void)
{
    struct flb_decompression_context *ctx;
    char   *output_buf;
    size_t  output_len;
    int     ret;
    char   *original_text = "this test ensures corrupted data with a checksum fails";
    size_t  original_len = strlen(original_text);
    void   *compressed_buf = NULL;
    size_t  compressed_len = 0;
    char   *corrupted_input;

    compressed_buf = compress_with_checksum(original_text, original_len, &compressed_len);
    TEST_CHECK(compressed_buf != NULL);

    ctx = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_ZSTD, compressed_len);
    TEST_CHECK(ctx != NULL);

    /* Create a corrupted copy of the input */
    corrupted_input = flb_malloc(compressed_len);
    TEST_CHECK(corrupted_input != NULL);
    memcpy(corrupted_input, compressed_buf, compressed_len);
    /* Corrupt a byte in the middle */
    corrupted_input[compressed_len / 2]++;

    append_to_context(ctx, corrupted_input, compressed_len);

    output_buf = flb_malloc(original_len + 1);
    output_len = original_len;

    ret = flb_decompress(ctx, output_buf, &output_len);

    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(ctx->state == FLB_DECOMPRESSOR_STATE_FAILED);

    flb_free(compressed_buf);
    flb_free(corrupted_input);
    flb_free(output_buf);
    flb_decompression_context_destroy(ctx);
}


TEST_LIST = {
    { "compress_small_string",          test_compress_small_string },
    { "decompress_small_string",        test_decompress_small_string },
    { "compress_empty_input",           test_compress_empty_input },
    { "decompress_invalid_data",        test_decompress_invalid_data },
    { "compress_decompress_large_data", test_compress_decompress_large_data },
    { "decompress_unknown_size",        test_decompress_unknown_size },
    { "streaming_decompress_multi_chunk", test_zstd_streaming_decompress_multi_chunk },
    { "streaming_decompress_corrupted_data", test_zstd_streaming_decompress_corrupted_data },
    { NULL, NULL }
};
