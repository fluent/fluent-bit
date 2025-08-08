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

void test_zstd_streaming_decompress_multi_chunk(void)
{
    struct flb_decompression_context *ctx;
    char   *output_buf;
    size_t output_len;
    size_t total_written = 0;
    int    ret;
    size_t chunk1_size = 0;
    size_t chunk2_size = 0;
    size_t chunk3_size = 0;
    char  *original_text = "zstd streaming is a feature that must be tested with multiple, uneven chunks!";
    size_t original_len;
    void  *compressed_buf = NULL;
    size_t compressed_len = 0;

    original_len = strlen(original_text);
    compressed_buf = compress_with_checksum(original_text, original_len, &compressed_len);
    TEST_CHECK(compressed_buf != NULL);

    ctx = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_ZSTD, compressed_len);
    TEST_CHECK(ctx != NULL);
    output_buf = flb_malloc(original_len + 1);

    chunk1_size = compressed_len / 3;
    chunk2_size = compressed_len / 2;
    chunk3_size = compressed_len - chunk1_size - chunk2_size;

    append_to_context(ctx, compressed_buf, chunk1_size);
    output_len = original_len;
    ret = flb_decompress(ctx, output_buf, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    total_written += output_len;

    append_to_context(ctx, (char *)compressed_buf + chunk1_size, chunk2_size);
    output_len = original_len - total_written;
    ret = flb_decompress(ctx, output_buf + total_written, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    total_written += output_len;

    append_to_context(ctx, (char *)compressed_buf + chunk1_size + chunk2_size, chunk3_size);
    output_len = original_len - total_written;
    ret = flb_decompress(ctx, output_buf + total_written, &output_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    total_written += output_len;

    TEST_CHECK(total_written == original_len);
    TEST_CHECK(memcmp(original_text, output_buf, original_len) == 0);

    flb_free(compressed_buf);
    flb_free(output_buf);
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
