/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_mem.h>
#include <miniz/miniz.h>
#include "flb_tests_internal.h"

static void check_limits(int algorithm, void *compressed, size_t compressed_size,
                         char *original, size_t original_size)
{
    void *output;
    size_t output_size;
    size_t limit;
    int ret;

    for (limit = original_size - 1; limit <= original_size + 1; limit++) {
        output = NULL;
        output_size = 0;
        ret = flb_decompress_buffer(algorithm, compressed, compressed_size, limit,
                                    &output, &output_size);
        if (limit < original_size) {
            TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
            TEST_CHECK(output == NULL);
            TEST_CHECK(output_size == 0);
        }
        else {
            TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
            TEST_CHECK(output_size == original_size);
            if (output != NULL && output_size == original_size) {
                TEST_CHECK(memcmp(output, original, original_size) == 0);
            }
            flb_free(output);
        }
    }
    ret = flb_decompress_buffer(algorithm, compressed, compressed_size, 0,
                                &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output == NULL);
    TEST_CHECK(output_size == 0);
}

static void test_bounded_codecs(void)
{
    char *original;
    size_t original_size = FLB_DECOMPRESSION_BUFFER_SIZE * 3 + 17;
    void *compressed;
    size_t compressed_size;
    size_t result;
    int algorithm;
    int ret;
    ZSTD_CCtx *context;

    original = flb_malloc(original_size);
    TEST_ASSERT(original != NULL);
    memset(original, 'x', original_size);
    for (algorithm = FLB_COMPRESSION_ALGORITHM_GZIP;
         algorithm <= FLB_COMPRESSION_ALGORITHM_SNAPPY; algorithm++) {
        compressed = NULL;
        if (algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
            ret = flb_gzip_compress(original, original_size, &compressed, &compressed_size);
        }
        else if (algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
            ret = flb_zstd_compress(original, original_size, &compressed, &compressed_size);
        }
        else {
            ret = flb_snappy_compress(original, original_size,
                                      (char **) &compressed, &compressed_size);
        }
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            check_limits(algorithm, compressed, compressed_size, original, original_size);
            flb_free(compressed);
        }
    }

    context = ZSTD_createCCtx();
    TEST_ASSERT(context != NULL);
    result = ZSTD_CCtx_setParameter(context, ZSTD_c_contentSizeFlag, 0);
    TEST_CHECK(!ZSTD_isError(result));
    compressed_size = ZSTD_compressBound(original_size);
    compressed = flb_malloc(compressed_size);
    TEST_ASSERT(compressed != NULL);
    compressed_size = ZSTD_compress2(context, compressed, compressed_size,
                                     original, original_size);
    TEST_CHECK(!ZSTD_isError(compressed_size));
    TEST_CHECK(ZSTD_getFrameContentSize(compressed, compressed_size) == ZSTD_CONTENTSIZE_UNKNOWN);
    check_limits(FLB_COMPRESSION_ALGORITHM_ZSTD, compressed, compressed_size,
                  original, original_size);
    flb_free(compressed);
    ZSTD_freeCCtx(context);
    flb_free(original);
}

static void test_advertised_sizes(void)
{
    unsigned char raw_snappy[] = {0xfe, 0xff, 0xff, 0xff, 0x0f};
    unsigned char framed_snappy[] = {
        FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y',
        FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA, 9, 0, 0, 0, 0, 0, 0,
        0xfe, 0xff, 0xff, 0xff, 0x0f
    };
    unsigned char gzip[] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f};
    void *output;
    size_t output_size;
    int ret;

    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_SNAPPY,
                                raw_snappy, sizeof(raw_snappy), 4096, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output == NULL && output_size == 0);
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_SNAPPY,
                                framed_snappy, sizeof(framed_snappy), 4096, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output == NULL && output_size == 0);
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP,
                                gzip, sizeof(gzip), 4096, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output == NULL && output_size == 0);
}

static void test_snappy_framed_checksum(void)
{
    unsigned char framed[] = {
        FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y',
        FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA, 7, 0, 0,
        0x6e, 0x57, 0xf1, 0x21, 'a', 'b', 'c'
    };
    void *output;
    size_t output_size;
    int ret;

    check_limits(FLB_COMPRESSION_ALGORITHM_SNAPPY, framed, sizeof(framed), "abc", 3);
    framed[14] ^= 1;
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_SNAPPY, framed, sizeof(framed),
                                4096, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output == NULL && output_size == 0);
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_SNAPPY, framed, sizeof(framed) - 1,
                                4096, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output == NULL && output_size == 0);
}

static void test_invalid_input(void)
{
    void *output;
    size_t output_size;
    int algorithm;
    int ret;
    char original[4096];
    unsigned char *compressed;
    size_t compressed_size;

    for (algorithm = FLB_COMPRESSION_ALGORITHM_GZIP;
         algorithm <= FLB_COMPRESSION_ALGORITHM_SNAPPY; algorithm++) {
        ret = flb_decompress_buffer(algorithm, NULL, 1, 4096, &output, &output_size);
        TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
        TEST_CHECK(output == NULL && output_size == 0);
        ret = flb_decompress_buffer(algorithm, "\xff", 1, 4096, &output, &output_size);
        TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
        TEST_CHECK(output == NULL && output_size == 0);
    }

    /* A forged small gzip ISIZE must not allow inflate to write beyond it. */
    memset(original, 'x', sizeof(original));
    ret = flb_gzip_compress(original, sizeof(original), (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    memset(compressed + compressed_size - 4, 0, 4);
    compressed[compressed_size - 4] = 1;
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP, compressed, compressed_size,
                                4096, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output == NULL && output_size == 0);
    flb_free(compressed);
}

static void test_context_output_growth(void)
{
    struct flb_decompression_context *context;
    char original[4096];
    char output[4096];
    void *compressed;
    size_t compressed_size;
    size_t output_size;
    int algorithm;
    int ret;

    memset(original, 'x', sizeof(original));
    for (algorithm = FLB_COMPRESSION_ALGORITHM_ZSTD;
         algorithm <= FLB_COMPRESSION_ALGORITHM_SNAPPY; algorithm++) {
        if (algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
            ret = flb_zstd_compress(original, sizeof(original), &compressed, &compressed_size);
        }
        else {
            ret = flb_snappy_compress(original, sizeof(original),
                                      (char **) &compressed, &compressed_size);
        }
        TEST_ASSERT(ret == 0);
        context = flb_decompression_context_create(algorithm, compressed_size);
        TEST_ASSERT(context != NULL);
        context->output_limit = sizeof(original);
        memcpy(flb_decompression_context_get_append_buffer(context), compressed, compressed_size);
        context->input_buffer_length = compressed_size;
        output_size = 1;
        ret = flb_decompress(context, output, &output_size);
        TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
        TEST_CHECK(output_size == 1);
        TEST_CHECK(context->input_buffer_length == compressed_size);
        TEST_CHECK(context->state != FLB_DECOMPRESSOR_STATE_FAILED);
        output_size = sizeof(output) - 1;
        ret = flb_decompress(context, output + 1, &output_size);
        TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
        TEST_CHECK(output_size == sizeof(original) - 1);
        TEST_CHECK(memcmp(original, output, sizeof(original)) == 0);
        TEST_CHECK(context->input_buffer_length == 0);
        flb_decompression_context_destroy(context);
        flb_free(compressed);
    }
}

static void test_zstd_window_budget(void)
{
    /* Unknown content size, 128 KiB window, and a final raw block containing abc. */
    unsigned char frame[] = {0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38,
                              0x19, 0x00, 0x00, 'a', 'b', 'c'};
    void *output;
    size_t output_size;
    int ret;

    check_limits(FLB_COMPRESSION_ALGORITHM_ZSTD, frame, sizeof(frame), "abc", 3);
    /* A window larger than the default HTTP budget does not imply large output. */
    frame[5] = 0x68; /* 8 MiB window. */
    check_limits(FLB_COMPRESSION_ALGORITHM_ZSTD, frame, sizeof(frame), "abc", 3);
    frame[5] = 0x90; /* 256 MiB exceeds the fixed decoder window cap. */
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_ZSTD, frame, sizeof(frame),
                                3, &output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output == NULL && output_size == 0);
}

static void test_gzip_optional_header(void)
{
    unsigned char *compressed;
    unsigned char *with_header;
    size_t compressed_size;
    void *output;
    size_t output_size;
    uint32_t crc;
    int ret;

    ret = flb_gzip_compress("abc", 3, (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    with_header = flb_malloc(compressed_size + 7);
    TEST_ASSERT(with_header != NULL);
    memcpy(with_header, compressed, 10);
    with_header[3] = 0x0e; /* FEXTRA, FNAME and FHCRC. */
    with_header[10] = 2;
    with_header[11] = 0;
    with_header[12] = 'a';
    with_header[13] = 'b';
    with_header[14] = 0; /* Empty file name is valid. */
    crc = mz_crc32(MZ_CRC32_INIT, with_header, 15);
    with_header[15] = crc & 0xff;
    with_header[16] = (crc >> 8) & 0xff;
    memcpy(with_header + 17, compressed + 10, compressed_size - 10);
    check_limits(FLB_COMPRESSION_ALGORITHM_GZIP, with_header, compressed_size + 7, "abc", 3);
    with_header[15] ^= 1;
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP, with_header,
                                compressed_size + 7, 3, &output, &output_size);
    TEST_CHECK(ret != FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output == NULL && output_size == 0);
    flb_free(with_header);
    flb_free(compressed);
}

TEST_LIST = {
    {"bounded_codecs", test_bounded_codecs},
    {"advertised_sizes", test_advertised_sizes},
    {"invalid_input", test_invalid_input},
    {"snappy_framed_checksum", test_snappy_framed_checksum},
    {"context_output_growth", test_context_output_growth},
    {"zstd_window_budget", test_zstd_window_budget},
    {"gzip_optional_header", test_gzip_optional_header},
    {0}
};
