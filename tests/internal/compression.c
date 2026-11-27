/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_mem.h>
#include <cfl/cfl_checksum.h>
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

/* A delivery boundary in the middle of a member is a wait for more input, not
 * corruption: both outcomes are acceptable while streaming. */
static int decompress_waited_or_succeeded(int ret)
{
    return ret == FLB_DECOMPRESSOR_SUCCESS ||
           ret == FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
}

/* Growing to make room for an append has to account for the consumed prefix: the
 * append cursor is read_buffer + input_buffer_length, not input_buffer_length. */
static void test_reserve_covers_the_read_cursor(void)
{
    struct flb_decompression_context *context;
    unsigned char output[64];
    unsigned char filler[4096];
    unsigned char *compressed = NULL;
    size_t compressed_size = 0;
    size_t cursor_offset;
    size_t resident;
    size_t produced;
    int ret;

    memset(filler, 'r', sizeof(filler));

    TEST_CHECK(flb_decompression_context_reserve(NULL, 16, 0) == FLB_DECOMPRESSOR_FAILURE);

    ret = flb_gzip_compress("abc", 3, (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 32);
    TEST_ASSERT(context != NULL);

    TEST_CHECK(flb_decompression_context_reserve(context, 8, 16) ==
               FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(flb_decompression_context_reserve(context, 8, 32) == FLB_DECOMPRESSOR_SUCCESS);

    /* Consume the fixed header so the read cursor leaves the start of the block. */
    memcpy(flb_decompression_context_get_append_buffer(context), compressed, 10);
    context->input_buffer_length += 10;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_ASSERT(context->read_buffer != context->input_buffer);

    cursor_offset = (size_t) ((uintptr_t) context->read_buffer -
                              (uintptr_t) context->input_buffer);
    resident = context->input_buffer_length;

    /* The grow has to cover the consumed prefix as well as what is appended. */
    ret = flb_decompression_context_reserve(context, sizeof(filler), 0);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_size >= cursor_offset + resident + sizeof(filler));

    memcpy(flb_decompression_context_get_append_buffer(context), filler, sizeof(filler));
    context->input_buffer_length += sizeof(filler);
    TEST_CHECK(context->input_buffer_length == resident + sizeof(filler));

    /* The cap is caller policy: below the requirement it refuses instead of
     * handing back a block the append would overrun. */
    TEST_CHECK(flb_decompression_context_reserve(context, 16, 8) ==
               FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    /* An unrepresentable request is refused rather than wrapped. */
    TEST_CHECK(flb_decompression_context_reserve(context, SIZE_MAX, 0) ==
               FLB_DECOMPRESSOR_FAILURE);

    flb_decompression_context_destroy(context);
    flb_free(compressed);
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

static void test_snappy_legacy_framed(void)
{
    const unsigned char frames[][23] = {
        {0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y',
         1, 7, 0, 0, 0x6e, 0x57, 0xf1, 0x21, 'a', 'b', 'c'},
        {0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y',
         0, 9, 0, 0, 0x6e, 0x57, 0xf1, 0x21, 3, 8, 'a', 'b', 'c'}
    };
    const size_t lengths[] = {21, 23};
    unsigned char *storage;
    unsigned char *input;
    char *output;
    size_t output_size;
    size_t alignment;
    size_t kind;
    size_t length;
    int ret;

    storage = flb_malloc(64);
    TEST_ASSERT(storage != NULL);
    for (kind = 0; kind < 2; kind++) {
        for (alignment = 0; alignment < 4; alignment++) {
            input = storage + alignment;
            length = lengths[kind];
            memcpy(input, frames[kind], length);
            /* Fixed wire bytes verify little-endian CRCs at every alignment. */
            ret = flb_snappy_uncompress_framed_data((char *) input, length,
                                                    &output, &output_size);
            TEST_CHECK(ret == 0);
            TEST_CHECK(output_size == 3);
            if (output != NULL && output_size == 3) {
                TEST_CHECK(memcmp(output, "abc", 3) == 0);
            }
            flb_free(output);

            input[14] ^= 1;
            ret = flb_snappy_uncompress_framed_data((char *) input, length,
                                                    &output, &output_size);
            TEST_CHECK(ret != 0);
            TEST_CHECK(output == NULL && output_size == 0);
            input[14] ^= 1;
            ret = flb_snappy_uncompress_framed_data((char *) input, length - 1,
                                                    &output, &output_size);
            TEST_CHECK(ret != 0);
            TEST_CHECK(output == NULL && output_size == 0);

            /* Append the other frame type, without a second identifier. */
            memcpy(input + length, frames[1 - kind] + 10, lengths[1 - kind] - 10);
            ret = flb_snappy_uncompress_framed_data((char *) input, 34,
                                                    &output, &output_size);
            TEST_CHECK(ret == 0);
            TEST_CHECK(output_size == 6);
            if (output != NULL && output_size == 6) {
                TEST_CHECK(memcmp(output, "abcabc", 6) == 0);
            }
            flb_free(output);
        }
    }
    /* The report's minimal frame and a checksum shorter than four bytes. */
    memcpy(storage, frames[0], 18);
    storage[11] = 4;
    ret = flb_snappy_uncompress_framed_data((char *) storage, 18, &output, &output_size);
    TEST_CHECK(ret != 0);
    TEST_CHECK(output == NULL && output_size == 0);
    storage[11] = 3;
    ret = flb_snappy_uncompress_framed_data((char *) storage, 17, &output, &output_size);
    TEST_CHECK(ret != 0);
    TEST_CHECK(output == NULL && output_size == 0);
    ret = flb_snappy_uncompress_framed_data(NULL, 0, &output, &output_size);
    TEST_CHECK(ret != 0);
    TEST_CHECK(output == NULL && output_size == 0);
    flb_free(storage);
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

static void test_dispatcher_argument_validation(void)
{
    struct flb_decompression_context *context;
    void *saved_inner;
    char output[16];
    size_t output_size;
    int ret;

    /* A null context must be refused rather than dereferenced. */
    output_size = sizeof(output);
    ret = flb_gzip_decompressor_dispatch(NULL, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 1024);
    TEST_ASSERT(context != NULL);

    /* A null length must be refused before it is read or written. */
    ret = flb_gzip_decompressor_dispatch(context, output, NULL);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    ret = flb_gzip_decompressor_dispatch(context, NULL, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    /* A different codec owns a different backend structure. */
    context->algorithm = FLB_COMPRESSION_ALGORITHM_ZSTD;
    ret = flb_gzip_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    context->algorithm = FLB_COMPRESSION_ALGORITHM_GZIP;

    /* A context without its backend must fail rather than crash. */
    saved_inner = context->inner_context;
    context->inner_context = NULL;
    output_size = sizeof(output);
    ret = flb_gzip_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    context->inner_context = saved_inner;

    /* An empty input buffer is reported as insufficient data, not a failure. */
    output_size = sizeof(output);
    ret = flb_gzip_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_INSUFFICIENT_DATA);
    TEST_CHECK(output_size == 0);

    flb_decompression_context_destroy(context);
}

static void test_zstd_dispatcher_argument_validation(void)
{
    struct flb_decompression_context *context;
    void *saved_inner;
    void *compressed;
    size_t compressed_size;
    char original[] = "payload for the zstd dispatcher guard";
    char output[64];
    size_t output_size;
    int ret;

    /* A null context must be refused rather than dereferenced. */
    output_size = sizeof(output);
    ret = flb_zstd_decompressor_dispatch(NULL, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_ZSTD, 4096);
    TEST_ASSERT(context != NULL);

    /* A null length must be refused before it is read or written. */
    ret = flb_zstd_decompressor_dispatch(context, output, NULL);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    /* A null output buffer must be refused, never handed to the backend. */
    ret = flb_zstd_decompressor_dispatch(context, NULL, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    /* A context without its backend must fail rather than crash. */
    saved_inner = context->inner_context;
    context->inner_context = NULL;
    output_size = sizeof(output);
    ret = flb_zstd_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    context->inner_context = saved_inner;

    /* From here on a frame is resident, so the dispatcher reaches far enough to
     * need every remaining argument to be valid. */
    ret = flb_zstd_compress(original, sizeof(original) - 1, &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);

    memcpy(flb_decompression_context_get_append_buffer(context), compressed, compressed_size);
    context->input_buffer_length += compressed_size;

    /* A different codec owns a different backend structure: the tag has to be
     * checked before inner_context is cast to one. */
    context->algorithm = FLB_COMPRESSION_ALGORITHM_GZIP;
    output_size = sizeof(output);
    ret = flb_zstd_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(context->state != FLB_DECOMPRESSOR_STATE_FAILED);
    context->algorithm = FLB_COMPRESSION_ALGORITHM_ZSTD;

    context->output_limit = 0;
    context->output_size = 1;
    output_size = sizeof(output);
    ret = flb_zstd_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output_size == 0);
    context->output_size = 0;

    /* A zero-capacity call leaves the frame available for a later decode. */
    output_size = 0;
    ret = flb_zstd_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_length == compressed_size);

    /* Rechecking the same frame must enforce the same output budget. */
    context->output_limit = sizeof(original) - 2;
    output_size = sizeof(output);
    ret = flb_decompress(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output_size == 0);
    output_size = sizeof(output);
    ret = flb_decompress(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_LIMIT_EXCEEDED);
    TEST_CHECK(output_size == 0);
    TEST_CHECK(context->input_buffer_length == compressed_size);
    context->output_limit = sizeof(original) - 1;

    /* A refused call must leave the frame intact so it still decodes. */
    memset(output, 0, sizeof(output));
    output_size = sizeof(output);
    ret = flb_zstd_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output_size == sizeof(original) - 1);
    if (output_size == sizeof(original) - 1) {
        TEST_CHECK(memcmp(output, original, output_size) == 0);
    }

    context->state = FLB_DECOMPRESSOR_STATE_FAILED;
    output_size = sizeof(output);
    ret = flb_zstd_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output_size == 0);

    flb_decompression_context_destroy(context);
    flb_free(compressed);
}

static void test_context_resize_empty(void)
{
    struct flb_decompression_context *context;
    uint8_t *buffer;
    int ret;

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 4096);
    TEST_ASSERT(context != NULL);
    buffer = context->input_buffer;

    ret = flb_decompression_context_resize_buffer(context, 0);
    TEST_ASSERT(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer == buffer);
    TEST_CHECK(context->read_buffer == buffer);
    TEST_CHECK(context->input_buffer_size == 4096);

    context->read_buffer += 1000;
    ret = flb_decompression_context_resize_buffer(context, 0);
    TEST_ASSERT(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer == buffer);
    TEST_CHECK(context->read_buffer == buffer + 1000);
    TEST_CHECK(context->input_buffer_size == 4096);

    flb_decompression_context_destroy(context);
}

static void test_context_resize_bounds(void)
{
    struct flb_decompression_context *context;
    size_t available;
    int ret;

    /* A null context must be refused rather than dereferenced. */
    ret = flb_decompression_context_resize_buffer(NULL, 1024);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 4096);
    TEST_ASSERT(context != NULL);

    memset(flb_decompression_context_get_append_buffer(context), 'a', 3000);
    context->input_buffer_length = 3000;

    /* A size below the resident length stays refused. */
    ret = flb_decompression_context_resize_buffer(context, 2999);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(context->input_buffer_size == 4096);

    /* Growing tracks input_buffer_size even when realloc() keeps the address. */
    ret = flb_decompression_context_resize_buffer(context, 8192);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_size == 8192);

    available = flb_decompression_context_get_available_space(context);
    TEST_CHECK(available == 8192 - 3000);

    /* Move the cursor: resident data now occupies [1000, 3000). */
    context->read_buffer += 1000;
    context->input_buffer_length = 2000;

    /* offset + length is 3000, so a smaller size would drop live bytes. */
    ret = flb_decompression_context_resize_buffer(context, 2999);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(context->input_buffer_size == 8192);

    /* The exact minimum is accepted and the tail survives intact. */
    ret = flb_decompression_context_resize_buffer(context, 3000);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_size == 3000);
    TEST_CHECK(context->input_buffer_length == 2000);
    TEST_CHECK((size_t) (context->read_buffer - context->input_buffer) == 1000);
    TEST_CHECK(context->read_buffer[0] == 'a');
    TEST_CHECK(context->read_buffer[1999] == 'a');

    available = flb_decompression_context_get_available_space(context);
    TEST_CHECK(available == 0);

    flb_decompression_context_destroy(context);
}

static void test_gzip_optional_field_boundaries(void)
{
    struct flb_decompression_context *context;
    unsigned char *compressed;
    unsigned char header[14];
    char output[3];
    uint32_t crc;
    size_t compressed_size;
    size_t output_size;
    size_t offset;
    size_t length;
    int ret;

    ret = flb_gzip_compress("abc", 3, (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    memcpy(header, compressed, 10);
    header[3] = 0x06; /* FEXTRA and FHCRC. */
    header[10] = 0;
    header[11] = 0;
    crc = mz_crc32(MZ_CRC32_INIT, header, 12);
    header[12] = crc & 0xff;
    header[13] = (crc >> 8) & 0xff;

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP,
                                               compressed_size + sizeof(header));
    TEST_ASSERT(context != NULL);

    /* Deliver the fixed header, the empty extra field and the checksum separately. */
    for (offset = 0; offset < sizeof(header); offset += length) {
        length = offset == 0 ? 10 : 2;
        memcpy(flb_decompression_context_get_append_buffer(context), header + offset, length);
        context->input_buffer_length += length;
        output_size = sizeof(output);
        ret = flb_decompress(context, output, &output_size);
        TEST_CHECK(decompress_waited_or_succeeded(ret));
        TEST_CHECK(output_size == 0);
    }
    TEST_CHECK(context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_BODY);

    length = compressed_size - 10;
    memcpy(flb_decompression_context_get_append_buffer(context), compressed + 10, length);
    context->input_buffer_length += length;
    output_size = sizeof(output);
    ret = flb_decompress(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_ASSERT(output_size == sizeof(output));
    TEST_CHECK(memcmp(output, "abc", sizeof(output)) == 0);
    TEST_CHECK(context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER);

    flb_decompression_context_destroy(context);
    flb_free(compressed);
}

static void test_gzip_footer_failure(void)
{
    struct flb_decompression_context *context;
    unsigned char *compressed;
    size_t compressed_size;
    size_t output_size;
    char output[16];
    int ret;

    ret = flb_gzip_compress("abc", 3, (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, compressed_size);
    TEST_ASSERT(context != NULL);
    compressed[compressed_size - 1] ^= 1;
    memcpy(context->input_buffer, compressed, compressed_size);
    context->input_buffer_length = compressed_size;
    flb_free(compressed);

    output_size = 0;
    ret = flb_gzip_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_length == compressed_size);

    output_size = sizeof(output);
    ret = flb_gzip_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output_size == 0);
    TEST_CHECK(context->state == FLB_DECOMPRESSOR_STATE_FAILED);

    output_size = sizeof(output);
    ret = flb_gzip_decompressor_dispatch(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output_size == 0);
    ret = flb_decompress(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(output_size == 0);
    flb_decompression_context_destroy(context);
}

static void test_gzip_header_boundary_resume(void)
{
    struct flb_decompression_context *context;
    unsigned char *compressed;
    size_t compressed_size;
    size_t output_size;
    size_t total;
    size_t offset;
    char original[] = "payload that survives a header sized delivery";
    char output[128];
    int ret;

    /* flb_gzip_compress() writes no optional header fields, so the fixed header
     * is 10 bytes and a delivery of exactly that size stops at its end. */
    ret = flb_gzip_compress(original, sizeof(original) - 1,
                            (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(compressed_size > 10);
    TEST_ASSERT(compressed[3] == 0x00);

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 4096);
    TEST_ASSERT(context != NULL);

    /* Stopping at the end of the header must be reported as 'need more data'
     * rather than pinning the context to the failed state. */
    memcpy(flb_decompression_context_get_append_buffer(context), compressed, 10);
    context->input_buffer_length += 10;

    output_size = sizeof(output);
    ret = flb_decompress(context, output, &output_size);
    /* This is the assertion the C-1 fix wanted all along: a boundary at the end of
     * the header is reported as a wait. While INSUFFICIENT_DATA aliased SUCCESS it
     * was indistinguishable from "the member finished". */
    TEST_CHECK(ret == FLB_DECOMPRESSOR_INSUFFICIENT_DATA);
    TEST_CHECK(output_size == 0);
    TEST_CHECK(context->state != FLB_DECOMPRESSOR_STATE_FAILED);

    /* The same context has to decode the member once the rest arrives. */
    memcpy(flb_decompression_context_get_append_buffer(context),
           compressed + 10, compressed_size - 10);
    context->input_buffer_length += compressed_size - 10;

    output_size = sizeof(output);
    ret = flb_decompress(context, output, &output_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(output_size == sizeof(original) - 1);
    if (output_size == sizeof(original) - 1) {
        TEST_CHECK(memcmp(output, original, output_size) == 0);
    }

    flb_decompression_context_destroy(context);

    /* One byte at a time keeps every split point resumable. */
    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 64);
    TEST_ASSERT(context != NULL);

    total = 0;
    for (offset = 0; offset < compressed_size; offset++) {
        memcpy(flb_decompression_context_get_append_buffer(context),
               &compressed[offset], 1);
        context->input_buffer_length += 1;

        while (context->input_buffer_length > 0 && total < sizeof(output)) {
            output_size = sizeof(output) - total;
            ret = flb_decompress(context, output + total, &output_size);
            TEST_CHECK(decompress_waited_or_succeeded(ret));
            if (!decompress_waited_or_succeeded(ret)) {
                break;
            }

            total += output_size;
            if (output_size == 0) {
                break;
            }
        }

        TEST_CHECK(context->state != FLB_DECOMPRESSOR_STATE_FAILED);
    }

    TEST_CHECK(total == sizeof(original) - 1);
    if (total == sizeof(original) - 1) {
        TEST_CHECK(memcmp(output, original, total) == 0);
    }

    flb_decompression_context_destroy(context);
    flb_free(compressed);
}

/* Append one framed chunk: type byte, 24-bit little-endian length, payload. */
static void snappy_append_chunk(unsigned char **stream, size_t *stream_size,
                                unsigned char type,
                                const unsigned char *payload, size_t payload_size)
{
    unsigned char header[4];
    unsigned char *grown;

    grown = flb_realloc(*stream, *stream_size + 4 + payload_size);
    TEST_ASSERT(grown != NULL);
    *stream = grown;

    header[0] = type;
    header[1] = (unsigned char) (payload_size & 0xff);
    header[2] = (unsigned char) ((payload_size >> 8) & 0xff);
    header[3] = (unsigned char) ((payload_size >> 16) & 0xff);
    memcpy(*stream + *stream_size, header, 4);
    if (payload_size > 0) {
        memcpy(*stream + *stream_size + 4, payload, payload_size);
    }
    *stream_size += 4 + payload_size;
}

/* Uncompressed-data chunk: masked crc32c of the raw block, then the block. */
static void snappy_append_data_chunk(unsigned char **stream, size_t *stream_size,
                                     const unsigned char *payload, size_t payload_size)
{
    uint32_t checksum;
    unsigned char *chunk;

    chunk = flb_malloc(4 + payload_size);
    TEST_ASSERT(chunk != NULL);

    checksum = cfl_checksum_crc32c((unsigned char *) payload, payload_size);
    checksum = ((checksum >> 15) | (checksum << 17)) + 0xa282ead8u;

    chunk[0] = (unsigned char) (checksum & 0xff);
    chunk[1] = (unsigned char) ((checksum >> 8) & 0xff);
    chunk[2] = (unsigned char) ((checksum >> 16) & 0xff);
    chunk[3] = (unsigned char) ((checksum >> 24) & 0xff);
    memcpy(chunk + 4, payload, payload_size);

    snappy_append_chunk(stream, stream_size, FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA,
                        chunk, 4 + payload_size);
    flb_free(chunk);
}

static void snappy_begin_stream(unsigned char **stream, size_t *stream_size)
{
    snappy_append_chunk(stream, stream_size, FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER,
                        (const unsigned char *) "sNaPpY", 6);
}

/* Compressed-data chunk: masked crc32c of the expanded block, then a Snappy
 * block-format bitstream (which carries its own varint length preamble). */
static void snappy_append_compressed_chunk(unsigned char **stream, size_t *stream_size,
                                           const unsigned char *payload, size_t payload_size)
{
    uint32_t checksum;
    char *block = NULL;
    size_t block_size = 0;
    unsigned char *chunk;
    int ret;

    ret = flb_snappy_compress((char *) payload, payload_size, &block, &block_size);
    TEST_ASSERT(ret == 0);

    chunk = flb_malloc(4 + block_size);
    TEST_ASSERT(chunk != NULL);

    checksum = cfl_checksum_crc32c((unsigned char *) payload, payload_size);
    checksum = ((checksum >> 15) | (checksum << 17)) + 0xa282ead8u;

    chunk[0] = (unsigned char) (checksum & 0xff);
    chunk[1] = (unsigned char) ((checksum >> 8) & 0xff);
    chunk[2] = (unsigned char) ((checksum >> 16) & 0xff);
    chunk[3] = (unsigned char) ((checksum >> 24) & 0xff);
    memcpy(chunk + 4, block, block_size);

    snappy_append_chunk(stream, stream_size, FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA,
                        chunk, 4 + block_size);
    flb_free(chunk);
    flb_free(block);
}

/* Read a Snappy block-format varint, used to recover the expanded size a
 * compressed-data chunk advertises without decoding it. */
static int snappy_read_varint(const unsigned char *data, size_t size, size_t *value)
{
    size_t shift = 0;
    size_t result = 0;
    size_t i;

    for (i = 0; i < size && i < 5; i++) {
        result |= ((size_t) (data[i] & 0x7f)) << shift;
        if ((data[i] & 0x80) == 0) {
            *value = result;
            return FLB_TRUE;
        }
        shift += 7;
    }

    return FLB_FALSE;
}

/* Walk a fixture built by this suite independently of the decoder: report the
 * offset just past the last chunk wholly contained in the first size bytes and
 * how many bytes those chunks expand to. */
static void snappy_stream_prefix(const unsigned char *stream, size_t size,
                                 size_t *span, size_t *expanded)
{
    size_t offset = 0;
    size_t length;
    size_t block_size;
    unsigned char type;

    *span = 0;
    *expanded = 0;

    while (size - offset >= 4) {
        type = stream[offset];
        length = ((size_t) stream[offset + 1]) | ((size_t) stream[offset + 2] << 8) |
                 ((size_t) stream[offset + 3] << 16);

        if (length > size - offset - 4) {
            break;
        }
        if (type == FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA && length >= 4) {
            *expanded += length - 4;
        }
        else if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA && length >= 4 &&
                 snappy_read_varint(stream + offset + 8, length - 4, &block_size)) {
            *expanded += block_size;
        }
        offset += 4 + length;
    }

    *span = offset;
}

/* Append input to a streaming context in feed_step increments, draining after
 * every append. Returns the bytes delivered and flags any error return or a
 * decoder that cannot advance without more input. */
static size_t snappy_stream_pump(struct flb_decompression_context *context,
                                 const unsigned char *input, size_t input_size,
                                 size_t feed_step,
                                 unsigned char *output, size_t output_capacity,
                                 int *failed)
{
    size_t appended = 0;
    size_t delivered = 0;
    size_t available;
    size_t append_size;
    size_t previous_input;
    size_t produced;
    int ret;

    while (appended < input_size || context->input_buffer_length > 0) {
        if (appended < input_size) {
            available = flb_decompression_context_get_available_space(context);
            append_size = feed_step;
            if (append_size > input_size - appended) {
                append_size = input_size - appended;
            }
            if (append_size > available) {
                append_size = available;
            }
            if (append_size == 0) {
                *failed = FLB_TRUE;
                break;
            }
            memcpy(flb_decompression_context_get_append_buffer(context),
                   input + appended, append_size);
            context->input_buffer_length += append_size;
            appended += append_size;
        }

        previous_input = context->input_buffer_length;
        produced = output_capacity - delivered;
        if (produced == 0) {
            *failed = FLB_TRUE;
            break;
        }
        ret = flb_decompress(context, output + delivered, &produced);
        if (!decompress_waited_or_succeeded(ret)) {
            *failed = FLB_TRUE;
            break;
        }
        delivered += produced;

        /* Same no-progress rule the production callers apply, relaxed only while
         * input is still queued to hand over: waiting for more bytes is correct
         * behaviour there, not a stall. */
        if (produced == 0 && previous_input == context->input_buffer_length &&
            appended == input_size) {
            break;
        }
    }

    return delivered;
}

static void test_snappy_empty_and_invalid_context(void)
{
    struct flb_decompression_context *context;
    const unsigned char raw_block[] = {3, 8, 'a', 'b', 'c'};
    unsigned char output = 0xff;
    size_t produced = 1;
    void *backend;
    int ret;

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY, 16);
    TEST_ASSERT(context != NULL);
    context->input_buffer[0] = 0; /* Raw Snappy length prefix for an empty block. */
    context->input_buffer_length = 1;
    context->output_limit = 0;

    backend = context->inner_context;
    context->inner_context = NULL;
    ret = flb_decompress(context, &output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(produced == 0);
    TEST_CHECK(context->input_buffer_length == 1);
    context->inner_context = backend;

    produced = 1;
    ret = flb_decompress(context, &output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(produced == 0);
    TEST_CHECK(output == 0xff);
    TEST_CHECK(context->input_buffer_length == 0);
    memcpy(flb_decompression_context_get_append_buffer(context), raw_block, sizeof(raw_block));
    context->input_buffer_length = sizeof(raw_block);
    context->output_limit = 3;
    produced = 1;
    ret = flb_decompress(context, &output, &produced);
    TEST_ASSERT(ret == FLB_DECOMPRESSOR_SUCCESS && produced == 1);
    TEST_CHECK(output == 'a');

    /* An inconsistent resident span must fail before copying cached output. */
    context->input_buffer_length--;
    produced = 1;
    ret = flb_decompress(context, &output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(produced == 0);
    TEST_CHECK(output == 'a');
    TEST_CHECK(context->state == FLB_DECOMPRESSOR_STATE_FAILED);
    flb_decompression_context_destroy(context);
}

/* A payload arriving while an earlier decode is still being drained must not be
 * retired together with the span that decode already consumed. */
static void test_snappy_append_during_drain(void)
{
    struct flb_decompression_context *context;
    unsigned char payload_a[300];
    unsigned char payload_b[211];
    unsigned char *stream_a = NULL;
    unsigned char *stream_b = NULL;
    size_t stream_a_size = 0;
    size_t stream_b_size = 0;
    unsigned char output[512];
    size_t delivered = 0;
    size_t produced;
    int ret;

    memset(payload_a, 'A', sizeof(payload_a));
    memset(payload_b, 'B', sizeof(payload_b));

    snappy_begin_stream(&stream_a, &stream_a_size);
    snappy_append_data_chunk(&stream_a, &stream_a_size, payload_a, sizeof(payload_a));
    snappy_begin_stream(&stream_b, &stream_b_size);
    snappy_append_data_chunk(&stream_b, &stream_b_size, payload_b, sizeof(payload_b));

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY, 8192);
    TEST_ASSERT(context != NULL);

    /* Deliver stream A, decode it, then drain only part of its output. */
    memcpy(flb_decompression_context_get_append_buffer(context), stream_a, stream_a_size);
    context->input_buffer_length += stream_a_size;

    produced = 16;
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(produced == 16);
    delivered += produced;

    /* A second payload arrives while the first is still being drained. */
    memcpy(flb_decompression_context_get_append_buffer(context), stream_b, stream_b_size);
    context->input_buffer_length += stream_b_size;

    while (context->input_buffer_length > 0 && delivered < sizeof(output)) {
        produced = sizeof(output) - delivered;
        ret = flb_decompress(context, output + delivered, &produced);
        if (ret != FLB_DECOMPRESSOR_SUCCESS || produced == 0) {
            break;
        }
        delivered += produced;
    }

    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(delivered == sizeof(payload_a) + sizeof(payload_b));
    if (delivered == sizeof(payload_a) + sizeof(payload_b)) {
        TEST_CHECK(memcmp(output, payload_a, sizeof(payload_a)) == 0);
        TEST_CHECK(memcmp(output + sizeof(payload_a), payload_b, sizeof(payload_b)) == 0);
    }

    flb_decompression_context_destroy(context);
    flb_free(stream_a);
    flb_free(stream_b);
}

/* Waiting for input has to be observable and must never be credited as a
 * completed decode: it used to alias SUCCESS, which is how a delivery boundary
 * inside a gzip header got written off as corruption. */
static void test_insufficient_data_is_not_success(void)
{
    struct flb_decompression_context *context;
    char original[4096];
    char output[8192];
    unsigned char *stream = NULL;
    size_t stream_size = 0;
    void *compressed = NULL;
    size_t compressed_size = 0;
    size_t delivered = 0;
    size_t produced;
    size_t cut;
    size_t waits = 0;
    int ret;

    /* The contract: a wait is neither success nor an error. */
    TEST_CHECK(FLB_DECOMPRESSOR_INSUFFICIENT_DATA != FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(FLB_DECOMPRESSOR_INSUFFICIENT_DATA > 0);
    TEST_CHECK(FLB_DECOMPRESSOR_FAILURE < 0);
    TEST_CHECK(FLB_DECOMPRESSOR_LIMIT_EXCEEDED < 0);
    TEST_CHECK(FLB_DECOMPRESSOR_ALLOCATION_FAILURE < 0);

    memset(original, 'y', sizeof(original));
    ret = flb_gzip_compress(original, sizeof(original), &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);

    /* Every prefix of a member: never an error, output budget credited exactly by
     * what was handed out, and at least one boundary reported as a wait. */
    for (cut = 1; cut < compressed_size; cut++) {
        context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP,
                                                   compressed_size + 32);
        TEST_ASSERT(context != NULL);

        memcpy(flb_decompression_context_get_append_buffer(context), compressed, cut);
        context->input_buffer_length += cut;

        produced = sizeof(output);
        ret = flb_decompress(context, output, &produced);

        TEST_CHECK(decompress_waited_or_succeeded(ret));
        TEST_CHECK(context->state != FLB_DECOMPRESSOR_STATE_FAILED);
        /* Bytes emitted alongside a wait still count against the budget. */
        TEST_CHECK(context->output_size == produced);
        if (ret == FLB_DECOMPRESSOR_INSUFFICIENT_DATA) {
            waits++;
        }

        /* Completing the member must deliver everything, exactly once. */
        memcpy(flb_decompression_context_get_append_buffer(context),
               (unsigned char *) compressed + cut, compressed_size - cut);
        context->input_buffer_length += compressed_size - cut;
        delivered = produced;

        while (context->input_buffer_length > 0 && delivered < sizeof(output)) {
            produced = sizeof(output) - delivered;
            ret = flb_decompress(context, output + delivered, &produced);
            if (!decompress_waited_or_succeeded(ret)) {
                break;
            }
            delivered += produced;
            if (produced == 0 && context->input_buffer_length > 0) {
                break;
            }
        }

        TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
        TEST_CHECK(delivered == sizeof(original));
        if (delivered == sizeof(original)) {
            TEST_CHECK(memcmp(output, original, delivered) == 0);
        }
        TEST_CHECK(context->output_size == sizeof(original));

        flb_decompression_context_destroy(context);
    }

    TEST_CHECK(waits > 0);
    flb_free(compressed);

    /* A framed stream cut inside a chunk reports the wait explicitly. */
    memset(original, 'z', 300);
    snappy_begin_stream(&stream, &stream_size);
    snappy_append_data_chunk(&stream, &stream_size, (unsigned char *) original, 300);

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY,
                                               stream_size + 32);
    TEST_ASSERT(context != NULL);

    /* Identifier plus a data-chunk header whose payload never arrives. */
    memcpy(flb_decompression_context_get_append_buffer(context), stream, 14);
    context->input_buffer_length += 14;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);

    memcpy(flb_decompression_context_get_append_buffer(context), stream + 14, 20);
    context->input_buffer_length += 20;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_INSUFFICIENT_DATA);
    TEST_CHECK(produced == 0);
    /* The identifier was retired by the first decode and the incomplete chunk
     * (its 4-byte header plus these 16 payload bytes) is kept for the rest. */
    TEST_CHECK(context->input_buffer_length == 24);

    flb_decompression_context_destroy(context);
    flb_free(stream);
}

/* A one-shot caller has declared the input complete, so a decoder that cannot
 * advance has run out of stream: that must surface as a failure. */
static void test_complete_input_maps_wait_to_failure(void)
{
    unsigned char *compressed = NULL;
    size_t compressed_size = 0;
    void *payload = NULL;
    size_t payload_size = 0;
    int ret;

    ret = flb_gzip_compress("abcdefghij", 10, (void **) &compressed, &compressed_size);
    TEST_ASSERT(ret == 0);

    /* Whole member: succeeds. */
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP, compressed,
                                compressed_size, 4096, &payload, &payload_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(payload_size == 10);
    flb_free(payload);
    payload = NULL;

    /* Keep ISIZE so the budget check passes, but leave the decoder four footer bytes short. */
    TEST_ASSERT(compressed_size >= 8);
    memmove(compressed + compressed_size - 8, compressed + compressed_size - 4, 4);
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP, compressed,
                                compressed_size - 4, 4096, &payload, &payload_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(payload == NULL && payload_size == 0);

    /* Header only: also a failure rather than "nothing to do". */
    ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP, compressed,
                                10, 4096, &payload, &payload_size);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(payload == NULL && payload_size == 0);

    flb_free(compressed);
}

/* Framed chunks are self-delimiting, so everything complete must be delivered
 * before the rest of the stream arrives. */
static void test_snappy_streaming_framed(void)
{
    struct flb_decompression_context *context;
    static const size_t feed_steps[] = {1, 2, 3, 5, 7, 11, 64, 997};
    unsigned char payload_a[300];
    unsigned char payload_b[1200];
    unsigned char payload_c[211];
    unsigned char expected[sizeof(payload_a) + sizeof(payload_b) + sizeof(payload_c)];
    unsigned char output[4096];
    unsigned char *stream = NULL;
    size_t stream_size = 0;
    size_t delivered;
    size_t i;
    int failed;

    memset(payload_a, 'A', sizeof(payload_a));
    for (i = 0; i < sizeof(payload_b); i++) {
        payload_b[i] = (unsigned char) ('a' + (i % 16));
    }
    memset(payload_c, 'C', sizeof(payload_c));

    snappy_begin_stream(&stream, &stream_size);
    snappy_append_data_chunk(&stream, &stream_size, payload_a, sizeof(payload_a));
    snappy_append_compressed_chunk(&stream, &stream_size, payload_b, sizeof(payload_b));
    /* Skippable and padding chunks carry no output but must not stall the flow. */
    snappy_append_chunk(&stream, &stream_size,
                        FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_BASE + 5,
                        (const unsigned char *) "meta", 4);
    snappy_append_chunk(&stream, &stream_size, FLB_SNAPPY_FRAME_TYPE_PADDING,
                        (const unsigned char *) "\0\0\0\0\0\0", 6);
    snappy_append_data_chunk(&stream, &stream_size, payload_c, sizeof(payload_c));

    memcpy(expected, payload_a, sizeof(payload_a));
    memcpy(expected + sizeof(payload_a), payload_b, sizeof(payload_b));
    memcpy(expected + sizeof(payload_a) + sizeof(payload_b), payload_c, sizeof(payload_c));

    for (i = 0; i < sizeof(feed_steps) / sizeof(feed_steps[0]); i++) {
        context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY,
                                                   stream_size + 32);
        TEST_ASSERT(context != NULL);

        failed = FLB_FALSE;
        delivered = snappy_stream_pump(context, stream, stream_size, feed_steps[i],
                                       output, sizeof(output), &failed);

        TEST_CHECK(failed == FLB_FALSE);
        TEST_CHECK(delivered == sizeof(expected));
        if (delivered == sizeof(expected)) {
            TEST_CHECK(memcmp(output, expected, sizeof(expected)) == 0);
        }
        TEST_CHECK(context->input_buffer_length == 0);

        flb_decompression_context_destroy(context);
    }

    flb_free(stream);
}

/* A framed stream cut inside a chunk must wait for the remainder instead of
 * failing, keep the partial bytes resident, and finish once they arrive. */
static void test_snappy_truncated_stream_waits(void)
{
    struct flb_decompression_context *context;
    unsigned char payload_a[300];
    unsigned char payload_c[211];
    unsigned char expected[sizeof(payload_a) + sizeof(payload_c)];
    unsigned char output[4096];
    unsigned char *stream = NULL;
    size_t stream_size = 0;
    size_t delivered;
    size_t total;
    size_t span;
    size_t expanded;
    size_t cut;
    int failed;

    memset(payload_a, 'A', sizeof(payload_a));
    memset(payload_c, 'C', sizeof(payload_c));

    snappy_begin_stream(&stream, &stream_size);
    snappy_append_data_chunk(&stream, &stream_size, payload_a, sizeof(payload_a));
    snappy_append_chunk(&stream, &stream_size,
                        FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_BASE + 5,
                        (const unsigned char *) "meta", 4);
    snappy_append_data_chunk(&stream, &stream_size, payload_c, sizeof(payload_c));

    memcpy(expected, payload_a, sizeof(payload_a));
    memcpy(expected + sizeof(payload_a), payload_c, sizeof(payload_c));
    total = sizeof(expected);

    for (cut = 1; cut < stream_size; cut++) {
        snappy_stream_prefix(stream, cut, &span, &expanded);

        context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY,
                                                   stream_size + 32);
        TEST_ASSERT(context != NULL);

        failed = FLB_FALSE;
        delivered = snappy_stream_pump(context, stream, cut, cut,
                                       output, sizeof(output), &failed);

        TEST_CHECK(failed == FLB_FALSE);
        TEST_CHECK(delivered == expanded);
        /* Only the trailing fragment stays resident and waits for its bytes. */
        TEST_CHECK(context->input_buffer_length == cut - span);

        delivered += snappy_stream_pump(context, stream + cut, stream_size - cut,
                                        stream_size - cut,
                                        output + delivered, sizeof(output) - delivered,
                                        &failed);

        TEST_CHECK(failed == FLB_FALSE);
        TEST_CHECK(delivered == total);
        if (delivered == total) {
            TEST_CHECK(memcmp(output, expected, total) == 0);
        }
        TEST_CHECK(context->input_buffer_length == 0);

        flb_decompression_context_destroy(context);
    }

    flb_free(stream);
}

/* Declaring the input complete keeps the one-shot contract: a fragment at the
 * end of a framed stream stays corruption, not a chunk boundary. */
static void test_snappy_complete_input_stays_one_shot(void)
{
    struct flb_decompression_context *context;
    unsigned char payload[300];
    unsigned char output[512];
    unsigned char *stream = NULL;
    size_t stream_size = 0;
    size_t produced;
    int ret;

    memset(payload, 'A', sizeof(payload));

    snappy_begin_stream(&stream, &stream_size);
    snappy_append_data_chunk(&stream, &stream_size, payload, sizeof(payload));

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY,
                                               stream_size + 32);
    TEST_ASSERT(context != NULL);
    context->input_complete = FLB_TRUE;

    memcpy(flb_decompression_context_get_append_buffer(context),
           stream, stream_size - 1);
    context->input_buffer_length += stream_size - 1;

    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);

    TEST_CHECK(ret == FLB_DECOMPRESSOR_FAILURE);
    TEST_CHECK(produced == 0);
    TEST_CHECK(context->input_buffer_length == stream_size - 1);

    flb_decompression_context_destroy(context);
    flb_free(stream);
}

/*
 * A resume point is only durable where a fresh decoder can start from scratch, so
 * the predicate has to distinguish "nothing resident" from "a new payload can
 * begin here". These are the positions in_tail persists.
 */
static void test_payload_boundary_predicate(void)
{
    struct flb_decompression_context *context;
    char original[2048];
    char output[8192];
    unsigned char *gzip_frame = NULL;
    unsigned char *gzip_second = NULL;
    unsigned char *zstd_frame = NULL;
    unsigned char *snappy_stream = NULL;
    size_t snappy_stream_size = 0;
    size_t gzip_size = 0;
    size_t gzip_second_size = 0;
    size_t zstd_size = 0;
    size_t produced;
    int ret;

    memset(original, 'k', sizeof(original));

    /* No context means no answer, and never "resumable". */
    TEST_CHECK(flb_decompression_context_at_payload_boundary(NULL) == FLB_FALSE);

    ret = flb_gzip_compress(original, sizeof(original), (void **) &gzip_frame,
                            &gzip_size);
    TEST_ASSERT(ret == 0);
    ret = flb_gzip_compress("second member", 13, (void **) &gzip_second,
                            &gzip_second_size);
    TEST_ASSERT(ret == 0);
    ret = flb_zstd_compress(original, sizeof(original), (void **) &zstd_frame,
                            &zstd_size);
    TEST_ASSERT(ret == 0);

    /* --- gzip: resumable only once a member has been fully retired --- */

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP,
                                               gzip_size + gzip_second_size + 64);
    TEST_ASSERT(context != NULL);

    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    /* A partial header is still "expecting a header", but bytes are held, so the
     * position after them is not a start. */
    memcpy(flb_decompression_context_get_append_buffer(context), gzip_frame, 4);
    context->input_buffer_length += 4;
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    /* Completing only the fixed header is the exact position that used to be
     * persisted and then poisoned the file: nothing is resident, yet inflate
     * state cannot be rebuilt from it. */
    memcpy(flb_decompression_context_get_append_buffer(context), gzip_frame + 4, 6);
    context->input_buffer_length += 6;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    /* Finish the member and it becomes a boundary again. */
    memcpy(flb_decompression_context_get_append_buffer(context),
           gzip_frame + 10, gzip_size - 10);
    context->input_buffer_length += gzip_size - 10;

    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    /* Two members in one span: the first decode retires only the first, and a
     * boundary with undecoded bytes still held is not resumable. */
    memcpy(flb_decompression_context_get_append_buffer(context), gzip_frame, gzip_size);
    memcpy(flb_decompression_context_get_append_buffer(context) + gzip_size,
           gzip_second, gzip_second_size);
    context->input_buffer_length += gzip_size + gzip_second_size;

    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_CHECK(context->input_buffer_length == gzip_second_size);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    /* Corruption is terminal: a failed context can never resume anywhere. */
    memcpy(flb_decompression_context_get_append_buffer(context), "not gzip at all", 15);
    context->input_buffer_length += 15;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret < 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    flb_decompression_context_destroy(context);

    /* --- zstd: resumable at a frame boundary only --- */

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_ZSTD,
                                               zstd_size * 2 + 64);
    TEST_ASSERT(context != NULL);

    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    /* Half a frame: the frame size is not resolvable yet, so only the resident
     * span keeps this from looking like a start. */
    memcpy(flb_decompression_context_get_append_buffer(context), zstd_frame,
           zstd_size / 2);
    context->input_buffer_length += zstd_size / 2;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    memcpy(flb_decompression_context_get_append_buffer(context),
           zstd_frame + zstd_size / 2, zstd_size - zstd_size / 2);
    context->input_buffer_length += zstd_size - zstd_size / 2;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    /* Second frame still resident after the first retires. */
    memcpy(flb_decompression_context_get_append_buffer(context), zstd_frame, zstd_size);
    memcpy(flb_decompression_context_get_append_buffer(context) + zstd_size,
           zstd_frame, zstd_size);
    context->input_buffer_length += zstd_size * 2;

    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_length == zstd_size);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);
    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    flb_decompression_context_destroy(context);

    /* --- framed Snappy: only the start of a stream is resumable --- */

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_SNAPPY, 256);
    TEST_ASSERT(context != NULL);

    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_TRUE);

    /* The stream identifier retires on its own decode, leaving nothing resident
     * at a clean chunk boundary. Framing is only recognised through that leading
     * identifier, so from here on no later position can be resumed from. */
    snappy_begin_stream(&snappy_stream, &snappy_stream_size);

    memcpy(flb_decompression_context_get_append_buffer(context),
           snappy_stream, snappy_stream_size);
    context->input_buffer_length += snappy_stream_size;
    produced = sizeof(output);
    ret = flb_decompress(context, output, &produced);
    TEST_CHECK(decompress_waited_or_succeeded(ret));
    TEST_CHECK(context->input_buffer_length == 0);
    TEST_CHECK(flb_decompression_context_at_payload_boundary(context) == FLB_FALSE);

    flb_decompression_context_destroy(context);

    flb_free(snappy_stream);
    flb_free(gzip_frame);
    flb_free(gzip_second);
    flb_free(zstd_frame);
}

TEST_LIST = {
    {"bounded_codecs", test_bounded_codecs},
    {"advertised_sizes", test_advertised_sizes},
    {"invalid_input", test_invalid_input},
    {"snappy_framed_checksum", test_snappy_framed_checksum},
    {"snappy_legacy_framed", test_snappy_legacy_framed},
    {"context_output_growth", test_context_output_growth},
    {"zstd_window_budget", test_zstd_window_budget},
    {"gzip_optional_header", test_gzip_optional_header},
    {"context_resize_empty", test_context_resize_empty},
    {"dispatcher_argument_validation", test_dispatcher_argument_validation},
    {"zstd_dispatcher_argument_validation", test_zstd_dispatcher_argument_validation},
    {"snappy_empty_and_invalid_context", test_snappy_empty_and_invalid_context},
    {"snappy_append_during_drain", test_snappy_append_during_drain},
    {"snappy_streaming_framed", test_snappy_streaming_framed},
    {"snappy_truncated_stream_waits", test_snappy_truncated_stream_waits},
    {"snappy_complete_input_stays_one_shot", test_snappy_complete_input_stays_one_shot},
    {"reserve_covers_the_read_cursor", test_reserve_covers_the_read_cursor},
    {"insufficient_data_is_not_success", test_insufficient_data_is_not_success},
    {"complete_input_maps_wait_to_failure", test_complete_input_maps_wait_to_failure},
    {"context_resize_bounds", test_context_resize_bounds},
    {"gzip_optional_field_boundaries", test_gzip_optional_field_boundaries},
    {"gzip_footer_failure", test_gzip_footer_failure},
    {"gzip_header_boundary_resume", test_gzip_header_boundary_resume},
    {"payload_boundary_predicate", test_payload_boundary_predicate},
    {0}
};
