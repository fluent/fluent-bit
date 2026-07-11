/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_compression.h>

#include "flb_tests_internal.h"

/*
 * After a gzip member is consumed read_buffer sits at a non-zero offset inside
 * input_buffer. Appending another chunk that is larger than the remaining
 * window makes the caller resize the buffer and then copy the chunk at
 * get_append_buffer(). resize_buffer() reallocated to new_size while ignoring
 * the read_buffer offset, so the copy ran read_buffer_offset bytes past the end
 * of the reallocation (heap-buffer-overflow under AddressSanitizer).
 */
void test_resize_buffer_read_offset()
{
    int ret;
    void *gz = NULL;
    size_t gz_len = 0;
    size_t primed_len;
    struct flb_decompression_context *dctx;
    uint8_t *stream;
    uint8_t *append_ptr;
    char out[256];
    size_t out_len;
    size_t available;
    size_t append_len = 200;
    char *append_data;
    int iterations = 0;
    /* trailing bytes of a next (incomplete) member; keeps input pending after
     * the first member so read_buffer stays advanced instead of rewinding */
    const size_t trailing = 8;

    ret = flb_gzip_compress("fluent-bit", 10, &gz, &gz_len);
    TEST_CHECK(ret == 0);
    /* keep the consumed member within the first half of the 128 byte window so
     * get_append_buffer() does not rewind read_buffer to the base */
    TEST_CHECK(gz_len > 0 && gz_len < 64);

    primed_len = gz_len + trailing;
    stream = flb_malloc(primed_len);
    TEST_CHECK(stream != NULL);
    memcpy(stream, gz, gz_len);
    memset(stream + gz_len, 0, trailing);

    dctx = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP, 128);
    TEST_CHECK(dctx != NULL);

    append_ptr = flb_decompression_context_get_append_buffer(dctx);
    memcpy(append_ptr, stream, primed_len);
    dctx->input_buffer_length += primed_len;

    /* decompress the first member; the loop stops once the leftover trailing
     * bytes are too short to form the next header */
    do {
        out_len = sizeof(out);
        ret = flb_decompress(dctx, out, &out_len);
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            break;
        }
    } while (dctx->input_buffer_length > 0 && ++iterations < 64);

    /* read_buffer now sits at a non-zero offset with the trailing bytes pending */
    TEST_CHECK(dctx->read_buffer != dctx->input_buffer);
    TEST_CHECK(dctx->input_buffer_length == trailing);

    available = flb_decompression_context_get_available_space(dctx);
    TEST_CHECK(append_len > available);

    /* mirrors the packed-forward append in in_forward: resize to
     * input_buffer_length + len, then copy len bytes at get_append_buffer() */
    ret = flb_decompression_context_resize_buffer(
            dctx, dctx->input_buffer_length + append_len);
    TEST_CHECK(ret == FLB_DECOMPRESSOR_SUCCESS);

    append_data = flb_malloc(append_len);
    TEST_CHECK(append_data != NULL);
    memset(append_data, 'A', append_len);

    append_ptr = flb_decompression_context_get_append_buffer(dctx);
    memcpy(append_ptr, append_data, append_len);
    dctx->input_buffer_length += append_len;

    TEST_CHECK(memcmp(append_ptr, append_data, append_len) == 0);

    flb_free(append_data);
    flb_decompression_context_destroy(dctx);
    flb_free(stream);
    flb_free(gz);
}

TEST_LIST = {
    {"resize_buffer_read_offset", test_resize_buffer_read_offset},
    { 0 }
};
