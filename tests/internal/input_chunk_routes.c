#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_mem.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_utils.h>
#include <string.h>

#include "flb_tests_internal.h"

#define TEST_STREAM_PATH "/tmp/flb-chunk-direct-test"

static int write_legacy_chunk_metadata(struct cio_chunk *chunk,
                                       int event_type,
                                       const char *tag,
                                       int tag_len)
{
    int ret;
    int meta_size;
    char *meta;

    meta_size = FLB_INPUT_CHUNK_META_HEADER + tag_len;
    meta = flb_malloc(meta_size);
    if (!meta) {
        flb_errno();
        return -1;
    }

    meta[0] = FLB_INPUT_CHUNK_MAGIC_BYTE_0;
    meta[1] = FLB_INPUT_CHUNK_MAGIC_BYTE_1;

    if (event_type == FLB_INPUT_LOGS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_LOGS;
    }
    else if (event_type == FLB_INPUT_METRICS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_METRICS;
    }
    else if (event_type == FLB_INPUT_TRACES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_TRACES;
    }
    else if (event_type == FLB_INPUT_PROFILES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_PROFILES;
    }
    else {
        meta[2] = FLB_INPUT_CHUNK_TYPE_LOGS;
    }

    meta[3] = 0;

    memcpy(meta + FLB_INPUT_CHUNK_META_HEADER, tag, tag_len);

    ret = cio_meta_write(chunk, meta, meta_size);

    flb_free(meta);

    return ret;
}

static void test_chunk_metadata_direct_routes()
{
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct flb_input_chunk ic;
    struct flb_chunk_direct_route output_routes[2];
    struct flb_chunk_direct_route *loaded_routes;
    char *content_buf;
    const char *tag_buf;
    const char *tag_string;
    const char payload[] = "direct route payload validation string";
    int tag_len;
    int route_count;
    int ret;
    int err;
    int expected_tag_len;
    size_t content_size;
    size_t payload_size;

    payload_size = sizeof(payload) - 1;
    tag_string = "test.tag";
    expected_tag_len = strlen(tag_string);

    cio_utils_recursive_delete(TEST_STREAM_PATH);
    memset(&opts, 0, sizeof(opts));
    cio_options_init(&opts);
    opts.root_path = TEST_STREAM_PATH;
    opts.flags = CIO_OPEN;
    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    stream = cio_stream_create(ctx, "direct", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    if (!stream) {
        cio_destroy(ctx);
        return;
    }

    chunk = cio_chunk_open(ctx, stream, "meta", CIO_OPEN, 1024, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        cio_destroy(ctx);
        return;
    }

    ret = cio_chunk_is_up(chunk);
    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    tag_len = expected_tag_len;
    ret = write_legacy_chunk_metadata(chunk, FLB_INPUT_LOGS,
                                      tag_string, tag_len);
    TEST_CHECK(ret == 0);

    ret = cio_chunk_write(chunk, payload, payload_size);
    TEST_CHECK(ret == 0);

    ret = cio_chunk_get_content(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        TEST_CHECK(content_buf != NULL);
        TEST_CHECK(content_size == payload_size);
        if (content_size == payload_size) {
            TEST_CHECK(memcmp(content_buf, payload, payload_size) == 0);
        }
    }

    output_routes[0].id = 511;
    output_routes[0].label = "alpha";
    output_routes[0].label_length = 5;
    output_routes[1].id = 70000;
    output_routes[1].label = "beta";
    output_routes[1].label_length = 4;
    ret = flb_input_chunk_write_header_v2(chunk,
                                          FLB_INPUT_LOGS,
                                          (char *) tag_string,
                                          tag_len,
                                          output_routes,
                                          2);
    TEST_CHECK(ret == 0);

    memset(&ic, 0, sizeof(ic));
    ic.chunk = chunk;

    TEST_CHECK(flb_input_chunk_has_direct_routes(&ic) == FLB_TRUE);

    ret = cio_chunk_get_content(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        TEST_CHECK(content_buf != NULL);
        TEST_CHECK(content_size == payload_size);
        if (content_size == payload_size) {
            TEST_CHECK(memcmp(content_buf, payload, payload_size) == 0);
        }
    }

    ret = flb_input_chunk_get_direct_routes(&ic, &loaded_routes, &route_count);
    TEST_CHECK(ret == 0);
    TEST_CHECK(route_count == 2);
    if (ret == 0 && route_count == 2) {
        TEST_CHECK(loaded_routes != NULL);
        if (loaded_routes) {
            TEST_CHECK(loaded_routes[0].id == 511);
            TEST_CHECK(loaded_routes[1].id == 70000);
            TEST_CHECK(loaded_routes[0].label != NULL);
            TEST_CHECK(loaded_routes[1].label != NULL);
            if (loaded_routes[0].label && loaded_routes[1].label) {
                TEST_CHECK(strcmp(loaded_routes[0].label, "alpha") == 0);
                TEST_CHECK(strcmp(loaded_routes[1].label, "beta") == 0);
            }
            flb_input_chunk_destroy_direct_routes(loaded_routes, route_count);
        }
    }

    ret = flb_input_chunk_get_tag(&ic, &tag_buf, &tag_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(tag_len == expected_tag_len);
    if (ret == 0 && tag_len == expected_tag_len) {
        TEST_CHECK(memcmp(tag_buf, tag_string, expected_tag_len) == 0);
    }

    cio_chunk_close(chunk, CIO_TRUE);
    cio_destroy(ctx);
    cio_utils_recursive_delete(TEST_STREAM_PATH);
}

TEST_LIST = {
    { "chunk_metadata_direct_routes", test_chunk_metadata_direct_routes },
    { 0 }
};
