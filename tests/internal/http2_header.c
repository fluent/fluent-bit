#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_http_common.h>
#include <nghttp2/nghttp2.h>

#include "flb_tests_internal.h"

static nghttp2_nv make_nv(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name = (uint8_t *)name;
    nv.value = (uint8_t *)value;
    nv.namelen = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static int pack_headers_frame(uint8_t **out_buf, size_t *out_len,
                              int32_t stream_id, const nghttp2_nv *nva,
                              size_t nvlen)
{
    nghttp2_hd_deflater deflater;
    nghttp2_nv *nva_copy;
    nghttp2_frame frame;
    nghttp2_bufs bufs;
    nghttp2_buf_chain *ci;
    size_t copied = 0;
    nghttp2_mem *mem = nghttp2_mem_default();
    int rv;

    rv = nghttp2_bufs_init2(&bufs, 4096, 16, NGHTTP2_FRAME_HDLEN, mem);
    if (rv != 0) {
        return rv;
    }
    rv = nghttp2_hd_deflate_init(&deflater, mem);
    if (rv != 0) {
        nghttp2_bufs_free(&bufs);
        return rv;
    }
    rv = nghttp2_nv_array_copy(&nva_copy, nva, nvlen, mem);
    if (rv != 0) {
        nghttp2_bufs_free(&bufs);
        nghttp2_hd_deflate_free(&deflater);
        return rv;
    }
    nghttp2_frame_headers_init(&frame.headers, NGHTTP2_FLAG_END_HEADERS,
                               stream_id, NGHTTP2_HCAT_RESPONSE,
                               NULL, nva_copy, nvlen);
    rv = nghttp2_frame_pack_headers(&bufs, &frame.headers, &deflater);
    nghttp2_frame_headers_free(&frame.headers, mem);
    nghttp2_nv_array_del(nva_copy, mem);
    nghttp2_hd_deflate_free(&deflater);
    if (rv != 0) {
        nghttp2_bufs_free(&bufs);
        return rv;
    }
    *out_len = nghttp2_bufs_len(&bufs);
    *out_buf = flb_malloc(*out_len);
    if (*out_buf == NULL) {
        nghttp2_bufs_free(&bufs);
        return NGHTTP2_ERR_NOMEM;
    }
    for (ci = bufs.head; ci; ci = ci->next) {
        size_t len = nghttp2_buf_len(&ci->buf);
        memcpy(*out_buf + copied, ci->buf.pos, len);
        copied += len;
    }
    nghttp2_bufs_free(&bufs);
    return 0;
}

void test_http2_duplicate_content_type()
{
    struct flb_http_client_ng client;
    struct flb_http_client_session session;
    struct flb_http_stream *stream;
    uint8_t *frame;
    size_t frame_len;
    nghttp2_nv nva1[2];
    nghttp2_nv nva2[1];
    int ret;

    memset(&client, 0, sizeof(client));
    client.temporary_buffer = cfl_sds_create_size(4096);

    ret = flb_http_client_session_init(&session, &client,
                                       HTTP_PROTOCOL_VERSION_20, NULL);
    TEST_CHECK(ret == 0);

    stream = flb_http_stream_create(&session, 1, HTTP_STREAM_ROLE_CLIENT, NULL);
    TEST_CHECK(stream != NULL);
    stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;

    nghttp2_session_set_stream_user_data(session.http2.inner_session,
                                         1, stream);

    nva1[0] = make_nv(":status", "200");
    nva1[1] = make_nv("content-type", "text/plain");
    ret = pack_headers_frame(&frame, &frame_len, 1, nva1, 2);
    TEST_CHECK(ret == 0);
    flb_http2_client_session_ingest(&session.http2, frame, frame_len);
    flb_free(frame);
    TEST_CHECK(stream->response.content_type != NULL);
    TEST_CHECK(strcmp(stream->response.content_type, "text/plain") == 0);

    nva2[0] = make_nv("content-type", "application/json");
    ret = pack_headers_frame(&frame, &frame_len, 1, nva2, 1);
    TEST_CHECK(ret == 0);
    flb_http2_client_session_ingest(&session.http2, frame, frame_len);
    flb_free(frame);
    TEST_CHECK(stream->response.content_type != NULL);
    TEST_CHECK(strcmp(stream->response.content_type, "application/json") == 0);

    flb_http_client_session_destroy(&session);
    cfl_sds_destroy(client.temporary_buffer);
}

TEST_LIST = {
    { "http2_duplicate_content_type", test_http2_duplicate_content_type },
    { 0 }
};
