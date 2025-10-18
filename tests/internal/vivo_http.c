/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <fluent-bit/flb_info.h>

#include "flb_tests_internal.h"

#include "plugins/out_vivo_exporter/vivo_stream.h"
#include "plugins/out_vivo_exporter/vivo_http.h"

#include <monkey/mk_core/mk_iov.h>

static void test_vivo_http_empty_stream_sets_next_id_header(void)
{
    struct vivo_exporter ctx;
    struct vivo_stream *stream;
    mk_request_t request;
    struct mk_iov *extra;
    int found = 0;
    int i;

    memset(&ctx, 0, sizeof(ctx));
    ctx.stream_queue_size = 1024;

    stream = vivo_stream_create(&ctx);
    if (!TEST_CHECK(stream != NULL)) {
        return;
    }

    memset(&request, 0, sizeof(request));

    vivo_http_serve_content(&request, stream);

    TEST_CHECK(request.headers.status == 200);

    extra = request.headers._extra_rows;
    if (!TEST_CHECK(extra != NULL)) {
        vivo_stream_destroy(stream);
        return;
    }

    for (i = 0; i < extra->buf_idx; i++) {
        char *entry = extra->buf_to_free[i];

        if (entry && strstr(entry, VIVO_STREAM_NEXT_ID) != NULL) {
            found = 1;
            break;
        }
    }

    if (!TEST_CHECK(found == 1)) {
        TEST_MSG("expected %s header to be present", VIVO_STREAM_NEXT_ID);
    }

    mk_iov_free(extra);
    vivo_stream_destroy(stream);
}

TEST_LIST = {
    {"vivo_http_empty_stream_sets_next_id_header", test_vivo_http_empty_stream_sets_next_id_header},
    {NULL, NULL}
};
