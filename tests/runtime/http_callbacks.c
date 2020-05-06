/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_http_client.h>

#include "flb_tests_runtime.h"

static void debug_cb_request_headers(char *name, void *p1, void *p2)
{
    struct flb_http_client *c = p1;

    fprintf(stderr, "[http] request headers\n%s", c->header_buf);
}

void flb_test_http_callbacks()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "1",
                    "Grace", "5",
                    "Daemon", "false",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd, "samples", "1", NULL);

    out_ffd = flb_output(ctx, (char *) "http", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "host", "google.com",
                   "port", "80",
                   "uri" , "/",
                   NULL);

    flb_output_set_callback(ctx, out_ffd, "_debug.http.request_headers",
                            debug_cb_request_headers);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(5);

    flb_stop(ctx);
    flb_destroy(ctx);

}

/* Test list */
TEST_LIST = {
    {"http_callbacks", flb_test_http_callbacks },
    {NULL, NULL}
};
