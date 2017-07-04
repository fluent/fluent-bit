/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <monkey/mk_lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void cb_worker(void *data)
{
    printf("test worker callback; data=%p\n", data);
}

void cb_main(mk_request_t *request, void *data)
{
    char *buf = "this is a test\n";
    int len = 15;
    (void) data;

    mk_http_status(request, 200);
    mk_http_header(request, "X-Monkey", 8, "OK", 2);
    mk_http_send(request, buf, len, NULL);
}

int main()
{
    int vid;
    mk_ctx_t *ctx;

    ctx = mk_create();
    mk_config_set(ctx,
                  "Listen", "2020",
                  NULL);

    vid = mk_vhost_create(ctx, NULL);
    mk_vhost_set(ctx, vid,
                 "Name", "monotop",
                 NULL);
    mk_vhost_handler(ctx, vid, "/test", cb_main, NULL);

    mk_worker_callback(ctx,
                       cb_worker,
                       ctx);

    mk_start(ctx);

    sleep(60);

    mk_stop(ctx);

    return 0;
}
