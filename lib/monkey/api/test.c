/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <monkey/mk_lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void cb_main(mk_session_t *session, mk_request_t *request)
{
    (void) session;
    char *buf = "this is a test\n";
    int len = 15;

    mk_http_status(request, 200);
    mk_http_header(request, "X-Monkey", 8, "OK", 2);
    mk_http_send(request, buf, len, NULL);
}

int main()
{
    mk_ctx_t *ctx;
    mk_vhost_t *vh;

    ctx = mk_create();
    mk_config_set(ctx, "Listen", "8080");

    vh = mk_vhost_create(ctx, NULL);
    mk_vhost_set(vh,
                 "Name", "monotop",
                 NULL);
    mk_vhost_handler(vh, "/test", cb_main);
    mk_start(ctx);

    return 0;
}
