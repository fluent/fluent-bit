/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <pthread.h>
#include <fluent-bit/flb_lib.h>
#include <monkey/mk_lib.h>

static void cb_root(mk_session_t *session, mk_request_t *request)
{
    (void) session;
    char *buf = "this is a test\n";
    int len = 15;

    mk_http_status(request, 200);
    mk_http_send(request, buf, len, NULL);
}

static void monkey_http_service(void *data)
{
    mk_ctx_t *ctx;
    mk_vhost_t *vh;
    struct flb_config *config = data;

    ctx = mk_create();
    if (!ctx) {
        return;
    }
    mk_config_set(ctx, "Listen", config->http_port);

    vh = mk_vhost_create(ctx, NULL);
    mk_vhost_set(vh,
                 "Name", "default",
                 NULL);
    mk_vhost_handler(vh, "/", cb_root);
    mk_start(ctx);
}


int flb_http_start(struct flb_config *config)
{
    pthread_t tid;

    tid = mk_utils_worker_spawn(monkey_http_service, config);
    return 0;
}

int flb_http_stop()
{

}
