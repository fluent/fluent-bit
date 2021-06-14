/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_LIB_H
#define MK_LIB_H

#define _GNU_SOURCE

#include <monkey/mk_info.h>
#include <monkey/mk_tls.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_config.h>
#include <monkey/mk_fifo.h>
#include <monkey/mk_http_internal.h>
#include <monkey/mk_core.h>

struct mk_lib_ctx {
    pthread_t worker_tid;
    struct mk_server *server;
    struct mk_fifo *fifo;
};

typedef struct mk_fifo_queue mk_mq_t;
typedef struct mk_lib_ctx mk_ctx_t;
typedef struct mk_http_request mk_request_t;
typedef struct mk_http_session mk_session_t;

MK_EXPORT int mk_start(mk_ctx_t *ctx);
MK_EXPORT int mk_stop(mk_ctx_t *ctx);

MK_EXPORT mk_ctx_t *mk_create();
MK_EXPORT int mk_destroy(mk_ctx_t *ctx);

MK_EXPORT int mk_config_set(mk_ctx_t *ctx, ...);

MK_EXPORT int mk_vhost_create(mk_ctx_t *ctx, char *name);

MK_EXPORT int mk_vhost_set(mk_ctx_t *ctx, int vid, ...);
MK_EXPORT int mk_vhost_handler(mk_ctx_t *ctx, int vid, char *regex,
                               void (*cb)(mk_request_t *, void *), void *data);

MK_EXPORT int mk_http_status(mk_request_t *req, int status);
MK_EXPORT int mk_http_header(mk_request_t *req,
                             char *key, int key_len,
                             char *val, int val_len);
MK_EXPORT int mk_http_send(mk_request_t *req, char *buf, size_t len,
                           void (*cb_finish)(mk_request_t *));
MK_EXPORT int mk_http_done(mk_request_t *req);

MK_EXPORT int mk_worker_callback(mk_ctx_t *ctx,
                                 void (*cb_func) (void *),
                                 void *data);
//MK_EXPORT int mk_mq_create(mk_ctx_t *ctx, char *name);
MK_EXPORT int mk_mq_create(mk_ctx_t *ctx, char *name, void (*cb), void *data);

MK_EXPORT int mk_mq_send(mk_ctx_t *ctx, int qid, void *data, size_t size);

MK_EXPORT int mk_main();

#endif
