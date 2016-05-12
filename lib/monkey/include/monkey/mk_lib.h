/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/mk_config.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_http_internal.h>

struct mk_lib_ctx {
    struct mk_server_config *config;
};

typedef struct mk_lib_ctx mk_ctx_t;
typedef struct host mk_vhost_t;
typedef struct mk_http_request mk_request_t;
typedef struct mk_http_session mk_session_t;

MK_EXPORT int mk_start(mk_ctx_t *ctx);

MK_EXPORT mk_ctx_t *mk_create();
MK_EXPORT int mk_config_set(mk_ctx_t *ctx, ...);

MK_EXPORT mk_vhost_t *mk_vhost_create(mk_ctx_t *ctx, char *name);
MK_EXPORT int mk_vhost_set(mk_vhost_t *vh, ...);
MK_EXPORT int mk_vhost_handler(mk_vhost_t *vh, char *regex,
                               void (*cb)(mk_session_t *, mk_request_t *));

int mk_http_status(mk_request_t *req, int status);
int mk_http_header(mk_request_t *req,
                   char *key, int key_len,
                   char *val, int val_len);
int mk_http_send(mk_request_t *req, char *buf, size_t len,
                 void (*cb_finish)(mk_request_t *));

#endif
