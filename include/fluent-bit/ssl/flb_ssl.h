/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_SSL_H
#define FLB_SSL_H

#define FLB_SSL_WANT_POLLIN  -2
#define FLB_SSL_WANT_POLLOUT -3

struct flb_ssl_config;

struct flb_ssl;

struct flb_ssl *flb_ssl_server(void);

void flb_ssl_free(struct flb_ssl *ctx);

int flb_ssl_bind(struct flb_ssl *ctx, const char *ip, const char *port);

int flb_ssl_getfd(struct flb_ssl *ctx);

int flb_ssl_accept(struct flb_ssl *ctx, struct flb_ssl **cctx);

int flb_ssl_read(struct flb_ssl *ctx, char *buf, int len);

int flb_ssl_configure(struct flb_ssl *ctx, struct flb_ssl_config *config);

/* flb_ssl_config */
struct flb_ssl_config *flb_ssl_config_new(void);

void flb_ssl_config_free(struct flb_ssl_config *config);

void flb_ssl_config_set_verify(struct flb_ssl_config *config);

void flb_ssl_config_set_insecure_noverify(struct flb_ssl_config *config);

void flb_ssl_config_set_debug(struct flb_ssl_config *config);

void flb_ssl_config_set_nodebug(struct flb_ssl_config *config);

void flb_ssl_config_set_ca_path(struct flb_ssl_config *config, const char *path);

void flb_ssl_config_set_ca_file(struct flb_ssl_config *config, const char *file);

void flb_ssl_config_set_cert_file(struct flb_ssl_config *config, const char *file);

void flb_ssl_config_set_key_file(struct flb_ssl_config *config, const char *file, const char *passwd);
#endif
