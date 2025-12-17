/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_OAUTH2_H
#define FLB_OAUTH2_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_lock.h>
#include <fluent-bit/tls/flb_tls.h>

#define FLB_OAUTH2_PORT              "443"
#define FLB_OAUTH2_HTTP_ENCODING     "application/x-www-form-urlencoded"
#define FLB_OAUTH2_DEFAULT_SKEW_SECS 60
#define FLB_OAUTH2_DEFAULT_EXPIRES   300

enum flb_oauth2_auth_method {
    FLB_OAUTH2_AUTH_METHOD_BASIC = 0,
    FLB_OAUTH2_AUTH_METHOD_POST  = 1
};

struct flb_oauth2_config {
    int enabled;
    flb_sds_t token_url;
    flb_sds_t client_id;
    flb_sds_t client_secret;
    flb_sds_t scope;
    flb_sds_t audience;

    enum flb_oauth2_auth_method auth_method;

    int refresh_skew;
    int timeout;
    int connect_timeout;
};

struct flb_oauth2 {
    flb_sds_t auth_url;
    flb_sds_t payload;

    /* Parsed URL */
    flb_sds_t host;
    flb_sds_t port;
    flb_sds_t uri;

    /* Configuration */
    struct flb_oauth2_config cfg;

    /* Internal state */
    int payload_manual;
    flb_lock_t lock;
    time_t expires_at;
    int refresh_skew;

    /* Token info after successful auth */
    flb_sds_t access_token;
    flb_sds_t token_type;
    uint64_t  expires_in;

    /* TLS Context */
#ifdef FLB_HAVE_TLS
    struct flb_tls *tls;
#else
    void *tls;
#endif

    /* Upstream context */
    struct flb_upstream *u;
};

struct flb_oauth2 *flb_oauth2_create(struct flb_config *config,
                                     const char *auth_url, int expire_sec);
struct flb_oauth2 *flb_oauth2_create_from_config(
                                struct flb_config *config,
                                const struct flb_oauth2_config *cfg);
void flb_oauth2_destroy(struct flb_oauth2 *ctx);
void flb_oauth2_config_destroy(struct flb_oauth2_config *cfg);
int flb_oauth2_token_len(struct flb_oauth2 *ctx);
void flb_oauth2_payload_clear(struct flb_oauth2 *ctx);
int flb_oauth2_payload_append(struct flb_oauth2 *ctx,
                              const char *key_str, int key_len,
                              const char *val_str, int val_len);
char *flb_oauth2_token_get_ng(struct flb_oauth2 *ctx);
char *flb_oauth2_token_get(struct flb_oauth2 *ctx);
int flb_oauth2_get_access_token(struct flb_oauth2 *ctx,
                                flb_sds_t *token_out,
                                int force_refresh);
void flb_oauth2_invalidate_token(struct flb_oauth2 *ctx);
int flb_oauth2_token_expired(struct flb_oauth2 *ctx);

int flb_oauth2_parse_json_response(const char *json_data, size_t json_size,
                        struct flb_oauth2 *ctx);

struct mk_list *flb_oauth2_get_config_map(struct flb_config *config);

#endif
