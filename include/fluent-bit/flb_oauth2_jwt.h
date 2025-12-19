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

#ifndef FLB_OAUTH2_JWT_H
#define FLB_OAUTH2_JWT_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config_map.h>
#include <stdint.h>

struct flb_config;
struct mk_list;

enum flb_oauth2_jwt_status {
    FLB_OAUTH2_JWT_OK = 0,
    FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT = -1000,
    FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT = -1001,
    FLB_OAUTH2_JWT_ERR_BASE64_HEADER = -1002,
    FLB_OAUTH2_JWT_ERR_BASE64_PAYLOAD = -1003,
    FLB_OAUTH2_JWT_ERR_BASE64_SIGNATURE = -1004,
    FLB_OAUTH2_JWT_ERR_JSON_HEADER = -1005,
    FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD = -1006,
    FLB_OAUTH2_JWT_ERR_MISSING_KID = -1007,
    FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED = -1008,
    FLB_OAUTH2_JWT_ERR_MISSING_EXP = -1009,
    FLB_OAUTH2_JWT_ERR_MISSING_ISS = -1010,
    FLB_OAUTH2_JWT_ERR_MISSING_AUD = -1011,
    FLB_OAUTH2_JWT_ERR_MISSING_BEARER_TOKEN = -1012,
    FLB_OAUTH2_JWT_ERR_MISSING_AUTH_HEADER = -1013,
    FLB_OAUTH2_JWT_ERR_VALIDATION_UNAVAILABLE = -1014
};

struct flb_oauth2_jwt_claims {
    flb_sds_t kid;
    flb_sds_t alg;
    flb_sds_t issuer;
    flb_sds_t audience;
    flb_sds_t client_id;
    uint64_t expiration;
    int has_azp;
};

struct flb_oauth2_jwt {
    flb_sds_t header_json;
    flb_sds_t payload_json;
    flb_sds_t signing_input;
    unsigned char *signature;
    size_t signature_len;
    struct flb_oauth2_jwt_claims claims;
};

struct flb_oauth2_jwt_cfg {
    int         validate;                 /* enable validation */
    flb_sds_t   issuer;                   /* expected issuer */
    flb_sds_t   jwks_url;                 /* JWKS endpoint */
    flb_sds_t   allowed_audience;         /* audience claim to enforce */
    struct mk_list *allowed_clients;      /* list of authorized azp/client_id */
    int         jwks_refresh_interval;    /* refresh cadence in seconds */
};

struct flb_oauth2_jwt_validation_request {
    const char *token;                    /* raw JWT token */
    size_t token_length;                  /* JWT length */
    flb_sds_t issuer;                     /* required issuer */
    flb_sds_t audience;                   /* required audience */
    flb_sds_t client_id;                  /* required client id/azp */
    int64_t current_time;                 /* optional unix time override */
    int64_t leeway;                       /* optional expiration leeway */
};

struct flb_oauth2_jwt_validation_response {
    int status;                           /* validation status */
};

struct flb_oauth2_jwt_ctx;

/* Allocate and populate a validation context from configuration. */
struct flb_oauth2_jwt_ctx *flb_oauth2_jwt_context_create(struct flb_config *config,
                                                         struct flb_oauth2_jwt_cfg *cfg);

/* Release validation resources. */
void flb_oauth2_jwt_context_destroy(struct flb_oauth2_jwt_ctx *ctx);

/* Validate a bearer token (JWT) using the supplied context. */
int flb_oauth2_jwt_validate(struct flb_oauth2_jwt_ctx *ctx,
                            const char *authorization_header,
                            size_t authorization_header_len);

/* Parse a JWT and populate the supplied structure. */
int flb_oauth2_jwt_parse(const char *token,
                         size_t token_len,
                         struct flb_oauth2_jwt *jwt);

/* Destroy a parsed JWT structure. */
void flb_oauth2_jwt_destroy(struct flb_oauth2_jwt *jwt);

/* Human readable error for logging. */
const char *flb_oauth2_jwt_status_message(int status);

/* Get OAuth2 JWT config map for input plugins */
struct mk_list *flb_oauth2_jwt_get_config_map(struct flb_config *config);

#endif
