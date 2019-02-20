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

#ifndef FLB_OUT_STACKDRIVER_H
#define FLB_OUT_STACKDRIVER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>

/* refresh token every 50 minutes */
#define FLB_STD_TOKEN_REFRESH 3000

/* Stackdriver Logging write scope */
#define FLB_STD_SCOPE     "https://www.googleapis.com/auth/logging.write"

/* Stackdriver authorization URL */
#define FLB_STD_AUTH_URL  "https://www.googleapis.com/oauth2/v4/token"

/* Stackdriver Logging 'write' end-point */
#define FLB_STD_WRITE_URI "/v2/entries:write"
#define FLB_STD_WRITE_URL \
    "https://logging.googleapis.com" FLB_STD_WRITE_URI

/* Timestamp format */
#define FLB_STD_TIME_FMT  "%Y-%m-%dT%H:%M:%S"

/* Default Resource type */
#define FLB_SDS_RESOURCE_TYPE "global"

struct flb_stackdriver {
    /* credentials */
    flb_sds_t credentials_file;

    /* parsed credentials file */
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
    bool metadata_server_auth;

    /* metadata server (GCP specific, WIP) */
    flb_sds_t zone;
    flb_sds_t instance_id;
    flb_sds_t instance_name;

    /* other */
    flb_sds_t resource;

    /* oauth2 context */
    struct flb_oauth2 *o;

    /* upstream context for stackdriver write end-point */
    struct flb_upstream *u;

    /* upstream context for metadata end-point */
    struct flb_upstream *metadata_u;

    /* Fluent Bit context */
    struct flb_config *config;
};

#endif
