/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_GCP_AUTH_H
#define FLB_GCP_AUTH_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/tls/flb_tls.h>

#include <time.h>

#define FLB_GCP_SCOPE_STORAGE_READ_WRITE \
    "https://www.googleapis.com/auth/devstorage.read_write"
#define FLB_GCP_SCOPE_STORAGE_READ_ONLY \
    "https://www.googleapis.com/auth/devstorage.read_only"
#define FLB_GCP_AUTH_URL                 "https://oauth2.googleapis.com/token"
#define FLB_GCP_METADATA_SERVER          "http://metadata.google.internal"
#define FLB_GCP_METADATA_TOKEN_URI \
    "/computeMetadata/v1/instance/service-accounts/default/token"
#define FLB_GCP_METADATA_TOKEN_SIZE_MAX  14336
#define FLB_GCP_TOKEN_REFRESH            3000

/* refresh federation tokens this many seconds before their server-stated expiry */
#define FLB_GCP_TOKEN_EXPIRY_SAFETY      300

/* Workload Identity Federation (external account, OIDC token file source) */
#define FLB_GCP_GOOGLE_STS_URL           "https://sts.googleapis.com"
#define FLB_GCP_GOOGLE_IAM_URL           "https://iamcredentials.googleapis.com"
#define FLB_GCP_STS_TOKEN_ENDPOINT       "/v1/token"

/* upper bound of the STS and IAM responses (Google tokens can be ~12 KiB) */
#define FLB_GCP_TOKEN_RESPONSE_SIZE_MAX  32768

#define FLB_GCP_TARGET_RESOURCE_TEMPLATE \
    "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s"

#define FLB_GCP_STS_GRANT_TYPE            "urn:ietf:params:oauth:grant-type:token-exchange"
#define FLB_GCP_STS_REQUESTED_TOKEN_TYPE  "urn:ietf:params:oauth:token-type:access_token"
#define FLB_GCP_STS_SUBJECT_TOKEN_TYPE    "urn:ietf:params:oauth:token-type:jwt"
#define FLB_GCP_STS_SCOPE                 "https://www.googleapis.com/auth/cloud-platform"

#define FLB_GCP_GEN_ACCESS_TOKEN_ENDPOINT \
    "/v1/projects/-/serviceAccounts/%s:generateAccessToken"

struct flb_gcp_credentials {
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
};

/* optional seam: returns 0 and fills *payload (an sds, may be reallocated) or -1 */
typedef int (*flb_gcp_metadata_fetch_cb)(void *data, flb_sds_t *payload);

struct flb_gcp_auth_config {
    struct flb_config *config;          /* required */
    const char *scope;                  /* required: JWT claim and IAM body scope */
    const char *log_name;               /* optional; instance name for log lines */
    const char *credentials_file;       /* optional; NULL -> env vars -> metadata */
    const char *metadata_server;        /* optional; NULL -> FLB_GCP_METADATA_SERVER */
    int identity_federation;            /* FLB_TRUE enables WIF */
    const char *project_number;
    const char *pool_id;
    const char *provider_id;
    const char *identity_token_file;
    const char *google_service_account;
    const char *subject_token_type;     /* NULL -> FLB_GCP_STS_SUBJECT_TOKEN_TYPE */
    const char *sts_url;                /* optional; NULL -> FLB_GCP_GOOGLE_STS_URL */
    const char *iam_url;                /* optional; NULL -> FLB_GCP_GOOGLE_IAM_URL */

    /* TLS/network settings for the STS, IAM and oauth2 upstreams */
    int tls_verify;
    int tls_debug;
    int tls_verify_hostname;
    int ipv6;
    const char *tls_vhost;
    const char *tls_ca_path;
    const char *tls_ca_file;
    const char *tls_crt_file;
    const char *tls_key_file;
    const char *tls_key_passwd;

    flb_gcp_metadata_fetch_cb metadata_fetch;   /* optional; NULL -> real HTTP GET */
    void *metadata_fetch_data;
};

/* Callers must use the API below; the layout is exposed for tests only. */
struct flb_gcp_auth {
    struct flb_config *config;
    flb_sds_t scope;
    flb_sds_t log_prefix;               /* "[gcp_auth]" or "[gcp_auth:<name>]" */

    pthread_mutex_t token_mutex;
    int token_mutex_initialized;

    /* service-account / metadata server */
    struct flb_oauth2 *o;
    struct flb_gcp_credentials *credentials;
    flb_sds_t credentials_file;
    int metadata_server_auth;
    flb_sds_t metadata_server;
    struct flb_upstream *metadata_u;
    flb_gcp_metadata_fetch_cb metadata_fetch;
    void *metadata_fetch_data;

    /* Workload Identity Federation (external account) */
    int has_identity_federation;
    flb_sds_t project_number;
    flb_sds_t pool_id;
    flb_sds_t provider_id;
    flb_sds_t identity_token_file;
    flb_sds_t google_service_account;
    flb_sds_t subject_token_type;
    flb_sds_t sts_audience;
    struct flb_tls *sts_tls;
    struct flb_upstream *sts_u;
    struct flb_tls *iam_tls;
    struct flb_upstream *iam_u;
    flb_sds_t federation_token;
    time_t federation_token_expiry;
};

struct flb_gcp_auth *flb_gcp_auth_create(const struct flb_gcp_auth_config *cfg);
void flb_gcp_auth_destroy(struct flb_gcp_auth *ctx);

/* returns a new sds "Bearer <token>" (caller destroys) or NULL; thread safe */
flb_sds_t flb_gcp_auth_get_header(struct flb_gcp_auth *ctx);

/* drops the cached token so the next get_header fetches a fresh one; thread safe */
void flb_gcp_auth_invalidate_token(struct flb_gcp_auth *ctx);
int flb_gcp_auth_uses_metadata_server(struct flb_gcp_auth *ctx);
int flb_gcp_auth_uses_identity_federation(struct flb_gcp_auth *ctx);

/* exported for reuse and unit tests */
int flb_gcp_jwt_encode(const char *payload, const char *secret,
                       char **out_signature, size_t *out_size);
int flb_gcp_credentials_read(const char *path, struct flb_gcp_credentials *out);
void flb_gcp_credentials_destroy(struct flb_gcp_credentials *c);
time_t flb_gcp_utc_to_epoch(int year, int mon, int mday,
                            int hour, int min, int sec);

/* Builds the service-account JWT claim set; returns 0, or -1 (no credentials,
 * or the buffer is too small). */
int flb_gcp_auth_build_jwt_claim(struct flb_gcp_auth *ctx, time_t issued,
                                 char *buf, size_t size);

/* Reads the (trimmed) OIDC subject token; the file is never cached. */
int flb_gcp_read_identity_token(const char *path, flb_sds_t *out_token);

/* Expiry of a federated token from the STS and (optional) IAM payloads. */
time_t flb_gcp_federation_token_expiry(time_t now,
                                       const char *sts_payload, size_t sts_size,
                                       const char *iam_payload, size_t iam_size);

#endif
