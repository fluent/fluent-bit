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

#ifndef FLB_OUT_BIGQUERY
#define FLB_OUT_BIGQUERY

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>

/* refresh token every 50 minutes */
#define FLB_BIGQUERY_TOKEN_REFRESH 3000

/* BigQuery streaming inserts oauth scope */
#define FLB_BIGQUERY_SCOPE     "https://www.googleapis.com/auth/bigquery.insertdata"

/* BigQuery authorization URL */
#define FLB_BIGQUERY_AUTH_URL  "https://oauth2.googleapis.com/token"

#define FLB_BIGQUERY_RESOURCE_TEMPLATE  "/bigquery/v2/projects/%s/datasets/%s/tables/%s/insertAll"
#define FLB_BIGQUERY_URL_BASE           "https://www.googleapis.com"

#define FLB_BIGQUERY_GOOGLE_STS_URL     "https://sts.googleapis.com"
#define FLB_BIGQUERY_GOOGLE_IAM_URL     "https://iamcredentials.googleapis.com"
#define FLB_BIGQUERY_AWS_STS_ENDPOINT   "/?Action=GetCallerIdentity&Version=2011-06-15"

#define FLB_BIGQUERY_GOOGLE_CLOUD_TARGET_RESOURCE \
    "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s"

#define FLB_BIGQUERY_GOOGLE_STS_TOKEN_GRANT_TYPE            "urn:ietf:params:oauth:grant-type:token-exchange"
#define FLB_BIGQUERY_GOOGLE_STS_TOKEN_REQUESTED_TOKEN_TYPE  "urn:ietf:params:oauth:token-type:access_token"
#define FLB_BIGQUERY_GOOGLE_STS_TOKEN_SCOPE                 "https://www.googleapis.com/auth/cloud-platform"
#define FLB_BIGQUERY_GOOGLE_STS_TOKEN_SUBJECT_TOKEN_TYPE    "urn:ietf:params:aws:token-type:aws4_request"
#define FLB_BIGQUERY_GOOGLE_CLOUD_TOKEN_ENDPOINT            "/v1/token"

#define FLB_BIGQUERY_GOOGLE_GEN_ACCESS_TOKEN_REQUEST_BODY \
    "{\"scope\": [\"https://www.googleapis.com/auth/cloud-platform\"]}"

#define FLB_BIGQUERY_GOOGLE_GEN_ACCESS_TOKEN_URL \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"

struct flb_bigquery_oauth_credentials {
    /* parsed credentials file */
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
};

struct flb_bigquery {
    /* credentials */
    flb_sds_t credentials_file;

    struct flb_bigquery_oauth_credentials *oauth_credentials;

    /* Workload Identity Federation */
    int has_identity_federation;
    flb_sds_t project_number;
    flb_sds_t pool_id;
    flb_sds_t provider_id;
    flb_sds_t aws_region;
    flb_sds_t google_service_account;

    /* AWS IMDS */
    struct flb_tls *aws_tls;
    struct flb_aws_provider *aws_provider;

    /* AWS STS */
    flb_sds_t aws_sts_endpoint;
    struct flb_tls *aws_sts_tls;
    struct flb_upstream *aws_sts_upstream;

    /* Google STS API */
    struct flb_tls *google_sts_tls;
    struct flb_upstream *google_sts_upstream;

    /* Google Service Account Credentials API */
    struct flb_tls *google_iam_tls;
    struct flb_upstream *google_iam_upstream;

    /* Google OAuth access token for service account, that was exchanged for AWS credentials */
    flb_sds_t sa_token;
    time_t sa_token_expiry;

    /* bigquery configuration */
    flb_sds_t project_id;
    flb_sds_t dataset_id;
    flb_sds_t table_id;

    int skip_invalid_rows;
    int ignore_unknown_values;
    int buffer_size;

    flb_sds_t uri;

    /* oauth2 context */
    struct flb_oauth2 *o;

    /* mutex for acquiring oauth tokens */
    pthread_mutex_t token_mutex;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Fluent Bit context */
    struct flb_config *config;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

#endif
