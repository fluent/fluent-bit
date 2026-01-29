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

#ifndef FLB_OUT_S3_AUTH_H
#define FLB_OUT_S3_AUTH_H

#include "s3.h"

/* Unified presigned URL types */
typedef enum {
    S3_PRESIGNED_URL_CREATE_MULTIPART,
    S3_PRESIGNED_URL_UPLOAD_PART,
    S3_PRESIGNED_URL_COMPLETE_MULTIPART,
    S3_PRESIGNED_URL_ABORT_MULTIPART
} s3_presigned_url_type_t;

/* Initialize authorization endpoint upstream connection */
int s3_auth_init_endpoint(struct flb_s3 *ctx);

/* Request presigned URL from authorization endpoint */
int s3_auth_request_presigned_url(struct flb_s3 *ctx,
                                   flb_sds_t *result_url,
                                   char *url);

/* Unified presigned URL fetcher - works for both standard and blob uploads */
int s3_auth_fetch_presigned_url(struct flb_s3 *ctx,
                                 flb_sds_t *result_url,
                                 int url_type,
                                 const char *s3_key,
                                 const char *upload_id,
                                 int part_number);

#endif
