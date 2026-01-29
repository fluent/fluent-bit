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

#ifndef FLB_OUT_S3_MULTIPART_H
#define FLB_OUT_S3_MULTIPART_H

#include "s3.h"
#include <sys/types.h>  /* for off_t */

/* Calculate optimal part size within AWS S3 limits (5MiB-5GiB, max 10000 parts) */
size_t flb_s3_calculate_optimal_part_size(size_t configured_part_size,
                                          size_t file_size);

/* Get MD5 hash in base64 format */
int s3_multipart_get_md5_base64(char *buf, size_t buf_size,
                                char *md5_str, size_t md5_str_size);

/* Create HTTP headers for multipart upload */
int s3_multipart_create_headers(struct flb_s3 *ctx, char *body_md5,
                                struct flb_aws_header **headers, int *num_headers,
                                int multipart_upload);

/* Create multipart upload structure (used by orchestration layer) */
struct multipart_upload *s3_multipart_upload_new(struct flb_s3 *ctx,
                                                  const char *tag,
                                                  int tag_len,
                                                  const char *path);

/* Destroy multipart upload structure */
void s3_multipart_upload_destroy(struct multipart_upload *m_upload);

/*
 * AWS S3 Multipart Upload API wrappers
 */

/* Initiate multipart upload (CreateMultipartUpload API) and get upload_id */
int s3_multipart_initiate(struct flb_s3 *ctx,
                          struct multipart_upload *m_upload,
                          char *pre_signed_url);

/* Upload a single part */
int s3_multipart_upload_part(struct flb_s3 *ctx,
                              struct multipart_upload *m_upload,
                              char *body, size_t body_size,
                              char *pre_signed_url);

/* Complete multipart upload */
int s3_multipart_complete(struct flb_s3 *ctx,
                          struct multipart_upload *m_upload,
                          char *pre_signed_url);

/* Abort multipart upload */
int s3_multipart_abort(struct flb_s3 *ctx,
                       struct multipart_upload *m_upload,
                       char *pre_signed_url);

/* Abort multipart upload with presigned URL support (helper function) */
int s3_multipart_abort_with_url(struct flb_s3 *ctx,
                                 struct multipart_upload *m_upload);

/*
 * Check if multipart upload exists on S3
 * Returns: 1 if exists, 0 if not exists, -1 on error
 * Used during recovery to validate stored upload_id
 *
 * IMPORTANT: s3_key must be the actual persisted key from the original upload.
 * Do NOT regenerate the key using time(NULL) or current seq_index as this may
 * not match the original key if the key format includes timestamps or sequence numbers.
 */
int s3_multipart_check_upload_exists(struct flb_s3 *ctx,
                                      const char *s3_key,
                                      const char *upload_id);

/*
 * High-level file upload functions
 */

/* Upload file part from source (file or memory) */
int s3_multipart_upload_part_from_source(struct flb_s3 *ctx,
                                   struct s3_data_source *src,
                                   struct multipart_upload *m_upload,
                                   flb_sds_t pre_signed_url);

/* Upload entire file using streaming multipart upload */
int s3_multipart_upload_file(struct flb_s3 *ctx,
                              const char *file_path,
                              const char *s3_key,
                              const char *tag, int tag_len);

#endif /* FLB_OUT_S3_MULTIPART_H */