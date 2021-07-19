/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_OUT_S3
#define FLB_OUT_S3

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

/* Upload data to S3 in 5MB chunks */
#define MIN_CHUNKED_UPLOAD_SIZE 5242880
#define MAX_CHUNKED_UPLOAD_SIZE 50000000

#define UPLOAD_TIMER_MAX_WAIT 60000
#define UPLOAD_TIMER_MIN_WAIT 6000

#define MULTIPART_UPLOAD_STATE_NOT_CREATED              0
#define MULTIPART_UPLOAD_STATE_CREATED                  1
#define MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS     2

#define DEFAULT_FILE_SIZE     100000000
#define MAX_FILE_SIZE         50000000000
#define MAX_FILE_SIZE_STR     "50,000,000,000"

#define MAX_FILE_SIZE_PUT_OBJECT         50000000

#define DEFAULT_UPLOAD_TIMEOUT 3600

#define COMPRESS_NONE  0
#define COMPRESS_GZIP  1
#define COMPRESS_ARROW 2

/*
 * If we see repeated errors on an upload/chunk, we will discard it
 * This saves us from scenarios where something goes wrong and an upload can
 * not proceed (may be some other process completed it or deleted the upload)
 * instead of erroring out forever, we eventually discard the upload.
 *
 * The same is done for chunks, just to be safe, even though realistically
 * I can't think of a reason why a chunk could become unsendable.
 */
#define MAX_UPLOAD_ERRORS 5

struct multipart_upload {
    flb_sds_t s3_key;
    flb_sds_t tag;
    flb_sds_t upload_id;
    int upload_state;
    time_t init_time;

    /*
     * maximum of 10,000 parts in an upload, for each we need to store mapping
     * of Part Number to ETag
     */
    flb_sds_t etags[10000];
    int part_number;

    /*
     * we use async http, so we need to check that all part requests have
     * completed before we complete the upload
     */
    int parts_uploaded;

    /* ongoing tracker of how much data has been sent for this upload */
    size_t bytes;

    struct mk_list _head;

    /* see note for MAX_UPLOAD_ERRORS */
    int upload_errors;
    int complete_errors;
};

struct flb_s3 {
    char *bucket;
    char *region;
    char *s3_key_format;
    char *tag_delimiters;
    char *endpoint;
    char *sts_endpoint;
    char *canned_acl;
    char *content_type;
    int free_endpoint;
    int use_put_object;
    int send_content_md5;
    int compression;

    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    /* tls instances can't be re-used; aws provider requires a separate one */
    struct flb_tls *provider_tls;
    /* one for the standard chain provider, one for sts assume role */
    struct flb_tls *sts_provider_tls;
    struct flb_tls *client_tls;

    struct flb_aws_client *s3_client;
    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;

    flb_sds_t buffer_dir;

    char *store_dir;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;  /* default active stream */
    struct flb_fstore_stream *stream_upload;  /* multipart upload stream */

    /*
     * used to track that unset buffers were found on startup that have not
     * been sent
     */
    int has_old_buffers;
    /* old multipart uploads read on start up */
    int has_old_uploads;

    struct mk_list uploads;

    size_t file_size;
    size_t upload_chunk_size;
    time_t upload_timeout;

    int timer_created;
    int timer_ms;
    int key_fmt_has_uuid;

    struct flb_output_instance *ins;
};

int upload_part(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                char *body, size_t body_size);

int create_multipart_upload(struct flb_s3 *ctx,
                            struct multipart_upload *m_upload);

int complete_multipart_upload(struct flb_s3 *ctx,
                              struct multipart_upload *m_upload);

void multipart_read_uploads_from_fs(struct flb_s3 *ctx);

void multipart_upload_destroy(struct multipart_upload *m_upload);

struct flb_http_client *mock_s3_call(char *error_env_var, char *api);
int s3_plugin_under_test();

int get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size);

#endif
