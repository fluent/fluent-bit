/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_s3_local_buffer.h>

/* Upload data to S3 in 5MB chunks */
#define MIN_CHUNKED_UPLOAD_SIZE 5242880
#define MAX_CHUNKED_UPLOAD_SIZE 50000000

#define UPLOAD_TIMER_MAX_WAIT 60000

#define MULTIPART_UPLOAD_STATE_NOT_CREATED              0
#define MULTIPART_UPLOAD_STATE_CREATED                  1
#define MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS     2

#define DEFAULT_FILE_SIZE     100000000
#define MAX_FILE_SIZE         50000000000
#define MAX_FILE_SIZE_STR     "50,000,000,000"

#define MAX_FILE_SIZE_PUT_OBJECT         50000000

#define DEFAULT_UPLOAD_TIMEOUT 3600

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
    char *chunk_buffer_dir;
    char *endpoint;
    int free_endpoint;
    int use_put_object;

    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    /* tls instances can't be re-used; aws provider requires a separate one */
    struct flb_tls provider_tls;
    /* one for the standard chain provider, one for sts assume role */
    struct flb_tls sts_provider_tls;
    struct flb_tls client_tls;

    struct flb_aws_client *s3_client;
    int json_date_format;
    flb_sds_t json_date_key;

    struct flb_local_buffer store;
    flb_sds_t buffer_dir;

    struct flb_local_buffer upload_store;
    flb_sds_t upload_dir;

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

    struct flb_output_instance *ins;
};

int upload_part(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                char *body, size_t body_size);

int create_multipart_upload(struct flb_s3 *ctx,
                            struct multipart_upload *m_upload);

int complete_multipart_upload(struct flb_s3 *ctx,
                              struct multipart_upload *m_upload);

void read_uploads_from_fs(struct flb_s3 *ctx);

void multipart_upload_destroy(struct multipart_upload *m_upload);

#endif
