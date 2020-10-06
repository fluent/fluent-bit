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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_scheduler.h>
#include <stdlib.h>
#include <msgpack.h>

#include "s3.h"
#include "s3_store.h"

static int construct_request_buffer(struct flb_s3 *ctx, flb_sds_t new_data,
                                    struct s3_file *chunk,
                                    char **out_buf, size_t *out_size);

static int s3_put_object(struct flb_s3 *ctx, const char *tag, time_t create_time,
                         char *body, size_t body_size);

static int put_all_chunks(struct flb_s3 *ctx);

static void cb_s3_upload(struct flb_config *ctx, void *data);

static struct multipart_upload *get_upload(struct flb_s3 *ctx,
                                           const char *tag, int tag_len);

static struct multipart_upload *create_upload(struct flb_s3 *ctx,
                                              const char *tag, int tag_len);


static char *mock_error_response(char *error_env_var)
{
    char *err_val = NULL;
    char *error = NULL;
    int len = 0;

    err_val = getenv(error_env_var);
    if (err_val != NULL && strlen(err_val) > 0) {
        error = flb_malloc(strlen(err_val) + sizeof(char));
        if (error == NULL) {
            flb_errno();
            return NULL;
        }

        len = strlen(err_val);
        memcpy(error, err_val, len);
        error[len] = '\0';
        return error;
    }

    return NULL;
}

int s3_plugin_under_test()
{
    if (getenv("FLB_S3_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

struct flb_http_client *mock_s3_call(char *error_env_var, char *api)
{
    /* create an http client so that we can set the response */
    struct flb_http_client *c = NULL;
    char *error = mock_error_response(error_env_var);
    char *resp;
    int len;

    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        flb_free(error);
        return NULL;
    }
    mk_list_init(&c->headers);

    if (error != NULL) {
        c->resp.status = 400;
        /* resp.data is freed on destroy, payload is supposed to reference it */
        c->resp.data = error;
        c->resp.payload = c->resp.data;
        c->resp.payload_size = strlen(error);
    }
    else {
        c->resp.status = 200;
        c->resp.payload = "";
        c->resp.payload_size = 0;
        if (strcmp(api, "CreateMultipartUpload") == 0) {
            /* mocked success response */
            c->resp.payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
              "<Bucket>example-bucket</Bucket>\n"
              "<Key>example-object</Key>\n"
              "<UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>\n"
            "</InitiateMultipartUploadResult>";
            c->resp.payload_size = strlen(c->resp.payload);
        }
        else if (strcmp(api, "UploadPart") == 0) {
            /* mocked success response */
            resp =            "Date:  Mon, 1 Nov 2010 20:34:56 GMT\n"
                              "ETag: \"b54357faf0632cce46e942fa68356b38\"\n"
                              "Content-Length: 0\n"
                              "Connection: keep-alive\n"
                              "Server: AmazonS3";
            /* since etag is in the headers, this code uses resp.data */
            len = strlen(resp);
            c->resp.data = flb_malloc(len + 1);
            if (!c->resp.data) {
                flb_errno();
                return NULL;
            }
            memcpy(c->resp.data, resp, len);
            c->resp.data[len] = '\0';
            c->resp.data_size = len;
        }
        else {
            c->resp.payload = "";
            c->resp.payload_size = 0;
        }
    }

    return c;
}

static flb_sds_t concat_path(char *p1, char *p2)
{
    flb_sds_t dir;
    flb_sds_t tmp;

    dir = flb_sds_create_size(64);

    tmp = flb_sds_printf(&dir, "%s/%s", p1, p2);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(dir);
        return NULL;
    }
    dir = tmp;

    return dir;
}

void multipart_upload_destroy(struct multipart_upload *m_upload)
{
    int i;
    flb_sds_t etag;

    if (!m_upload) {
        return;
    }

    if (m_upload->s3_key) {
        flb_sds_destroy(m_upload->s3_key);
    }
    if (m_upload->tag) {
        flb_sds_destroy(m_upload->tag);
    }
    if (m_upload->upload_id) {
        flb_sds_destroy(m_upload->upload_id);
    }

    for (i = 0; i < m_upload->part_number; i++) {
        etag = m_upload->etags[i];
        if (etag) {
            flb_sds_destroy(etag);
        }
    }

    flb_free(m_upload);
}

static void s3_context_destroy(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct multipart_upload *m_upload;

    if (!ctx) {
        return;
    }

    if (ctx->base_provider) {
        flb_aws_provider_destroy(ctx->base_provider);
    }

    if (ctx->provider) {
        flb_aws_provider_destroy(ctx->provider);
    }

    if (ctx->provider_tls.context) {
        flb_tls_context_destroy(ctx->provider_tls.context);
    }

    if (ctx->sts_provider_tls.context) {
        flb_tls_context_destroy(ctx->sts_provider_tls.context);
    }

    if (ctx->client_tls.context) {
        flb_tls_context_destroy(ctx->client_tls.context);
    }

    if (ctx->s3_client) {
        flb_aws_client_destroy(ctx->s3_client);
    }

    if (ctx->free_endpoint == FLB_TRUE) {
        flb_free(ctx->endpoint);
    }

    if (ctx->buffer_dir) {
        flb_sds_destroy(ctx->buffer_dir);
    }

    /* Remove uploads */
    mk_list_foreach_safe(head, tmp, &ctx->uploads) {
        m_upload = mk_list_entry(head, struct multipart_upload, _head);
        mk_list_del(&m_upload->_head);
        multipart_upload_destroy(m_upload);
    }

    flb_free(ctx);
}

static int cb_s3_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    int ret;
    flb_sds_t tmp_sds;
    int async_flags;
    int len;
    char *role_arn = NULL;
    char *external_id = NULL;
    char *session_name;
    const char *tmp;
    struct flb_s3 *ctx = NULL;
    struct flb_aws_client_generator *generator;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_s3));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->uploads);

    /* Export context */
    flb_output_set_context(ins, ctx);

    /* initialize config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_ISO8601;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. ", tmp);
            return -1;
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    tmp = flb_output_get_property("bucket", ins);
    if (!tmp) {
        flb_plg_error(ctx->ins, "'bucket' is a required parameter");
        return -1;
    }

    tmp = flb_output_get_property("chunk_buffer_dir", ins);
    if (tmp) {
        len = strlen(tmp);
        if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
            flb_plg_error(ctx->ins, "'chunk_buffer_dir' can not end in a / or \\");
            return -1;
        }
    }

    /*
     * store_dir is the user input, buffer_dir is what the code uses
     * We append the bucket name to the dir, to support multiple instances
     * of this plugin using the same buffer dir
     */
    tmp_sds = concat_path(ctx->store_dir, ctx->bucket);
    if (!tmp_sds) {
        flb_plg_error(ctx->ins, "Could not construct buffer path");
        return -1;
    }
    ctx->buffer_dir = tmp_sds;

    tmp = flb_output_get_property("s3_key_format", ins);
    if (tmp) {
        if (tmp[0] != '/') {
            flb_plg_error(ctx->ins, "'s3_key_format' must start with a '/'");
            return -1;
        }
    }

    /* validate 'total_file_size' */
    if (ctx->file_size <= 0) {
        flb_plg_error(ctx->ins, "Failed to parse total_file_size %s", tmp);
        return -1;
    }
    if (ctx->file_size < 1000000) {
        flb_plg_error(ctx->ins, "total_file_size must be at least 1MB");
        return -1;
    }
    if (ctx->file_size > MAX_FILE_SIZE) {
        flb_plg_error(ctx->ins, "Max total_file_size is %s bytes", MAX_FILE_SIZE_STR);
        return -1;
    }
    flb_plg_info(ctx->ins, "Using upload size %lu bytes", ctx->file_size);


    if (ctx->use_put_object == FLB_FALSE) {
        /* upload_chunk_size */
        if (ctx->upload_chunk_size <= 0) {
            flb_plg_error(ctx->ins, "Failed to parse upload_chunk_size %s", tmp);
            return -1;
        }
        if (ctx->upload_chunk_size > ctx->file_size) {
            flb_plg_error(ctx->ins,
                          "upload_chunk_size can not be larger than total_file_size");
            return -1;
        }
        if (ctx->upload_chunk_size < MIN_CHUNKED_UPLOAD_SIZE) {
            flb_plg_error(ctx->ins, "upload_chunk_size must be at least 5,242,880 bytes");
            return -1;
        }
        if (ctx->upload_chunk_size > MAX_CHUNKED_UPLOAD_SIZE) {
            flb_plg_error(ctx->ins, "Max upload_chunk_size is 50M");
            return -1;
        }

        if (ctx->file_size < 2 * MIN_CHUNKED_UPLOAD_SIZE) {
            flb_plg_info(ctx->ins,
                         "total_file_size is less than 10 MB, will use PutObject API");
            ctx->use_put_object = FLB_TRUE;
        }
    }

    if (ctx->upload_chunk_size != MIN_CHUNKED_UPLOAD_SIZE &&
        (ctx->upload_chunk_size * 2) > ctx->file_size) {
        flb_plg_error(ctx->ins, "total_file_size is less than 2x upload_chunk_size");
        return -1;
    }

    if (ctx->use_put_object == FLB_TRUE) {
        /*
         * code internally uses 'upload_chunk_size' as the unit for each Put,
         * regardless of which API is used to send data
         */
        ctx->upload_chunk_size = ctx->file_size;
        if (ctx->file_size > MAX_FILE_SIZE_PUT_OBJECT) {
            flb_plg_error(ctx->ins, "Max total_file_size is 50M when use_put_object is enabled");
            return -1;
        }
    }

    tmp = flb_output_get_property("endpoint", ins);
    if (tmp) {
        ctx->endpoint = removeProtocol((char *) tmp, "https://");
        ctx->free_endpoint = FLB_FALSE;
    }
    else {
        /* default endpoint for the given region */
        ctx->endpoint = flb_s3_endpoint(ctx->bucket, ctx->region);
        ctx->free_endpoint = FLB_TRUE;
        if (!ctx->endpoint) {
            flb_plg_error(ctx->ins,  "Could not construct S3 endpoint");
            return -1;
        }
    }

    tmp = flb_output_get_property("sts_endpoint", ins);
    if (tmp) {
        ctx->sts_endpoint = (char *) tmp;
    }

    ctx->client_tls.context = flb_tls_context_new(FLB_TRUE,
                                                  ins->tls_debug,
                                                  ins->tls_vhost,
                                                  ins->tls_ca_path,
                                                  ins->tls_ca_file,
                                                  ins->tls_crt_file,
                                                  ins->tls_key_file,
                                                  ins->tls_key_passwd);
    if (!ctx->client_tls.context) {
        flb_plg_error(ctx->ins, "Failed to create tls context");
        return -1;
    }

    /* AWS provider needs a separate TLS instance */
    ctx->provider_tls.context = flb_tls_context_new(FLB_TRUE,
                                                    ins->tls_debug,
                                                    ins->tls_vhost,
                                                    ins->tls_ca_path,
                                                    ins->tls_ca_file,
                                                    ins->tls_crt_file,
                                                    ins->tls_key_file,
                                                    ins->tls_key_passwd);
    if (!ctx->provider_tls.context) {
        flb_errno();
        return -1;
    }

    ctx->provider = flb_standard_chain_provider_create(config,
                                                       &ctx->provider_tls,
                                                       ctx->region,
                                                       ctx->sts_endpoint,
                                                       NULL,
                                                       flb_aws_client_generator());

    if (!ctx->provider) {
        flb_plg_error(ctx->ins, "Failed to create AWS Credential Provider");
        return -1;
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        /* Use the STS Provider */
        ctx->base_provider = ctx->provider;
        role_arn = (char *) tmp;
        tmp = flb_output_get_property("external_id", ins);
        if (tmp) {
            external_id = (char *) tmp;
        }

        /* STS provider needs yet another separate TLS instance */
        ctx->sts_provider_tls.context = flb_tls_context_new(FLB_TRUE,
                                                            ins->tls_debug,
                                                            ins->tls_vhost,
                                                            ins->tls_ca_path,
                                                            ins->tls_ca_file,
                                                            ins->tls_crt_file,
                                                            ins->tls_key_file,
                                                            ins->tls_key_passwd);

        if (!ctx->sts_provider_tls.context) {
            flb_errno();
            return -1;
        }

        session_name = flb_sts_session_name();
        if (!session_name) {
            flb_plg_error(ctx->ins, "Failed to create aws iam role "
                      "session name");
            flb_errno();
            return -1;
        }

        ctx->provider = flb_sts_provider_create(config,
                                                &ctx->sts_provider_tls,
                                                ctx->base_provider,
                                                external_id,
                                                role_arn,
                                                session_name,
                                                ctx->region,
                                                ctx->sts_endpoint,
                                                NULL,
                                                flb_aws_client_generator());
        if (!ctx->provider) {
            flb_plg_error(ctx->ins, "Failed to create AWS STS Credential "
                         "Provider");
            return -1;
        }

    }

    /* Initialize local storage */
    ret = s3_store_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to initialize S3 storage: %s",
                      ctx->store_dir);
        return -1;
    }

    /* read any remaining buffers from previous (failed) executions */
    ctx->has_old_buffers = s3_store_has_data(ctx);
    ctx->has_old_uploads = s3_store_has_uploads(ctx);

    /* Multipart */
    multipart_read_uploads_from_fs(ctx);

    if (mk_list_size(&ctx->uploads) > 0) {
        /* note that these should be sent */
        ctx->has_old_uploads = FLB_TRUE;
    }

    /* create S3 client */
    generator = flb_aws_client_generator();
    ctx->s3_client = generator->create();
    if (!ctx->s3_client) {
        return -1;
    }
    ctx->s3_client->name = "s3_client";
    ctx->s3_client->has_auth = FLB_TRUE;
    ctx->s3_client->provider = ctx->provider;
    ctx->s3_client->region = ctx->region;
    ctx->s3_client->service = "s3";
    ctx->s3_client->port = 443;
    ctx->s3_client->flags = 0;
    ctx->s3_client->proxy = NULL;
    ctx->s3_client->s3_mode = S3_MODE_SIGNED_PAYLOAD;

    ctx->s3_client->upstream = flb_upstream_create(config, ctx->endpoint, 443,
                                                   FLB_IO_TLS, &ctx->client_tls);
    if (!ctx->s3_client->upstream) {
        flb_plg_error(ctx->ins, "Connection initialization error");
        return -1;
    }

    ctx->s3_client->host = ctx->endpoint;

    /* set to sync mode and initialize credentials */
    ctx->provider->provider_vtable->sync(ctx->provider);
    ctx->provider->provider_vtable->init(ctx->provider);

    ctx->timer_created = FLB_FALSE;
    ctx->timer_ms = (int) (ctx->upload_timeout / 6) * 1000;
    if (ctx->timer_ms > UPLOAD_TIMER_MAX_WAIT) {
        ctx->timer_ms = UPLOAD_TIMER_MAX_WAIT;
    }
    else if (ctx->timer_ms == 0) {
        ctx->timer_ms = UPLOAD_TIMER_MIN_WAIT;
    }

    /* init must use sync mode */
    async_flags = ctx->s3_client->upstream->flags;
    ctx->s3_client->upstream->flags &= ~(FLB_IO_ASYNC);

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to S3; buffer=%s",
                     ctx->fs->root_path);
        ctx->has_old_buffers = FLB_FALSE;
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            ctx->has_old_buffers = FLB_TRUE;
            flb_plg_error(ctx->ins,
                          "Failed to send locally buffered data left over "
                          "from previous executions; will retry. Buffer=%s",
                          ctx->fs->root_path);
        }
    }

    /* clean up any old uploads found on start up */
    if (ctx->has_old_uploads == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Completing multipart uploads from previous "
                     "executions to S3; buffer=%s",
                     ctx->stream_upload->path);
        ctx->has_old_uploads = FLB_FALSE;

        /*
         * we don't need to worry if this fails; it will retry each
         * time the upload callback is called
         */
         cb_s3_upload(config, ctx);
    }

    if (ctx->use_put_object == FLB_TRUE) {
        /*
         * Run S3 in async mode.
         * Multipart uploads don't work with async mode right now in high throughput
         * cases. Its not clear why. Realistically, the performance of sync mode
         * will be sufficient for most users, and long term we can do the work
         * to enable async if needed.
         */
        ctx->s3_client->upstream->flags = async_flags;
    }

    return 0;
}

/*
 * return value is one of FLB_OK, FLB_RETRY, FLB_ERROR
 *
 * Chunk is allowed to be NULL
 */
static int upload_data(struct flb_s3 *ctx, struct s3_file *chunk,
                       struct multipart_upload *m_upload,
                       char *body, size_t body_size,
                       const char *tag, int tag_len)
{
    int init_upload = FLB_FALSE;
    int complete_upload = FLB_FALSE;
    int size_check = FLB_FALSE;
    int part_num_check = FLB_FALSE;
    int timeout_check = FLB_FALSE;
    time_t create_time;
    int ret;

    if (ctx->use_put_object == FLB_TRUE) {
        goto put_object;
    }

    if (s3_plugin_under_test() == FLB_TRUE) {
        init_upload = FLB_TRUE;
        complete_upload = FLB_TRUE;
        if (ctx->use_put_object == FLB_TRUE) {
            goto put_object;
        }
        else {
            goto multipart;
        }
    }

    if (m_upload == NULL) {
        if (chunk != NULL && time(NULL) > (chunk->create_time + ctx->upload_timeout)) {
            /* timeout already reached, just PutObject */
            goto put_object;
        }
        else if (body_size >= ctx->file_size) {
            /* already big enough, just use PutObject API */
            goto put_object;
        }
        else if(body_size > MIN_CHUNKED_UPLOAD_SIZE) {
            init_upload = FLB_TRUE;
            goto multipart;
        }
        else {
            goto put_object;
        }
    }
    else {
        /* existing upload */
        if (body_size < MIN_CHUNKED_UPLOAD_SIZE) {
            complete_upload = FLB_TRUE;
        }

        goto multipart;
    }

put_object:

    /*
     * remove chunk from buffer list- needed for async http so that the
     * same chunk won't be sent more than once
     */
    if (chunk) {
        create_time = chunk->create_time;
    }
    else {
        create_time = time(NULL);
    }

    ret = s3_put_object(ctx, tag, create_time, body, body_size);
    if (ret < 0) {
        /* re-add chunk to list */
        if (chunk) {
            s3_store_file_unlock(chunk);
            chunk->failures += 1;
        }
        return FLB_RETRY;
    }

    /* data was sent successfully- delete the local buffer */
    if (chunk) {
        s3_store_file_delete(ctx, chunk);
    }
    return FLB_OK;

multipart:

    if (init_upload == FLB_TRUE) {
        m_upload = create_upload(ctx, tag, tag_len);
        if (!m_upload) {
            flb_plg_error(ctx->ins, "Could not find or create upload for tag %s", tag);
            if (chunk) {
                s3_store_file_unlock(chunk);
            }
            return FLB_RETRY;
        }
    }

    if (m_upload->upload_state == MULTIPART_UPLOAD_STATE_NOT_CREATED) {
        ret = create_multipart_upload(ctx, m_upload);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not initiate multipart upload");
            if (chunk) {
                s3_store_file_unlock(chunk);
            }
            return FLB_RETRY;
        }
        m_upload->upload_state = MULTIPART_UPLOAD_STATE_CREATED;
    }

    ret = upload_part(ctx, m_upload, body, body_size);
    if (ret < 0) {
        m_upload->upload_errors += 1;
        /* re-add chunk to list */
        if (chunk) {
            s3_store_file_unlock(chunk);
            chunk->failures += 1;
        }
        return FLB_RETRY;
    }
    m_upload->part_number += 1;

    /* data was sent successfully- delete the local buffer */
    if (chunk) {
        s3_store_file_delete(ctx, chunk);
        chunk = NULL;
    }

    if (m_upload->bytes >= ctx->file_size) {
        size_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "Will complete upload for %s because uploaded data is greater"
                     " than size set by total_file_size", m_upload->s3_key);
    }
    if (m_upload->part_number >= 10000) {
        part_num_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "Will complete upload for %s because 10,000 chunks "
                     "(the API limit) have been uploaded", m_upload->s3_key);
    }
    if (time(NULL) > (m_upload->init_time + ctx->upload_timeout)) {
        timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "Will complete upload for %s because upload_timeout"
                     " has elapsed", m_upload->s3_key);
    }
    if (size_check || part_num_check || timeout_check) {
        complete_upload = FLB_TRUE;
    }

    if (complete_upload == FLB_TRUE) {
        /* mark for completion- the upload timer will handle actual completion */
        m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
    }

    return FLB_OK;
}


/*
 * Attempts to send all chunks to S3 using PutObject
 * Used on shut down to try to send all buffered data
 * Used on start up to try to send any leftover buffers from previous executions
 */
static int put_all_chunks(struct flb_s3 *ctx)
{
    struct s3_file *chunk;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    char *buffer = NULL;
    size_t buffer_size;
    int ret;

    mk_list_foreach(head, &ctx->fs->streams) {
        /* skip multi upload stream */
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach_safe(f_head, tmp, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            chunk = fsf->data;

            /* Locked chunks are being processed, skip */
            if (chunk->locked == FLB_TRUE) {
                continue;
            }

            if (chunk->failures >= MAX_UPLOAD_ERRORS) {
                flb_plg_warn(ctx->ins,
                             "Chunk for tag %s failed to send %i times, "
                             "will not retry",
                             (char *) fsf->meta_buf, MAX_UPLOAD_ERRORS);
                flb_fstore_file_inactive(ctx->fs, fsf);
                continue;
            }

            ret = construct_request_buffer(ctx, NULL, chunk,
                                           &buffer, &buffer_size);
            if (ret < 0) {
                flb_plg_error(ctx->ins,
                              "Could not construct request buffer for %s",
                              chunk->file_path);
                return -1;
            }

            ret = s3_put_object(ctx, (const char *)
                                fsf->meta_buf,
                                chunk->create_time, buffer, buffer_size);
            flb_free(buffer);
            if (ret < 0) {
                s3_store_file_unlock(chunk);
                chunk->failures += 1;
                return -1;
            }

            /* data was sent successfully- delete the local buffer */
            s3_store_file_delete(ctx, chunk);
        }
    }

    return 0;
}

/*
 * Either new_data or chunk can be NULL, but not both
 */
static int construct_request_buffer(struct flb_s3 *ctx, flb_sds_t new_data,
                                    struct s3_file *chunk,
                                    char **out_buf, size_t *out_size)
{
    char *body;
    char *tmp;
    size_t body_size = 0;
    char *buffered_data = NULL;
    size_t buffer_size = 0;
    int ret;

    if (new_data == NULL && chunk == NULL) {
        flb_plg_error(ctx->ins, "[construct_request_buffer] Something went wrong"
                      " both chunk and new_data are NULL");
        return -1;
    }

    if (chunk) {
        ret = s3_store_file_read(ctx, chunk, &buffered_data, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                          chunk->file_path);
            return -1;
        }

        /*
         * lock the chunk from buffer list- needed for async http so that the
         * same chunk won't be sent more than once.
         */
        s3_store_file_lock(chunk);
        body = buffered_data;
        body_size = buffer_size;
    }

    /*
     * If new data is arriving, increase the original 'buffered_data' size
     * to append the new one.
     */
    if (new_data) {
        body_size += flb_sds_len(new_data);

        tmp = flb_realloc(buffered_data, body_size + 1);
        if (!tmp) {
            flb_errno();
            flb_free(buffered_data);
            if (chunk) {
                s3_store_file_unlock(chunk);
            }
            return -1;
        }
        body = buffered_data = tmp;
        memcpy(body + buffer_size, new_data, flb_sds_len(new_data));
        body[body_size] = '\0';
    }

    *out_buf = body;
    *out_size = body_size;

    return 0;
}

static int s3_put_object(struct flb_s3 *ctx, const char *tag, time_t create_time,
                         char *body, size_t body_size)
{
    flb_sds_t s3_key = NULL;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    char *random_alphanumeric;
    int len;
    char uri[1024]; /* max S3 key length */

    s3_key = flb_get_s3_key(ctx->s3_key_format, create_time, tag, ctx->tag_delimiters);
    if (!s3_key) {
        flb_plg_error(ctx->ins, "Failed to construct S3 Object Key for %s", tag);
        return -1;
    }

    len = strlen(s3_key);
    memcpy(uri, s3_key, len);
    if ((len + 16) <= 1024) {
        random_alphanumeric = flb_sts_session_name();
        if (!random_alphanumeric) {
            flb_sds_destroy(s3_key);
            flb_plg_error(ctx->ins, "Failed to create randomness for S3 key %s", tag);
            return -1;
        }

        memcpy(&uri[len], "-object", 7);
        memcpy(&uri[len + 7], random_alphanumeric, 8);
        uri[len + 15] = '\0';
        flb_free(random_alphanumeric);
    }
    else {
        uri[len] = '\0';
    }

    s3_client = ctx->s3_client;
    if (s3_plugin_under_test() == FLB_TRUE) {
        c = mock_s3_call("TEST_PUT_OBJECT_ERROR", "PutObject");
    }
    else {
        c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                              uri, body, body_size,
                                              NULL, 0);
    }
    if (c) {
        flb_plg_debug(ctx->ins, "PutObject http status=%d", c->resp.status);
        if (c->resp.status == 200) {
            flb_plg_info(ctx->ins, "Successfully uploaded object %s", uri);
            flb_sds_destroy(s3_key);
            flb_http_client_destroy(c);
            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "PutObject", ctx->ins);
        if (c->resp.data != NULL) {
            flb_plg_error(ctx->ins, "Raw PutObject response: %s", c->resp.data);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "PutObject request failed");
    flb_sds_destroy(s3_key);
    return -1;
}

static struct multipart_upload *get_upload(struct flb_s3 *ctx,
                                           const char *tag, int tag_len)
{
    struct multipart_upload *m_upload = NULL;
    struct multipart_upload *tmp_upload = NULL;
    struct mk_list *tmp;
    struct mk_list *head;

    mk_list_foreach_safe(head, tmp, &ctx->uploads) {
        tmp_upload = mk_list_entry(head, struct multipart_upload, _head);

        if (tmp_upload->upload_state == MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS) {
            continue;
        }
        if (tmp_upload->upload_errors >= MAX_UPLOAD_ERRORS) {
            tmp_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
            flb_plg_error(ctx->ins, "Upload for %s has reached max upload errors",
                          tmp_upload->s3_key);
            continue;
        }
        if (strcmp(tmp_upload->tag, tag) == 0) {
            m_upload = tmp_upload;
            break;
        }
    }

    return m_upload;
}

static struct multipart_upload *create_upload(struct flb_s3 *ctx,
                                              const char *tag, int tag_len)
{
    struct multipart_upload *m_upload = NULL;
    flb_sds_t s3_key = NULL;
    flb_sds_t tmp_sds = NULL;

    /* create new upload for this key */
    m_upload = flb_calloc(1, sizeof(struct multipart_upload));
    if (!m_upload) {
        flb_errno();
        return NULL;
    }
    s3_key = flb_get_s3_key(ctx->s3_key_format, time(NULL), tag, ctx->tag_delimiters);
    if (!s3_key) {
        flb_plg_error(ctx->ins, "Failed to construct S3 Object Key for %s", tag);
        flb_free(m_upload);
        return NULL;
    }
    m_upload->s3_key = s3_key;
    tmp_sds = flb_sds_create_len(tag, tag_len);
    if (!tmp_sds) {
        flb_errno();
        flb_free(m_upload);
        return NULL;
    }
    m_upload->tag = tmp_sds;
    m_upload->upload_state = MULTIPART_UPLOAD_STATE_NOT_CREATED;
    m_upload->part_number = 1;
    m_upload->init_time = time(NULL);
    mk_list_add(&m_upload->_head, &ctx->uploads);

    return m_upload;
}

static void cb_s3_upload(struct flb_config *config, void *data)
{
    struct flb_s3 *ctx = data;
    struct s3_file *chunk = NULL;
    struct multipart_upload *m_upload = NULL;
    struct flb_fstore_file *fsf;
    char *buffer = NULL;
    size_t buffer_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    int complete;
    int ret;
    time_t now;

    flb_plg_debug(ctx->ins, "Running upload timer callback..");

    now = time(NULL);

    /* Check all chunks and see if any have timed out */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        chunk = fsf->data;

        if (now < (chunk->create_time + ctx->upload_timeout)) {
            continue; /* Only send chunks which have timed out */
        }

        /* Locked chunks are being processed, skip */
        if (chunk->locked == FLB_TRUE) {
            continue;
        }

        m_upload = get_upload(ctx, (const char *) fsf->meta_buf, fsf->meta_size);

        ret = construct_request_buffer(ctx, NULL, chunk, &buffer, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                          chunk->file_path);
            continue;
        }

        /* FYI: if construct_request_buffer() succeedeed, the s3_file is locked */
        ret = upload_data(ctx, chunk, m_upload, buffer, buffer_size,
                          (const char *) fsf->meta_buf, fsf->meta_size);
        flb_free(buffer);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "Could not send chunk with tag %s",
                          (char *) fsf->meta_buf);
        }
    }

    /* Check all uploads and see if any need completion */
    mk_list_foreach_safe(head, tmp, &ctx->uploads) {
        m_upload = mk_list_entry(head, struct multipart_upload, _head);
        complete = FLB_FALSE;

        if (m_upload->complete_errors >= MAX_UPLOAD_ERRORS) {
            flb_plg_error(ctx->ins,
                          "Upload for %s has reached max completion errors, "
                          "plugin will give up", m_upload->s3_key);
            mk_list_del(&m_upload->_head);
            continue;
        }

        if (m_upload->upload_state == MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS) {
            complete = FLB_TRUE;
        }
        if (time(NULL) > (m_upload->init_time + ctx->upload_timeout)) {
            flb_plg_info(ctx->ins, "Completing upload for %s because upload_timeout"
                         " has passed", m_upload->s3_key);
            complete = FLB_TRUE;
        }
        if (complete == FLB_TRUE) {
            m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
            mk_list_del(&m_upload->_head);
            ret = complete_multipart_upload(ctx, m_upload);
            if (ret == 0) {
                multipart_upload_destroy(m_upload);
            }
            else {
                mk_list_add(&m_upload->_head, &ctx->uploads);
                /* data was persisted, this can be retried */
                m_upload->complete_errors += 1;
                flb_plg_error(ctx->ins, "Could not complete upload %s, will retry..",
                              m_upload->s3_key);
            }
        }
    }
}

static void cb_s3_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    struct flb_s3 *ctx = out_context;
    flb_sds_t json = NULL;
    struct s3_file *chunk = NULL;
    struct multipart_upload *m_upload = NULL;
    char *buffer = NULL;
    size_t buffer_size;
    int timeout_check = FLB_FALSE;
    size_t chunk_size = 0;
    size_t upload_size = 0;
    int ret;
    int len;
    (void) i_ins;
    (void) config;

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to S3; buffer=%s",
                     ctx->fs->root_path);
        ctx->has_old_buffers = FLB_FALSE;
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            ctx->has_old_buffers = FLB_TRUE;
            flb_plg_error(ctx->ins,
                          "Failed to send locally buffered data left over "
                          "from previous executions; will retry. Buffer=%s",
                          ctx->fs->root_path);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    /*
     * create a timer that will run periodically and check if uploads
     * are ready for completion
     * this is created once on the first flush
     */
    if (ctx->timer_created == FLB_FALSE) {
        flb_plg_debug(ctx->ins,
                      "Creating upload timer with frequency %ds",
                      ctx->timer_ms / 1000);

        ret = flb_sched_timer_cb_create(config, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->timer_ms,
                                        cb_s3_upload,
                                        ctx);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create upload timer");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->timer_created = FLB_TRUE;
    }

    json = flb_pack_msgpack_to_json_format(data, bytes,
                                           FLB_PACK_JSON_FORMAT_LINES,
                                           ctx->json_date_format,
                                           ctx->json_date_key);

    if (json == NULL) {
        flb_plg_error(ctx->ins, "Could not marshal msgpack to JSON");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    len = flb_sds_len(json);

    /* Get a chunk candidate matching the given 'Tag' */
    chunk = s3_store_file_get(ctx, tag, tag_len);

    if (chunk != NULL && chunk->failures >= MAX_UPLOAD_ERRORS) {
        flb_plg_warn(ctx->ins, "Chunk for tag %s failed to send %d times, "
                     "will not retry", tag, MAX_UPLOAD_ERRORS);
        s3_store_file_inactive(ctx, chunk);
        chunk = NULL;
    }

    /* if timeout has elapsed, we must put whatever data we have */
    if (chunk != NULL && time(NULL) > (chunk->create_time + ctx->upload_timeout)) {
        timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "upload_timeout reached for %s", tag);
    }

    m_upload = get_upload(ctx, tag, tag_len);

    if (m_upload != NULL && time(NULL) > (m_upload->init_time + ctx->upload_timeout)) {
        timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "upload_timeout reached for %s", tag);
    }

    chunk_size = len;
    if (chunk) {
        chunk_size += chunk->size;
    }

    upload_size = len;
    if (m_upload) {
        upload_size += m_upload->bytes;
    }

    if (chunk_size < ctx->upload_chunk_size && upload_size < ctx->file_size) {
        if (timeout_check == FLB_FALSE) {
            /* add data to local buffer */
            ret = s3_store_buffer_put(ctx, chunk,
                                      tag, tag_len, json, (size_t) len);
            if (s3_plugin_under_test() == FLB_TRUE) {
                goto send_data;
            }
            flb_sds_destroy(json);
            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            FLB_OUTPUT_RETURN(FLB_OK);
        }
    }

send_data:
    ret = construct_request_buffer(ctx, json, chunk, &buffer, &buffer_size);
    flb_sds_destroy(json);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                      chunk->file_path);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = upload_data(ctx, chunk, m_upload, buffer, buffer_size, tag, tag_len);
    flb_free(buffer);

    FLB_OUTPUT_RETURN(ret);
}

static int cb_s3_exit(void *data, struct flb_config *config)
{
    int ret;
    struct flb_s3 *ctx = data;
    struct multipart_upload *m_upload = NULL;
    struct mk_list *tmp;
    struct mk_list *head;

    if (!ctx) {
        return 0;
    }

    if (s3_store_has_data(ctx) == FLB_TRUE) {
        if (ctx->use_put_object == FLB_TRUE) {
            /* exit must run in sync mode  */
            ctx->s3_client->upstream->flags &= ~(FLB_IO_ASYNC);
        }
        flb_plg_info(ctx->ins, "Sending all locally buffered data to S3");
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Cloud not send all chunks on exit");
        }
    }

    if (s3_store_has_uploads(ctx) == FLB_TRUE) {
        mk_list_foreach_safe(head, tmp, &ctx->uploads) {
            m_upload = mk_list_entry(head, struct multipart_upload, _head);

            if (m_upload->bytes > 0) {
                m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
                mk_list_del(&m_upload->_head);
                ret = complete_multipart_upload(ctx, m_upload);
                if (ret == 0) {
                    multipart_upload_destroy(m_upload);
                }
                else {
                    mk_list_add(&m_upload->_head, &ctx->uploads);
                    flb_plg_error(ctx->ins, "Could not complete upload %s",
                                  m_upload->s3_key);
                }
            }
        }
    }

    s3_store_exit(ctx);
    s3_context_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    "Specifies the format of the date. Supported formats are double, iso8601 and epoch."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_s3, json_date_key),
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_SIZE, "total_file_size", "100000000",
     0, FLB_TRUE, offsetof(struct flb_s3, file_size),
     "Specifies the size of files in S3. Maximum size is 50GB, minimim is 1MB"
    },
    {
     FLB_CONFIG_MAP_SIZE, "upload_chunk_size", "5242880",
     0, FLB_TRUE, offsetof(struct flb_s3, upload_chunk_size),
     "This plugin uses the S3 Multipart Upload API to stream data to S3, "
     "ensuring your data gets-off-the-box as quickly as possible. "
     "This parameter configures the size of each “part” in the upload. "
     "The total_file_size option configures the size of the file you will see "
     "in S3; this option determines the size of chunks uploaded until that "
     "size is reached. These chunks are temporarily stored in chunk_buffer_path "
     "until their size reaches upload_chunk_size, which point the chunk is "
     "uploaded to S3. Default: 5M, Max: 50M, Min: 5M."
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "10m",
     0, FLB_TRUE, offsetof(struct flb_s3, upload_timeout),
     "Optionally specify a timeout for uploads. "
     "Whenever this amount of time has elapsed, Fluent Bit will complete an "
     "upload and create a new file in S3. For example, set this value to 60m "
     "and you will get a new file in S3 every hour. Default is 10m."
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, bucket),
    "S3 bucket name."
    },
    {
     FLB_CONFIG_MAP_STR, "region", "us-east-1",
     0, FLB_TRUE, offsetof(struct flb_s3, region),
    "AWS region."
    },
    {
     FLB_CONFIG_MAP_STR, "role_arn", NULL,
     0, FLB_FALSE, 0,
     "ARN of an IAM role to assume (ex. for cross account access)."
    },
    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, endpoint),
    "Custom endpoint for the S3 API."
    },
    {
     FLB_CONFIG_MAP_STR, "sts_endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, sts_endpoint),
    "Custom endpoint for the STS API."
    },

    {
     FLB_CONFIG_MAP_STR, "store_dir", "/tmp/fluent-bit/s3",
     0, FLB_TRUE, offsetof(struct flb_s3, store_dir),
     "Directory to locally buffer data before sending. Plugin uses the S3 Multipart "
     "upload API to send data in chunks of 5 MB at a time- only a small amount of"
     " data will be locally buffered at any given point in time."
    },

    {
     FLB_CONFIG_MAP_STR, "s3_key_format", "/fluent-bit-logs/$TAG/%Y/%m/%d/%H/%M/%S",
     0, FLB_TRUE, offsetof(struct flb_s3, s3_key_format),
    "Format string for keys in S3. This option supports strftime time formatters "
    "and a syntax for selecting parts of the Fluent log tag using a syntax inspired "
    "by the rewrite_tag filter. Add $TAG in the format string to insert the full "
    "log tag; add $TAG[0] to insert the first part of the tag in the s3 key. "
    "The tag is split into “parts” using the characters specified with the "
    "s3_key_format_tag_delimiters option. See the in depth examples and tutorial"
    " in the documentation."
    },

    {
     FLB_CONFIG_MAP_STR, "s3_key_format_tag_delimiters", ".",
     0, FLB_TRUE, offsetof(struct flb_s3, tag_delimiters),
    "A series of characters which will be used to split the tag into “parts” for "
    "use with the s3_key_format option. See the in depth examples and tutorial in "
    "the documentation."
    },

    {
     FLB_CONFIG_MAP_BOOL, "use_put_object", "false",
     0, FLB_TRUE, offsetof(struct flb_s3, use_put_object),
     "Use the S3 PutObject API, instead of the multipart upload API"
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_s3_plugin = {
    .name         = "s3",
    .description  = "Send to S3",
    .cb_init      = cb_s3_init,
    .cb_flush     = cb_s3_flush,
    .cb_exit      = cb_s3_exit,
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
    .config_map   = config_map
};
