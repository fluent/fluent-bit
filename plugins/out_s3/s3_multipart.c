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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_fstore.h>
#include <ctype.h>

#include "s3.h"
#include "s3_store.h"

#define COMPLETE_MULTIPART_UPLOAD_BASE_LEN 100
#define COMPLETE_MULTIPART_UPLOAD_PART_LEN 124

flb_sds_t get_etag(char *response, size_t size);

static inline int try_to_write(char *buf, int *off, size_t left,
                               const char *str, size_t str_len)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        return FLB_FALSE;
    }
    memcpy(buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}


/* the 'tag' or key in the upload_dir is s3_key + \n + upload_id */
static flb_sds_t upload_key(struct multipart_upload *m_upload)
{
    flb_sds_t key;
    flb_sds_t tmp;

    key = flb_sds_create_size(64);

    tmp = flb_sds_printf(&key, "%s\n%s", m_upload->s3_key, m_upload->upload_id);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(key);
        return NULL;
    }
    key = tmp;

    return key;
}

/* the 'tag' or key in the upload_dir is s3_key + \n + upload_id */
static int upload_data_from_key(struct multipart_upload *m_upload, char *key)
{
    flb_sds_t tmp_sds;
    int len = 0;
    int original_len;
    char *tmp;

    original_len = strlen(key);

    tmp = strchr(key, '\n');
    if (!tmp) {
        return -1;
    }

    len = tmp - key;
    tmp_sds = flb_sds_create_len(key, len);
    if (!tmp_sds) {
        flb_errno();
        return -1;
    }
    m_upload->s3_key = tmp_sds;

    tmp++;
    original_len -= (len + 1);

    tmp_sds = flb_sds_create_len(tmp, original_len);
    if (!tmp_sds) {
        flb_errno();
        return -1;
    }
    m_upload->upload_id = tmp_sds;

    return 0;
}

/* parse etags from file data */
static void parse_etags(struct multipart_upload *m_upload, char *data)
{
    char *line = data;
    char *start;
    char *end;
    flb_sds_t etag;
    int part_num;
    int len;

    if (!data) {
        return;
    }

    line = strtok(data, "\n");

    if (!line) {
        return;
    }

    do {
        start = strstr(line, "part_number=");
        if (!start) {
            return;
        }
        start += 12;
        end = strchr(start, '\t');
        if (!end) {
            flb_debug("[s3 restart parser] Did not find tab separator in line %s", start);
            return;
        }
        *end = '\0';
        part_num = atoi(start);
        if (part_num <= 0) {
            flb_debug("[s3 restart parser] Could not parse part_number from %s", start);
            return;
        }
        m_upload->part_number = part_num;
        *end = '\t';

        start = strstr(line, "tag=");
        if (!start) {
            flb_debug("[s3 restart parser] Could not find 'etag=' %s", line);
            return;
        }

        start += 4;
        len = strlen(start);

        if (len <= 0) {
            flb_debug("[s3 restart parser] Could not find etag %s", line);
            return;
        }

        etag = flb_sds_create_len(start, len);
        if (!etag) {
            flb_debug("[s3 restart parser] Could create etag");
            return;
        }
        flb_debug("[s3 restart parser] found part number %d=%s", part_num, etag);
        m_upload->etags[part_num - 1] = etag;

        line = strtok(NULL, "\n");
    } while (line != NULL);
}

static struct multipart_upload *upload_from_file(struct flb_s3 *ctx,
                                                 struct flb_fstore_file *fsf)
{
    struct multipart_upload *m_upload = NULL;
    char *buffered_data = NULL;
    size_t buffer_size = 0;
    int ret;

    ret = s3_store_file_upload_read(ctx, fsf, &buffered_data, &buffer_size);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                      fsf->name);
        return NULL;
    }

    /* always make sure we have a fresh copy of metadata */
    ret = s3_store_file_meta_get(ctx, fsf);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not read file metadata: %s",
                      fsf->name);
        flb_free(buffered_data);
        return NULL;
    }

    m_upload = flb_calloc(1, sizeof(struct multipart_upload));
    if (!m_upload) {
        flb_errno();
        flb_free(buffered_data);
        return NULL;
    }
    m_upload->init_time = time(NULL);
    m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;

    ret = upload_data_from_key(m_upload, fsf->meta_buf);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not extract upload data from: %s",
                      fsf->name);
        flb_free(buffered_data);
        multipart_upload_destroy(m_upload);
        return NULL;
    }

    parse_etags(m_upload, buffered_data);
    flb_free(buffered_data);
    if (m_upload->part_number == 0) {
        flb_plg_error(ctx->ins, "Could not extract upload data from %s",
                      fsf->name);
        multipart_upload_destroy(m_upload);
        return NULL;
    }

    /* code expects it to be 1 more than the last part read */
    m_upload->part_number++;

    return m_upload;
}

void multipart_read_uploads_from_fs(struct flb_s3 *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct multipart_upload *m_upload = NULL;
    struct flb_fstore_file *fsf;

    mk_list_foreach_safe(head, tmp, &ctx->stream_upload->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        m_upload = upload_from_file(ctx, fsf);
        if (!m_upload) {
            flb_plg_error(ctx->ins,
                          "Could not process multipart upload data in %s",
                          fsf->name);
            continue;
        }
        mk_list_add(&m_upload->_head, &ctx->uploads);
        flb_plg_info(ctx->ins,
                     "Successfully read existing upload from file system, s3_key=%s",
                     m_upload->s3_key);
    }
}

/* store list of part number and etag */
static flb_sds_t upload_data(flb_sds_t etag, int part_num)
{
    flb_sds_t data;
    flb_sds_t tmp;

    data = flb_sds_create_size(64);

    tmp = flb_sds_printf(&data, "part_number=%d\tetag=%s\n", part_num, etag);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(data);
        return NULL;
    }
    data = tmp;

    return data;
}

/* persists upload data to the file system */
static int save_upload(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                       flb_sds_t etag)
{
    int ret;
    flb_sds_t key;
    flb_sds_t data;
    struct flb_fstore_file *fsf;

    key = upload_key(m_upload);
    if (!key) {
        flb_plg_debug(ctx->ins, "Could not constuct upload key for buffer dir");
        return -1;
    }

    data = upload_data(etag, m_upload->part_number);
    if (!data) {
        flb_plg_debug(ctx->ins, "Could not constuct upload key for buffer dir");
        return -1;
    }

    fsf = s3_store_file_upload_get(ctx, key, flb_sds_len(key));

    /* Write the key to the file */
    ret = s3_store_file_upload_put(ctx, fsf, key, data);

    flb_sds_destroy(key);
    flb_sds_destroy(data);

    return ret;
}

static int remove_upload_from_fs(struct flb_s3 *ctx, struct multipart_upload *m_upload)
{
    flb_sds_t key;
    struct flb_fstore_file *fsf;

    key = upload_key(m_upload);
    if (!key) {
        flb_plg_debug(ctx->ins, "Could not construct upload key");
        return -1;
    }

    fsf = s3_store_file_upload_get(ctx, key, flb_sds_len(key));
    if (fsf) {
        s3_store_file_upload_delete(ctx, fsf);
    }
    flb_sds_destroy(key);
    return 0;
}

/*
 * https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
 */
static int complete_multipart_upload_payload(struct flb_s3 *ctx,
                                             struct multipart_upload *m_upload,
                                             char **out_buf, size_t *out_size)
{
    char *buf;
    int i;
    int offset = 0;
    flb_sds_t etag;
    size_t size = COMPLETE_MULTIPART_UPLOAD_BASE_LEN;
    char part_num[11];

    size = size + (COMPLETE_MULTIPART_UPLOAD_PART_LEN * m_upload->part_number);

    buf = flb_malloc(size + 1);
    if (!buf) {
        flb_errno();
        return -1;
    }

    if (!try_to_write(buf, &offset, size,
                      "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">", 73)) {
        goto error;
    }

    for (i = 0; i < m_upload->part_number; i++) {
        etag = m_upload->etags[i];
        if (etag == NULL) {
            continue;
        }
        if (!try_to_write(buf, &offset, size,
                          "<Part><ETag>", 12)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          etag, 0)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          "</ETag><PartNumber>", 19)) {
            goto error;
        }

        if (!sprintf(part_num, "%d", i + 1)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          part_num, 0)) {
            goto error;
        }

        if (!try_to_write(buf, &offset, size,
                          "</PartNumber></Part>", 20)) {
            goto error;
        }
    }

    if (!try_to_write(buf, &offset, size,
                      "</CompleteMultipartUpload>", 26)) {
        goto error;
    }

    buf[offset] = '\0';

    *out_buf = buf;
    *out_size = offset;
    return 0;

error:
    flb_free(buf);
    flb_plg_error(ctx->ins, "Failed to construct CompleteMultipartUpload "
                  "request body");
    return -1;
}

int complete_multipart_upload(struct flb_s3 *ctx,
                              struct multipart_upload *m_upload,
                              char *pre_signed_url)
{
    char *body = NULL;
    size_t size;
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    int ret;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    flb_sds_t presigned_host = NULL;
    const char *original_host = NULL;
    char *original_upstream_host = NULL;
    int original_upstream_port = 0;
    int presigned_port = 0;
    int result = -1;

    if (!m_upload->upload_id) {
        flb_plg_error(ctx->ins, "Cannot complete multipart upload for key %s: "
                      "upload ID is unset ", m_upload->s3_key);
        return -1;
    }

    if (pre_signed_url != NULL) {
        ret = s3_parse_presigned_url(ctx, pre_signed_url, &presigned_host, &uri, &presigned_port);
        if (ret != 0) {
            return -1;
        }

        if (presigned_port != 0 && presigned_port != ctx->port) {
            flb_plg_error(ctx->ins, "Pre signed URL uses unexpected port %d", presigned_port);
            flb_sds_destroy(presigned_host);
            flb_sds_destroy(uri);
            return -1;
        }

        original_host = ctx->s3_client->host;
        original_upstream_host = ctx->s3_client->upstream->tcp_host;
        original_upstream_port = ctx->s3_client->upstream->tcp_port;
        ctx->s3_client->host = presigned_host;
        ctx->s3_client->upstream->tcp_host = presigned_host;
        ctx->s3_client->upstream->tcp_port = presigned_port != 0 ? presigned_port : ctx->port;
    }
    else {
        uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 11 +
                                  flb_sds_len(m_upload->upload_id));
        if (!uri) {
            flb_errno();
            return -1;
        }

        tmp = flb_sds_printf(&uri, "/%s%s?uploadId=%s", ctx->bucket,
                            m_upload->s3_key, m_upload->upload_id);
        if (!tmp) {
            goto cleanup;
        }
        uri = tmp;
    }

    ret = complete_multipart_upload_payload(ctx, m_upload, &body, &size);
    if (ret < 0) {
        goto cleanup;
    }

    s3_client = ctx->s3_client;
    if (s3_plugin_under_test() == FLB_TRUE) {
        c = mock_s3_call("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", "CompleteMultipartUpload");
    }
    else {
        c = s3_client->client_vtable->request(s3_client, FLB_HTTP_POST,
                                              uri, body, size,
                                              NULL, 0);
    }
    flb_free(body);
    body = NULL;

    if (c) {
        flb_plg_debug(ctx->ins, "CompleteMultipartUpload http status=%d",
                      c->resp.status);
        if (c->resp.status == 200) {
            flb_plg_info(ctx->ins, "Successfully completed multipart upload "
                         "for %s, UploadId=%s", m_upload->s3_key,
                         m_upload->upload_id);
            flb_http_client_destroy(c);
            /* remove this upload from the file system */
            remove_upload_from_fs(ctx, m_upload);
            result = 0;
            goto cleanup;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "CompleteMultipartUpload", ctx->ins);
        if (c->resp.payload != NULL) {
            flb_plg_debug(ctx->ins, "Raw CompleteMultipartUpload response: %s",
                          c->resp.payload);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "CompleteMultipartUpload request failed");
    result = -1;

cleanup:
    if (body != NULL) {
        flb_free(body);
    }

    if (original_host != NULL) {
        ctx->s3_client->host = original_host;
        ctx->s3_client->upstream->tcp_host = original_upstream_host;
        ctx->s3_client->upstream->tcp_port = original_upstream_port;
        flb_sds_destroy(presigned_host);
    }

    if (uri != NULL) {
        flb_sds_destroy(uri);
    }

    return result;
}

int abort_multipart_upload(struct flb_s3 *ctx,
                           struct multipart_upload *m_upload,
                           char *pre_signed_url)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    flb_sds_t presigned_host = NULL;
    const char *original_host = NULL;
    char *original_upstream_host = NULL;
    int original_upstream_port = 0;
    int presigned_port = 0;
    int result = -1;
    int ret;

    if (!m_upload->upload_id) {
        flb_plg_error(ctx->ins, "Cannot complete multipart upload for key %s: "
                      "upload ID is unset ", m_upload->s3_key);
        return -1;
    }

    if (pre_signed_url != NULL) {
        ret = s3_parse_presigned_url(ctx, pre_signed_url, &presigned_host, &uri, &presigned_port);
        if (ret != 0) {
            return -1;
        }

        if (presigned_port != 0 && presigned_port != ctx->port) {
            flb_plg_error(ctx->ins, "Pre signed URL uses unexpected port %d", presigned_port);
            flb_sds_destroy(presigned_host);
            flb_sds_destroy(uri);
            return -1;
        }

        original_host = ctx->s3_client->host;
        original_upstream_host = ctx->s3_client->upstream->tcp_host;
        original_upstream_port = ctx->s3_client->upstream->tcp_port;
        ctx->s3_client->host = presigned_host;
        ctx->s3_client->upstream->tcp_host = presigned_host;
        ctx->s3_client->upstream->tcp_port = presigned_port != 0 ? presigned_port : ctx->port;
    }
    else {
        uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 11 +
                                  flb_sds_len(m_upload->upload_id));
        if (!uri) {
            flb_errno();
            return -1;
        }

        tmp = flb_sds_printf(&uri, "/%s%s?uploadId=%s", ctx->bucket,
                            m_upload->s3_key, m_upload->upload_id);
        if (!tmp) {
            goto abort_cleanup;
        }
        uri = tmp;
    }

    s3_client = ctx->s3_client;
    if (s3_plugin_under_test() == FLB_TRUE) {
        c = mock_s3_call("TEST_ABORT_MULTIPART_UPLOAD_ERROR", "AbortMultipartUpload");
    }
    else {
        c = s3_client->client_vtable->request(s3_client, FLB_HTTP_DELETE,
                                              uri, NULL, 0,
                                              NULL, 0);
    }
    if (c) {
        flb_plg_debug(ctx->ins, "AbortMultipartUpload http status=%d",
                      c->resp.status);
        if (c->resp.status == 204) {
            flb_plg_info(ctx->ins, "Successfully completed multipart upload "
                         "for %s, UploadId=%s", m_upload->s3_key,
                         m_upload->upload_id);
            flb_http_client_destroy(c);
            /* remove this upload from the file system */
            remove_upload_from_fs(ctx, m_upload);
            result = 0;
            goto abort_cleanup;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "AbortMultipartUpload", ctx->ins);
        if (c->resp.payload != NULL) {
            flb_plg_debug(ctx->ins, "Raw AbortMultipartUpload response: %s",
                          c->resp.payload);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "AbortMultipartUpload request failed");
    result = -1;

abort_cleanup:
    if (original_host != NULL) {
        ctx->s3_client->host = original_host;
        ctx->s3_client->upstream->tcp_host = original_upstream_host;
        ctx->s3_client->upstream->tcp_port = original_upstream_port;
        flb_sds_destroy(presigned_host);
    }

    if (uri != NULL) {
        flb_sds_destroy(uri);
    }

    return result;
}

int create_multipart_upload(struct flb_s3 *ctx,
                            struct multipart_upload *m_upload,
                            char *pre_signed_url)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    struct flb_aws_header *headers = NULL;
    int num_headers = 0;
    int ret;
    flb_sds_t presigned_host = NULL;
    const char *original_host = NULL;
    char *original_upstream_host = NULL;
    int original_upstream_port = 0;
    int presigned_port = 0;

    if (pre_signed_url != NULL) {
        ret = s3_parse_presigned_url(ctx, pre_signed_url, &presigned_host, &uri, &presigned_port);
        if (ret != 0) {
            return -1;
        }

        if (presigned_port != 0 && presigned_port != ctx->port) {
            flb_plg_error(ctx->ins, "Pre signed URL uses unexpected port %d", presigned_port);
            flb_sds_destroy(presigned_host);
            flb_sds_destroy(uri);
            return -1;
        }

        original_host = ctx->s3_client->host;
        original_upstream_host = ctx->s3_client->upstream->tcp_host;
        original_upstream_port = ctx->s3_client->upstream->tcp_port;
        ctx->s3_client->host = presigned_host;
        ctx->s3_client->upstream->tcp_host = presigned_host;
        ctx->s3_client->upstream->tcp_port = presigned_port != 0 ? presigned_port : ctx->port;
    }
    else {
        uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 8);
        if (!uri) {
            flb_errno();
            return -1;
        }

        tmp = flb_sds_printf(&uri, "/%s%s?uploads=", ctx->bucket, m_upload->s3_key);
        if (!tmp) {
            ret = -1;
            goto cleanup;
        }
        uri = tmp;
    }

    s3_client = ctx->s3_client;
    if (s3_plugin_under_test() == FLB_TRUE) {
        c = mock_s3_call("TEST_CREATE_MULTIPART_UPLOAD_ERROR", "CreateMultipartUpload");
    }
    else {
        ret = create_headers(ctx, NULL, &headers, &num_headers, FLB_TRUE);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create headers");
            goto cleanup;
        }
        c = s3_client->client_vtable->request(s3_client, FLB_HTTP_POST,
                                              uri, NULL, 0, headers, num_headers);
        if (headers) {
           flb_free(headers);
        }
    }
    ret = -1;

cleanup:
    if (original_host != NULL) {
        ctx->s3_client->host = original_host;
        ctx->s3_client->upstream->tcp_host = original_upstream_host;
        ctx->s3_client->upstream->tcp_port = original_upstream_port;
        flb_sds_destroy(presigned_host);
    }

    if (uri != NULL) {
        flb_sds_destroy(uri);
    }

    if (c) {
        flb_plg_debug(ctx->ins, "CreateMultipartUpload http status=%d",
                      c->resp.status);
        if (c->resp.status == 200) {
            tmp = flb_aws_xml_get_val(c->resp.payload, c->resp.payload_size,
                                  "<UploadId>", "</UploadId>");
            if (!tmp) {
                flb_plg_error(ctx->ins, "Could not find upload ID in "
                              "CreateMultipartUpload response");
                flb_plg_debug(ctx->ins, "Raw CreateMultipartUpload response: %s",
                              c->resp.payload);
                flb_http_client_destroy(c);
                return -1;
            }
            m_upload->upload_id = tmp;
            flb_plg_info(ctx->ins, "Successfully initiated multipart upload "
                         "for %s, UploadId=%s", m_upload->s3_key,
                         m_upload->upload_id);
            flb_http_client_destroy(c);
            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "CreateMultipartUpload", ctx->ins);
        if (c->resp.payload != NULL) {
            flb_plg_debug(ctx->ins, "Raw CreateMultipartUpload response: %s",
                          c->resp.payload);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "CreateMultipartUpload request failed");
    return ret;
}

/* gets the ETag value from response headers */
flb_sds_t get_etag(char *response, size_t size)
{
    char *tmp;
    int start;
    int end;
    int len;
    int i = 0;
    flb_sds_t etag;

    if (response == NULL) {
        return NULL;
    }

    tmp = strstr(response, "ETag:");
    if (!tmp) {
        return NULL;
    }
    i = tmp - response;

    /* advance to end of ETag key */
    i += 5;

    /* advance across any whitespace and the opening quote */
    while (i < size && (response[i] == '\"' || isspace(response[i]) != 0)) {
        i++;
    }
    start = i;
    /* advance until we hit whitespace or the end quote */
    while (i < size && (response[i] != '\"' && isspace(response[i]) == 0)) {
        i++;
    }
    end = i;
    len = end - start;

    etag = flb_sds_create_len(response + start, len);
    if (!etag) {
        flb_errno();
        return NULL;
    }

    return etag;
}

int upload_part(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                char *body, size_t body_size, char *pre_signed_url)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    int ret;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    struct flb_aws_header *headers = NULL;
    int num_headers = 0;
    char body_md5[25];
    flb_sds_t presigned_host = NULL;
    const char *original_host = NULL;
    char *original_upstream_host = NULL;
    int original_upstream_port = 0;
    int presigned_port = 0;
    int result = -1;

    if (pre_signed_url != NULL) {
        ret = s3_parse_presigned_url(ctx, pre_signed_url, &presigned_host, &uri, &presigned_port);
        if (ret != 0) {
            return -1;
        }

        if (presigned_port != 0 && presigned_port != ctx->port) {
            flb_plg_error(ctx->ins, "Pre signed URL uses unexpected port %d", presigned_port);
            flb_sds_destroy(presigned_host);
            flb_sds_destroy(uri);
            return -1;
        }

        original_host = ctx->s3_client->host;
        original_upstream_host = ctx->s3_client->upstream->tcp_host;
        original_upstream_port = ctx->s3_client->upstream->tcp_port;
        ctx->s3_client->host = presigned_host;
        ctx->s3_client->upstream->tcp_host = presigned_host;
        ctx->s3_client->upstream->tcp_port = presigned_port != 0 ? presigned_port : ctx->port;
    }
    else {
        uri = flb_sds_create_size(flb_sds_len(m_upload->s3_key) + 8);
        if (!uri) {
            flb_errno();
            return -1;
        }

        tmp = flb_sds_printf(&uri, "/%s%s?partNumber=%d&uploadId=%s",
                             ctx->bucket, m_upload->s3_key, m_upload->part_number,
                             m_upload->upload_id);
        if (!tmp) {
            goto cleanup;
        }
        uri = tmp;
    }

    memset(body_md5, 0, sizeof(body_md5));
    if (ctx->send_content_md5 == FLB_TRUE) {
        ret = get_md5_base64(body, body_size, body_md5, sizeof(body_md5));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Failed to create Content-MD5 header");
            goto cleanup;
        }

        num_headers = 1;
        headers = flb_malloc(sizeof(struct flb_aws_header) * num_headers);
        if (headers == NULL) {
            flb_errno();
            goto cleanup;
        }

        headers[0].key = "Content-MD5";
        headers[0].key_len = 11;
        headers[0].val = body_md5;
        headers[0].val_len = strlen(body_md5);
    }

    s3_client = ctx->s3_client;
    if (s3_plugin_under_test() == FLB_TRUE) {
        c = mock_s3_call("TEST_UPLOAD_PART_ERROR", "UploadPart");
    }
    else {
        c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                              uri, body, body_size,
                                              headers, num_headers);
    }
    if (headers != NULL) {
        flb_free(headers);
        headers = NULL;
    }

    if (c) {
        flb_plg_info(ctx->ins, "UploadPart http status=%d",
                      c->resp.status);
        if (c->resp.status == 200) {
            tmp = get_etag(c->resp.data, c->resp.data_size);
            if (!tmp) {
                flb_plg_error(ctx->ins, "Could not find ETag in "
                              "UploadPart response");
                flb_plg_debug(ctx->ins, "Raw UploadPart response: %s",
                              c->resp.payload);
                flb_http_client_destroy(c);
                goto cleanup;
            }
            m_upload->etags[m_upload->part_number - 1] = tmp;
            flb_plg_info(ctx->ins, "Successfully uploaded part #%d "
                         "for %s, UploadId=%s, ETag=%s", m_upload->part_number,
                         m_upload->s3_key, m_upload->upload_id, tmp);
            flb_http_client_destroy(c);
            /* track how many bytes are have gone toward this upload */
            m_upload->bytes += body_size;

            /* finally, attempt to persist the data for this upload */
            ret = save_upload(ctx, m_upload, tmp);
            if (ret == 0) {
                flb_plg_debug(ctx->ins, "Successfully persisted upload data, UploadId=%s",
                              m_upload->upload_id);
            }
            else {
                flb_plg_warn(ctx->ins, "Was not able to persisted upload data to disk; "
                            "if fluent bit dies without completing this upload the part "
                            "could be lost, UploadId=%s, ETag=%s",
                            m_upload->upload_id, tmp);
            }
            result = 0;
            goto cleanup;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "UploadPart", ctx->ins);
        if (c->resp.payload != NULL) {
            flb_plg_debug(ctx->ins, "Raw UploadPart response: %s",
                          c->resp.payload);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "UploadPart request failed");

cleanup:
    if (original_host != NULL) {
        ctx->s3_client->host = original_host;
        ctx->s3_client->upstream->tcp_host = original_upstream_host;
        ctx->s3_client->upstream->tcp_port = original_upstream_port;
        flb_sds_destroy(presigned_host);
    }

    if (uri != NULL) {
        flb_sds_destroy(uri);
    }

    return result;
}
