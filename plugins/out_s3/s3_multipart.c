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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_base64.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "s3.h"
#include "s3_multipart.h"

#ifdef _WIN32
#include <windows.h>
/* Cross-platform sleep wrapper */
static inline void sleep_ms(int milliseconds) {
    Sleep(milliseconds);
}
#else
/* Cross-platform sleep wrapper */
static inline void sleep_ms(int milliseconds) {
    usleep(milliseconds * 1000);
}
#endif
#include "s3_store.h"
#include "s3_auth.h"

#define S3_MD5_BASE64_BUFFER_SIZE 25
#define S3_PART_NUMBER_BUFFER_SIZE 11
#define S3_XML_NAMESPACE "http://s3.amazonaws.com/doc/2006-03-01/"

static struct flb_aws_header content_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "",
    .val_len = 0,
};

static struct flb_aws_header canned_acl_header = {
    .key = "x-amz-acl",
    .key_len = 9,
    .val = "",
    .val_len = 0,
};

static struct flb_aws_header content_md5_header = {
    .key = "Content-MD5",
    .key_len = 11,
    .val = "",
    .val_len = 0,
};

static struct flb_aws_header storage_class_header = {
    .key = "x-amz-storage-class",
    .key_len = 19,
    .val = "",
    .val_len = 0,
};

extern int write_seq_index(char *seq_index_file, uint64_t seq_index);

static flb_sds_t extract_etag(char *response, size_t size)
{
    char *etag_header;
    char *start_quote;
    char *end_quote;
    flb_sds_t etag;

    if (response == NULL) {
        return NULL;
    }

    /* Find "ETag:" header in response */
    etag_header = strstr(response, "ETag:");
    if (!etag_header) {
        return NULL;
    }

    /* Find the opening quote after "ETag:" */
    start_quote = strchr(etag_header, '\"');
    if (!start_quote) {
        return NULL;
    }

    /* Verify start_quote is within bounds */
    if (start_quote >= response + size) {
        return NULL;
    }

    /* Find the closing quote */
    end_quote = strchr(start_quote + 1, '\"');
    if (!end_quote || end_quote >= response + size) {
        return NULL;
    }

    /* Extract ETag value including the quotes (required by AWS CompleteMultipartUpload API) */
    etag = flb_sds_create_len(start_quote, (int)(end_quote - start_quote + 1));
    if (!etag) {
        flb_errno();
        return NULL;
    }

    return etag;
}

/*
 * Calculate optimal part size for S3 multipart upload.
 *
 * NOTE: This function enforces AWS S3 multipart constraints where each part
 * (except the last) must be at least 5 MiB. For small files (< 5 MiB), this
 * function will still return 5 MiB even though only one part is needed, which
 * means the "small file optimization" logic does not actually reduce the part
 * size below the AWS minimum.
 *
 * Returns the optimal part size considering:
 * - User configuration
 * - File size to avoid exceeding 10000 parts limit
 * - AWS S3 hard limits (5 MiB minimum, 5 GiB maximum per part)
 */
size_t flb_s3_calculate_optimal_part_size(size_t configured_part_size,
                                          size_t file_size)
{
    size_t part_size;
    size_t min_required_chunk;
    size_t estimated_parts;

    /* Step 1: Determine initial part_size */
    if (configured_part_size > 0) {
        part_size = configured_part_size;
    }
    else if (file_size > 0 && file_size <= S3_DEFAULT_PART_SIZE) {
        /* Start with file_size for small files, will be clamped to AWS minimum below */
        part_size = file_size;
    }
    else {
        part_size = S3_DEFAULT_PART_SIZE;
    }

    /* Step 2: Adjust if file_size is known and would exceed parts limit */
    if (file_size > 0) {
        estimated_parts = (file_size + part_size - 1) / part_size;

        if (estimated_parts > S3_AWS_MAX_PARTS) {
            /* Calculate minimum required chunk size */
            min_required_chunk = (file_size + S3_AWS_MAX_PARTS - 1) / S3_AWS_MAX_PARTS;

            /* Choose larger of min_required or current part_size */
            if (min_required_chunk > part_size) {
                part_size = min_required_chunk;

                /* Round up to next MiB for sizes < 1 GiB */
                if (part_size < S3_GiB) {
                    part_size = ((part_size + S3_MiB - 1) / S3_MiB) * S3_MiB;
                }
                /* Round up to next GiB for sizes >= 1 GiB */
                else {
                    part_size = ((part_size + S3_GiB - 1) / S3_GiB) * S3_GiB;
                }
            }
        }
    }

    /* Step 3: Enforce AWS S3 hard limits for multipart upload */
    if (part_size < S3_AWS_MIN_PART_SIZE) {
        part_size = S3_AWS_MIN_PART_SIZE;
    }
    else if (part_size > S3_AWS_MAX_PART_SIZE) {
        part_size = S3_AWS_MAX_PART_SIZE;
    }

    return part_size;
}

int s3_multipart_get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size)
{
    unsigned char md5_bin[16];
    size_t olen;
    int ret;

    ret = flb_hash_simple(FLB_HASH_MD5,
                          (unsigned char *) buf, buf_size,
                          md5_bin, sizeof(md5_bin));

    if (ret != FLB_CRYPTO_SUCCESS) {
        return -1;
    }

    ret = flb_base64_encode((unsigned char*) md5_str, md5_str_size,
                            &olen, md5_bin, sizeof(md5_bin));
    if (ret != 0) {
        return ret;
    }

    /* Ensure NUL termination for safe use with strlen() */
    if (olen < md5_str_size) {
        md5_str[olen] = '\0';
    }
    else {
        /* Buffer too small for NUL terminator */
        return -1;
    }

    return 0;
}

static flb_sds_t build_s3_uri(struct flb_s3 *ctx,
                               const char *pre_signed_url,
                               const char *s3_key,
                               const char *query_params)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    flb_sds_t encoded_key = NULL;

    if (pre_signed_url != NULL) {
        uri = flb_sds_create(pre_signed_url);
        if (!uri) {
            flb_errno();
        }
        return uri;
    }

    encoded_key = flb_aws_uri_encode_path(s3_key, strlen(s3_key));
    if (!encoded_key) {
        flb_plg_error(ctx->ins, "Failed to URL encode S3 key: %s", s3_key);
        return NULL;
    }

    size_t uri_size = strlen(ctx->bucket) + flb_sds_len(encoded_key) +
                      strlen(query_params) + 16;

    uri = flb_sds_create_size(uri_size);
    if (!uri) {
        flb_errno();
        flb_sds_destroy(encoded_key);
        return NULL;
    }

    if (s3_key[0] == '/') {
        tmp = flb_sds_printf(&uri, "/%s%s%s", ctx->bucket, encoded_key, query_params);
    }
    else {
        tmp = flb_sds_printf(&uri, "/%s/%s%s", ctx->bucket, encoded_key, query_params);
    }

    flb_sds_destroy(encoded_key);

    if (!tmp) {
        flb_errno();
        flb_sds_destroy(uri);
        return NULL;
    }

    return tmp;
}

static flb_sds_t build_complete_multipart_xml(struct flb_s3 *ctx,
                                               struct multipart_upload *m_upload)
{
    flb_sds_t xml;
    flb_sds_t tmp;
    int i;
    int valid_parts = 0;

    /* Enforce integrity: check for NULL etags */
    for (i = 0; i < m_upload->part_number; i++) {
        if (m_upload->etags[i] == NULL) {
            flb_plg_error(ctx->ins, "Cannot complete multipart upload: part %d (index %d) "
                         "has NULL ETag. Total parts: %d",
                         i + 1, i, m_upload->part_number);
            return NULL;
        }
        valid_parts++;
    }

    flb_plg_debug(ctx->ins, "Building CompleteMultipartUpload payload: "
                  "%d valid parts", valid_parts);

    if (valid_parts == 0) {
        flb_plg_error(ctx->ins, "No valid ETags found for CompleteMultipartUpload");
        return NULL;
    }

    xml = flb_sds_create("<CompleteMultipartUpload xmlns=\"" S3_XML_NAMESPACE "\">");
    if (!xml) {
        flb_errno();
        return NULL;
    }

    for (i = 0; i < m_upload->part_number; i++) {
        tmp = flb_sds_printf(&xml,
                            "<Part><ETag>%s</ETag><PartNumber>%d</PartNumber></Part>",
                            m_upload->etags[i], i + 1);
        if (!tmp) {
            flb_errno();
            flb_sds_destroy(xml);
            return NULL;
        }
        xml = tmp;
    }

    tmp = flb_sds_cat(xml, "</CompleteMultipartUpload>",
                      strlen("</CompleteMultipartUpload>"));
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(xml);
        return NULL;
    }

    return tmp;
}

int s3_multipart_create_headers(struct flb_s3 *ctx, char *body_md5,
                      struct flb_aws_header **headers, int *num_headers,
                      int is_multipart)
{
    int n = 0;
    int headers_len = 0;
    struct flb_aws_header *s3_headers = NULL;

    if (ctx->content_type != NULL) {
        headers_len++;
    }
    if (ctx->canned_acl != NULL) {
        headers_len++;
    }
    if (body_md5 != NULL && strlen(body_md5) && is_multipart == FLB_FALSE) {
        headers_len++;
    }
    if (ctx->storage_class != NULL) {
        headers_len++;
    }

    if (headers_len == 0) {
        *num_headers = 0;
        *headers = NULL;
        return 0;
    }

    s3_headers = flb_calloc(headers_len, sizeof(struct flb_aws_header));
    if (s3_headers == NULL) {
        flb_errno();
        return -1;
    }

    if (ctx->content_type != NULL) {
        s3_headers[n] = content_type_header;
        s3_headers[n].val = ctx->content_type;
        s3_headers[n].val_len = strlen(ctx->content_type);
        n++;
    }
    if (ctx->canned_acl != NULL) {
        s3_headers[n] = canned_acl_header;
        s3_headers[n].val = ctx->canned_acl;
        s3_headers[n].val_len = strlen(ctx->canned_acl);
        n++;
    }
    if (body_md5 != NULL && strlen(body_md5) && is_multipart == FLB_FALSE) {
        s3_headers[n] = content_md5_header;
        s3_headers[n].val = body_md5;
        s3_headers[n].val_len = strlen(body_md5);
        n++;
    }
    if (ctx->storage_class != NULL) {
        s3_headers[n] = storage_class_header;
        s3_headers[n].val = ctx->storage_class;
        s3_headers[n].val_len = strlen(ctx->storage_class);
        n++;
    }

    *num_headers = headers_len;
    *headers = s3_headers;
    return 0;
}

void s3_multipart_upload_destroy(struct multipart_upload *m_upload)
{
    int i;

    if (!m_upload) {
        return;
    }

    if (m_upload->tag) {
        flb_sds_destroy(m_upload->tag);
    }
    if (m_upload->s3_key) {
        flb_sds_destroy(m_upload->s3_key);
    }
    if (m_upload->upload_id) {
        flb_sds_destroy(m_upload->upload_id);
    }

    for (i = 0; i < m_upload->part_number; i++) {
        if (m_upload->etags[i]) {
            flb_sds_destroy(m_upload->etags[i]);
        }
    }

    flb_free(m_upload);
}

/*
 * Create a multipart upload structure with S3 key generation
 * This is the common function used by both blob and chunk uploads
 */
struct multipart_upload *s3_multipart_upload_new(struct flb_s3 *ctx,
                                                  const char *tag,
                                                  int tag_len,
                                                  const char *path)
{
    struct multipart_upload *m_upload;
    flb_sds_t s3_key;
    flb_sds_t tmp_sds;

    m_upload = flb_calloc(1, sizeof(struct multipart_upload));
    if (!m_upload) {
        flb_errno();
        return NULL;
    }

    /* Use unified key generation (handles seq_index increment/persistence) */
    s3_key = s3_generate_key(ctx, tag, time(NULL), path);
    if (!s3_key) {
        flb_plg_error(ctx->ins, "Failed to construct S3 Object Key for %s", tag);
        flb_free(m_upload);
        return NULL;
    }
    m_upload->s3_key = s3_key;

    tmp_sds = flb_sds_create_len(tag, tag_len);
    if (!tmp_sds) {
        flb_errno();
        flb_sds_destroy(s3_key);
        flb_free(m_upload);
        return NULL;
    }
    m_upload->tag = tmp_sds;
    m_upload->part_number = 1;
    m_upload->init_time = time(NULL);

    return m_upload;
}

int s3_multipart_initiate(struct flb_s3 *ctx,
                          struct multipart_upload *m_upload,
                          char *pre_signed_url)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_header *headers = NULL;
    int num_headers = 0;
    int ret;

    /* Validate inputs */
    if (ctx == NULL || m_upload == NULL) {
        return -1;
    }

    uri = build_s3_uri(ctx, pre_signed_url, m_upload->s3_key, "?uploads=");
    if (!uri) {
        return -1;
    }

    ret = s3_multipart_create_headers(ctx, NULL, &headers, &num_headers, FLB_TRUE);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to create headers");
        flb_sds_destroy(uri);
        return -1;
    }

    c = s3_get_client(ctx)->client_vtable->request(s3_get_client(ctx), FLB_HTTP_POST,
                                               uri, NULL, 0, headers, num_headers);
    flb_free(headers);
    flb_sds_destroy(uri);

    if (!c) {
        flb_plg_error(ctx->ins, "CreateMultipartUpload request failed for %s",
                      m_upload->s3_key);
        return -1;
    }

    if (c->resp.status == 200) {
        tmp = flb_aws_xml_get_val(c->resp.payload, c->resp.payload_size,
                                  "<UploadId>", "</UploadId>");
        if (!tmp) {
            flb_plg_error(ctx->ins, "Could not find UploadId in "
                          "CreateMultipartUpload response");
            flb_http_client_destroy(c);
            return -1;
        }
        m_upload->upload_id = tmp;
        flb_http_client_destroy(c);
        return 0;
    }

    flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                            "CreateMultipartUpload", ctx->ins);
    flb_http_client_destroy(c);
    return -1;
}

int s3_multipart_upload_part(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                              char *body, size_t body_size, char *pre_signed_url)
{
    flb_sds_t uri = NULL;
    flb_sds_t tmp;
    flb_sds_t query_params;
    int ret;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    struct flb_aws_header *headers = NULL;
    int num_headers = 0;
    char body_md5[S3_MD5_BASE64_BUFFER_SIZE];

    query_params = flb_sds_create_size(128);
    if (!query_params) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&query_params, "?partNumber=%d&uploadId=%s",
                        m_upload->part_number, m_upload->upload_id);
    if (!tmp) {
        flb_sds_destroy(query_params);
        return -1;
    }
    query_params = tmp;

    uri = build_s3_uri(ctx, pre_signed_url, m_upload->s3_key, query_params);
    flb_sds_destroy(query_params);

    if (!uri) {
        return -1;
    }

    memset(body_md5, 0, sizeof(body_md5));
    if (ctx->send_content_md5 == FLB_TRUE) {
        ret = s3_multipart_get_md5_base64(body, body_size, body_md5, sizeof(body_md5));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Failed to create Content-MD5 header");
            flb_sds_destroy(uri);
            return -1;
        }

        headers = flb_malloc(sizeof(struct flb_aws_header));
        if (!headers) {
            flb_errno();
            flb_sds_destroy(uri);
            return -1;
        }

        headers[0].key = "Content-MD5";
        headers[0].key_len = 11;
        headers[0].val = body_md5;
        headers[0].val_len = strlen(body_md5);
        num_headers = 1;
    }

    s3_client = s3_get_client(ctx);

    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                          uri, body, body_size,
                                          headers, num_headers);

    flb_free(headers);
    flb_sds_destroy(uri);

    if (!c) {
        flb_plg_error(ctx->ins, "UploadPart request failed");
        return -1;
    }

    if (c->resp.status == 200) {
        tmp = extract_etag(c->resp.data, c->resp.data_size);
        if (!tmp) {
            flb_plg_error(ctx->ins, "Could not find ETag in UploadPart response");
            flb_http_client_destroy(c);
            return -1;
        }
        m_upload->etags[m_upload->part_number - 1] = tmp;
        m_upload->bytes += body_size;
        flb_http_client_destroy(c);
        return 0;
    }

    flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                            "UploadPart", ctx->ins);
    if (c->resp.payload != NULL) {
        flb_plg_debug(ctx->ins, "Raw UploadPart response: %s",
                      c->resp.payload);
    }
    flb_http_client_destroy(c);
    return -1;
}

int s3_multipart_complete(struct flb_s3 *ctx,
                          struct multipart_upload *m_upload,
                          char *pre_signed_url)
{
    flb_sds_t body = NULL;
    flb_sds_t uri = NULL;
    flb_sds_t query_params = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;

    if (!m_upload->upload_id) {
        flb_plg_error(ctx->ins, "Cannot complete multipart upload for key %s: "
                      "upload_id is unset", m_upload->s3_key);
        return S3_MULTIPART_ERROR_GENERAL;
    }

    body = build_complete_multipart_xml(ctx, m_upload);
    if (!body) {
        flb_plg_error(ctx->ins, "Failed to build CompleteMultipartUpload payload");
        return S3_MULTIPART_ERROR_GENERAL;
    }

    query_params = flb_sds_create_size(128);
    if (!query_params) {
        flb_errno();
        flb_sds_destroy(body);
        return S3_MULTIPART_ERROR_GENERAL;
    }

    tmp = flb_sds_printf(&query_params, "?uploadId=%s", m_upload->upload_id);
    if (!tmp) {
        flb_sds_destroy(query_params);
        flb_sds_destroy(body);
        return S3_MULTIPART_ERROR_GENERAL;
    }
    query_params = tmp;

    uri = build_s3_uri(ctx, pre_signed_url, m_upload->s3_key, query_params);
    flb_sds_destroy(query_params);

    if (!uri) {
        flb_sds_destroy(body);
        return S3_MULTIPART_ERROR_GENERAL;
    }

    s3_client = s3_get_client(ctx);

    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_POST,
                                          uri, body, flb_sds_len(body),
                                          NULL, 0);

    flb_sds_destroy(uri);
    flb_sds_destroy(body);

    if (!c) {
        flb_plg_error(ctx->ins, "CompleteMultipartUpload request failed");
        return S3_MULTIPART_ERROR_GENERAL;
    }

    if (c->resp.status == 200) {
        flb_http_client_destroy(c);
        return 0;
    }

    if (c->resp.payload != NULL &&
        strstr(c->resp.payload, "<Code>NoSuchUpload</Code>") != NULL) {
        flb_plg_warn(ctx->ins, "Upload %s does not exist (NoSuchUpload)",
                     m_upload->upload_id);
        flb_http_client_destroy(c);
        return S3_MULTIPART_ERROR_NO_SUCH_UPLOAD;
    }

    flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                            "CompleteMultipartUpload", ctx->ins);
    if (c->resp.payload != NULL) {
        flb_plg_debug(ctx->ins, "Raw CompleteMultipartUpload response: %s",
                      c->resp.payload);
    }
    flb_http_client_destroy(c);
    return S3_MULTIPART_ERROR_GENERAL;
}

int s3_multipart_abort(struct flb_s3 *ctx,
                       struct multipart_upload *m_upload,
                       char *pre_signed_url)
{
    flb_sds_t uri = NULL;
    flb_sds_t query_params = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;

    if (!m_upload->upload_id) {
        flb_plg_error(ctx->ins, "Cannot abort multipart upload for key %s: "
                      "upload_id is unset", m_upload->s3_key);
        return -1;
    }

    query_params = flb_sds_create_size(128);
    if (!query_params) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&query_params, "?uploadId=%s", m_upload->upload_id);
    if (!tmp) {
        flb_sds_destroy(query_params);
        return -1;
    }
    query_params = tmp;

    uri = build_s3_uri(ctx, pre_signed_url, m_upload->s3_key, query_params);
    flb_sds_destroy(query_params);

    if (!uri) {
        return -1;
    }

    s3_client = s3_get_client(ctx);

    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_DELETE,
                                          uri, NULL, 0,
                                          NULL, 0);

    flb_sds_destroy(uri);

    if (!c) {
        flb_plg_error(ctx->ins, "AbortMultipartUpload request failed");
        return -1;
    }

    flb_plg_debug(ctx->ins, "AbortMultipartUpload http status=%d", c->resp.status);

    if (c->resp.status == 204) {
        flb_plg_info(ctx->ins, "Successfully aborted multipart upload for %s, "
                     "UploadId=%s", m_upload->s3_key, m_upload->upload_id);
        flb_http_client_destroy(c);
        return 0;
    }

    flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                            "AbortMultipartUpload", ctx->ins);
    flb_http_client_destroy(c);
    return -1;
}

/*
 * Check if a multipart upload exists by calling ListParts API
 * Returns: 1=exists, 0=NoSuchUpload, -1=error (transient, retry)
 */
int s3_multipart_check_upload_exists(struct flb_s3 *ctx,
                                      const char *s3_key,
                                      const char *upload_id)
{
    flb_sds_t uri = NULL;
    flb_sds_t query_params = NULL;
    flb_sds_t tmp;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    int result;

    if (!s3_key || !upload_id) {
        flb_plg_error(ctx->ins, "Invalid parameters for upload existence check");
        return -1;
    }

    /* Build ListParts query (max-parts=1 for minimal response) */
    query_params = flb_sds_create_size(128);
    if (!query_params) {
        flb_errno();
        return -1;
    }

    tmp = flb_sds_printf(&query_params, "?uploadId=%s&max-parts=1", upload_id);
    if (!tmp) {
        flb_sds_destroy(query_params);
        return -1;
    }
    query_params = tmp;

    uri = build_s3_uri(ctx, NULL, s3_key, query_params);
    flb_sds_destroy(query_params);

    if (!uri) {
        return -1;
    }

    s3_client = s3_get_client(ctx);

    /* Call ListParts API */
    c = s3_client->client_vtable->request(s3_client, FLB_HTTP_GET,
                                          uri, NULL, 0, NULL, 0);
    flb_sds_destroy(uri);

    if (!c) {
        /* Network error or connection failed - transient error, should retry */
        flb_plg_warn(ctx->ins, "ListParts request failed (network error)");
        return -1;
    }

    /* Analyze response */
    if (c->resp.status == 200) {
        /* Upload exists */
        flb_plg_debug(ctx->ins, "Upload ID validation: exists");
        result = 1;
    }
    else if (c->resp.payload &&
             strstr(c->resp.payload, "<Code>NoSuchUpload</Code>")) {
        /* Upload does not exist (expired or aborted) - definitive answer */
        flb_plg_debug(ctx->ins, "Upload ID validation: NoSuchUpload");
        result = 0;
    }
    else {
        /* Any other error - treat as transient for safety */
        flb_plg_warn(ctx->ins, "ListParts returned error status %d (will retry)",
                     c->resp.status);
        if (c->resp.payload) {
            flb_plg_debug(ctx->ins, "Response: %s", c->resp.payload);
        }
        result = -1;
    }

    flb_http_client_destroy(c);
    return result;
}

/*
 * Upload a file part for multipart upload
 *
 * MEMORY USAGE:
 * This function allocates a buffer equal to the part size (offset_end - offset_start).
 * Larger values improve throughput but increase memory usage. For memory-constrained
 * environments, configure smaller upload_chunk_size (default: 100MB).
 *
 * TECHNICAL LIMITATION:
 * The S3 UploadPart API requires complete part data in memory to calculate Content-Length.
 * True streaming upload would require HTTP client support for chunked transfer encoding.
 */
int s3_multipart_upload_part_from_source(struct flb_s3 *ctx,
                                   struct s3_data_source *src,
                                   struct multipart_upload *m_upload,
                                   flb_sds_t pre_signed_url)
{
    int fd = -1;
    char *part_buffer = NULL;
    size_t part_size;
    size_t total_read = 0;
    ssize_t bytes_read;
    int ret = -1;
    off_t part_size_check;
    const char *file_path;
    off_t offset_start;
    off_t offset_end;

    if (src->type == S3_SOURCE_MEMORY) {
        return s3_multipart_upload_part(ctx, m_upload,
                                        src->memory.buf, src->memory.len,
                                        pre_signed_url);
    }

    /* File source logic */
    file_path = src->file.path;
    offset_start = src->file.offset_start;
    offset_end = src->file.offset_end;

    /* Validate offset ranges to prevent underflow */
    if (offset_start < 0 || offset_end < 0) {
        flb_plg_error(ctx->ins, "Invalid negative offsets: start=%lld, end=%lld",
                     (long long)offset_start, (long long)offset_end);
        return -1;
    }

    if (offset_end <= offset_start) {
        flb_plg_error(ctx->ins, "Invalid offset range: end (%lld) must be greater than start (%lld)",
                     (long long)offset_end, (long long)offset_start);
        return -1;
    }

    /*
     * Guard against 32-bit overflow: on 32-bit systems, size_t is 32-bit while off_t
     * may be 64-bit. If part size exceeds SIZE_MAX, the cast to size_t truncates,
     * causing undersized allocation and subsequent buffer overrun.
     *
     * NOTE: We must cast part_size_check to unsigned type for comparison because
     * casting SIZE_MAX to off_t (signed) produces -1 on systems where both types
     * have the same bit width, causing the comparison to always succeed for any
     * positive part_size_check value.
     */
    part_size_check = offset_end - offset_start;
    if ((uint64_t)part_size_check > (uint64_t)SIZE_MAX) {
        flb_plg_error(ctx->ins, "Part size %lld exceeds maximum allocatable size on this platform",
                     (long long)part_size_check);
        return -1;
    }
    part_size = (size_t)part_size_check;

    /* Verify no truncation occurred (defensive check) */
    if ((off_t)part_size != part_size_check) {
        flb_plg_error(ctx->ins, "Part size truncation detected: %lld -> %zu",
                     (long long)part_size_check, part_size);
        return -1;
    }

    /* Open file */
    fd = flb_s3_open(file_path, O_RDONLY);
    if (fd < 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to open file: %s", file_path);
        return -1;
    }

#ifndef _WIN32
    /* Attempt zero-copy mmap optimization */
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0) {
        off_t aligned_offset = offset_start & ~(page_size - 1);
        size_t extra_offset = (size_t)(offset_start - aligned_offset);
        size_t map_len;
        
        /* Guard against overflow when computing map_len = part_size + extra_offset */
        if (extra_offset > SIZE_MAX - part_size) {
            flb_plg_debug(ctx->ins, "mmap size overflow detected (part_size=%zu, extra_offset=%zu), "
                         "falling back to read() path", part_size, extra_offset);
            /* Skip mmap branch and fall back to read() path below */
        }
        else {
            map_len = part_size + extra_offset;
            void *map_addr = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, aligned_offset);

            if (map_addr != MAP_FAILED) {
                /* Use the mapped memory directly */
                char *mapped_ptr = (char *)map_addr + extra_offset;
                ret = s3_multipart_upload_part(ctx, m_upload, mapped_ptr, part_size, pre_signed_url);
                munmap(map_addr, map_len);
                flb_s3_close(fd);

                if (ret < 0) {
                    flb_plg_error(ctx->ins, "Failed to upload part %d (mmap)", m_upload->part_number);
                    return -1;
                }
                return 0;
            }
            /* Fallback to read() if mmap fails */
        }
    }
#endif

    /* Allocate part buffer for the complete part data */
    part_buffer = flb_malloc(part_size);
    if (!part_buffer) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to allocate part buffer (%zu bytes)", part_size);
        flb_s3_close(fd);
        return -1;
    }

    /* Seek to start offset */
    if (flb_s3_lseek(fd, offset_start, SEEK_SET) < 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to seek to offset %lld in file",
                     (long long)offset_start);
        flb_s3_close(fd);
        flb_free(part_buffer);
        return -1;
    }

    /*
     * Read directly into part_buffer to avoid redundant intermediate buffer.
     * Loop to handle short reads: read() may return fewer bytes than requested
     * (this is valid behavior on some filesystems like NFS, pipes, etc.)
     */
    while (total_read < part_size) {
        bytes_read = flb_s3_read(fd, part_buffer + total_read, part_size - total_read);

        if (bytes_read < 0) {
            flb_errno();
            flb_plg_error(ctx->ins, "Failed to read at offset %lld",
                         (long long)(offset_start + total_read));
            flb_s3_close(fd);
            flb_free(part_buffer);
            return -1;
        }

        if (bytes_read == 0) {
            /* Unexpected EOF before we read the expected part size */
            flb_plg_error(ctx->ins, "Unexpected EOF at offset %lld (read %zu of %zu bytes)",
                         (long long)(offset_start + total_read), total_read, part_size);
            flb_s3_close(fd);
            flb_free(part_buffer);
            return -1;
        }

        total_read += bytes_read;
    }

    /* Close file */
    flb_s3_close(fd);

    /* Upload the complete part */
    ret = s3_multipart_upload_part(ctx, m_upload, part_buffer, part_size, pre_signed_url);
    flb_free(part_buffer);

    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to upload part %d", m_upload->part_number);
        return -1;
    }

    return 0;
}

/*
 * Helper function to abort multipart upload with presigned URL support
 * This ensures consistent abort behavior across all error paths
 */
int s3_multipart_abort_with_url(struct flb_s3 *ctx,
                                 struct multipart_upload *m_upload)
{
    flb_sds_t abort_url = NULL;
    int ret;

    /* Fetch abort presigned URL if auth endpoint is configured */
    ret = s3_auth_fetch_presigned_url(ctx, &abort_url,
                                       S3_PRESIGNED_URL_ABORT_MULTIPART,
                                       m_upload->s3_key, m_upload->upload_id, 0);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to fetch presigned URL for abort multipart");
        /* Still attempt abort without presigned URL as fallback */
        ret = s3_multipart_abort(ctx, m_upload, NULL);
        return ret;
    }

    ret = s3_multipart_abort(ctx, m_upload, abort_url);
    flb_sds_destroy(abort_url);

    return ret;
}

static int initialize_multipart_upload(struct flb_s3 *ctx,
                                        const char *s3_key,
                                        const char *tag, int tag_len,
                                        struct multipart_upload **m_upload)
{
    struct multipart_upload *upload;

    upload = flb_calloc(1, sizeof(struct multipart_upload));
    if (!upload) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to allocate multipart upload structure");
        return FLB_RETRY;
    }

    upload->s3_key = flb_sds_create(s3_key);
    if (!upload->s3_key) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to create s3_key");
        flb_free(upload);
        return FLB_RETRY;
    }

    upload->tag = flb_sds_create_len(tag, tag_len);
    if (!upload->tag) {
        flb_errno();
        flb_sds_destroy(upload->s3_key);
        flb_free(upload);
        return FLB_RETRY;
    }

    upload->part_number = 0;
    upload->bytes = 0;
    upload->upload_id = NULL;

    *m_upload = upload;
    return 0;
}

/* Upload all parts of a file sequentially with retry support */
static int s3_multipart_upload_file_parts(struct flb_s3 *ctx,
                              const char *file_path,
                              off_t file_size,
                              struct multipart_upload *m_upload)
{
    off_t current_offset = 0;
    flb_sds_t pre_signed_url = NULL;
    int ret;
    int part_attempt;
    int backoff_ms;
    int max_attempts;

    /* Ensure retry loop always runs at least once */
    max_attempts = (ctx->part_delivery_attempt_limit > 0) ? ctx->part_delivery_attempt_limit : 1;

    while (current_offset < file_size) {
        /* Check if next part would exceed AWS S3 limit (10000 parts) */
        if (m_upload->part_number >= 10000) {
            flb_plg_error(ctx->ins, "Cannot upload part %d: exceeds AWS S3 maximum of 10000 parts",
                         m_upload->part_number + 1);
            return -1;
        }

        m_upload->part_number++;

        off_t offset_start = current_offset;
        off_t offset_end = current_offset + ctx->upload_chunk_size;

        if (offset_end > file_size) {
            offset_end = file_size;
        }

        /* Retry logic for this part upload */
        part_attempt = 0;
        ret = -1;

        while (part_attempt < max_attempts) {
            part_attempt++;

            /* Fetch presigned URL for this attempt */
            ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                               S3_PRESIGNED_URL_UPLOAD_PART,
                                               m_upload->s3_key, m_upload->upload_id,
                                               m_upload->part_number);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "Failed to fetch presigned URL for part %d, "
                             "attempt %d/%d",
                             m_upload->part_number, part_attempt, max_attempts);
                if (pre_signed_url) {
                    flb_sds_destroy(pre_signed_url);
                    pre_signed_url = NULL;
                }

                /* Retry presigned URL fetch with backoff */
                if (part_attempt < max_attempts) {
                    backoff_ms = 1000 * part_attempt;  /* 1s, 2s, 3s... */
                    flb_plg_info(ctx->ins, "Retrying presigned URL fetch after %d ms",
                                backoff_ms);
                    sleep_ms(backoff_ms);
                }
                continue;
            }

            /* Attempt to upload the part */
            struct s3_data_source src;
            src.type = S3_SOURCE_FILE;
            src.file.path = file_path;
            src.file.offset_start = offset_start;
            src.file.offset_end = offset_end;

            ret = s3_multipart_upload_part_from_source(ctx, &src, m_upload, pre_signed_url);

            if (pre_signed_url) {
                flb_sds_destroy(pre_signed_url);
                pre_signed_url = NULL;
            }

            if (ret == 0) {
                /* Success - break out of retry loop */
                break;
            }

            /* Upload failed */
            flb_plg_warn(ctx->ins, "Failed to upload part %d for %s, attempt %d/%d",
                        m_upload->part_number, m_upload->s3_key,
                        part_attempt, max_attempts);

            /* Apply exponential backoff before retry */
            if (part_attempt < max_attempts) {
                uint64_t shift_exp;
                /* Prevent overflow in shift operation */
                if (part_attempt - 1 >= 30) {
                    backoff_ms = 30000;  /* Max out immediately if exponent too large */
                }
                else {
                    shift_exp = 1ULL << (part_attempt - 1);
                    if (shift_exp > 30) {
                        backoff_ms = 30000;
                    }
                    else {
                        backoff_ms = 1000 * (int)shift_exp;
                        if (backoff_ms > 30000) {
                            backoff_ms = 30000;  /* Cap at 30 seconds */
                        }
                    }
                }
                flb_plg_info(ctx->ins, "Retrying part upload after %d ms", backoff_ms);
                sleep_ms(backoff_ms);
            }
        }

        /* Check if all retry attempts failed */
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to upload part %d for %s after %d attempts",
                         m_upload->part_number, m_upload->s3_key, max_attempts);
            return -1;
        }

        current_offset = offset_end;
    }

    return 0;
}

int s3_multipart_upload_file(struct flb_s3 *ctx,
                              const char *file_path,
                              const char *s3_key,
                              const char *tag, int tag_len)
{
    struct multipart_upload *m_upload = NULL;
#ifdef _WIN32
    struct _stat64 file_stat;
#else
    struct stat file_stat;
#endif
    flb_sds_t pre_signed_url = NULL;
    int ret;

    if (flb_s3_stat(file_path, &file_stat) != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to stat file: %s", file_path);
        return FLB_RETRY;
    }

    ret = initialize_multipart_upload(ctx, s3_key, tag, tag_len, &m_upload);
    if (ret != 0) {
        return ret;
    }

    ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                       S3_PRESIGNED_URL_CREATE_MULTIPART,
                                       m_upload->s3_key, NULL, 0);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to fetch presigned URL for create multipart");
        s3_multipart_upload_destroy(m_upload);
        return FLB_RETRY;
    }

    ret = s3_multipart_initiate(ctx, m_upload, pre_signed_url);
    if (pre_signed_url) {
        flb_sds_destroy(pre_signed_url);
        pre_signed_url = NULL;
    }

    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to initiate multipart upload for %s",
                     m_upload->s3_key);
        s3_multipart_upload_destroy(m_upload);
        return FLB_RETRY;
    }

    ret = s3_multipart_upload_file_parts(ctx, file_path, file_stat.st_size, m_upload);
    if (ret < 0) {
        s3_multipart_abort_with_url(ctx, m_upload);
        s3_multipart_upload_destroy(m_upload);
        return FLB_RETRY;
    }

    if (m_upload->bytes != (size_t)file_stat.st_size) {
        flb_plg_error(ctx->ins, "Size mismatch: uploaded %zu bytes, expected %lld bytes",
                     m_upload->bytes, (long long)file_stat.st_size);
        s3_multipart_abort_with_url(ctx, m_upload);
        s3_multipart_upload_destroy(m_upload);
        return FLB_RETRY;
    }

    ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                       S3_PRESIGNED_URL_COMPLETE_MULTIPART,
                                       m_upload->s3_key, m_upload->upload_id, 0);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to fetch presigned URL for complete multipart");
        if (pre_signed_url) {
            flb_sds_destroy(pre_signed_url);
        }
        s3_multipart_abort_with_url(ctx, m_upload);
        s3_multipart_upload_destroy(m_upload);
        return FLB_RETRY;
    }

    ret = s3_multipart_complete(ctx, m_upload, pre_signed_url);
    if (pre_signed_url) {
        flb_sds_destroy(pre_signed_url);
    }

    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to complete multipart upload for %s",
                     m_upload->s3_key);
        s3_multipart_upload_destroy(m_upload);
        return FLB_RETRY;
    }

    flb_plg_info(ctx->ins, "Successfully uploaded %s (%zu bytes, %d parts)",
                 m_upload->s3_key, m_upload->bytes, m_upload->part_number);
    s3_multipart_upload_destroy(m_upload);
    return FLB_OK;
}