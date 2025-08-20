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
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_sds.h>

#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>

#include <string.h>

#include "oci_logan_conf.h"
#include "oci_logan.h"


static int check_config_from_record(msgpack_object key,
                                   char *name, int len)
{
    if (key.type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    if (key.via.str.size != len) {
        return FLB_FALSE;
    }


    return memcmp(key.via.str.ptr, name, len) == 0;
}

/*
 * Authorization: Signature version="1",keyId="<tenancy_ocid>/<user_ocid>/<key_fingerprint>",
 * algorithm="rsa-sha256",headers="(request-target) date x-content-sha256 content-type content-length",
 * signature="signature"
 */
static flb_sds_t create_authorization_header_content(struct flb_oci_logan *ctx,
                                                     flb_sds_t signature)
{
    flb_sds_t content;

    content = flb_sds_create_size(512);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_SIGNATURE_VERSION,
                           sizeof(FLB_OCI_SIGN_SIGNATURE_VERSION) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_KEYID,
                           sizeof(FLB_OCI_SIGN_KEYID) - 1);
    flb_sds_cat_safe(&content, "=\"", 2);
    flb_sds_cat_safe(&content, ctx->key_id, flb_sds_len(ctx->key_id));
    flb_sds_cat_safe(&content, "\",", 2);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_ALGORITHM,
                           sizeof(FLB_OCI_SIGN_ALGORITHM) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_HEADERS,
                           sizeof(FLB_OCI_SIGN_HEADERS) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_SIGNATURE,
                           sizeof(FLB_OCI_SIGN_SIGNATURE) - 1);
    flb_sds_cat_safe(&content, "=\"", 2);
    flb_sds_cat_safe(&content, signature, flb_sds_len(signature));
    flb_sds_cat_safe(&content, "\"", 1);

    return content;
}

static flb_sds_t create_base64_sha256_signature(struct flb_oci_logan *ctx,
                                                flb_sds_t signing_string)
{
    int len = 0, ret;
    size_t outlen;
    flb_sds_t signature;
    unsigned char sha256_buf[32] = { 0 };
    unsigned char sig[256] = { 0 };
    size_t sig_len = sizeof(sig);

    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) signing_string,
                          flb_sds_len(signing_string),
                          sha256_buf, sizeof(sha256_buf));

    if(ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error generating hash buffer");
        return NULL;
    }

    ret =   flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                   FLB_CRYPTO_PADDING_PKCS1,
                                   FLB_HASH_SHA256,
                                   (unsigned char *) ctx->private_key,
                                   flb_sds_len(ctx->private_key),
                                   sha256_buf, sizeof(sha256_buf),
                                   sig, &sig_len);


    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error signing SHA256");
        return NULL;
    }

    signature = flb_sds_create_size(512);
    if (!signature) {
        flb_errno();
        return NULL;
    }

    /* base 64 encode */
    len = flb_sds_alloc(signature) - 1;
    flb_base64_encode((unsigned char*) signature, len, &outlen, sig,
                          sizeof(sig));
    signature[outlen] = '\0';
    flb_sds_len_set(signature, outlen);

    return signature;
}

static flb_sds_t get_date(void)
{

    flb_sds_t rfc1123date;
    time_t t;
    size_t size;
    struct tm tm = { 0 };

    /* Format Date */
    rfc1123date = flb_sds_create_size(32);
    if (!rfc1123date) {
        flb_errno();
        return NULL;
    }

    t = time(NULL);
    if (!gmtime_r(&t, &tm)) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return NULL;
    }
    size = strftime(rfc1123date, flb_sds_alloc(rfc1123date) - 1,
                    "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (size <= 0) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return NULL;
    }
    flb_sds_len_set(rfc1123date, size);
    return rfc1123date;
}

static flb_sds_t add_header_and_signing(struct flb_http_client *c,
                                        flb_sds_t signing_str, const char *header, int headersize,
                                        const char *val, int val_size)
{
    if (!signing_str) {
        return NULL;
    }

    flb_http_add_header(c, header, headersize, val, val_size);

    flb_sds_cat_safe(&signing_str, "\n", 1);
    flb_sds_cat_safe(&signing_str, header, headersize);
    flb_sds_cat_safe(&signing_str, ": ", 2);
    flb_sds_cat_safe(&signing_str, val, val_size);

    return signing_str;
}

static int build_headers(struct flb_http_client *c, struct flb_oci_logan *ctx,
                         flb_sds_t json, flb_sds_t hostname, int port, flb_sds_t uri)
{
    int ret = -1;
    flb_sds_t tmp_sds = NULL;
    flb_sds_t signing_str = NULL;
    flb_sds_t rfc1123date = NULL;
    flb_sds_t encoded_uri = NULL;
    flb_sds_t signature = NULL;
    flb_sds_t auth_header_str = NULL;

    flb_sds_t tmp_ref = NULL;

    size_t tmp_len = 0;

    unsigned char sha256_buf[32] = { 0 };

    tmp_sds = flb_sds_create_size(512);
    if (!tmp_sds) {
        flb_errno();
        goto error_label;
    }

    signing_str = flb_sds_create_size(1024);
    if (!signing_str) {
        flb_errno();
        goto error_label;
    }

    /* Add (requeset-target) to signing string */
    encoded_uri = flb_uri_encode(uri, flb_sds_len(uri));
    if (!encoded_uri) {
        flb_errno();
        goto error_label;
    }
    flb_sds_cat_safe(&signing_str, FLB_OCI_HEADER_REQUEST_TARGET,
                               sizeof(FLB_OCI_HEADER_REQUEST_TARGET) - 1);
    flb_sds_cat_safe(&signing_str, ": post ", sizeof(": post ") - 1);
    flb_sds_cat_safe(&signing_str, encoded_uri,
                               flb_sds_len(encoded_uri));

    /* Add Host to Header */
    if (((c->flags & FLB_IO_TLS) && c->port == 443)
        || (!(c->flags & FLB_IO_TLS) && c->port == 80)) {
        /* default port */
        tmp_ref = flb_sds_copy(tmp_sds, c->host, strlen(c->host));
    }
    else {
        tmp_ref = flb_sds_printf(&tmp_sds, "%s:%i", c->host, c->port);
    }
    if (!tmp_ref) {
        flb_plg_error(ctx->ins, "cannot compose temporary host header");
        goto error_label;
    }
    tmp_sds = tmp_ref;
    tmp_ref = NULL;

    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_HOST,
                                         sizeof(FLB_OCI_HEADER_HOST) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add Date header */
    rfc1123date = get_date();
    if (!rfc1123date) {
        flb_plg_error(ctx->ins, "cannot compose temporary date header");
        goto error_label;
    }
    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_DATE,
                                         sizeof(FLB_OCI_HEADER_DATE) - 1, rfc1123date,
                                         flb_sds_len(rfc1123date));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add x-content-sha256 Header */
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) json,
                          flb_sds_len(json),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error forming hash buffer for x-content-sha256 Header");
        goto error_label;
    }

    tmp_sds = flb_sds_create_size(512);
    if (!tmp_sds) {
        flb_errno();
        goto error_label;
    }

    flb_base64_encode((unsigned char*) tmp_sds, flb_sds_len(tmp_sds) - 1,
                      &tmp_len, sha256_buf, sizeof(sha256_buf));

    tmp_sds[tmp_len] = '\0';
    flb_sds_len_set(tmp_sds, tmp_len);

    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_X_CONTENT_SHA256,
                                         sizeof(FLB_OCI_HEADER_X_CONTENT_SHA256) - 1, tmp_sds,
                                         flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add content-Type */
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_TYPE, sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                                         FLB_OCI_HEADER_CONTENT_TYPE_VAL,
                                         sizeof(FLB_OCI_HEADER_CONTENT_TYPE_VAL) - 1);
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add content-Length */
    tmp_len = snprintf(tmp_sds, flb_sds_alloc(tmp_sds) - 1, "%i",
                       (int) flb_sds_len(json));
    flb_sds_len_set(tmp_sds, tmp_len);
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_LENGTH, sizeof(FLB_OCI_HEADER_CONTENT_LENGTH) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add Authorization header */
    signature = create_base64_sha256_signature(ctx, signing_str);
    if (!signature) {
        flb_plg_error(ctx->ins, "cannot compose signing signature");
        goto error_label;
    }

    auth_header_str = create_authorization_header_content(ctx, signature);
    if (!auth_header_str) {
        flb_plg_error(ctx->ins, "cannot compose authorization header");
        goto error_label;
    }

    flb_http_add_header(c, FLB_OCI_HEADER_AUTH, sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header_str, flb_sds_len(auth_header_str));

    /* User-Agent */
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        FLB_OCI_HEADER_USER_AGENT_VAL,
                        sizeof(FLB_OCI_HEADER_USER_AGENT_VAL) - 1);

    /* Accept */
    flb_http_add_header(c, "Accept", 6, "*/*", 3);

    ret = 0;

    error_label:
    if (tmp_sds) {
        flb_sds_destroy(tmp_sds);
    }
    if (signing_str) {
        flb_sds_destroy(signing_str);
    }
    if (rfc1123date) {
        flb_sds_destroy(rfc1123date);
    }
    if (encoded_uri) {
        flb_sds_destroy(encoded_uri);
    }
    if (signature) {
        flb_sds_destroy(signature);
    }
    if (auth_header_str) {
        flb_sds_destroy(auth_header_str);
    }
    return ret;
}

static struct flb_oci_error_response* parse_response_error(struct flb_oci_logan *ctx,
                                                           char *response, size_t response_len)
{
    int tok_size = 32, ret, i;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    char *key;
    char *val;
    int key_len;
    int val_len;
    struct flb_oci_error_response *error_response;

    jsmn_init(&parser);

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    ret = jsmn_parse(&parser, response, response_len, tokens, tok_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_free(tokens);
        flb_plg_info(ctx->ins,
                     "Unable to parser error response. reponse is not valid json");
        return NULL;
    }
    tok_size = ret;

    error_response = flb_calloc(1, sizeof(struct flb_oci_error_response));
    if (!error_response) {
        flb_errno();
        flb_free(tokens);
        return NULL;
    }

    /* Parse JSON tokens */
    for (i = 0; i < tok_size; i++) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type != JSMN_STRING) {
            continue;
        }

        key = response + t->start;
        key_len = (t->end - t->start);

        i++;
        t = &tokens[i];
        val = response + t->start;
        val_len = (t->end - t->start);

        if (val_len < 1) {
            continue;
        }

        if ((key_len == sizeof(FLB_OCI_ERROR_RESPONSE_CODE) - 1)
            && strncasecmp(key, FLB_OCI_ERROR_RESPONSE_CODE,
                           sizeof(FLB_OCI_ERROR_RESPONSE_CODE) - 1) == 0) {
            /* code */
            error_response->code = flb_sds_create_len(val, val_len);
            if (!error_response->code) {
                flb_free(error_response);
                flb_free(tokens);
                return NULL;
            }
        }
        else if ((key_len == sizeof(FLB_OCI_ERROR_RESPONSE_MESSAGE) - 1)
            && strncasecmp(key, FLB_OCI_ERROR_RESPONSE_MESSAGE,
                           sizeof(FLB_OCI_ERROR_RESPONSE_MESSAGE) - 1) == 0) {

            /* message */
            error_response->message = flb_sds_create_len(val, val_len);
            if (!error_response->message) {
                flb_free(error_response);
                flb_free(tokens);
                return NULL;
            }
        }
    }

    flb_free(tokens);
    return error_response;
}

static int retry_error(struct flb_http_client *c, struct flb_oci_logan *ctx)
{
    struct flb_oci_error_response *error_response = NULL;
    int tmp_len;
    int ret = FLB_FALSE;

    /* possible retry error message */
    if ( !(c->resp.status == 400 || c->resp.status == 401
        || c->resp.status == 404 || c->resp.status == 409
        || c->resp.status == 429 || c->resp.status == 500)) {
        return FLB_FALSE;
    }

    /* parse error message */
    error_response = parse_response_error(ctx, c->resp.payload,
                                          c->resp.payload_size);
    if (!error_response) {
        return FLB_FALSE;
    }

    if (error_response->code) {
        tmp_len = flb_sds_len(error_response->code);
        if (c->resp.status == 400
            && (tmp_len == sizeof(FLB_OCI_ERROR_CODE_RELATED_RESOURCE_NOT_FOUND) - 1)
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_RELATED_RESOURCE_NOT_FOUND, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
        else if( c->resp.status == 401
            &&( tmp_len == sizeof(FLB_OCI_ERROR_CODE_NOT_AUTHENTICATED)-1 )
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_NOT_AUTHENTICATED, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
        else if (c->resp.status == 404
            && (tmp_len == sizeof(FLB_OCI_ERROR_CODE_NOT_AUTHENTICATEDORNOTFOUND) - 1)
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_NOT_AUTHENTICATEDORNOTFOUND, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
        else if (c->resp.status == 409
            && (tmp_len == sizeof(FLB_OCI_ERROR_CODE_INCORRECTSTATE) - 1)
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_INCORRECTSTATE, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
        else if (c->resp.status == 409
            && (tmp_len == sizeof(FLB_OCI_ERROR_CODE_NOT_AUTH_OR_RESOURCE_EXIST) - 1)
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_NOT_AUTH_OR_RESOURCE_EXIST, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
        else if (c->resp.status == 429
            && (tmp_len == sizeof(FLB_OCI_ERROR_CODE_TOO_MANY_REQUESTS) - 1)
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_TOO_MANY_REQUESTS, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
        else if (c->resp.status == 500
            && (tmp_len == sizeof(FLB_OCI_ERROR_CODE_INTERNAL_SERVER_ERROR) - 1)
            && strncasecmp(error_response->code, FLB_OCI_ERROR_CODE_INTERNAL_SERVER_ERROR, tmp_len) == 0) {
            ret = FLB_TRUE;
        }
    }

    if (error_response->code) {
        flb_sds_destroy(error_response->code);
    }
    if (error_response->message) {
        flb_sds_destroy(error_response->message);
    }
    flb_free(error_response);

    return ret;
}

static int cb_oci_logan_init(struct flb_output_instance *ins,
                             struct flb_config *config,
                             void *data)
{
    struct flb_oci_logan *ctx;
    ctx = flb_oci_logan_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize plugin");
        return -1;
    }
    flb_plg_info(ins, "initialized logan plugin");
    flb_output_set_context(ins, ctx);
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

static flb_sds_t compose_uri(struct flb_oci_logan *ctx,
                             flb_sds_t log_set, flb_sds_t log_group_id)
{
    flb_sds_t uri_param;
    flb_sds_t full_uri;

    uri_param = flb_sds_create_size(512);
    if (!uri_param) {
        flb_errno();
        return NULL;
    }

    /* LogGroupId */
    if (log_group_id) {
        if (flb_sds_len(uri_param) > 0) {
            flb_sds_cat_safe(&uri_param, "&", 1);
        }
        flb_sds_cat_safe(&uri_param, FLB_OCI_LOG_GROUP_ID,
                         FLB_OCI_LOG_GROUP_ID_SIZE);
        flb_sds_cat_safe(&uri_param, "=", 1);
        flb_sds_cat_safe(&uri_param, log_group_id,
                         flb_sds_len(log_group_id));
    }

    if (!uri_param) {
        return NULL;
    }

    /* logSet */
    if (log_set) {
        if (flb_sds_len(uri_param) > 0) {
            flb_sds_cat_safe(&uri_param, "&", 1);
        }
        flb_sds_cat_safe(&uri_param, FLB_OCI_LOG_SET,
                                 FLB_OCI_LOG_SET_SIZE);
        flb_sds_cat_safe(&uri_param, "=", 1);
        flb_sds_cat_safe(&uri_param, log_set,
                                 flb_sds_len(log_set));
    }

    if (!uri_param) {
        return NULL;
    }

    flb_sds_cat_safe(&uri_param, "&", 1);
    flb_sds_cat_safe(&uri_param, FLB_OCI_PAYLOAD_TYPE,
                            sizeof(FLB_OCI_PAYLOAD_TYPE) - 1);
    flb_sds_cat_safe(&uri_param, "=", 1);
    flb_sds_cat_safe(&uri_param, "JSON", 4);


    if (!uri_param) {
        return NULL;
    }


    if (flb_sds_len(uri_param) == 0) {
        flb_sds_destroy(uri_param);
        return flb_sds_create(ctx->uri);
    }

    full_uri = flb_sds_create_size(
        flb_sds_len(ctx->uri) + 1 + flb_sds_len(uri_param));
    if (!full_uri) {
        flb_errno();
        flb_sds_destroy(uri_param);
        return NULL;
    }

    flb_sds_cat_safe(&full_uri, ctx->uri, flb_sds_len(ctx->uri));
    flb_sds_cat_safe(&full_uri, "?", 1);
    flb_sds_cat_safe(&full_uri, uri_param, flb_sds_len(uri_param));

    flb_sds_destroy(uri_param);

    return full_uri;
}

static int flush_to_endpoint(struct flb_oci_logan *ctx,
                             flb_sds_t payload,
                             flb_sds_t log_group_id,
                             flb_sds_t log_set_id)
{
    int out_ret = FLB_RETRY;
    int http_ret;
    size_t b_sent;
    flb_sds_t full_uri;
    struct flb_http_client *c = NULL;
    struct flb_connection *u_conn;

    full_uri = compose_uri(ctx, log_set_id, log_group_id);
    if(!full_uri) {
        flb_plg_error(ctx->ins, "unable to compose uri for logGroup: %s logSet: %s",
                      ctx->oci_la_log_group_id, ctx->oci_la_log_set_id);
    }

    flb_plg_debug(ctx->ins, "full_uri=%s", full_uri);

    u_conn = flb_upstream_conn_get(ctx->u);
    if(!u_conn) {
        goto error_label;
    }
    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, full_uri, (void*) payload,
                        flb_sds_len(payload), ctx->ins->host.name, ctx->ins->host.port, ctx->proxy, 0);
    if (!c) {
        goto error_label;
    }
    flb_http_allow_duplicated_headers(c, FLB_FALSE);

    flb_plg_debug(ctx->ins, "built client");
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);
    if (build_headers(c, ctx, payload, ctx->ins->host.name, ctx->ins->host.port, full_uri) < 0) {
        flb_plg_error(ctx->ins, "failed to build headers");
        goto error_label;
    }
    flb_plg_debug(ctx->ins, "built request");

    out_ret = FLB_OK;

    http_ret = flb_http_do(c, &b_sent);
    flb_plg_debug(ctx->ins, "placed request");

    if (http_ret == 0) {

        if (c->resp.status != 200) {
            flb_plg_debug(ctx->ins, "request header %s", c->header_buf);

            out_ret = FLB_ERROR;

            if (c->resp.payload && c->resp.payload_size > 0) {
                if (retry_error(c, ctx) == FLB_TRUE) {
                    out_ret = FLB_RETRY;
                }

                flb_plg_error(ctx->ins, "%s:%i, retry=%s, HTTP status=%i\n%s",
                              ctx->ins->host.name, ctx->ins->host.port,
                              (out_ret == FLB_RETRY ? "true" : "false"),
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, retry=%s, HTTP status=%i",
                              ctx->ins->host.name, ctx->ins->host.port,
                              (out_ret == FLB_RETRY ? "true" : "false"),
                              c->resp.status);
            }
        }
    }
    else {
        out_ret = FLB_RETRY;
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i), retry=%s",
                      ctx->ins->host.name, ctx->ins->host.port,
                      http_ret, (out_ret == FLB_RETRY ? "true" : "false"));
        goto error_label;
    }



    error_label:
    if (full_uri) {
        flb_sds_destroy(full_uri);
    }

    /* Destroy HTTP client context */
    if (c) {
        flb_http_client_destroy(c);
    }

    /* Release the TCP connection */
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }

    return out_ret;

}

static void pack_oci_fields(msgpack_packer *packer,
                            struct flb_oci_logan *ctx)
{
    int num_global_meta = 0;
    int num_event_meta = 0;
    int pck_sz = 2;
    struct mk_list *head = NULL;
    struct metadata_obj *f;


    /* number of meta properties */
    if(ctx->oci_la_global_metadata != NULL) {
        num_global_meta = mk_list_size(&ctx->global_metadata_fields);
    }
    if(ctx->oci_la_metadata != NULL) {
        num_event_meta = mk_list_size(&ctx->log_event_metadata_fields);
    }


    if (num_global_meta > 0) {
        msgpack_pack_map(packer, 2);
        msgpack_pack_str(packer, FLB_OCI_LOG_METADATA_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_LOG_METADATA,
                              FLB_OCI_LOG_METADATA_SIZE);

        msgpack_pack_map(packer, num_global_meta);
        /* pack kv list */
        mk_list_foreach(head, &ctx->global_metadata_fields) {
            f = mk_list_entry(head, struct metadata_obj, _head);

            msgpack_pack_str(packer, flb_sds_len(f->key));
            msgpack_pack_str_body(packer, f->key, flb_sds_len(f->key));

            msgpack_pack_str(packer, flb_sds_len(f->val));
            msgpack_pack_str_body(packer, f->val, flb_sds_len(f->val));

        }

    }
    else {
        msgpack_pack_map(packer, 1);
    }

    /*
     *logEvents":[
     {
     "entityId":"",
     "logSourceName":"LinuxSyslogSource",
     "logPath":"/var/log/messages",
     "metadata":{
     "Error ID":"1",
     "Environment":"prod",
     "Client Host Region":"PST"
     },
     "logRecords":[
     "May  8 2017 04:02:36 blr00akm syslogd 1.4.1: shutdown.",
     "May  8 2017 04:02:37 blr00akm syslogd 1.4.1: restart."
     ]
     },
     {

     }
     ]
     */
    msgpack_pack_str(packer, FLB_OCI_LOG_EVENTS_SIZE);
    msgpack_pack_str_body(packer, FLB_OCI_LOG_EVENTS, FLB_OCI_LOG_EVENTS_SIZE);

    msgpack_pack_array(packer, 1);

    if (ctx->oci_la_entity_id) {
        pck_sz++;
    }
    if (ctx->oci_la_log_path) {
        pck_sz++;
    }
    if (ctx->oci_la_entity_type) {
        pck_sz++;
    }

    if (num_event_meta > 0) {
        pck_sz++;
    }

    msgpack_pack_map(packer, pck_sz); /* entityId, logSourceName, logPath, logRecords */


    /* "entityType:"" */
    if (ctx->oci_la_entity_type) {
        msgpack_pack_str(packer, FLB_OCI_ENTITY_TYPE_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_ENTITY_TYPE, FLB_OCI_ENTITY_TYPE_SIZE);
        msgpack_pack_str(packer, flb_sds_len(ctx->oci_la_entity_type));
        msgpack_pack_str_body(packer, ctx->oci_la_entity_type,
                              flb_sds_len(ctx->oci_la_entity_type));
    }

    /* "entityId":"", */
    if (ctx->oci_la_entity_id) {
        msgpack_pack_str(packer, FLB_OCI_ENTITY_ID_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_ENTITY_ID, FLB_OCI_ENTITY_ID_SIZE);
        msgpack_pack_str(packer, flb_sds_len(ctx->oci_la_entity_id));
        msgpack_pack_str_body(packer, ctx->oci_la_entity_id,
                              flb_sds_len(ctx->oci_la_entity_id));
    }


    /* "logSourceName":"", */
    msgpack_pack_str(packer, FLB_OCI_LOG_SOURCE_NAME_SIZE);
    msgpack_pack_str_body(packer, FLB_OCI_LOG_SOURCE_NAME,
                          FLB_OCI_LOG_SOURCE_NAME_SIZE);
    msgpack_pack_str(packer, flb_sds_len(ctx->oci_la_log_source_name));
    msgpack_pack_str_body(packer, ctx->oci_la_log_source_name,
                          flb_sds_len(ctx->oci_la_log_source_name));


    /* "logPath":"" */
    if (ctx->oci_la_log_path) {
        msgpack_pack_str(packer, FLB_OCI_LOG_PATH_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_LOG_PATH, FLB_OCI_LOG_PATH_SIZE);
        msgpack_pack_str(packer, flb_sds_len(ctx->oci_la_log_path));
        msgpack_pack_str_body(packer, ctx->oci_la_log_path,
                              flb_sds_len(ctx->oci_la_log_path));
    }


    /* Add metadata */
    if (num_event_meta > 0) {
        /*
         "metadata":{
         "Error ID":"0",
         "Environment":"dev",
         "Client Host Region":"IST"
         },
         */
        msgpack_pack_str(packer, FLB_OCI_LOG_METADATA_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_LOG_METADATA,
                              FLB_OCI_LOG_METADATA_SIZE);

        msgpack_pack_map(packer, num_event_meta);
        /* pack kv list */
        mk_list_foreach(head, &ctx->log_event_metadata_fields) {
            f = mk_list_entry(head, struct metadata_obj, _head);

            msgpack_pack_str(packer, flb_sds_len(f->key));
            msgpack_pack_str_body(packer, f->key, flb_sds_len(f->key));

            msgpack_pack_str(packer, flb_sds_len(f->val));
            msgpack_pack_str_body(packer, f->val, flb_sds_len(f->val));

        }

    }
}

static int get_and_pack_oci_fields_from_record(msgpack_packer *packer,
                                               msgpack_object map,
                                               flb_sds_t *lg_id,
                                               flb_sds_t *ls_id,
                                               struct flb_oci_logan *ctx)
{
    int map_size = map.via.map.size;
    int pck_size = 1, i;
    msgpack_object *log_group_id= NULL;
    msgpack_object *log_set_id = NULL;
    msgpack_object *entity_id = NULL;
    msgpack_object *entity_type = NULL;
    msgpack_object *log_path = NULL;
    msgpack_object *log_source = NULL;
    msgpack_object *global_metadata = NULL;
    msgpack_object *metadata = NULL;

    for(i = 0; i < map_size; i++) {
        if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_LOG_GROUP_ID_KEY,
                                     FLB_OCI_LOG_GROUP_ID_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                log_group_id = &map.via.map.ptr[i].val;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_LOG_SET_ID_KEY,
                                     FLB_OCI_LOG_SET_ID_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                log_set_id = &map.via.map.ptr[i].val;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_LOG_ENTITY_ID_KEY,
                                     FLB_OCI_LOG_ENTITY_ID_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                entity_id = &map.via.map.ptr[i].val;
                pck_size++;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_LOG_ENTITY_TYPE_KEY,
                                     FLB_OCI_LOG_ENTITY_TYPE_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                entity_type = &map.via.map.ptr[i].val;
                pck_size++;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_LOG_SOURCE_NAME_KEY,
                                     FLB_OCI_LOG_SOURCE_NAME_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                log_source = &map.via.map.ptr[i].val;
                pck_size++;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_LOG_PATH_KEY,
                                     FLB_OCI_LOG_PATH_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                log_path = &map.via.map.ptr[i].val;
                pck_size++;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_METADATA_KEY,
                                     FLB_OCI_METADATA_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                metadata = &map.via.map.ptr[i].val;
                pck_size++;
            }
            continue;
        }
        else if (check_config_from_record(map.via.map.ptr[i].key,
                                     FLB_OCI_GLOBAL_METADATA_KEY,
                                     FLB_OCI_GLOBAL_METADATA_KEY_SIZE) == FLB_TRUE) {
            if (map.via.map.ptr[i].val.type == MSGPACK_OBJECT_STR) {
                global_metadata = &map.via.map.ptr[i].val;
            }
            continue;
        }
    }

    if (log_group_id == NULL || log_source == NULL) {
        flb_plg_error(ctx->ins,
                      "log source name and log group id are required");
        return -1;
    }
    if (global_metadata != NULL) {
        msgpack_pack_map(packer, 2);
        msgpack_pack_str(packer, FLB_OCI_LOG_METADATA_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_LOG_METADATA,
                              FLB_OCI_LOG_METADATA_SIZE);

        msgpack_pack_object(packer, *global_metadata);
    }
    else {
        msgpack_pack_map(packer, 1);
    }

    /*
     *logEvents":[
     {
     "entityId":"",
     "logSourceName":"LinuxSyslogSource",
     "logPath":"/var/log/messages",
     "metadata":{
     "Error ID":"1",
     "Environment":"prod",
     "Client Host Region":"PST"
     },
     "logRecords":[
     "May  8 2017 04:02:36 blr00akm syslogd 1.4.1: shutdown.",
     "May  8 2017 04:02:37 blr00akm syslogd 1.4.1: restart."
     ]
     },
     {

     }
     ]
     */
    msgpack_pack_str(packer, FLB_OCI_LOG_EVENTS_SIZE);
    msgpack_pack_str_body(packer, FLB_OCI_LOG_EVENTS, FLB_OCI_LOG_EVENTS_SIZE);

    msgpack_pack_array(packer, 1);

    if (metadata != NULL) {
        pck_size++;
        msgpack_pack_map(packer, pck_size); /* entityType, entityId, logSourceName, logPath, metadata, logRecords */
        msgpack_pack_str(packer, FLB_OCI_LOG_METADATA_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_LOG_METADATA,
                              FLB_OCI_LOG_METADATA_SIZE);
        msgpack_pack_object(packer, *global_metadata);

    }
    else {
        msgpack_pack_map(packer, pck_size); /* entityType, entityId, logSourceName, logPath, logRecords */
    }

    /* "entityType:"" */
    if (entity_type) {
        msgpack_pack_str(packer, FLB_OCI_ENTITY_TYPE_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_ENTITY_TYPE, FLB_OCI_ENTITY_TYPE_SIZE);
        msgpack_pack_object(packer, *entity_type);
    }

    /* "entityId":"", */
    if (entity_type) {
        msgpack_pack_str(packer, FLB_OCI_ENTITY_ID_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_ENTITY_ID, FLB_OCI_ENTITY_ID_SIZE);
        msgpack_pack_object(packer, *entity_id);
    }



    /* "logSourceName":"", */
    msgpack_pack_str(packer, FLB_OCI_LOG_SOURCE_NAME_SIZE);
    msgpack_pack_str_body(packer, FLB_OCI_LOG_SOURCE_NAME,
                          FLB_OCI_LOG_SOURCE_NAME_SIZE);
    msgpack_pack_object(packer, *log_source);


    /* "logPath":"" */
    if (log_path) {
        msgpack_pack_str(packer, FLB_OCI_LOG_PATH_SIZE);
        msgpack_pack_str_body(packer, FLB_OCI_LOG_PATH, FLB_OCI_LOG_PATH_SIZE);
        msgpack_pack_object(packer, *log_path);
    }

    *lg_id = flb_sds_create_len(log_group_id->via.str.ptr, log_group_id->via.str.size);
    if(!*lg_id) {
        return -1;
    }
    if (log_set_id != NULL) {
        *ls_id = flb_sds_create_len(log_set_id->via.str.ptr, log_set_id->via.str.size);
        if(!*ls_id) {
            return -1;
        }
    }
    return 0;

}

static int total_flush(struct flb_event_chunk *event_chunk,
                       struct flb_output_flush *out_flush,
                       struct flb_input_instance *ins, void *out_context,
                       struct flb_config *config)
{
    struct flb_oci_logan *ctx = out_context;
    flb_sds_t out_buf = NULL;
    int ret = 0, res = FLB_OK, ret1 = 0, i;
    msgpack_object map;
    int map_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int msg = -1, log = -1;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int num_records;
    flb_sds_t log_group_id = NULL;
    flb_sds_t log_set_id = NULL;
    int count = 0;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);
        res = FLB_ERROR;
        goto clean_up;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* pack oci fields */
    /* pack_oci_fields(&mp_pck, ctx); */

    num_records = flb_mp_count(event_chunk->data, event_chunk->size);

    while ((ret = flb_log_event_decoder_next(
        &log_decoder,
        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map      = *log_event.body;
        map_size = map.via.map.size;
        if (count < 1) {
            if (ctx->oci_config_in_record == FLB_FALSE) {
                pack_oci_fields(&mp_pck, ctx);
                log_group_id = ctx->oci_la_log_group_id;
                log_set_id = ctx->oci_la_log_set_id;
            } else {
                ret1 = get_and_pack_oci_fields_from_record(&mp_pck, map, &log_group_id, &log_set_id, ctx);
                if (ret1 != 0) {
                    break;
                }
            }
            msgpack_pack_str(&mp_pck, FLB_OCI_LOG_RECORDS_SIZE);
            msgpack_pack_str_body(&mp_pck, FLB_OCI_LOG_RECORDS,
                                  FLB_OCI_LOG_RECORDS_SIZE);
            msgpack_pack_array(&mp_pck, num_records);
            count++;
        }

        for(i = 0; i < map_size; i++) {
            if (check_config_from_record(map.via.map.ptr[i].key,
                                         "message",
                                         7) == FLB_TRUE) {
                msg = i;
            }
            if (check_config_from_record(map.via.map.ptr[i].key,
                                        "log",
                                        3) == FLB_TRUE) {
                log = i;
            }
        }
        if (log >= 0) {
            msgpack_pack_str(&mp_pck, map.via.map.ptr[log].val.via.str.size);
            msgpack_pack_str_body(&mp_pck, map.via.map.ptr[log].val.via.str.ptr,
                                  map.via.map.ptr[log].val.via.str.size);
        }
        else if (msg >= 0) {
            msgpack_pack_str(&mp_pck, map.via.map.ptr[msg].val.via.str.size);
            msgpack_pack_str_body(&mp_pck, map.via.map.ptr[msg].val.via.str.ptr,
                                  map.via.map.ptr[msg].val.via.str.size);
        }
        log = -1;
        msg = -1;
    }

    if (ret1 != 0) {
        res = FLB_ERROR;
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_log_event_decoder_destroy(&log_decoder);
        goto clean_up;
    }

    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                          config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    flb_plg_debug(ctx->ins, "payload=%s", out_buf);
    flb_plg_debug(ctx->ins, "lg_id=%s", log_group_id);

    ret = flush_to_endpoint(ctx, out_buf, log_group_id, log_set_id);
    if(ret != FLB_OK) {
        res = FLB_RETRY;
        goto clean_up;
    }

    clean_up:
    if (out_buf != NULL) {
        flb_sds_destroy(out_buf);
    }
    if (log_group_id != NULL && ctx->oci_config_in_record) {
        flb_sds_destroy(log_group_id);
    }
    if (log_set_id != NULL && ctx->oci_config_in_record) {
        flb_sds_destroy(log_set_id);
    }
    return res;
}

static void cb_oci_logan_flush(struct flb_event_chunk *event_chunk,
                              struct flb_output_flush *out_flush,
                              struct flb_input_instance *ins, void *out_context,
                              struct flb_config *config)
{
    struct flb_oci_logan *ctx = out_context;
    int ret = -1;

    ret = total_flush(event_chunk, out_flush,
                      ins, out_context,
                      config);
    if (ret != FLB_OK) {
        FLB_OUTPUT_RETURN(ret);
    }
    flb_plg_debug(ctx->ins, "success");

    FLB_OUTPUT_RETURN(FLB_OK);

}

static int cb_oci_logan_exit(void *data, struct flb_config *config)
{
    struct flb_oci_logan *ctx = data;

    flb_oci_logan_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "config_file_location", "",
        0, FLB_TRUE, offsetof(struct flb_oci_logan, config_file_location),
        "Location of the oci config file for user api key signing"
    },
    {
        FLB_CONFIG_MAP_STR, "profile_name", "DEFAULT",
        0, FLB_TRUE, offsetof(struct flb_oci_logan, profile_name),
        "name of the profile in the config file from which the user configs should be loaded"
    },
    {
        FLB_CONFIG_MAP_BOOL, "oci_config_in_record", "false",
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_config_in_record),
        "If true, oci_la_* configs will be read from the record"
    },
    {
        FLB_CONFIG_MAP_STR, "uri", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, uri),
        "Set the uri for rest api request"
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_log_group_id", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_log_group_id),
        "log group id"
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_log_set_id", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_log_set_id),
        ""
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_entity_id", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_entity_id),
        ""
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_entity_type", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_entity_type),
        ""
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_log_source_name", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_log_source_name),
        ""
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_log_set_id", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_log_set_id),
        ""
    },
    {
        FLB_CONFIG_MAP_STR, "oci_la_log_path", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_log_path),
        ""
    },
    {
        FLB_CONFIG_MAP_SLIST_2, "oci_la_global_metadata", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_global_metadata),
            ""
    },
    {
        FLB_CONFIG_MAP_SLIST_2, "oci_la_metadata", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_oci_logan, oci_la_metadata),
        ""
    },
    {
        FLB_CONFIG_MAP_STR, "namespace", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, namespace),
            "namespace in your tenancy where the log objects reside"
    },
    {
        FLB_CONFIG_MAP_STR, "proxy", NULL,
        0, FLB_TRUE, offsetof(struct flb_oci_logan, proxy),
            "define proxy if required, in http://host:port format, supports only http protocol"
    },

    {0}
};

/* Plugin reference */
struct flb_output_plugin out_oracle_log_analytics_plugin = {
    .name           = "oracle_log_analytics",
    .description    = "Oracle log analytics",
    .cb_init        = cb_oci_logan_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_oci_logan_flush,
    .cb_exit        = cb_oci_logan_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Events supported */
    .event_type   = FLB_OUTPUT_LOGS,


    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .workers = 1,
};
