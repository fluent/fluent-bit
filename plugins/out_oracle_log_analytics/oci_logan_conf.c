/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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


#include <sys/stat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_file.h>

#include <monkey/mk_core/mk_list.h>
#include <monkey/mk_core/mk_string.h>
#include <fluent-bit/flb_utils.h>

#include "oci_logan.h"
#include "oci_logan_conf.h"

char* short_names[] = {
    "yny\0",
    "hyd\0",
    "mel\0",
    "bom\0",
    "kix\0",
    "icn\0",
    "syd\0",
    "nrt\0",
    "yul\0",
    "yyz\0",
    "ams\0",
    "fra\0",
    "zrh\0",
    "jed\0",
    "dxb\0",
    "gru\0",
    "cwl\0",
    "lhr\0",
    "iad\0",
    "phx\0",
    "sjc\0",
    "vcp\0",
    "scl\0",
    "mtz\0",
    "mrs\0",
    "sin\0",
    "auh\0",
    "lin\0",
    "arn\0",
    "jnb\0",
    "cdg\0",
    "qro\0",
    "mad\0",
    "ord\0",
    "lfi\0",
    "luf\0",
    "ric\0",
    "pia\0",
    "tus\0",
    "ltn\0",
    "brs\0",
    "nja\0",
    "ukb\0",
    "mct\0",
    "wga\0",
    "bgy\0",
    "mxp\0",
    "snn\0",
    "dtm\0",
    "dus\0",
    "ork\0",
    "vll\0",
    "str\0",
    "beg\0",
    NULL
};

char *long_names[] = {
    "ap-chuncheon-1\0",
    "ap-hyderabad-1\0",
    "ap-melbourne-1\0",
    "ap-mumbai-1\0",
    "ap-osaka-1\0",
    "ap-seoul-1\0",
    "ap-sydney-1\0",
    "ap-tokyo-1\0",
    "ca-montreal-1\0",
    "ca-toronto-1\0",
    "eu-amsterdam-1\0",
    "eu-frankfurt-1\0",
    "eu-zurich-1\0",
    "me-jeddah-1\0",
    "me-dubai-1\0",
    "sa-saopaulo-1\0",
    "uk-cardiff-1\0",
    "uk-london-1\0",
    "us-ashburn-1\0",
    "us-phoenix-1\0",
    "us-sanjose-1\0",
    "sa-vinhedo-1\0",
    "sa-santiago-1\0",
    "il-jerusalem-1\0",
    "eu-marseille-1\0",
    "ap-singapore-1\0",
    "me-abudhabi-1\0",
    "eu-milan-1\0",
    "eu-stockholm-1\0",
    "af-johannesburg-1\0",
    "eu-paris-1\0",
    "mx-queretaro-1\0",
    "eu-madrid-1\0",
    "us-chicago-1\0",
    "us-langley-1\0",
    "us-luke-1\0",
    "us-gov-ashburn-1\0",
    "us-gov-chicago-1\0",
    "us-gov-phoenix-1\0",
    "uk-gov-london-1\0",
    "uk-gov-cardiff-1\0",
    "ap-chiyoda-1\0",
    "ap-ibaraki-1\0",
    "me-dcc-muscat-1\0",
    "ap-dcc-canberra-1\0",
    "eu-dcc-milan-1\0",
    "eu-dcc-milan-2\0",
    "eu-dcc-dublin-2\0",
    "eu-dcc-rating-2\0",
    "eu-dcc-rating-1\0",
    "eu-dcc-dublin-1\0",
    "eu-madrid-2\0",
    "eu-frankfurt-2\0",
    "eu-jovanovac-1\0",
    NULL
};

static void build_region_table(struct flb_oci_logan *ctx) {
    ctx->region_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 100, 0);
    int i;
    for(i = 0; short_names[i] != NULL; i++) {
        flb_hash_table_add(ctx->region_table,
                           short_names[i],
                           strlen(short_names[i]),
                           long_names[i],
                           strlen(long_names[i]));
    }

}

static int build_federation_client_headers(struct flb_oci_logan *ctx,
                                           struct flb_http_client *c,
                                           flb_sds_t json,
                                           flb_sds_t uri)
{
    int ret = -1;
    flb_sds_t tmp_sds = NULL;
    flb_sds_t signing_str = NULL;
    flb_sds_t rfc1123date = NULL;
    flb_sds_t encoded_uri = NULL;
    flb_sds_t signature = NULL;
    flb_sds_t auth_header_str = NULL;

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

    // Add (requeset-target) to signing string
    encoded_uri = flb_uri_encode(uri, flb_sds_len(uri));
    if (!encoded_uri) {
        flb_errno();
        goto error_label;
    }
    signing_str = flb_sds_cat(signing_str, FLB_OCI_HEADER_REQUEST_TARGET,
                              sizeof(FLB_OCI_HEADER_REQUEST_TARGET) - 1);
    signing_str = flb_sds_cat(signing_str, ": post ", sizeof(": post ") - 1);
    signing_str = flb_sds_cat(signing_str, encoded_uri,
                              flb_sds_len(encoded_uri));

    // Add Date header
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

    // Add x-content-sha256 Header
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) json,
                          flb_sds_len(json),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error forming hash buffer for x-content-sha256 Header");
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

    // Add content-Type
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_TYPE, sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                                         FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL,
                                         sizeof(FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL) - 1);
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    // Add content-Length
    tmp_len = snprintf(tmp_sds, flb_sds_alloc(tmp_sds) - 1, "%i",
                       (int) strlen(json));
    flb_sds_len_set(tmp_sds, tmp_len);
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_LENGTH, sizeof(FLB_OCI_HEADER_CONTENT_LENGTH) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    // Add Authorization header
    signature = create_base64_sha256_signature(ctx->fed_client->leaf_cert_ret->private_key_pem,
                                               signing_str);
    if (!signature) {
        flb_plg_error(ctx->ins, "cannot compose signing signature");
        goto error_label;
    }

    auth_header_str = create_fed_authorization_header_content(signature, ctx->fed_client->key_id);
    if (!auth_header_str) {
        flb_plg_error(ctx->ins, "cannot compose authorization header");
        goto error_label;
    }

    flb_http_add_header(c, FLB_OCI_HEADER_AUTH, sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header_str, flb_sds_len(auth_header_str));

    // User-Agent
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        FLB_OCI_HEADER_USER_AGENT_VAL,
                        sizeof(FLB_OCI_HEADER_USER_AGENT_VAL) - 1);

    // Accept
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

int refresh_security_token(struct flb_oci_logan *ctx,
                           struct flb_config *config)
{
    flb_sds_t region;
    flb_sds_t host;
    flb_sds_t fed_uri;
    char* err;
    struct flb_upstream *upstream;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;
    char *s_leaf_cert, *s_inter_cert, *s_pub_key;
    int ret = -1, sz;
    time_t now;
    size_t b_sent;
    flb_sds_t json;
    if (ctx->fed_client && ctx->fed_client->expire) {
        now = time(NULL);
        if (ctx->fed_client->expire > now) {
            return 0;
        }
    }
    if (!ctx->fed_client) {
        ctx->fed_client = flb_calloc(1, sizeof(struct federation_client));
    }
    if (!ctx->fed_client->leaf_cert_ret) {
        ctx->fed_client->leaf_cert_ret = flb_calloc(1, sizeof(struct cert_retriever));
    }
    if (!ctx->fed_client->intermediate_cert_ret) {
        ctx->fed_client->intermediate_cert_ret = flb_calloc(1, sizeof(struct cert_retriever));
    }

    ctx->fed_client->leaf_cert_ret->cert_pem = refresh_cert(ctx->cert_u,
                                                            LEAF_CERTIFICATE_URL,
                                                            ctx->ins);
    if (!ctx->fed_client->leaf_cert_ret->cert_pem) {
        return -1;
    }
    ctx->fed_client->leaf_cert_ret->private_key_pem = refresh_cert(ctx->cert_u,
                                                                   LEAF_CERTIFICATE_PRIVATE_KEY_URL,
                                                                   ctx->ins);
    if (!ctx->fed_client->leaf_cert_ret->private_key_pem) {
        return -1;
    }
    ctx->fed_client->leaf_cert_ret->cert = get_cert_from_string(ctx->fed_client->leaf_cert_ret->cert_pem);

    ctx->fed_client->intermediate_cert_ret->cert_pem = refresh_cert(ctx->cert_u,
                                                                    INTERMEDIATE_CERTIFICATE_URL,
                                                                    ctx->ins);
    if (!ctx->fed_client->intermediate_cert_ret->cert_pem) {
        return -1;
    }

    region = get_region(ctx->cert_u, GET_REGION_URL, ctx->region_table);
    flb_plg_info(ctx->ins, "region = %s", region);
    ctx->fed_client->region = region;
    host = flb_sds_create_size(512);
    flb_sds_snprintf(&host, flb_sds_alloc(host), "auth.%s.oci.oraclecloud.com", region);
    if (!ctx->fed_u) {
        upstream = flb_upstream_create(config, host, 443,
                                       FLB_IO_TLS, ctx->ins->tls);
        if (!upstream) {
            return -1;
        }

        ctx->fed_u = upstream;
    }
    ctx->fed_client->tenancy_id = get_tenancy_id_from_certificate(ctx->fed_client->leaf_cert_ret->cert);
    ret = session_key_supplier(&ctx->fed_client->private_key,
                               &ctx->fed_client->public_key,
                               ctx->ins);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "failed to create session key pair");
        return -1;
    }

    ctx->fed_client->key_id = flb_sds_create_size(512);
    flb_sds_snprintf(&ctx->fed_client->key_id, flb_sds_alloc(ctx->fed_client->key_id),
                     "%s/fed-x509/%s", ctx->fed_client->tenancy_id, fingerprint(ctx->fed_client->leaf_cert_ret->cert));
    // flb_plg_info(ctx->ins, "fed client key_id = %s", ctx->fed_client->key_id);

    // TODO: build headers
    u_conn = flb_upstream_conn_get(ctx->fed_u);
    if (!u_conn) {
        return -1;
    }

    s_leaf_cert = sanitize_certificate_string(ctx->fed_client->leaf_cert_ret->cert_pem);
    // flb_plg_info(ctx->ins, "sanitized leaf cert: %s", s_leaf_cert);
    s_pub_key = sanitize_certificate_string(ctx->fed_client->public_key);
    // flb_plg_info(ctx->ins, "pub key: %s", s_pub_key);
    s_inter_cert = sanitize_certificate_string(ctx->fed_client->intermediate_cert_ret->cert_pem);
    // flb_plg_info(ctx->ins, "sanitized inter cert: %s", s_inter_cert);
    sz = strlen(s_leaf_cert) + strlen(s_pub_key) + strlen(s_inter_cert);
    json = flb_sds_create_size(sz + 1000);
    flb_sds_snprintf(&json, flb_sds_alloc(json),
                     OCI_FEDERATION_REQUEST_PAYLOAD,
                     s_leaf_cert,
                     s_pub_key,
                     s_inter_cert);
    // flb_plg_info(ctx->ins, "fed client payload = %s", json);

    fed_uri = flb_sds_create_len("/v1/x509", 8);
    c = flb_http_client(u_conn, FLB_HTTP_POST, fed_uri,
                        json, flb_sds_len(json),
                        NULL, 0, NULL, 0);
    c->allow_dup_headers = FLB_FALSE;

    build_federation_client_headers(ctx, c, json, fed_uri);

    /*
    mk_list_foreach_safe(head, tmp, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_casecmp(kv->key, "host", 4) == 0) {
            flb_kv_item_destroy(kv);
            break;
        }
    }
     */


    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "http do error");
        flb_sds_destroy(json);
        flb_free(fed_uri);
        flb_free(s_leaf_cert);
        flb_free(s_pub_key);
        flb_free(s_inter_cert);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins, "http status = %d, response = %s, header = %s",
                      c->resp.status, c->resp.payload, c->header_buf);
        flb_sds_destroy(json);
        flb_free(fed_uri);
        flb_free(s_leaf_cert);
        flb_free(s_pub_key);
        flb_free(s_inter_cert);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    ctx->fed_client->security_token = parse_token(c->resp.payload,
                                                  c->resp.payload_size);
    flb_plg_info(ctx->ins, "security token = %s", ctx->fed_client->security_token);

    err = get_token_exp(ctx->fed_client->security_token, &ctx->fed_client->expire, ctx->ins);
    if (err) {
        flb_plg_error(ctx->ins, "token error = %s",err);
        flb_free(s_leaf_cert);
        flb_free(s_pub_key);
        flb_free(s_inter_cert);
        flb_free(fed_uri);
        flb_sds_destroy(json);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    flb_plg_info(ctx->ins, "token expiration time = %ld", ctx->fed_client->expire);
    flb_free(json);
    flb_free(fed_uri);
    flb_free(s_leaf_cert);
    flb_free(s_pub_key);
    flb_free(s_inter_cert);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return 0;

}

static int create_pk_context(flb_sds_t filepath, const char *key_passphrase,
                             struct flb_oci_logan *ctx)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ctx->ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ctx->ins, "error to open key file: %s", filepath);
        return -1;
    }

    kbuffer = flb_sds_create_size(finfo.size + 1);
    if (!kbuffer) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    ret = fread(kbuffer, finfo.size, 1, fp);
    if (ret < 1) {
        flb_sds_destroy(kbuffer);
        fclose(fp);
        flb_plg_error(ctx->ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    ctx->private_key = kbuffer;

    return 0;
}

static int file_to_buffer(const char *path,
                          char **out_buf, size_t *out_size)
{
    int ret;
    char *buf;
    ssize_t bytes;
    FILE *fp;
    struct stat st;

    if (!(fp = fopen(path, "r"))) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, (st.st_size + 1));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

int refresh_oke_workload_security_token(struct flb_oci_logan *ctx,
                                        struct flb_config *config)
{
    char* tmp, *host;
    const char* err = NULL;
    char buf[1024*8] = {0};
    size_t o_len;
    int port = 12250, ret;
    struct flb_tls *tls;
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    flb_sds_t auth_header;
    char *token = NULL;
    size_t tk_size;
    flb_sds_t json;
    flb_sds_t uri;
    size_t b_sent;
    time_t now;

    if (ctx->fed_client && ctx->fed_client->expire) {
        now = time(NULL);
        if (ctx->fed_client->expire > now) {
            return 0;
        }
    }

    if (!ctx->fed_client) {
        ctx->fed_client = flb_calloc(1, sizeof(struct federation_client));
    }

    /*
    tmp = getenv("OCI_RESOURCE_PRINCIPAL_REGION");
    if (!tmp) {
        flb_plg_error(ctx->ins, "Not a valid region");
        flb_sds_destroy(sa_cert_path);
        return -1;
    }
    ctx->fed_client->region = flb_sds_create_len(tmp, strlen(tmp));
     */
    session_key_supplier(&ctx->fed_client->private_key,
                         &ctx->fed_client->public_key,
                         ctx->ins);
    host = getenv("KUBERNETES_SERVICE_HOST");
    if (!host) {
        flb_plg_error(ctx->ins, "Host not found");
        return -1;
    }
    if (!ctx->fed_u) {
        tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                             0,
                             1,
                             NULL,
                             NULL,
                             ctx->oke_sa_ca_file,
                             NULL,
                             NULL,
                             NULL);
        ctx->fed_u = flb_upstream_create(config, host, port, FLB_IO_TLS, tls);
    }

    ret = file_to_buffer(ctx->oke_sa_token_file, &token, &tk_size);
    if (ret != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "failed to load kubernetes service account token");
        return -1;
    }

    char *s_pub_key = sanitize_certificate_string(ctx->fed_client->public_key);
    json = flb_sds_create_size(1024*4);
    flb_sds_snprintf(&json, flb_sds_alloc(json),
                     OCI_OKE_PROXYMUX_PAYLOAD, s_pub_key);
    uri = flb_sds_create_len("/resourcePrincipalSessionTokens",
                             sizeof("/resourcePrincipalSessionTokens") - 1);

    u_conn = flb_upstream_conn_get(ctx->fed_u);
    if (!u_conn) {
        flb_errno();
        flb_plg_error(ctx->ins,
                      "failed to establish connection with kubernetes upstream");
        return -1;
    }
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri, json, flb_sds_len(json), NULL, 0, NULL, 0);
    if (!c) {
        flb_errno();
        flb_plg_error(ctx->ins,
                      "failed to create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    auth_header = flb_sds_create_size(1024*4);
    ret = flb_sds_snprintf(&auth_header, flb_sds_alloc(auth_header), "Bearer %s", token);
    flb_http_add_header(c, FLB_OCI_HEADER_AUTH,
                        sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header,
                        ret);
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        "Fluent-Bit", 10);
    flb_http_add_header(c, FLB_OCI_HEADER_CONTENT_TYPE,
                        sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                        FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL,
                        sizeof(FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL) - 1);
    flb_http_add_header(c, "Accept", 6, "*/*", 3);
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "http do error");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    if (c->resp.status != 200) {
        flb_plg_info(ctx->ins, "request body = %s", json);
        flb_plg_info(ctx->ins, "request header = %s", c->header_buf);
        flb_plg_error(ctx->ins,
                      "HTTP Status = %d, payload = %s",
                      c->resp.status, c->resp.payload);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    c->resp.payload++;
    c->resp.payload[strlen(c->resp.payload) - 1] = '\0';
    flb_base64_decode((unsigned char*)buf,
                      sizeof(buf),
                      &o_len,
                      (unsigned char*) c->resp.payload,
                      strlen(c->resp.payload));
    ctx->key_id = parse_token(buf, strlen(buf));
    err = get_token_exp(ctx->key_id + 3, &ctx->fed_client->expire, ctx->ins);

    if (err != NULL) {
        flb_plg_error(ctx->ins,
                      "failed to extract token expiration time");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    flb_plg_info(ctx->ins, "token expiration time = %ld", ctx->fed_client->expire);
    // decode jwt token stored in buf
    // Make the request and fetch the security token

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return 0;
}

static int load_oci_credentials(struct flb_oci_logan *ctx)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char* key = NULL;
    char* val;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_debug(ctx->ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        /* process line */
        flb_plg_debug(ctx->ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
        }
        if(found_profile) {
            if(line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_debug(ctx->ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ctx->ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
                res = -1;
                break;
            }
            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                ctx->user = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                ctx->tenancy = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                ctx->key_file = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                ctx->key_fingerprint = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                ctx->region = flb_sds_create(val);
            }
            else {
                goto iterate;
            }
        }
        iterate:
        if (profile) {
            mk_mem_free(profile);
            profile = NULL;
        }
        if (key) {
            mk_mem_free(key);
            key = NULL;
        }
        line = strtok(NULL, "\n");
    }
    if (!found_profile) {
        flb_errno();
        res = -1;
    }

    flb_sds_destroy(content);
    if (profile) {
        mk_mem_free(profile);
    }
    if (key) {
        mk_mem_free(key);
    }
    return res;
}

static int global_metadata_fields_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_global_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_global_metadata) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->global_metadata_fields);
    }

    return 0;
}

static int log_event_metadata_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_metadata) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->log_event_metadata_fields);
    }

    return 0;
}

int set_upstream_ctx(struct flb_oci_logan *ctx,
                     struct flb_output_instance *ins,
                     struct flb_config *config)
{
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region ) {
            flb_errno();
            flb_plg_error(ctx->ins, "Region is required");
            return -1;
        }
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
    }

    io_flags = FLB_IO_TCP;
    default_port = 80;

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        default_port = 443;
    }
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    flb_output_net_default(host, default_port, ins);
    flb_sds_destroy(host);

    if (ctx->proxy) {
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            return -1;
        }

        ctx->proxy_host = p_host;
        ctx->proxy_port = atoi(p_port);
        flb_free(protocol);
        flb_free(p_port);
        flb_free(p_uri);
        flb_free(p_host);
    }

    if (ctx->proxy) {
        upstream = flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
                                       io_flags, ins->tls);
    }
    else {
        /* Prepare an upstream handler */
        upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        return -1;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return 0;
}

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config) {
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logan));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    build_region_table(ctx);

    if (strcasecmp(ctx->auth_type, INSTANCE_PRINCIPAL) == 0) {
        ctx->cert_u = flb_upstream_create(config, METADATA_HOST_BASE, 80, FLB_IO_TCP, NULL);
    }

    if (ctx->oci_config_in_record == FLB_FALSE) {
        if (ctx->oci_la_log_source_name == NULL ||
            ctx->oci_la_log_group_id == NULL) {
            flb_errno();
            flb_plg_error(ctx->ins,
                          "log source name and log group id are required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }
    if (ctx->oci_la_global_metadata != NULL) {
        mk_list_init(&ctx->global_metadata_fields);
        ret = global_metadata_fields_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_metadata != NULL) {
        mk_list_init(&ctx->log_event_metadata_fields);
        ret = log_event_metadata_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        if (!ctx->config_file_location) {
            flb_errno();
            flb_plg_error(ctx->ins, "config file location is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ret = load_oci_credentials(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (!ctx->uri) {
        if (!ctx->namespace) {
            flb_errno();
            flb_plg_error(ctx->ins, "Namespace is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->uri = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                       "/20200601/namespaces/%s/actions/uploadLogEventsFile",
                       ctx->namespace);
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
            flb_plg_error(ctx->ins, "failed to create pk context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    ctx->key_id = flb_sds_create_size(512*8);
    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                         "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0 ||
    strcasecmp(ctx->auth_type, WORKLOAD_IDENTITY) == 0) {
        ret = set_upstream_ctx(ctx, ins, config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot create Upstream context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    return ctx;
}

static void metadata_fields_destroy(struct flb_oci_logan *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct metadata_obj *f;

    mk_list_foreach_safe(head, tmp, &ctx->global_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        flb_sds_destroy(f->key);
        flb_sds_destroy(f->val);
        mk_list_del(&f->_head);
        flb_free(f);
    }

    mk_list_foreach_safe(head, tmp, &ctx->log_event_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        flb_sds_destroy(f->key);
        flb_sds_destroy(f->val);
        mk_list_del(&f->_head);
        flb_free(f);
    }

}

int flb_cert_ret_destroy(struct cert_retriever *cert_ret) {
    if (cert_ret->cert_pem) {
        flb_sds_destroy(cert_ret->cert_pem);
    }
    if (cert_ret->private_key_pem) {
        flb_sds_destroy(cert_ret->private_key_pem);
    }
    if (cert_ret->cert) {
        X509_free(cert_ret->cert);
    }
}
int flb_fed_client_destroy(struct federation_client *fd) {
    if (fd->security_token) {
        flb_sds_destroy(fd->security_token);
    }
    if (fd->leaf_cert_ret) {
        flb_cert_ret_destroy(fd->leaf_cert_ret);
    }
    if (fd->key_id) {
        flb_sds_destroy(fd->key_id);
    }
    if (fd->public_key) {
        flb_sds_destroy(fd->public_key);
    }
    if (fd->tenancy_id) {
        flb_sds_destroy(fd->tenancy_id);
    }
    if (fd->private_key) {
        flb_sds_destroy(fd->private_key);
    }
    if (fd->intermediate_cert_ret) {
        flb_cert_ret_destroy(fd->intermediate_cert_ret);
    }
    if (fd->region) {
        flb_sds_destroy(fd->region);
    }
}

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx) {
    if(ctx == NULL) {
        return 0;
    }

    if (ctx->fed_client) {
        flb_fed_client_destroy(ctx->fed_client);
    }
    if (ctx->cert_u) {
        flb_upstream_destroy(ctx->cert_u);
    }
    if (ctx->fed_u) {
        flb_upstream_destroy(ctx->fed_u);
    }
    if (ctx->private_key) {
        flb_sds_destroy(ctx->private_key);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->key_id) {
        flb_sds_destroy(ctx->key_id);
    }
    if (ctx->key_file) {
        flb_sds_destroy(ctx->key_file);
    }
    if(ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if(ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if(ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if(ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    metadata_fields_destroy(ctx);

    flb_free(ctx);
    return 0;
}