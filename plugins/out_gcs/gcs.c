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

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_aws_util.h>

#include "gcs.h"
#include "gcs_store.h"

#include <sys/stat.h>

static int gcs_ctx_destroy(void *data, struct flb_config *config);

static struct flb_aws_header *get_content_encoding_header(int compression_type)
{
    static struct flb_aws_header gzip_header = {
        .key = "Content-Encoding",
        .key_len = 16,
        .val = "gzip",
        .val_len = 4,
    };

    switch (compression_type) {
    case FLB_GCS_COMPRESSION_GZIP:
        return &gzip_header;
    default:
        return NULL;
    }
}

static inline int key_cmp(char *str, int len, char *cmp) {
    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int gcs_under_test_mode(void)
{
    char *env;

    env = getenv("FLB_GCS_PLUGIN_UNDER_TEST");

    if (env && strcasecmp(env, "true") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}


static void mock_gcs_call_increment_counter(const char *api)
{
    char env_var[64];
    char *val;
    int count;
    char buf[16];

    snprintf(env_var, sizeof(env_var), "TEST_GCS_%s_CALL_COUNT", api);
    val = getenv(env_var);
    count = val ? atoi(val) : 0;
    count++;
    snprintf(buf, sizeof(buf), "%d", count);
    setenv(env_var, buf, 1);
}

static int read_seq_index(const char *path, uint64_t *out_value)
{
    FILE *fp;
    unsigned long long val;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (fscanf(fp, "%llu", &val) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out_value = (uint64_t) val;
    return 0;
}

static int write_seq_index(const char *path, uint64_t value)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }
    fprintf(fp, "%llu", (unsigned long long) value);
    fclose(fp);
    return 0;
}

static int init_seq_index(struct flb_gcs *ctx)
{
    flb_sds_t path;

    path = flb_sds_create_size(256);
    if (!path) {
        flb_errno();
        return -1;
    }
    flb_sds_printf(&path, "%s/gcs_seq_index", ctx->store_dir);
    if (!path) {
        return -1;
    }
    ctx->seq_index_file = path;

    if (read_seq_index(ctx->seq_index_file, &ctx->seq_index) == -1) {
        ctx->seq_index = 0;
        if (write_seq_index(ctx->seq_index_file, ctx->seq_index) == -1) {
            return -1;
        }
    }
    return 0;
}

static int gcs_get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size)
{
    unsigned char md5_bin[16];
    size_t olen;
    int ret;

    ret = flb_hash_simple(FLB_HASH_MD5, (unsigned char *) buf, buf_size,
                          md5_bin, sizeof(md5_bin));
    if (ret != FLB_CRYPTO_SUCCESS) {
        return -1;
    }

    ret = flb_base64_encode((unsigned char *) md5_str, md5_str_size,
                            &olen, md5_bin, sizeof(md5_bin));
    if (ret != 0) {
        return -1;
    }
    return 0;
}

static int random_hex_suffix(char *buf, size_t buf_size)
{
    unsigned char rnd[4];
    int ret;

    if (buf_size < 9) {
        return -1;
    }

    ret = flb_random_bytes(rnd, sizeof(rnd));
    if (ret != 0) {
        return -1;
    }

    snprintf(buf, buf_size, "%02x%02x%02x%02x", rnd[0], rnd[1], rnd[2], rnd[3]);
    return 0;
}

/* credential parse and oauth helpers based on bigquery/stackdriver style */
static int flb_gcs_read_credentials_file(struct flb_gcs *ctx, char *creds,
                                         struct flb_gcs_oauth_credentials *c)
{
    int i, ret, len, key_len, val_len;
    int tok_size = 32;
    char *buf, *key, *val;
    flb_sds_t tmp;
    struct stat st;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;

    ret = stat(creds, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open credentials file: %s", creds);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "credentials file is not a valid file: %s",
                      creds);
        return -1;
    }

    buf = mk_file_to_buffer(creds);
    if (!buf) {
        flb_plg_error(ctx->ins, "error reading credentials file: %s", creds);
        return -1;
    }

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_free(buf);
        return -1;
    }

    ret = jsmn_parse(&parser, buf, st.st_size, tokens, tok_size);
    if (ret <= 0) {
        flb_plg_error(ctx->ins, "invalid JSON credentials file: %s", creds);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_plg_error(ctx->ins, "invalid JSON map on file: %s", creds);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    for (i = 1; i < ret; i++) {
        t = &tokens[i];
        if (t->type != JSMN_STRING) {
            continue;
        }

        if (t->start == -1 || t->end == -1 ||
            (t->start == 0 && t->end == 0)) {
            break;
        }
        key = buf + t->start;
        key_len = t->end - t->start;

        i++;
        if (i >= ret) {
            break;
        }
        t = &tokens[i];
        if (t->start == -1 || t->end == -1) {
            continue;
        }
        val = buf + t->start;
        val_len = t->end - t->start;

        if (key_cmp(key, key_len, "type") == 0) {
            c->type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "project_id") == 0) {
            c->project_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key_id") == 0) {
            c->private_key_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key") == 0) {
            tmp = flb_sds_create_len(val, val_len);
            if (tmp) {
                len = flb_sds_len(tmp);
                c->private_key = flb_sds_create_size(len);
                if (!c->private_key) {
                    flb_errno();
                    flb_sds_destroy(tmp);
                    flb_free(buf);
                    flb_free(tokens);
                    return -1;
                }
                flb_unescape_string(tmp, len, &c->private_key);
                flb_sds_destroy(tmp);
            }
        }
        else if (key_cmp(key, key_len, "client_email") == 0) {
            c->client_email = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "client_id") == 0) {
            c->client_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "auth_uri") == 0) {
            c->auth_uri = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_uri") == 0) {
            c->token_uri = flb_sds_create_len(val, val_len);
        }
    }

    flb_free(buf);
    flb_free(tokens);

    if (!c->private_key) {
        flb_plg_error(ctx->ins, "no private key");
        return -1;
    }

    return c->client_email ? 0 : -1;
}

static void flb_gcs_credentials_destroy(struct flb_gcs_oauth_credentials *c)
{
    if (!c) {
        return;
    }

    if (c->type) {
        flb_sds_destroy(c->type);
    }
    if (c->project_id) {
        flb_sds_destroy(c->project_id);
    }
    if (c->private_key_id) {
        flb_sds_destroy(c->private_key_id);
    }
    if (c->private_key) {
        flb_sds_destroy(c->private_key);
    }
    if (c->client_email) {
        flb_sds_destroy(c->client_email);
    }
    if (c->client_id) {
        flb_sds_destroy(c->client_id);
    }
    if (c->auth_uri) {
        flb_sds_destroy(c->auth_uri);
    }
    if (c->token_uri) {
        flb_sds_destroy(c->token_uri);
    }

    flb_free(c);
}

int gcs_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                              unsigned char *in_buf, size_t in_size, size_t *olen)
{
    int i;
    size_t len;
    int result;

    result = flb_base64_encode((unsigned char *) out_buf, out_size - 1, &len, in_buf, in_size);
    if (result != 0) {
        return -1;
    }
    for (i = 0; i < len && out_buf[i] != '='; i++) {
        if (out_buf[i] == '+') out_buf[i] = '-';
        else if (out_buf[i] == '/') out_buf[i] = '_';
    }
    *olen = i;
    return 0;
}

static int gcs_jwt_encode(struct flb_gcs *ctx, char *payload, char *secret,
                          char **out_signature, size_t *out_size)
{
    int ret, len, buf_size;
    size_t olen, sig_len;
    char *buf, *sigd;
    char *headers = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    unsigned char sha256_buf[32] = {0};
    flb_sds_t out;
    unsigned char sig[256] = {0};

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    len = strlen(headers);
    ret = gcs_jwt_base64_url_encode((unsigned char *) buf, buf_size, (unsigned char *) headers,
                                    len, &olen);
    if (ret != 0) {
        flb_free(buf);
        return -1;
    }

    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        flb_free(buf);
        return -1;
    }
    out = flb_sds_cat(out, buf, olen);
    out = flb_sds_cat(out, ".", 1);
    if (!out) {
        flb_free(buf);
        return -1;
    }

    len = strlen(payload);
    ret = gcs_jwt_base64_url_encode((unsigned char *) buf, buf_size, (unsigned char *) payload,
                                    len, &olen);
    if (ret != 0) {
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }
    out = flb_sds_cat(out, buf, olen);
    if (!out) {
        flb_free(buf);
        return -1;
    }

    ret = flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) out, flb_sds_len(out),
                          sha256_buf, sizeof(sha256_buf));
    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    len = strlen(secret) + 1;
    ret = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY, FLB_CRYPTO_PADDING_PKCS1,
                                 FLB_HASH_SHA256, (unsigned char *) secret, len,
                                 sha256_buf, sizeof(sha256_buf), sig, &sig_len);
    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }
    ret = gcs_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, sig_len, &olen);
    if (ret != 0) {
        flb_free(buf);
        flb_free(sigd);
        flb_sds_destroy(out);
        return -1;
    }
    out = flb_sds_cat(out, ".", 1);
    out = flb_sds_cat(out, sigd, olen);
    if (!out) {
        flb_free(buf);
        flb_free(sigd);
        return -1;
    }

    *out_signature = out;
    *out_size = flb_sds_len(out);
    flb_free(buf);
    flb_free(sigd);

    return 0;
}

static int gcs_get_oauth2_token(struct flb_gcs *ctx)
{
    int ret;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    flb_oauth2_payload_clear(ctx->o);
    issued = time(NULL);
    expires = issued + FLB_GCS_TOKEN_REFRESH;
    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", \"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->oauth_credentials->client_email, FLB_GCS_SCOPE, FLB_GCS_AUTH_URL, expires, issued);

    ret = gcs_jwt_encode(ctx, payload, ctx->oauth_credentials->private_key, &sig_data, &sig_size);
    if (ret != 0) {
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "grant_type", -1,
                                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer", -1);
    if (ret == -1) {
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "assertion", -1, sig_data, sig_size);
    flb_sds_destroy(sig_data);
    if (ret == -1 || !flb_oauth2_token_get(ctx->o)) {
        return -1;
    }

    return 0;
}

static flb_sds_t get_google_token(struct flb_gcs *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        ret = gcs_get_oauth2_token(ctx);
    }

    if (ret == 0) {
        output = flb_sds_create(ctx->o->token_type);
        if (output) {
            flb_sds_printf(&output, " %s", ctx->o->access_token);
        }
    }
    pthread_mutex_unlock(&ctx->token_mutex);

    return output;
}

static int upload_queue_contains(struct flb_gcs *ctx, struct gcs_file *chunk)
{
    struct mk_list *head;
    struct upload_queue *entry;

    mk_list_foreach(head, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        if (entry->upload_file == chunk) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}

static int add_to_queue(struct flb_gcs *ctx, struct gcs_file *chunk,
                        const char *tag, int tag_len)
{
    struct upload_queue *entry;

    if (upload_queue_contains(ctx, chunk) == FLB_TRUE) {
        return 0;
    }

    entry = flb_calloc(1, sizeof(struct upload_queue));
    if (!entry) {
        return -1;
    }

    entry->tag = flb_strndup(tag, tag_len);
    if (!entry->tag) {
        flb_free(entry);
        return -1;
    }

    entry->upload_file = chunk;
    entry->tag_len = tag_len;
    entry->upload_time = chunk->create_time + ctx->upload_timeout;
    if (entry->upload_time < time(NULL)) {
        entry->upload_time = time(NULL);
    }
    mk_list_add(&entry->_head, &ctx->upload_queue);
    return 0;
}

static void remove_from_queue(struct upload_queue *entry)
{
    mk_list_del(&entry->_head);
    flb_free(entry->tag);
    flb_free(entry);
}


static void clear_upload_queue(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct upload_queue *entry;

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        remove_from_queue(entry);
    }
}

static void clear_file_chunks(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf;

    if (!ctx || !ctx->fs_stream) {
        return;
    }

    mk_list_foreach(head, &ctx->fs_stream->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);

        if (fsf->data) {
            flb_free(fsf->data);
            fsf->data = NULL;
        }
    }
}

static int construct_request_buffer(struct flb_gcs *ctx,
                                    struct upload_queue *entry,
                                    char **out_buffer,
                                    size_t *out_size)
{
    int ret;

    ret = gcs_store_file_read(ctx, entry->upload_file, out_buffer, out_size);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int gcs_upload_object(struct flb_gcs *ctx,
                             flb_sds_t auth,
                             flb_sds_t uri,
                             char *body,
                             size_t body_size)
{
    int ret;
    size_t bytes = 0;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_aws_header *encoding_header;
    struct flb_aws_header content_type_header = {
        .key = "Content-Type",
        .key_len = 12
    };
    struct flb_aws_header canned_acl_header = {
        .key = "x-goog-acl",
        .key_len = 10
    };
    struct flb_aws_header content_md5_header = {
        .key = "Content-MD5",
        .key_len = 11
    };
    struct flb_aws_header storage_class_header = {
        .key = "x-goog-storage-class",
        .key_len = 20
    };
    char final_body_md5[25];

    if (gcs_under_test_mode() == FLB_TRUE) {
        mock_gcs_call_increment_counter("UploadObject");

        if (getenv("TEST_GCS_UPLOAD_ERROR") != NULL) {
            return -1;
        }

        return 0;
    }

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        return -1;
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, uri, body, body_size,
                        FLB_GCS_DEFAULT_HOST, FLB_GCS_DEFAULT_PORT, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    content_type_header.val = ctx->content_type;
    content_type_header.val_len = flb_sds_len(ctx->content_type);
    flb_http_add_header(c, content_type_header.key, content_type_header.key_len,
                        content_type_header.val, content_type_header.val_len);
    flb_http_add_header(c, "Authorization", 13, auth, flb_sds_len(auth));
    encoding_header = get_content_encoding_header(ctx->compression_type);
    if (encoding_header) {
        flb_http_add_header(c, encoding_header->key, encoding_header->key_len,
                            encoding_header->val, encoding_header->val_len);
    }

    if (ctx->canned_acl) {
        canned_acl_header.val = ctx->canned_acl;
        canned_acl_header.val_len = flb_sds_len(ctx->canned_acl);
        flb_http_add_header(c, canned_acl_header.key, canned_acl_header.key_len,
                            canned_acl_header.val, canned_acl_header.val_len);
    }
    if (ctx->storage_class) {
        storage_class_header.val = ctx->storage_class;
        storage_class_header.val_len = flb_sds_len(ctx->storage_class);
        flb_http_add_header(c, storage_class_header.key, storage_class_header.key_len,
                            storage_class_header.val, storage_class_header.val_len);
    }
    if (ctx->send_content_md5 == FLB_TRUE) {
        memset(final_body_md5, 0, sizeof(final_body_md5));
        if (gcs_get_md5_base64(body, body_size, final_body_md5,
                               sizeof(final_body_md5)) == 0) {
            content_md5_header.val = final_body_md5;
            content_md5_header.val_len = strlen(final_body_md5);
            flb_http_add_header(c, content_md5_header.key, content_md5_header.key_len,
                                content_md5_header.val, content_md5_header.val_len);
        }
    }

    ret = flb_http_do(c, &bytes);
    if (ret == 0 &&
        (c->resp.status < 200 || c->resp.status >= 300)) {
        flb_plg_error(ctx->ins,
                      "gcs upload failed with status=%i",
                      c->resp.status);
        ret = -1;
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return ret;
}

static int upload_data(struct flb_gcs *ctx,
                       struct upload_queue *entry,
                       char *buffer,
                       size_t buffer_size)
{
    int ret;
    int append_random;
    int ret_seq;
    flb_sds_t auth;
    flb_sds_t gcs_key;
    flb_sds_t gcs_key_final;
    flb_sds_t uri;
    void *gz_data = NULL;
    size_t gz_size = 0;
    char *upload_body;
    size_t upload_size;
    char random_hex[9];

    if (gcs_under_test_mode() == FLB_TRUE) {
        auth = flb_sds_create("Bearer test-token");
    }
    else {
        auth = get_google_token(ctx);
    }

    if (!auth) {
        return -1;
    }

    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index++;
    }

    gcs_key = flb_get_s3_key(ctx->gcs_key_format, time(NULL),
                             entry->tag, ctx->tag_delimiters, ctx->seq_index);
    if (!gcs_key) {
        if (ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
            ctx->seq_index--;
        }
        flb_sds_destroy(auth);
        return -1;
    }

    gcs_key_final = gcs_key;
    append_random = FLB_FALSE;
    if (!ctx->key_fmt_has_uuid && !ctx->key_fmt_has_seq_index && !ctx->static_file_path) {
        append_random = FLB_TRUE;
    }
    if (append_random == FLB_TRUE) {
        if (random_hex_suffix(random_hex, sizeof(random_hex)) == 0) {
            gcs_key_final = flb_sds_create_size(flb_sds_len(gcs_key) + 16);
            if (!gcs_key_final) {
                flb_errno();
                if (ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
                    ctx->seq_index--;
                }
                flb_sds_destroy(auth);
                flb_sds_destroy(gcs_key);
                return -1;
            }
            flb_sds_printf(&gcs_key_final, "%s-object%s", gcs_key, random_hex);
            if (!gcs_key_final) {
                if (ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
                    ctx->seq_index--;
                }
                flb_sds_destroy(auth);
                flb_sds_destroy(gcs_key);
                return -1;
            }
            flb_sds_destroy(gcs_key);
        }
    }

    if (ctx->key_fmt_has_seq_index) {
        ret_seq = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret_seq == -1) {
            flb_sds_destroy(auth);
            flb_sds_destroy(gcs_key_final);
            return -1;
        }
    }

    uri = flb_sds_create_size(512);
    if (!uri) {
        flb_errno();
        flb_sds_destroy(auth);
        flb_sds_destroy(gcs_key_final);
        return -1;
    }
    flb_sds_printf(&uri, "/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
                   ctx->bucket, gcs_key_final);
    if (!uri) {
        flb_sds_destroy(auth);
        flb_sds_destroy(gcs_key_final);
        return -1;
    }
    flb_sds_destroy(gcs_key_final);

    upload_body = buffer;
    upload_size = buffer_size;
    if (ctx->compression_type == FLB_GCS_COMPRESSION_GZIP) {
        ret = flb_gzip_compress(buffer, buffer_size, &gz_data, &gz_size);
        if (ret == 0 && gz_data) {
            upload_body = gz_data;
            upload_size = gz_size;
            flb_plg_debug(ctx->ins,
                          "Pre-compression chunk size is %zu, After compression, chunk is %zu bytes",
                          buffer_size, gz_size);
        }
    }

    ret = gcs_upload_object(ctx, auth, uri, upload_body, upload_size);
    if (gz_data) {
        flb_free(gz_data);
    }
    flb_sds_destroy(auth);
    flb_sds_destroy(uri);

    if (ret != 0 && ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
        ctx->seq_index--;
        write_seq_index(ctx->seq_index_file, ctx->seq_index);
    }

    return ret;
}

static int process_upload_queue(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct upload_queue *entry;
    char *buffer;
    size_t buffer_size;
    int ret;
    time_t now;

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        now = time(NULL);
        if (now < entry->upload_time) {
            continue;
        }
        gcs_store_file_lock(entry->upload_file);

        ret = construct_request_buffer(ctx, entry, &buffer, &buffer_size);
        if (ret == -1) {
            gcs_store_file_unlock(entry->upload_file);
            entry->retry_counter++;
            continue;
        }

        ret = upload_data(ctx, entry, buffer, buffer_size);

        if (ret == 0) {
            gcs_store_file_delete(ctx, entry->upload_file);
            flb_free(buffer);
            remove_from_queue(entry);
            if (ctx->preserve_data_ordering == FLB_TRUE) {
                break;
            }
        }
        else {
            flb_free(buffer);
            gcs_store_file_unlock(entry->upload_file);
            entry->retry_counter++;
            entry->upload_time = now + (2 * entry->retry_counter);
            if (ctx->preserve_data_ordering == FLB_TRUE) {
                break;
            }
        }
    }

    return 0;
}


static int attach_recovered_chunk(struct flb_gcs *ctx, struct flb_fstore_file *fsf)
{
    struct gcs_file *chunk;
    char *buf;
    size_t size;
    int ret;

    if (!fsf) {
        return -1;
    }

    if (fsf->data) {
        return 0;
    }

    chunk = flb_calloc(1, sizeof(struct gcs_file));
    if (!chunk) {
        flb_errno();
        return -1;
    }

    ret = flb_fstore_file_content_copy(ctx->fs, fsf, (void **) &buf, &size);
    if (ret != 0) {
        flb_free(chunk);
        return -1;
    }

    chunk->fsf = fsf;
    chunk->size = size;

    if (ctx->upload_timeout > 0) {
        chunk->create_time = time(NULL) - ctx->upload_timeout;
    }
    else {
        chunk->create_time = time(NULL);
    }

    fsf->data = chunk;
    ctx->current_buffer_size += size;

    flb_free(buf);

    return 0;
}

static void enqueue_backlog_files(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf;
    struct gcs_file *chunk;

    mk_list_foreach(head, &ctx->fs_stream->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);

        if (attach_recovered_chunk(ctx, fsf) == -1) {
            flb_plg_warn(ctx->ins,
                         "could not recover buffered chunk %s, skipping",
                         fsf->name);
            continue;
        }

        chunk = fsf->data;
        if (chunk) {
            add_to_queue(ctx, chunk, (const char *) fsf->meta_buf, fsf->meta_size);
        }
    }
}


static void cb_gcs_upload(struct flb_config *config, void *data)
{
    struct flb_gcs *ctx = data;

    (void) config;

    if (!ctx) {
        return;
    }

    process_upload_queue(ctx);
}


static void gcs_upload_queue(struct flb_config *config, void *data)
{
    int async_flags;
    struct flb_gcs *ctx = data;

    (void) config;

    if (!ctx) {
        return;
    }

    if (mk_list_size(&ctx->upload_queue) == 0) {
        cb_gcs_upload(config, data);
        return;
    }

    async_flags = flb_stream_get_flags(&ctx->u->base);
    flb_stream_disable_async_mode(&ctx->u->base);

    process_upload_queue(ctx);

    flb_stream_set_flags(&ctx->u->base, async_flags);
}

static int flush_init(struct flb_gcs *ctx)
{
    int ret;
    struct flb_sched *sched;

    if (ctx->timer_created == FLB_TRUE) {
        return 0;
    }

    sched = flb_sched_ctx_get();
    if (!sched) {
        return -1;
    }

    if (ctx->preserve_data_ordering == FLB_TRUE) {
        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->timer_ms, gcs_upload_queue, ctx, NULL);
    }
    else {
        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->timer_ms, cb_gcs_upload, ctx, NULL);
    }
    if (ret == -1) {
        return -1;
    }

    ctx->timer_created = FLB_TRUE;
    return 0;
}

/* init/flush/exit */
static int cb_gcs_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    struct flb_gcs *ctx;
    const char *tmp;
    (void) data;

    ctx = flb_calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins; ctx->config = config;
    mk_list_init(&ctx->upload_queue);
    ctx->retry_time = 0;
    ctx->upload_queue_success = FLB_FALSE;
    ctx->timer_created = FLB_FALSE;
    ctx->timer_ms = (int) (ctx->upload_timeout / 6) * 1000;
    if (ctx->timer_ms > 60000) {
        ctx->timer_ms = 60000;
    }
    else if (ctx->timer_ms < 1000) {
        ctx->timer_ms = 1000;
    }
    flb_output_config_map_set(ins, ctx);

    if (!ctx->bucket) {
        goto error;
    }

    if (!ctx->store_dir) {
        ctx->store_dir = flb_sds_create("/tmp");
        if (!ctx->store_dir) {
            goto error;
        }
    }

    if (gcs_store_init(ctx) == -1) {
        goto error;
    }

    tmp = getenv("GOOGLE_SERVICE_CREDENTIALS");
    if (!ctx->credentials_file && tmp) {
        ctx->credentials_file = flb_sds_create(tmp);
        if (!ctx->credentials_file) {
            goto error;
        }
    }

    ctx->oauth_credentials = flb_calloc(1, sizeof(struct flb_gcs_oauth_credentials));
    if (!ctx->credentials_file ||
        flb_gcs_read_credentials_file(ctx, ctx->credentials_file, ctx->oauth_credentials) == -1) {
        flb_errno();
        goto error;
    }

    ctx->o = flb_oauth2_create(config, FLB_GCS_AUTH_URL, FLB_GCS_TOKEN_REFRESH);
    if (!ctx->o) {
        goto error;
    }
    if (pthread_mutex_init(&ctx->token_mutex, NULL) == 0) {
        ctx->token_mutex_initialized = FLB_TRUE;
    }
    else {
        goto error;
    }
    ctx->u = flb_upstream_create(config, FLB_GCS_DEFAULT_HOST, FLB_GCS_DEFAULT_PORT,
                                 FLB_IO_TLS, ins->tls);
    if (!ctx->u) {
        goto error;
    }
    ctx->out_format = FLB_PACK_JSON_FORMAT_LINES;
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    if (ctx->content_type == NULL) {
        ctx->content_type = flb_sds_create("application/json");
        if (!ctx->content_type) {
            goto error;
        }
    }

    tmp = flb_output_get_property("compression", ins);
    if (tmp && strcasecmp(tmp, "gzip") == 0) {
        ctx->compression_type = FLB_GCS_COMPRESSION_GZIP;
    }

    if (strstr(ctx->gcs_key_format, "$INDEX")) {
        if (init_seq_index(ctx) == -1) {
            goto error;
        }
        ctx->key_fmt_has_seq_index = FLB_TRUE;
    }
    if (strstr(ctx->gcs_key_format, "$UUID")) {
        ctx->key_fmt_has_uuid = FLB_TRUE;
    }

    if (gcs_store_has_data(ctx) == FLB_TRUE) {
        enqueue_backlog_files(ctx);

        if (mk_list_size(&ctx->upload_queue) > 0 && flush_init(ctx) == -1) {
            goto error;
        }

        process_upload_queue(ctx);
    }

    flb_output_set_context(ins, ctx);
    return 0;

error:
    gcs_ctx_destroy(ctx, config);
    return -1;
}

static void cb_gcs_flush(struct flb_event_chunk *event_chunk, struct flb_output_flush *out_flush,
                         struct flb_input_instance *i_ins, void *out_context, struct flb_config *config)
{
    struct flb_gcs *ctx = out_context;
    flb_sds_t payload;
    int ret;
    struct gcs_file *chunk;

    if (flush_init(ctx) == -1) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    (void) out_flush;
    (void) i_ins;

    payload = flb_pack_msgpack_to_json_format(event_chunk->data, event_chunk->size,
                                              ctx->out_format, ctx->json_date_format,
                                              ctx->json_date_key, config->json_escape_unicode);
    if (!payload) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    chunk = gcs_store_file_get(ctx, event_chunk->tag, flb_sds_len(event_chunk->tag));
    if (gcs_store_buffer_put(ctx, chunk, event_chunk->tag, flb_sds_len(event_chunk->tag),
                             payload, flb_sds_len(payload)) == -1) {
        flb_sds_destroy(payload);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    flb_sds_destroy(payload);

    chunk = gcs_store_file_get(ctx, event_chunk->tag, flb_sds_len(event_chunk->tag));
    if (!chunk) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = add_to_queue(ctx, chunk, event_chunk->tag, flb_sds_len(event_chunk->tag));
    if (ret == -1) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /*
     * Non-order-preserving mode: try to flush as many queued entries as possible.
     * Preserve-order mode: process at most one queue entry per flush to keep
     * strict FIFO progression.
     */
    ret = process_upload_queue(ctx);
    if (ret == -1) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int gcs_ctx_destroy(void *data, struct flb_config *config)
{
    struct flb_gcs *ctx = data; (void) config;
    if (!ctx) {
        return 0;
    }

    if (ctx->o) {
        flb_oauth2_destroy(ctx->o);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    process_upload_queue(ctx);
    clear_upload_queue(ctx);

    clear_file_chunks(ctx);

    gcs_store_exit(ctx);

    flb_gcs_credentials_destroy(ctx->oauth_credentials);

    if (ctx->token_mutex_initialized == FLB_TRUE) {
        pthread_mutex_destroy(&ctx->token_mutex);
    }
    flb_free(ctx);

    return 0;
}

static int cb_gcs_exit(void *data, struct flb_config *config)
{
    gcs_ctx_destroy(data, config);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, bucket),
     "GCS bucket."
    },
    {
     FLB_CONFIG_MAP_STR, "object_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, object_key),
     "Object key."
    },
    {
     FLB_CONFIG_MAP_STR, "gcs_key_format", "fluent-bit-logs/$TAG/%Y/%m/%d/%H/%M/%S",
     0, FLB_TRUE, offsetof(struct flb_gcs, gcs_key_format),
     "Format string for keys in GCS."
    },
    {
     FLB_CONFIG_MAP_STR, "gcs_key_format_tag_delimiters", ".",
     0, FLB_TRUE, offsetof(struct flb_gcs, tag_delimiters),
     "Characters used to split tag parts for gcs_key_format."
    },
    {
     FLB_CONFIG_MAP_BOOL, "static_file_path", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, static_file_path),
     "Disable random suffix when UUID is not used in gcs_key_format."
    },
    {
     FLB_CONFIG_MAP_STR, "canned_acl", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, canned_acl),
     "Predefined canned ACL for objects."
    },
    {
     FLB_CONFIG_MAP_STR, "storage_class", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, storage_class),
     "Storage class for uploaded objects."
    },
    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "10m",
     0, FLB_TRUE, offsetof(struct flb_gcs, upload_timeout),
     "Upload timeout before chunk is flushed."
    },
    {
     FLB_CONFIG_MAP_BOOL, "send_content_md5", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, send_content_md5),
     "Send Content-MD5 header with uploads."
    },
    {
     FLB_CONFIG_MAP_BOOL, "preserve_data_ordering", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, preserve_data_ordering),
     "Enable preserve-order upload queue semantics."
    },
    {
     FLB_CONFIG_MAP_INT, "store_chunk_limit", "0",
     0, FLB_TRUE, offsetof(struct flb_gcs, store_chunk_limit),
     "Maximum number of buffered fstore chunks for out_gcs (0 means unlimited)."
    },
    {
     FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", (char *) NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, store_dir_limit_size),
     "Limit total buffered bytes in store_dir (0 means unlimited)."
    },
    {
     FLB_CONFIG_MAP_STR, "content_type", "application/json",
     0, FLB_TRUE, offsetof(struct flb_gcs, content_type),
     "Content type."
    },
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, credentials_file),
     "Service account JSON file."
    },
    {
     FLB_CONFIG_MAP_STR, "store_dir", "/tmp/fluent-bit/gcs",
     0, FLB_TRUE, offsetof(struct flb_gcs, store_dir),
     "Directory for intermediate files."
    },
    {
     FLB_CONFIG_MAP_STR, "compression", "none",
     0, FLB_FALSE, 0,
     "Compression: none or gzip."
    },
    {0}
};

struct flb_output_plugin out_gcs_plugin = {
    .name        = "gcs",
    .description = "Google Cloud Storage",
    .cb_init     = cb_gcs_init,
    .cb_flush    = cb_gcs_flush,
    .cb_exit     = cb_gcs_exit,
    .event_type  = FLB_OUTPUT_LOGS,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET | FLB_IO_TLS,
    .workers     = 1,
};
