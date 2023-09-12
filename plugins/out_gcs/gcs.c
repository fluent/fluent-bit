/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <msgpack.h>

#include "gcs.h"
#include "gcs_store.h"

#define DEFAULT_GCS_PORT 443
#define DEFAULT_GCS_INSECURE_PORT 80

static int construct_request_buffer(struct flb_gcs *ctx, flb_sds_t new_data,
                                    struct gcs_file *chunk,
                                    char **out_buf, size_t *out_size);

static int gcs_upload_object(struct flb_gcs *ctx, const char *tag, time_t create_time,
                         char *body, size_t body_size);

static int put_all_chunks(struct flb_gcs *ctx);

static void cb_gcs_upload(struct flb_config *ctx, void *data);

static void remove_from_queue(struct upload_queue *entry);

static inline int key_cmp(char *str, int len, char *cmp) {

    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int flb_gcs_read_credentials_file(struct flb_gcs *ctx,
                                              char *creds,
                                              struct flb_gcs_oauth_credentials *ctx_creds)
{
    int i;
    int ret;
    int len;
    int key_len;
    int val_len;
    int tok_size = 32;
    char *buf;
    char *key;
    char *val;
    flb_sds_t tmp;
    struct stat st;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;

    /* Validate credentials path */
    ret = stat(creds, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open credentials file: %s",
                      creds);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "credentials file "
                      "is not a valid file: %s", creds);
        return -1;
    }

    /* Read file content */
    buf = mk_file_to_buffer(creds);
    if (!buf) {
        flb_plg_error(ctx->ins, "error reading credentials file: %s",
                      creds);
        return -1;
    }

    /* Parse content */
    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    ret = jsmn_parse(&parser, buf, st.st_size, tokens, tok_size);
    if (ret <= 0) {
        flb_plg_error(ctx->ins, "invalid JSON credentials file: %s",
                      creds);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_plg_error(ctx->ins, "invalid JSON map on file: %s",
                      creds);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    /* Parse JSON tokens */
    for (i = 1; i < ret; i++) {
        t = &tokens[i];
        if (t->type != JSMN_STRING) {
            continue;
        }

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)){
            break;
        }

        /* Key */
        key = buf + t->start;
        key_len = (t->end - t->start);

        /* Value */
        i++;
        t = &tokens[i];
        val = buf + t->start;
        val_len = (t->end - t->start);

        if (key_cmp(key, key_len, "type") == 0) {
            ctx_creds->type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "project_id") == 0) {
            ctx_creds->project_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key_id") == 0) {
            ctx_creds->private_key_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key") == 0) {
            tmp = flb_sds_create_len(val, val_len);
            if (tmp) {
                /* Unescape private key */
                len = flb_sds_len(tmp);
                ctx_creds->private_key = flb_sds_create_size(len);
                flb_unescape_string(tmp, len,
                                    &ctx_creds->private_key);
                flb_sds_destroy(tmp);
            }
        }
        else if (key_cmp(key, key_len, "client_email") == 0) {
            ctx_creds->client_email = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "client_id") == 0) {
            ctx_creds->client_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "auth_uri") == 0) {
            ctx_creds->auth_uri = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_uri") == 0) {
            ctx_creds->token_uri = flb_sds_create_len(val, val_len);
        }
    }

    if (!ctx_creds->private_key) {
        flb_plg_error(ctx->ins, "no private key");
        return -1;
    }

    flb_free(buf);
    flb_free(tokens);

    return 0;
}

int gcs_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                          unsigned char *in_buf, size_t in_size,
                          size_t *olen)

{
    int i;
    size_t len;
    int    result;

    /* do normal base64 encoding */
    result = flb_base64_encode((unsigned char *) out_buf, out_size - 1,
                               &len, in_buf, in_size);
    if (result != 0) {
        return -1;
    }

    /* Replace '+' and '/' characters */
    for (i = 0; i < len && out_buf[i] != '='; i++) {
        if (out_buf[i] == '+') {
            out_buf[i] = '-';
        }
        else if (out_buf[i] == '/') {
            out_buf[i] = '_';
        }
    }

    /* Now 'i' becomes the new length */
    *olen = i;
    return 0;
}

static int gcs_jwt_encode(struct flb_gcs *ctx,
                               char *payload, char *secret,
                               char **out_signature, size_t *out_size)
{
    int ret;
    int len;
    int buf_size;
    size_t olen;
    char *buf;
    char *sigd;
    char *headers = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    unsigned char sha256_buf[32] = {0};
    flb_sds_t out;
    unsigned char sig[256] = {0};
    size_t sig_len;

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* Encode header */
    len = strlen(headers);
    ret = flb_base64_encode((unsigned char *) buf, buf_size - 1,
                            &olen, (unsigned char *) headers, len);
    if (ret != 0) {
        flb_free(buf);

        return ret;
    }

    /* Create buffer to store JWT */
    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    /* Append header */
    out = flb_sds_cat(out, buf, olen);
    out = flb_sds_cat(out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    gcs_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                          (unsigned char *) payload, len, &olen);

    /* Append Payload */
    out = flb_sds_cat(out, buf, olen);

    /* do sha256() of base64(header).base64(payload) */
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char *) out, flb_sds_len(out),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error hashing token");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    /* In mbedTLS cert length must include the null byte */
    len = strlen(secret) + 1;

    ret = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                 FLB_CRYPTO_PADDING_PKCS1,
                                 FLB_HASH_SHA256,
                                 (unsigned char *) secret, len,
                                 sha256_buf, sizeof(sha256_buf),
                                 sig, &sig_len);

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error creating RSA context");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_errno();
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    gcs_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    out = flb_sds_cat(out, ".", 1);
    out = flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);

    return 0;
}

/* Create a new oauth2 context and get a oauth2 token */
static int gcs_get_oauth2_token(struct flb_gcs *ctx)
{
    int ret;
    char *token;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    /* Clear any previous oauth2 payload content */
    flb_oauth2_payload_clear(ctx->o);

    /* JWT encode for oauth2 */
    issued = time(NULL);
    expires = issued + FLB_GCS_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->oauth_credentials->client_email, FLB_GCS_SCOPE,
             FLB_GCS_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = gcs_jwt_encode(ctx, payload, ctx->oauth_credentials->private_key,
                              &sig_data, &sig_size);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "JWT signature generation failed");
        return -1;
    }

    flb_plg_debug(ctx->ins, "JWT signature:\n%s", sig_data);

    ret = flb_oauth2_payload_append(ctx->o,
                                    "grant_type", -1,
                                    "urn%3Aietf%3Aparams%3Aoauth%3A"
                                    "grant-type%3Ajwt-bearer", -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "assertion", -1,
                                    sig_data, sig_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }
    flb_sds_destroy(sig_data);

    /* Retrieve access token */
    token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

static flb_sds_t get_google_token(struct flb_gcs *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)){
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        ret = gcs_get_oauth2_token(ctx);
    }

    /* Copy string to prevent race conditions (get_oauth2 can free the string) */
    if (ret == 0) {
        output = flb_sds_create(ctx->o->token_type);
        flb_sds_printf(&output, " %s", ctx->o->access_token);
    }

    if (pthread_mutex_unlock(&ctx->token_mutex)){
        flb_plg_error(ctx->ins, "error unlocking mutex");
        if (output) {
            flb_sds_destroy(output);
        }
        return NULL;
    }

    return output;
}

int flb_gcs_oauth_credentials_destroy(struct flb_gcs_oauth_credentials *creds)
{
    if (!creds) {
        return -1;
    }
    flb_sds_destroy(creds->type);
    flb_sds_destroy(creds->project_id);
    flb_sds_destroy(creds->private_key_id);
    flb_sds_destroy(creds->private_key);
    flb_sds_destroy(creds->client_email);
    flb_sds_destroy(creds->client_id);
    flb_sds_destroy(creds->auth_uri);
    flb_sds_destroy(creds->token_uri);

    flb_free(creds);

    return 0;
}

int gcs_plugin_under_test()
{
    if (getenv("FLB_GCS_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
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

/* Reads in index value from metadata file and sets seq_index to value */
static int read_seq_index(char *seq_index_file, uint64_t *seq_index)
{
    FILE *fp;
    int ret;

    fp = fopen(seq_index_file, "r");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    ret = fscanf(fp, "%"PRIu64, seq_index);
    if (ret != 1) {
        flb_errno();
        return -1;
    }

    fclose(fp);
    return 0;
}

/* Writes index value to metadata file */
static int write_seq_index(char *seq_index_file, uint64_t seq_index)
{
    FILE *fp;
    int ret;

    fp = fopen(seq_index_file, "w+");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    ret = fprintf(fp, "%"PRIu64, seq_index);
    if (ret < 0) {
        flb_errno();
        return -1;
    }

    fclose(fp);
    return 0;
}

static int init_seq_index(void *context) {
    int ret;
    const char *tmp;
    char tmp_buf[1024];
    struct flb_gcs *ctx = context;

    ctx->key_fmt_has_seq_index = FLB_TRUE;

    ctx->stream_metadata = flb_fstore_stream_create(ctx->fs, "sequence");
    if (!ctx->stream_metadata) {
        flb_plg_error(ctx->ins, "could not initialize metadata stream");
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;
        return -1;
    }

    /* Construct directories and file path names */
    ctx->metadata_dir = flb_sds_create(ctx->stream_metadata->path);
    if (ctx->metadata_dir == NULL) {
        flb_plg_error(ctx->ins, "Failed to create metadata path");
        flb_errno();
        return -1;
    }
    tmp = "/index_metadata";
    ret = flb_sds_cat_safe(&ctx->metadata_dir, tmp, strlen(tmp));
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create metadata path");
        flb_errno();
        return -1;
    }

    ctx->seq_index_file = flb_sds_create(ctx->metadata_dir);
    if (ctx->seq_index_file == NULL) {
        flb_plg_error(ctx->ins, "Failed to create sequential index file path");
        flb_errno();
        return -1;
    }
    tmp = "/seq_index_";
    ret = flb_sds_cat_safe(&ctx->seq_index_file, tmp, strlen(tmp));
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create sequential index file path");
        flb_errno();
        return -1;
    }

    sprintf(tmp_buf, "%d", ctx->ins->id);
    ret = flb_sds_cat_safe(&ctx->seq_index_file, tmp_buf, strlen(tmp_buf));
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create sequential index file path");
        flb_errno();
        return -1;
    }

    /* Create directory path if it doesn't exist */
    ret = mkdir(ctx->metadata_dir, 0700);
    if (ret < 0 && errno != EEXIST) {
        flb_plg_error(ctx->ins, "Failed to create metadata directory");
        return -1;
    }

    /* Check if index file doesn't exist and set index value */
    if (access(ctx->seq_index_file, F_OK) != 0) {
        ctx->seq_index = 0;
        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write to sequential index metadata file");
            return -1;
        }
    }
    else {
        ret = read_seq_index(ctx->seq_index_file, &ctx->seq_index);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to read from sequential index "
                          "metadata file");
            return -1;
        }
        flb_plg_info(ctx->ins, "Successfully recovered index. "
                     "Continuing at index=%zu", ctx->seq_index);
    }
    return 0;
}

static void gcs_context_destroy(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct upload_queue *upload_contents;

    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_gcs_oauth_credentials_destroy(ctx->oauth_credentials);

    if (ctx->buffer_dir) {
        flb_sds_destroy(ctx->buffer_dir);
    }

    if (ctx->metadata_dir) {
        flb_sds_destroy(ctx->metadata_dir);
    }

    if (ctx->seq_index_file) {
        flb_sds_destroy(ctx->seq_index_file);
    }

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        upload_contents = mk_list_entry(head, struct upload_queue, _head);
        gcs_store_file_delete(ctx, upload_contents->upload_file);
        remove_from_queue(upload_contents);
    }

    flb_free(ctx);
}

static int cb_gcs_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    int ret;
    int io_flags = FLB_IO_TLS;
    flb_sds_t tmp_sds;
    int async_flags;
    const char *tmp;
    struct flb_gcs *ctx = NULL;
    (void) config;
    (void) data;
    flb_sds_t token;
    struct flb_gcs_oauth_credentials *creds;

    ctx = flb_calloc(1, sizeof(struct flb_gcs));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->upload_queue);

    ctx->retry_time = 0;
    ctx->upload_queue_success = FLB_FALSE;

    /* Export context */
    flb_output_set_context(ins, ctx);

    /* initialize config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Lookup GCS credentials file */
    creds = flb_calloc(1, sizeof(struct flb_gcs_oauth_credentials));
    if (!creds) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    ctx->oauth_credentials = creds;

    if (ctx->credentials_file == NULL) {
        tmp = getenv("GOOGLE_SERVICE_CREDENTIALS");
        if (tmp) {
            ctx->credentials_file = flb_sds_create(tmp);
        }
    }

    if (ctx->credentials_file == NULL) {
        flb_plg_error(ctx->ins, "`google_service_credentials` should be set");
        return -1;
    }

    if (ctx->credentials_file) {
        ret = flb_gcs_read_credentials_file(ctx,
                                                 ctx->credentials_file,
                                                 ctx->oauth_credentials);
        if (ret != 0) {
            flb_gcs_oauth_credentials_destroy(ctx->oauth_credentials);
            flb_sds_destroy(ctx->credentials_file);
            return -1;
        }
    }

    /* Create mutex for acquiring oauth tokens (they are shared across flush coroutines) */
    pthread_mutex_init(&ctx->token_mutex, NULL);

   

    /* the check against -1 is works here because size_t is unsigned
     * and (int) -1 == unsigned max value
     * Fluent Bit uses -1 (which becomes max value) to indicate undefined
     */
    if (ctx->ins->total_limit_size != -1) {
        flb_plg_warn(ctx->ins, "Please use 'store_dir_limit_size' with gcs output instead of 'storage.total_limit_size'. "
                     "GCS has its own buffer files located in the store_dir.");
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
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

    /* Initialize local storage */
    ret = gcs_store_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to initialize GCS storage: %s",
                      ctx->store_dir);
        return -1;
    }

    tmp = flb_output_get_property("gcs_key_format", ins);
    if (tmp) {
        if (tmp[0] == '/') {
            flb_plg_error(ctx->ins, "'gcs_key_format' shouldn't start with a '/'");
            return -1;
        }
        if (strstr((char *) tmp, "$INDEX")) {
            ret = init_seq_index(ctx);
            if (ret < 0) {
                return -1;
            }
        }
        if (strstr((char *) tmp, "$UUID")) {
            ctx->key_fmt_has_uuid = FLB_TRUE;
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

    tmp = flb_output_get_property("compression", ins);
    if (tmp) {
        ret = flb_aws_compression_get_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unknown compression: %s", tmp);
            return -1;
        }

        ctx->compression = ret;
    }

    tmp = flb_output_get_property("content_type", ins);
    if (tmp) {
        ctx->content_type = (char *) tmp;
    } else {
        flb_plg_error(ctx->ins, "'content_type' should be set");
        return -1;
    }

    tmp = flb_output_get_property("canned_acl", ins);
    if (tmp) {
        ctx->canned_acl = (char *) tmp;
    }

    tmp = flb_output_get_property("storage_class", ins);
    if (tmp) {
        ctx->storage_class = (char *) tmp;
    }

    /* read any remaining buffers from previous (failed) executions */
    ctx->has_old_buffers = gcs_store_has_data(ctx);


    /* create GCS upstream */
    /*
     * Create upstream context for BigQuery Streaming Inserts
     * (no oauth2 service)
     */
    ctx->u = flb_upstream_create_url(config, FLB_GCS_URL_BASE,
                                     io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(config, FLB_GCS_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }
    flb_output_upstream_set(ctx->u, ctx->ins);

    /* Retrief oauth2 token */
    token = get_google_token(ctx);
    if (!token) {
        flb_plg_warn(ctx->ins, "token retrieval failed");
    }

    ctx->timer_created = FLB_FALSE;
    ctx->timer_ms = (int) (ctx->upload_timeout / 6) * 1000;
    if (ctx->timer_ms > UPLOAD_TIMER_MAX_WAIT) {
        ctx->timer_ms = UPLOAD_TIMER_MAX_WAIT;
    }
    else if (ctx->timer_ms < UPLOAD_TIMER_MIN_WAIT) {
        ctx->timer_ms = UPLOAD_TIMER_MIN_WAIT;
    }

    /* init must use sync mode */
    async_flags = flb_stream_get_flags(&ctx->u->base);
    flb_stream_disable_async_mode(&ctx->u->base);

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to GCS; buffer=%s",
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

    /*
        * Run GCS in async mode.
        * Multipart uploads don't work with async mode right now in high throughput
        * cases. Its not clear why. Realistically, the performance of sync mode
        * will be sufficient for most users, and long term we can do the work
        * to enable async if needed.
    */
    flb_stream_set_flags(&ctx->u->base, async_flags);

    return 0;
}


/*
 * return value is one of FLB_OK, FLB_RETRY, FLB_ERROR
 *
 * Chunk is allowed to be NULL
 */
static int upload_data(struct flb_gcs *ctx, struct gcs_file *chunk,
                       char *body, size_t body_size,
                       const char *tag, int tag_len)
{
    time_t create_time;
    int ret;
    void *payload_buf = NULL;
    size_t payload_size = 0;

    if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        /* Map payload */
        ret = flb_aws_compression_compress(ctx->compression, body, body_size, &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to compress data");
            return FLB_RETRY;
        } else {
            body = (void *) payload_buf;
            body_size = payload_size;
        }
    }

    /* Upload object exceed MAX_CHUNKED_UPLOAD_COMPRESS_SIZE (5 GB) */
    if(body_size > MAX_CHUNKED_UPLOAD_COMPRESS_SIZE) {
        flb_plg_error(ctx->ins, "file size %zu too large", body_size);
        return -1;
    }

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

    ret = gcs_upload_object(ctx, tag, create_time, body, body_size);
    if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        flb_free(payload_buf);
    }
    if (ret < 0) {
        /* re-add chunk to list */
        if (chunk) {
            gcs_store_file_unlock(chunk);
            chunk->failures += 1;
        }
        return FLB_RETRY;
    }

    /* data was sent successfully- delete the local buffer */
    if (chunk) {
        gcs_store_file_delete(ctx, chunk);
    }
    return FLB_OK;

}


/*
 * Attempts to send all chunks to GCS using UploadObject
 * Used on shut down to try to send all buffered data
 * Used on start up to try to send any leftover buffers from previous executions
 */
static int put_all_chunks(struct flb_gcs *ctx)
{
    struct gcs_file *chunk;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    char *buffer = NULL;
    size_t buffer_size;
    int ret;

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        /* skip metadata stream */
        if (fs_stream == ctx->stream_metadata) {
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

            if (ctx->compression != FLB_AWS_COMPRESS_NONE) {
                /* Map payload */
                ret = flb_aws_compression_compress(ctx->compression, buffer, buffer_size, &payload_buf, &payload_size);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "Failed to compress data, uploading uncompressed data instead to prevent data loss");
                } else {
                    flb_plg_info(ctx->ins, "Pre-compression chunk size is %zu, After compression, chunk is %zu bytes", buffer_size, payload_size);
                    buffer = (void *) payload_buf;
                    buffer_size = payload_size;
                }
            }

            ret = gcs_upload_object(ctx, (const char *)
                                fsf->meta_buf,
                                chunk->create_time, buffer, buffer_size);
            flb_free(buffer);
            if (ret < 0) {
                gcs_store_file_unlock(chunk);
                chunk->failures += 1;
                return -1;
            }

            /* data was sent successfully- delete the local buffer */
            gcs_store_file_delete(ctx, chunk);
        }
    }

    return 0;
}

/*
 * Either new_data or chunk can be NULL, but not both
 */
static int construct_request_buffer(struct flb_gcs *ctx, flb_sds_t new_data,
                                    struct gcs_file *chunk,
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
        ret = gcs_store_file_read(ctx, chunk, &buffered_data, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                          chunk->file_path);
            return -1;
        }

        /*
         * lock the chunk from buffer list- needed for async http so that the
         * same chunk won't be sent more than once.
         */
        gcs_store_file_lock(chunk);
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
                gcs_store_file_unlock(chunk);
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

static int gcs_upload_object(struct flb_gcs *ctx, const char *tag, time_t create_time,
                         char *body, size_t body_size)
{
    flb_sds_t gcs_key = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c = NULL;
    char *random_alphanumeric;
    size_t b_sent;
    int append_random = FLB_FALSE;
    int len;
    int ret;
    char *final_key;
    flb_sds_t uri;
    flb_sds_t tmp;
    flb_sds_t token;
    char buffer[15];
    char final_body_md5[25];
    int retry = 1;

    gcs_key = flb_get_s3_key(ctx->gcs_key_format, create_time, tag, ctx->tag_delimiters,
                            ctx->seq_index);
    if (!gcs_key) {
        flb_plg_error(ctx->ins, "Failed to construct GCS Object Key for %s", tag);
        return -1;
    }

    len = strlen(gcs_key);
    if ((len + 16) <= 1024 && !ctx->key_fmt_has_uuid && !ctx->static_file_path &&
        !ctx->key_fmt_has_seq_index) {
        append_random = FLB_TRUE;
        len += 16;
    }
    len += strlen(ctx->bucket + 46);

    uri = flb_sds_create_size(len);

    if (append_random == FLB_TRUE) {
        random_alphanumeric = flb_sts_session_name();
        if (!random_alphanumeric) {
            flb_sds_destroy(gcs_key);
            flb_sds_destroy(uri);
            flb_plg_error(ctx->ins, "Failed to create randomness for GCS key %s", tag);
            return -1;
        }
        /* only use 8 chars of the random string */
        random_alphanumeric[8] = '\0';

        tmp = flb_sds_printf(&uri, "/upload/storage/v1/b/%s/o?uploadType=media&name=%s-object%s", ctx->bucket, gcs_key,
                             random_alphanumeric);
        flb_free(random_alphanumeric);
    }
    else {
        tmp = flb_sds_printf(&uri, "/upload/storage/v1/b/%s/o?uploadType=media&name=%s", ctx->bucket, gcs_key);
    }

    if (!tmp) {
        flb_sds_destroy(gcs_key);
        flb_plg_error(ctx->ins, "Failed to create Upload Object URI");
        return -1;
    }
    flb_sds_destroy(gcs_key);
    uri = tmp;

    memset(final_body_md5, 0, sizeof(final_body_md5));
    if (ctx->send_content_md5 == FLB_TRUE) {
        ret = gcs_get_md5_base64(body, body_size,
                             final_body_md5, sizeof(final_body_md5));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Failed to create Content-MD5 header");
            flb_sds_destroy(uri);
            return -1;
        }
    }

    /* Update file and increment index value right before request */
    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index++;

        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0 && access(ctx->seq_index_file, F_OK) == 0) {
            ctx->seq_index--;
            flb_sds_destroy(gcs_key);
            flb_plg_error(ctx->ins, "Failed to update sequential index metadata file");
            return -1;
        }
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        return -1;
    }
    /* Get or renew Token */
    token = get_google_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri,
                        body, body_size, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(token);
        flb_sds_destroy(body);
        
        return -1;
    }

    /* Compose User-Agent header */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    /* Compose Content-Type header */
    flb_http_add_header(c, "Content-Type", 12, ctx->content_type, strlen(ctx->content_type));
    /* Compose and append Authorization header */
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));
    /* Compose Content-Length header */
    len = snprintf(buffer, sizeof(buffer), "%zu", body_size);
    flb_http_add_header(c, "Content-Length", 14, buffer, len);
    /* Compose ACL header */
    if (ctx->canned_acl) {
        flb_http_add_header(c, "x-goog-acl", 10, ctx->canned_acl, strlen(ctx->canned_acl));
    }
    /* Compose Storage Class header */
    if (ctx->storage_class) {
        flb_http_add_header(c, "x-goog-storage-class", 20, ctx->storage_class, strlen(ctx->storage_class));
    }
    /* Compose MD5 header */
    if (ctx->send_content_md5 == FLB_TRUE) {
        flb_http_add_header(c, "Content-MD5", 11, final_body_md5, sizeof(final_body_md5));
    }

    /* Check whether to auto retry */
    if (ctx->retry_requests == FLB_TRUE) {
        retry++;
    }
    while (retry > 0) {
        /* Send HTTP request */
        ret = flb_http_do(c, &b_sent);
        if (c->resp.status == 200) {
            break;
        }
        retry--;
    }
    /* The request was issued successfully, validate the 'error' field */
    flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
    if (c->resp.status == 200) {
        /*
            * URI contains bucket name, so we must advance over it
            * to print the object key
            */
        final_key = uri + strlen(ctx->bucket) + 1;
        flb_plg_info(ctx->ins, "Successfully uploaded object %s", final_key);
        flb_sds_destroy(uri);
        flb_http_client_destroy(c);

        return 0;
    }
    else {
        if (c->resp.data != NULL) {
            flb_plg_error(ctx->ins, "Raw UploadObject response: %s", c->resp.data);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "UploadObject request failed");
    flb_sds_destroy(uri);
    goto decrement_index;

decrement_index:
    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index--;

        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to decrement index after request error");
            return -1;
        }
    }
    return -1;
}

int gcs_get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size)
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

    return 0;
}

/* Adds an entry to upload queue */
static int add_to_queue(struct flb_gcs *ctx, struct gcs_file *upload_file, const char *tag, int tag_len)
{
    struct upload_queue *upload_contents;
    char *tag_cpy;

    /* Create upload contents object and add to upload queue */
    upload_contents = flb_malloc(sizeof(struct upload_queue));
    if (upload_contents == NULL) {
        flb_plg_error(ctx->ins, "Error allocating memory for upload_queue entry");
        flb_errno();
        return -1;
    }
    upload_contents->upload_file = upload_file;
    upload_contents->tag_len = tag_len;
    upload_contents->retry_counter = 0;
    upload_contents->upload_time = -1;

    /* Necessary to create separate string for tag to prevent corruption */
    tag_cpy = flb_malloc(tag_len);
    if (tag_cpy == NULL) {
        flb_free(upload_contents);
        flb_plg_error(ctx->ins, "Error allocating memory for tag in add_to_queue");
        flb_errno();
        return -1;
    }
    strncpy(tag_cpy, tag, tag_len);
    upload_contents->tag = tag_cpy;

    /* Add entry to upload queue */
    mk_list_add(&upload_contents->_head, &ctx->upload_queue);
    return 0;
}

/* Removes an entry from upload_queue */
void remove_from_queue(struct upload_queue *entry)
{
    mk_list_del(&entry->_head);
    flb_free(entry->tag);
    flb_free(entry);
    return;
}

/* Validity check for upload queue object */
static int upload_queue_valid(struct upload_queue *upload_contents, time_t now,
                              void *out_context)
{
    struct flb_gcs *ctx = out_context;

    if (upload_contents == NULL) {
        flb_plg_error(ctx->ins, "Error getting entry from upload_queue");
        return -1;
    }
    if (upload_contents->_head.next == NULL || upload_contents->_head.prev == NULL) {
        flb_plg_debug(ctx->ins, "Encountered previously deleted entry in "
                      "upload_queue. Deleting invalid entry");
        mk_list_del(&upload_contents->_head);
        return -1;
    }
    if (upload_contents->upload_file->locked == FLB_FALSE) {
        flb_plg_debug(ctx->ins, "Encountered unlocked file in upload_queue. "
                      "Exiting");
        return -1;
    }
    if (upload_contents->upload_file->size <= 0) {
        flb_plg_debug(ctx->ins, "Encountered empty chunk file in upload_queue. "
                      "Deleting empty chunk file");
        remove_from_queue(upload_contents);
        return -1;
    }
    if (now < upload_contents->upload_time) {
        flb_plg_debug(ctx->ins, "Found valid chunk file but not ready to upload");
        return -1;
    }
    return 0;
}

static int send_upload_request(void *out_context, flb_sds_t chunk,
                               struct gcs_file *upload_file,
                               const char *tag, int tag_len)
{
    int ret;
    char *buffer;
    size_t buffer_size;
    struct flb_gcs *ctx = out_context;

    /* Create buffer to upload to GCS */
    ret = construct_request_buffer(ctx, chunk, upload_file, &buffer, &buffer_size);
    flb_sds_destroy(chunk);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                      upload_file->file_path);
        return -1;
    }

    /* Upload to GCS */
    ret = upload_data(ctx, upload_file, buffer, buffer_size, tag, tag_len);
    flb_free(buffer);

    return ret;
}

static int buffer_chunk(void *out_context, struct gcs_file *upload_file, flb_sds_t chunk,
                        int chunk_size, const char *tag, int tag_len)
{
    int ret;
    struct flb_gcs *ctx = out_context;

    ret = gcs_store_buffer_put(ctx, upload_file, tag, tag_len, chunk, (size_t) chunk_size);
    flb_sds_destroy(chunk);
    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not buffer chunk. Data order preservation "
                     "will be compromised");
        return -1;
    }
    return 0;
}

/* Uploads all chunk files in queue synchronously */
static void gcs_upload_queue(struct flb_config *config, void *out_context)
{
    int ret;
    int async_flags;
    time_t now;
    struct upload_queue *upload_contents;
    struct flb_gcs *ctx = out_context;
    struct mk_list *tmp;
    struct mk_list *head;

    flb_plg_debug(ctx->ins, "Running upload timer callback (upload_queue)..");

    /* No chunks in upload queue. Scan for timed out chunks. */
    if (mk_list_size(&ctx->upload_queue) == 0) {
        flb_plg_debug(ctx->ins, "No files found in upload_queue. Scanning for timed "
                      "out chunks");
        cb_gcs_upload(config, out_context);
    }

    /* upload timer must use sync mode */
    async_flags = flb_stream_get_flags(&ctx->u->base);
    flb_stream_disable_async_mode(&ctx->u->base);

    /* Iterate through each file in upload queue */
    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        upload_contents = mk_list_entry(head, struct upload_queue, _head);

        now = time(NULL);

        /* Checks if upload_contents is valid */
        ret = upload_queue_valid(upload_contents, now, ctx);
        if (ret < 0) {
            goto exit;
        }

        /* Try to upload file. Return value can be -1, FLB_OK, FLB_ERROR, FLB_RETRY. */
        ret = send_upload_request(ctx, NULL, upload_contents->upload_file,
                                  upload_contents->tag, upload_contents->tag_len);
        if (ret < 0) {
            goto exit;
        }
        else if (ret == FLB_OK) {
            remove_from_queue(upload_contents);
            ctx->retry_time = 0;
            ctx->upload_queue_success = FLB_TRUE;
        }
        else {
            gcs_store_file_lock(upload_contents->upload_file);
            ctx->upload_queue_success = FLB_FALSE;

            /* If retry limit was reached, discard file and remove file from queue */
            upload_contents->retry_counter++;
            if (upload_contents->retry_counter >= MAX_UPLOAD_ERRORS) {
                flb_plg_warn(ctx->ins, "Chunk file failed to send %d times, will not "
                             "retry", upload_contents->retry_counter);
                gcs_store_file_inactive(ctx, upload_contents->upload_file);
                remove_from_queue(upload_contents);
                continue;
            }

            /* Retry in N seconds */
            upload_contents->upload_time = now + 2 * upload_contents->retry_counter;
            ctx->retry_time += 2 * upload_contents->retry_counter;
            flb_plg_debug(ctx->ins, "Failed to upload file in upload_queue. Will not "
                          "retry for %d seconds", 2 * upload_contents->retry_counter);
            break;
        }
    }

exit:
    /* re-enable async mode */
    flb_stream_set_flags(&ctx->u->base, async_flags);
}

static void cb_gcs_upload(struct flb_config *config, void *data)
{
    struct flb_gcs *ctx = data;
    struct gcs_file *chunk = NULL;
    struct flb_fstore_file *fsf;
    char *buffer = NULL;
    size_t buffer_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    int ret;
    time_t now;
    int async_flags;

    flb_plg_debug(ctx->ins, "Running upload timer callback (cb_gcs_upload)..");

    /* upload timer must use sync mode */
    async_flags = flb_stream_get_flags(&ctx->u->base);
    flb_stream_disable_async_mode(&ctx->u->base);

    now = time(NULL);

    /* Check all chunks and see if any have timed out */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        chunk = fsf->data;

        if (now < (chunk->create_time + ctx->upload_timeout + ctx->retry_time)) {
            continue; /* Only send chunks which have timed out */
        }

        /* Locked chunks are being processed, skip */
        if (chunk->locked == FLB_TRUE) {
            continue;
        }

        ret = construct_request_buffer(ctx, NULL, chunk, &buffer, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                          chunk->file_path);
            continue;
        }

        /* FYI: if construct_request_buffer() succeedeed, the gcs_file is locked */
        ret = upload_data(ctx, chunk, buffer, buffer_size,
                          (const char *) fsf->meta_buf, fsf->meta_size);
        flb_free(buffer);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "Could not send chunk with tag %s",
                          (char *) fsf->meta_buf);
        }
    }

    flb_stream_set_flags(&ctx->u->base, async_flags);
}

static flb_sds_t flb_pack_msgpack_extract_log_key(void *out_context, const char *data,
                                                  uint64_t bytes)
{
    int i;
    int records = 0;
    int map_size;
    int check = FLB_FALSE;
    int found = FLB_FALSE;
    int log_key_missing = 0;
    int ret;
    int alloc_error = 0;
    struct flb_gcs *ctx = out_context;
    char *val_buf;
    char *key_str = NULL;
    size_t key_str_size = 0;
    size_t off = 0;
    size_t msgpack_size = bytes + bytes / 4;
    size_t val_offset = 0;
    flb_sds_t out_buf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object key;
    msgpack_object val;

    /* Iterate the original buffer and perform adjustments */
    records = flb_mp_count(data, bytes);
    if (records <= 0) {
        return NULL;
    }

    /* Allocate buffer to store log_key contents */
    val_buf = flb_malloc(msgpack_size);
    if (val_buf == NULL) {
        flb_plg_error(ctx->ins, "Could not allocate enough "
                      "memory to read record");
        flb_errno();
        return NULL;
    }

    msgpack_unpacked_init(&result);
    while (!alloc_error &&
           msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        if (root.via.array.size != 2) {
            continue;
        }

        /* Get the record/map */
        map = root.via.array.ptr[1];
        if (map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }
        map_size = map.via.map.size;

        /* Reset variables for found log_key and correct type */
        found = FLB_FALSE;
        check = FLB_FALSE;

        /* Extract log_key from record and append to output buffer */
        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;
            val = map.via.map.ptr[i].val;

            if (key.type == MSGPACK_OBJECT_BIN) {
                key_str  = (char *) key.via.bin.ptr;
                key_str_size = key.via.bin.size;
                check = FLB_TRUE;
            }
            if (key.type == MSGPACK_OBJECT_STR) {
                key_str  = (char *) key.via.str.ptr;
                key_str_size = key.via.str.size;
                check = FLB_TRUE;
            }

            if (check == FLB_TRUE) {
                if (strncmp(ctx->log_key, key_str, key_str_size) == 0) {
                    found = FLB_TRUE;

                    /*
                     * Copy contents of value into buffer. Necessary to copy
                     * strings because flb_msgpack_to_json does not handle nested
                     * JSON gracefully and double escapes them.
                     */
                    if (val.type == MSGPACK_OBJECT_BIN) {
                        memcpy(val_buf + val_offset, val.via.bin.ptr, val.via.bin.size);
                        val_offset += val.via.bin.size;
                        val_buf[val_offset] = '\n';
                        val_offset++;
                    }
                    else if (val.type == MSGPACK_OBJECT_STR) {
                        memcpy(val_buf + val_offset, val.via.str.ptr, val.via.str.size);
                        val_offset += val.via.str.size;
                        val_buf[val_offset] = '\n';
                        val_offset++;
                    }
                    else {
                        ret = flb_msgpack_to_json(val_buf + val_offset,
                                                  msgpack_size - val_offset, &val);
                        if (ret < 0) {
                            break;
                        }
                        val_offset += ret;
                        val_buf[val_offset] = '\n';
                        val_offset++;
                    }
                    /* Exit early once log_key has been found for current record */
                    break;
                }
            }
        }

        /* If log_key was not found in the current record, mark log key as missing */
        if (found == FLB_FALSE) {
            log_key_missing++;
        }
    }

    /* Throw error once per chunk if at least one log key was not found */
    if (log_key_missing == FLB_TRUE) {
        flb_plg_error(ctx->ins, "Could not find log_key '%s' in %d records",
                      ctx->log_key, log_key_missing);
    }

    /* Release the unpacker */
    msgpack_unpacked_destroy(&result);

    /* If nothing was read, destroy buffer */
    if (val_offset == 0) {
        flb_free(val_buf);
        return NULL;
    }
    val_buf[val_offset] = '\0';

    /* Create output buffer to store contents */
    out_buf = flb_sds_create(val_buf);
    if (out_buf == NULL) {
        flb_plg_error(ctx->ins, "Error creating buffer to store log_key contents.");
        flb_errno();
    }
    flb_free(val_buf);

    return out_buf;
}

static void flush_init(void *out_context)
{
    int ret;
    struct flb_gcs *ctx = out_context;
    struct flb_sched *sched;

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to GCS; buffer=%s",
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

        sched = flb_sched_ctx_get();

        if (ctx->preserve_data_ordering) {
            ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                            ctx->timer_ms, gcs_upload_queue, ctx, NULL);
        }
        else {
            ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                            ctx->timer_ms, cb_gcs_upload, ctx, NULL);
        }
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create upload timer");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->timer_created = FLB_TRUE;
    }
}

static void cb_gcs_flush(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    int ret;
    int chunk_size;
    int upload_timeout_check = FLB_FALSE;
    int total_file_size_check = FLB_FALSE;
    flb_sds_t chunk = NULL;
    struct gcs_file *upload_file = NULL;
    struct flb_gcs *ctx = out_context;

    /* Cleanup old buffers and initialize upload timer */
    flush_init(ctx);

    /* Process chunk */
    if (ctx->log_key) {
        chunk = flb_pack_msgpack_extract_log_key(ctx,
                                                 event_chunk->data,
                                                 event_chunk->size);
    }
    else {
        chunk = flb_pack_msgpack_to_json_format(event_chunk->data,
                                                event_chunk->size,
                                                FLB_PACK_JSON_FORMAT_LINES,
                                                ctx->json_date_format,
                                                ctx->date_key);
    }
    if (chunk == NULL) {
        flb_plg_error(ctx->ins, "Could not marshal msgpack to output string");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    chunk_size = flb_sds_len(chunk);

    /* Get a file candidate matching the given 'tag' */
    upload_file = gcs_store_file_get(ctx,
                                    event_chunk->tag,
                                    flb_sds_len(event_chunk->tag));

    /* Discard upload_file if it has failed to upload MAX_UPLOAD_ERRORS times */
    if (upload_file != NULL && upload_file->failures >= MAX_UPLOAD_ERRORS) {
        flb_plg_warn(ctx->ins, "File with tag %s failed to send %d times, will not "
                     "retry", event_chunk->tag, MAX_UPLOAD_ERRORS);
        gcs_store_file_inactive(ctx, upload_file);
        upload_file = NULL;
    }

    /* If upload_timeout has elapsed, upload file */
    if (upload_file != NULL && time(NULL) >
        (upload_file->create_time + ctx->upload_timeout)) {
        upload_timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "upload_timeout reached for %s",
                     event_chunk->tag);
    }


    /* If total_file_size has been reached, upload file */
    if (upload_file && upload_file->size + chunk_size > ctx->file_size) {
        total_file_size_check = FLB_TRUE;
    }

    /* File is ready for upload */
    if (upload_timeout_check == FLB_TRUE || total_file_size_check == FLB_TRUE) {
        if (ctx->preserve_data_ordering == FLB_TRUE) {
            /* Buffer last chunk in file and lock file to prevent further changes */
            ret = buffer_chunk(ctx, upload_file, chunk, chunk_size,
                               event_chunk->tag, flb_sds_len(event_chunk->tag));
            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            gcs_store_file_lock(upload_file);

            /* Add chunk file to upload queue */
            ret = add_to_queue(ctx, upload_file,
                               event_chunk->tag, flb_sds_len(event_chunk->tag));
            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            /* Go through upload queue and return error if something went wrong */
            gcs_upload_queue(config, ctx);
            if (ctx->upload_queue_success == FLB_FALSE) {
                ctx->upload_queue_success = FLB_TRUE;
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            FLB_OUTPUT_RETURN(FLB_OK);
        }
        else {
            /* Send upload directly without upload queue */
            ret = send_upload_request(ctx, chunk, upload_file,
                                      event_chunk->tag,
                                      flb_sds_len(event_chunk->tag));
            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            FLB_OUTPUT_RETURN(ret);
        }
    }

    /* Buffer current chunk in filesystem and wait for next chunk from engine */
    ret = buffer_chunk(ctx, upload_file, chunk, chunk_size,
                       event_chunk->tag, flb_sds_len(event_chunk->tag));
    if (ret < 0) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_gcs_exit(void *data, struct flb_config *config)
{
    int ret;
    struct flb_gcs *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (gcs_store_has_data(ctx) == FLB_TRUE) {
        flb_stream_disable_async_mode(&ctx->u->base);
        flb_plg_info(ctx->ins, "Sending all locally buffered data to GCS");
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not send all chunks on exit");
        }
    }

    gcs_store_exit(ctx);
    gcs_context_destroy(ctx);

    return 0;
}


/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, credentials_file),
     "Set the path for the google service credentials file"
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_gcs, json_date_key),
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_SIZE, "total_file_size", "100000000",
     0, FLB_TRUE, offsetof(struct flb_gcs, file_size),
     "Specifies the size of files in GCS. Maximum size is 50GB, minimum is 1MB"
    },
    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "10m",
     0, FLB_TRUE, offsetof(struct flb_gcs, upload_timeout),
     "Optionally specify a timeout for uploads. "
     "Whenever this amount of time has elapsed, Fluent Bit will complete an "
     "upload and create a new file in GCS. For example, set this value to 60m "
     "and you will get a new file in GCS every hour. Default is 10m."
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, bucket),
    "GCS bucket name."
    },
    {
     FLB_CONFIG_MAP_STR, "canned_acl", NULL,
     0, FLB_FALSE, 0,
    "Predefined Canned ACL policy for GCS objects."
    },
    {
     FLB_CONFIG_MAP_STR, "compression", NULL,
     0, FLB_FALSE, 0,
    "Compression type for GCS objects. 'gzip' and 'arrow' are the supported values. "
    "'arrow' is only an available if Apache Arrow was enabled at compile time. "
    "Defaults to no compression. "
    "If 'gzip' is selected, the Content-Encoding HTTP Header will be set to 'gzip'."
    },
    {
     FLB_CONFIG_MAP_STR, "content_type", NULL,
     0, FLB_FALSE, 0,
    "A standard MIME type for the GCS object; this will be set "
    "as the Content-Type HTTP header."
    },
    {
     FLB_CONFIG_MAP_STR, "store_dir", "/tmp/fluent-bit/gcs",
     0, FLB_TRUE, offsetof(struct flb_gcs, store_dir),
     "Directory to locally buffer data before sending. Plugin uses the GCS Multipart "
     "upload API to send data in chunks of 5 MB at a time- only a small amount of"
     " data will be locally buffered at any given point in time."
    },

    {
     FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", (char *) NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, store_dir_limit_size),
     "GCS plugin has its own buffering system with files in the `store_dir`. "
     "Use the `store_dir_limit_size` to limit the amount of data GCS buffers in "
     "the `store_dir` to limit disk usage. If the limit is reached, "
     "data will be discarded. Default is 0 which means unlimited."
    },

    {
     FLB_CONFIG_MAP_STR, "gcs_key_format", "fluent-bit-logs/$TAG/%Y/%m/%d/%H/%M/%S",
     0, FLB_TRUE, offsetof(struct flb_gcs, gcs_key_format),
    "Format string for keys in GCS. This option supports strftime time formatters "
    "and a syntax for selecting parts of the Fluent log tag using a syntax inspired "
    "by the rewrite_tag filter. Add $TAG in the format string to insert the full "
    "log tag; add $TAG[0] to insert the first part of the tag in the gcs key. "
    "The tag is split into “parts” using the characters specified with the "
    "gcs_key_format_tag_delimiters option. Add $INDEX to enable sequential indexing "
    "for file names. Adding $INDEX will prevent random string being added to end of key"
    "when $UUID is not provided. See the in depth examples and tutorial in the "
    "documentation."
    },

    {
     FLB_CONFIG_MAP_STR, "gcs_key_format_tag_delimiters", ".",
     0, FLB_TRUE, offsetof(struct flb_gcs, tag_delimiters),
    "A series of characters which will be used to split the tag into “parts” for "
    "use with the gcs_key_format option. See the in depth examples and tutorial in "
    "the documentation."
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_retry_requests", "true",
     0, FLB_TRUE, offsetof(struct flb_gcs, retry_requests),
     "Immediately retry failed requests to AWS services once. This option "
     "does not affect the normal Fluent Bit retry mechanism with backoff. "
     "Instead, it enables an immediate retry with no delay for networking "
     "errors, which may help improve throughput when there are transient/random "
     "networking issues."
    },

    {
     FLB_CONFIG_MAP_BOOL, "send_content_md5", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, send_content_md5),
     "Send the Content-MD5 header with object uploads, as is required when Object Lock is enabled"
    },

    {
     FLB_CONFIG_MAP_BOOL, "preserve_data_ordering", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, preserve_data_ordering),
     "Normally, when an upload request fails, there is a high chance for the last "
     "received chunk to be swapped with a later chunk, resulting in data shuffling. "
     "This feature prevents this shuffling by using a queue logic for uploads."
    },

    {
     FLB_CONFIG_MAP_STR, "log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, log_key),
     "By default, the whole log record will be sent to GCS. "
     "If you specify a key name with this option, then only the value of "
     "that key will be sent to GCS."
    },
    {
     FLB_CONFIG_MAP_BOOL, "static_file_path", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, static_file_path),
     "Disables behavior where UUID string is automatically appended to end of GCS key name when "
     "$UUID is not provided in gcs_key_format. $UUID, time formatters, $TAG, and other dynamic "
     "key formatters all work as expected while this feature is set to true."
    },
    {
     FLB_CONFIG_MAP_STR, "storage_class", NULL,
     0, FLB_FALSE, 0,
     "Specify the storage class for GCS objects. If this option is not specified, objects "
     "will be stored with the default 'STANDARD' storage class."
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_gcs_plugin = {
    .name         = "gcs",
    .description  = "Send to GCS",
    .cb_init      = cb_gcs_init,
    .cb_flush     = cb_gcs_flush,
    .cb_exit      = cb_gcs_exit,
    .workers      = 1,
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
    .config_map   = config_map
};
