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
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>

#include <msgpack.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "gcs.h"

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "bucket", NULL,
        0, FLB_TRUE, offsetof(struct flb_gcs, bucket),
        "GCS bucket name (required)"
    },
    {
        FLB_CONFIG_MAP_STR, "project_id", NULL,
        0, FLB_FALSE, offsetof(struct flb_gcs, project_id),
        "Google Cloud Project ID"
    },
    {
        FLB_CONFIG_MAP_STR, "region", NULL,
        0, FLB_FALSE, offsetof(struct flb_gcs, region),
        "GCS bucket region"
    },
    {
        FLB_CONFIG_MAP_STR, "gcs_key_format", "/fluent-bit-logs/%Y/%m/%d/%H/%M/%S_${tag}.log",
        0, FLB_TRUE, offsetof(struct flb_gcs, object_key_format),
        "Format string for GCS object keys with time/tag placeholders"
    },
    {
        FLB_CONFIG_MAP_STR, "credentials_file", NULL,
        0, FLB_FALSE, offsetof(struct flb_gcs, credentials_file),
        "Path to GCS service account JSON credentials file"
    },
    {
        FLB_CONFIG_MAP_STR, "service_account_email", NULL,
        0, FLB_FALSE, offsetof(struct flb_gcs, service_account_email),
        "Service account email for authentication"
    },
    {
        FLB_CONFIG_MAP_STR, "store_dir", FLB_GCS_DEFAULT_STORE_DIR,
        0, FLB_TRUE, offsetof(struct flb_gcs, store_dir),
        "Directory to store temporary files before upload"
    },
    {
        FLB_CONFIG_MAP_SIZE, "total_file_size", "104857600",
        0, FLB_TRUE, offsetof(struct flb_gcs, total_file_size),
        "Target file size for uploads (default: 100MB)"
    },
    {
        FLB_CONFIG_MAP_SIZE, "upload_chunk_size", "5242880",
        0, FLB_TRUE, offsetof(struct flb_gcs, upload_chunk_size),
        "Size of upload chunks for resumable uploads (default: 5MB)"
    },
    {
        FLB_CONFIG_MAP_TIME, "upload_timeout", "300s",
        0, FLB_TRUE, offsetof(struct flb_gcs, upload_timeout),
        "Maximum time to wait for chunk accumulation before upload"
    },
    {
        FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", "0",
        0, FLB_TRUE, offsetof(struct flb_gcs, store_dir_limit_size),
        "Maximum size for store directory (0 = unlimited)"
    },
    {
        FLB_CONFIG_MAP_STR, "format", "json",
        0, FLB_TRUE, offsetof(struct flb_gcs, format),
        "Output format: text, json, parquet (default: json)"
    },
    {
        FLB_CONFIG_MAP_STR, "compression", "none",
        0, FLB_TRUE, offsetof(struct flb_gcs, compression),
        "Compression type: none, gzip (default: none)"
    },
    {
        FLB_CONFIG_MAP_STR, "log_key", NULL,
        0, FLB_FALSE, offsetof(struct flb_gcs, log_key),
        "Extract specific key from log record for output"
    },
    {
        FLB_CONFIG_MAP_STR, "json_date_key", "date",
        0, FLB_TRUE, offsetof(struct flb_gcs, json_date_key),
        "Date field name in JSON output"
    },
    {
        FLB_CONFIG_MAP_INT, "json_date_format", "0",
        0, FLB_TRUE, offsetof(struct flb_gcs, json_date_format),
        "Date format for JSON output: 0=epoch, 1=iso8601"
    },
    {
        FLB_CONFIG_MAP_INT, "retry_limit", "3",
        0, FLB_TRUE, offsetof(struct flb_gcs, retry_limit),
        "Number of retries for failed uploads"
    },
    {
        FLB_CONFIG_MAP_BOOL, "preserve_data_ordering", "true",
        0, FLB_TRUE, offsetof(struct flb_gcs, preserve_data_ordering),
        "Preserve log order during retries and failures"
    },
    {
        FLB_CONFIG_MAP_BOOL, "use_put_object", "false",
        0, FLB_TRUE, offsetof(struct flb_gcs, use_put_object),
        "Use simple PUT instead of resumable uploads for small files"
    },
    {0}
};

/* Configuration parsing and validation */
static int gcs_config_format(struct flb_gcs *ctx, const char *format_str)
{
    if (strcasecmp(format_str, "text") == 0) {
        ctx->format = FLB_GCS_FORMAT_TEXT;
    }
    else if (strcasecmp(format_str, "json") == 0) {
        ctx->format = FLB_GCS_FORMAT_JSON;
    }
    else if (strcasecmp(format_str, "parquet") == 0) {
        ctx->format = FLB_GCS_FORMAT_PARQUET;
#ifndef FLB_HAVE_PARQUET
        flb_plg_error(ctx->ins, "Parquet support not compiled in");
        return -1;
#endif
    }
    else {
        flb_plg_error(ctx->ins, "Invalid format: %s", format_str);
        return -1;
    }
    return 0;
}

static int gcs_config_compression(struct flb_gcs *ctx, const char *compression_str)
{
    if (strcasecmp(compression_str, "none") == 0) {
        ctx->compression = FLB_GCS_COMPRESSION_NONE;
    }
    else if (strcasecmp(compression_str, "gzip") == 0) {
        ctx->compression = FLB_GCS_COMPRESSION_GZIP;
    }
    else {
        flb_plg_error(ctx->ins, "Invalid compression: %s", compression_str);
        return -1;
    }
    return 0;
}

static int gcs_config_check(struct flb_gcs *ctx)
{
    /* Validate required parameters */
    if (!ctx->bucket) {
        flb_plg_error(ctx->ins, "Missing required parameter: bucket");
        return -1;
    }

    /* Validate bucket name format (basic check) */
    if (strlen(ctx->bucket) < 3 || strlen(ctx->bucket) > 63) {
        flb_plg_error(ctx->ins, "Invalid bucket name length (must be 3-63 chars)");
        return -1;
    }

    /* Validate upload chunk size */
    if (ctx->upload_chunk_size < 262144) { /* 256KB minimum */
        flb_plg_warn(ctx->ins, "Upload chunk size too small, setting to 256KB");
        ctx->upload_chunk_size = 262144;
    }
    if (ctx->upload_chunk_size > FLB_GCS_MAX_CHUNK_SIZE) {
        flb_plg_warn(ctx->ins, "Upload chunk size too large, setting to %d bytes",
                     FLB_GCS_MAX_CHUNK_SIZE);
        ctx->upload_chunk_size = FLB_GCS_MAX_CHUNK_SIZE;
    }

    /* Validate total file size */
    if (ctx->total_file_size < ctx->upload_chunk_size) {
        flb_plg_warn(ctx->ins, "Total file size smaller than chunk size, adjusting");
        ctx->total_file_size = ctx->upload_chunk_size;
    }

    /* Check store directory */
    if (ctx->store_dir) {
        struct stat st;
        if (stat(ctx->store_dir, &st) != 0) {
            if (mkdir(ctx->store_dir, 0755) != 0) {
                flb_plg_error(ctx->ins, "Cannot create store directory: %s", 
                              ctx->store_dir);
                return -1;
            }
        }
        else if (!S_ISDIR(st.st_mode)) {
            flb_plg_error(ctx->ins, "Store path is not a directory: %s", 
                          ctx->store_dir);
            return -1;
        }
    }

    return 0;
}

static int gcs_config_init(struct flb_gcs *ctx, struct flb_output_instance *ins)
{
    int ret;
    const char *tmp;

    /* Set configuration from config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Parse format string */
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = gcs_config_format(ctx, tmp);
        if (ret == -1) {
            return -1;
        }
    }

    /* Parse compression string */
    tmp = flb_output_get_property("compression", ins);
    if (tmp) {
        ret = gcs_config_compression(ctx, tmp);
        if (ret == -1) {
            return -1;
        }
    }

    /* Authentication type detection */
    ctx->auth_type = FLB_GCS_AUTH_ADC; /* Default to ADC */
    if (ctx->credentials_file) {
        ctx->auth_type = FLB_GCS_AUTH_SERVICE_ACCOUNT;
    }

    /* Validate configuration */
    ret = gcs_config_check(ctx);
    if (ret == -1) {
        return -1;
    }

    flb_plg_info(ctx->ins, "GCS plugin configured: bucket=%s, format=%s, compression=%s",
                 ctx->bucket,
                 ctx->format == FLB_GCS_FORMAT_TEXT ? "text" :
                 ctx->format == FLB_GCS_FORMAT_JSON ? "json" : "parquet",
                 ctx->compression == FLB_GCS_COMPRESSION_NONE ? "none" : "gzip");

    return 0;
}

/* OAuth2 authentication functions */
static int gcs_oauth2_init(struct flb_gcs *ctx)
{
    int ret;
    
    /* OAuth2 context for GCS */
    ctx->oauth2 = flb_oauth2_create(ctx->config, FLB_GCS_TOKEN_HOST, 443);
    if (!ctx->oauth2) {
        flb_plg_error(ctx->ins, "Failed to create OAuth2 context");
        return -1;
    }

    /* Configure OAuth2 based on authentication type */
    if (ctx->auth_type == FLB_GCS_AUTH_SERVICE_ACCOUNT) {
        if (!ctx->credentials_file) {
            flb_plg_error(ctx->ins, "Credentials file required for service account auth");
            return -1;
        }

        ret = flb_oauth2_payload_append(ctx->oauth2,
                                        "grant_type", -1,
                                        "urn:ietf:params:oauth:grant-type:jwt-bearer", -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to configure OAuth2 grant type");
            return -1;
        }

        /* Load service account credentials */
        ret = flb_oauth2_payload_append(ctx->oauth2,
                                        "scope", -1,
                                        FLB_GCS_SCOPE, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to configure OAuth2 scope");
            return -1;
        }
    }
    else {
        /* ADC or Workload Identity - simplified flow */
        ret = flb_oauth2_payload_append(ctx->oauth2,
                                        "scope", -1,
                                        FLB_GCS_SCOPE, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to configure OAuth2 scope");
            return -1;
        }
    }

    return 0;
}

/* HTTP client helper functions */
static struct flb_http_client *gcs_http_client(struct flb_gcs *ctx,
                                               int method,
                                               const char *uri,
                                               const char *body,
                                               size_t body_len)
{
    struct flb_http_client *c;
    char *auth_header;
    flb_sds_t token;

    /* Get current access token */
    token = gcs_oauth2_get_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "Failed to get access token");
        return NULL;
    }

    /* Create HTTP client */
    c = flb_http_client(ctx->u, method, uri, body, body_len,
                        NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client");
        flb_sds_destroy(token);
        return NULL;
    }

    /* Add authorization header */
    auth_header = flb_malloc(flb_sds_len(token) + 16);
    if (!auth_header) {
        flb_plg_error(ctx->ins, "Failed to allocate auth header");
        flb_http_client_destroy(c);
        flb_sds_destroy(token);
        return NULL;
    }

    snprintf(auth_header, flb_sds_len(token) + 16, "Bearer %s", token);
    flb_http_add_header(c, "Authorization", strlen("Authorization"),
                        auth_header, strlen(auth_header));

    flb_free(auth_header);
    flb_sds_destroy(token);

    return c;
}

/* Token management */
static flb_sds_t gcs_oauth2_get_token(struct flb_gcs *ctx)
{
    int ret;
    time_t now;

    /* Check if we have a valid cached token */
    now = time(NULL);
    if (ctx->access_token && ctx->token_expires > now + 60) {
        return flb_sds_create(ctx->access_token);
    }

    /* Refresh token */
    ret = gcs_oauth2_token_refresh(ctx);
    if (ret == -1) {
        return NULL;
    }

    if (!ctx->access_token) {
        return NULL;
    }

    return flb_sds_create(ctx->access_token);
}

static int gcs_oauth2_token_refresh(struct flb_gcs *ctx)
{
    int ret;
    char *token;
    time_t expires;

    if (!ctx->oauth2) {
        flb_plg_error(ctx->ins, "OAuth2 context not initialized");
        return -1;
    }

    /* Request new token */
    ret = flb_oauth2_token_get(ctx->oauth2, ctx->u_oauth);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to obtain OAuth2 token");
        return -1;
    }

    /* Extract token and expiration */
    token = flb_oauth2_token_get_property(ctx->oauth2, "access_token");
    if (!token) {
        flb_plg_error(ctx->ins, "No access token in OAuth2 response");
        return -1;
    }

    expires = flb_oauth2_token_get_expires(ctx->oauth2);

    /* Update cached token */
    if (ctx->access_token) {
        flb_sds_destroy(ctx->access_token);
    }
    ctx->access_token = flb_sds_create(token);
    ctx->token_expires = expires;

    flb_plg_debug(ctx->ins, "OAuth2 token refreshed, expires in %ld seconds",
                  expires - time(NULL));

    return 0;
}

/* Object key formatting */
static flb_sds_t gcs_format_object_key(struct flb_gcs *ctx, const char *tag,
                                       time_t timestamp)
{
    flb_sds_t key;
    struct tm *tm_info;
    char time_str[256];
    char *p, *q;
    int ret;

    if (!ctx->object_key_format) {
        return NULL;
    }

    /* Start with the format string */
    key = flb_sds_create(ctx->object_key_format);
    if (!key) {
        return NULL;
    }

    /* Replace time placeholders using strftime */
    tm_info = gmtime(&timestamp);
    if (tm_info) {
        /* Find time format specifiers and replace them */
        p = key;
        while ((p = strchr(p, '%')) != NULL) {
            /* Find the end of the format specifier */
            q = p + 1;
            if (*q && strchr("YmdHMSjwWUaAbBc", *q)) {
                char fmt[4] = {'%', *q, '\0', '\0'};
                
                ret = strftime(time_str, sizeof(time_str) - 1, fmt, tm_info);
                if (ret > 0) {
                    /* Replace the format specifier */
                    flb_sds_t new_key = flb_sds_create_len("", 0);
                    
                    /* Copy everything before the % */
                    new_key = flb_sds_cat(new_key, key, p - key);
                    
                    /* Add the formatted time */
                    new_key = flb_sds_cat(new_key, time_str, ret);
                    
                    /* Add everything after the format specifier */
                    new_key = flb_sds_cat(new_key, q + 1, flb_sds_len(key) - (q + 1 - key));
                    
                    flb_sds_destroy(key);
                    key = new_key;
                    p = key + (p - key) + ret - 2; /* Adjust pointer */
                }
                else {
                    p = q + 1; /* Skip this format specifier */
                }
            }
            else {
                p = q; /* Not a recognized format specifier */
            }
        }
    }

    /* Replace ${tag} placeholder */
    if (tag) {
        p = strstr(key, "${tag}");
        if (p) {
            flb_sds_t new_key = flb_sds_create_len("", 0);
            
            /* Copy everything before ${tag} */
            new_key = flb_sds_cat(new_key, key, p - key);
            
            /* Add the tag */
            new_key = flb_sds_cat(new_key, tag, strlen(tag));
            
            /* Add everything after ${tag} */
            new_key = flb_sds_cat(new_key, p + 6, flb_sds_len(key) - (p + 6 - key));
            
            flb_sds_destroy(key);
            key = new_key;
        }
    }

    /* Add file extension based on format and compression */
    const char *ext = gcs_get_file_extension(ctx);
    if (ext) {
        key = flb_sds_cat(key, ext, strlen(ext));
    }

    return key;
}

/* Get appropriate file extension */
static const char *gcs_get_file_extension(struct flb_gcs *ctx)
{
    static char ext_buf[16];
    const char *format_ext;

    /* Get format extension */
    switch (ctx->format) {
    case FLB_GCS_FORMAT_TEXT:
        format_ext = FLB_GCS_EXT_TEXT;
        break;
    case FLB_GCS_FORMAT_JSON:
        format_ext = FLB_GCS_EXT_JSON;
        break;
    case FLB_GCS_FORMAT_PARQUET:
        format_ext = FLB_GCS_EXT_PARQUET;
        break;
    default:
        format_ext = "";
    }

    /* Combine with compression extension */
    if (ctx->compression == FLB_GCS_COMPRESSION_GZIP) {
        snprintf(ext_buf, sizeof(ext_buf), "%s%s", format_ext, FLB_GCS_EXT_GZIP);
    }
    else {
        strncpy(ext_buf, format_ext, sizeof(ext_buf) - 1);
        ext_buf[sizeof(ext_buf) - 1] = '\0';
    }

    return ext_buf;
}

/* Get appropriate content type */
static const char *gcs_get_content_type(struct flb_gcs *ctx)
{
    if (ctx->compression == FLB_GCS_COMPRESSION_GZIP) {
        return "application/gzip";
    }

    switch (ctx->format) {
    case FLB_GCS_FORMAT_TEXT:
        return "text/plain";
    case FLB_GCS_FORMAT_JSON:
        return "application/json";
    case FLB_GCS_FORMAT_PARQUET:
        return "application/octet-stream";
    default:
        return "application/octet-stream";
    }
}

/* Plugin initialization */
static int cb_gcs_init(struct flb_output_instance *ins,
                       struct flb_config *config, void *data)
{
    struct flb_gcs *ctx;
    int ret;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_gcs));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;
    ctx->config = config;

    /* Initialize lists */
    mk_list_init(&ctx->uploads);
    mk_list_init(&ctx->files);

    /* Configure plugin */
    ret = gcs_config_init(ctx, ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Initialize OAuth2 */
    ret = gcs_oauth2_init(ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Create upstream connections */
    ctx->u = flb_upstream_create_url(config, FLB_GCS_ENDPOINT_BASE,
                                     FLB_IO_TLS, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "Failed to create GCS upstream connection");
        flb_oauth2_destroy(ctx->oauth2);
        flb_free(ctx);
        return -1;
    }

    ctx->u_oauth = flb_upstream_create(config, FLB_GCS_TOKEN_HOST, 443,
                                       FLB_IO_TLS, ins->tls);
    if (!ctx->u_oauth) {
        flb_plg_error(ctx->ins, "Failed to create OAuth upstream connection");
        flb_upstream_destroy(ctx->u);
        flb_oauth2_destroy(ctx->oauth2);
        flb_free(ctx);
        return -1;
    }

    /* Initialize file store for buffering */
    if (ctx->store_dir) {
        ctx->fs = flb_fstore_create(ctx->store_dir, FLB_FSTORE_FS);
        if (!ctx->fs) {
            flb_plg_error(ctx->ins, "Failed to initialize file store");
            flb_upstream_destroy(ctx->u_oauth);
            flb_upstream_destroy(ctx->u);
            flb_oauth2_destroy(ctx->oauth2);
            flb_free(ctx);
            return -1;
        }

        /* Create streams for different purposes */
        ctx->stream_active = flb_fstore_stream_create(ctx->fs, "active");
        ctx->stream_upload = flb_fstore_stream_create(ctx->fs, "upload");
    }

    /* Set plugin context */
    flb_output_set_context(ins, ctx);

    flb_plg_info(ctx->ins, "GCS plugin initialized");
    return 0;
}

/* Forward declarations for external functions */
int gcs_format_chunk(struct flb_gcs *ctx, const char *tag,
                     const void *data, size_t bytes,
                     flb_sds_t *formatted_data);

/* Plugin flush callback - main processing logic */
static void cb_gcs_flush(struct flb_event_chunk *event_chunk,
                         struct flb_output_flush *out_flush,
                         struct flb_input_instance *i_ins,
                         void *out_context,
                         struct flb_config *config)
{
    struct flb_gcs *ctx = out_context;
    struct gcs_file *file = NULL;
    flb_sds_t formatted_data = NULL;
    const char *tag;
    time_t timestamp;
    int ret;

    /* Get tag from input instance */
    tag = flb_input_name(i_ins);
    timestamp = time(NULL);

    /* Check if we need to refresh access token */
    if (!ctx->access_token || ctx->token_expires <= timestamp + 60) {
        ret = gcs_oauth2_token_refresh(ctx);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to refresh access token");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    /* Format the chunk data according to configured format */
    ret = gcs_format_chunk(ctx, tag, event_chunk->data, event_chunk->size,
                          &formatted_data);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to format chunk data");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Check if we have an active file for this tag or need to create one */
    struct mk_list *head;
    struct gcs_file *tmp_file;
    
    mk_list_foreach(head, &ctx->files) {
        tmp_file = mk_list_entry(head, struct gcs_file, _head);
        if (!tmp_file->locked && 
            flb_sds_cmp(tmp_file->tag, tag, strlen(tag)) == 0) {
            file = tmp_file;
            break;
        }
    }

    /* Create new file if needed */
    if (!file) {
        file = gcs_file_create(ctx, tag, timestamp);
        if (!file) {
            flb_plg_error(ctx->ins, "Failed to create new file");
            flb_sds_destroy(formatted_data);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Write formatted data to file */
    ret = gcs_file_write(ctx, file, formatted_data, flb_sds_len(formatted_data));
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to write data to file");
        flb_sds_destroy(formatted_data);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    flb_sds_destroy(formatted_data);

    /* Check if file should be uploaded based on size or timeout */
    if (file->size >= ctx->total_file_size ||
        (timestamp - file->create_time) >= ctx->upload_timeout) {
        
        /* Close and upload file */
        ret = gcs_file_close(ctx, file);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to close file");
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        ret = gcs_upload_file(ctx, file);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to upload file");
            file->failures++;
            
            if (file->failures >= FLB_GCS_MAX_UPLOAD_ERRORS) {
                flb_plg_error(ctx->ins, "File reached maximum upload failures, discarding");
                gcs_file_destroy(file);
            }
            
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        
        /* Upload successful, cleanup file */
        ctx->current_buffer_size -= file->size;
        gcs_file_destroy(file);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

/* Plugin exit callback */
static int cb_gcs_exit(void *data, struct flb_config *config)
{
    struct flb_gcs *ctx = data;

    if (!ctx) {
        return 0;
    }

    /* TODO: Complete any pending uploads */
    
    /* Cleanup file store */
    if (ctx->stream_upload) {
        flb_fstore_stream_destroy(ctx->stream_upload);
    }
    if (ctx->stream_active) {
        flb_fstore_stream_destroy(ctx->stream_active);
    }
    if (ctx->fs) {
        flb_fstore_destroy(ctx->fs);
    }

    /* Cleanup network connections */
    if (ctx->u_oauth) {
        flb_upstream_destroy(ctx->u_oauth);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    /* Cleanup OAuth2 */
    if (ctx->oauth2) {
        flb_oauth2_destroy(ctx->oauth2);
    }

    /* Cleanup tokens */
    if (ctx->access_token) {
        flb_sds_destroy(ctx->access_token);
    }

    /* Free context */
    flb_free(ctx);

    return 0;
}

/* Plugin registration */
struct flb_output_plugin out_gcs_plugin = {
    .name         = "gcs",
    .description  = "Send logs to Google Cloud Storage",
    .cb_init      = cb_gcs_init,
    .cb_flush     = cb_gcs_flush,
    .cb_exit      = cb_gcs_exit,
    .workers      = 1,
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
    .event_type   = FLB_OUTPUT_LOGS,
    .config_map   = config_map
};