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
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_kv.h>

#include <monkey/mk_core/mk_list.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_record_accessor.h>
#include <msgpack.h>

#include "encrypt.h"
#include "hashmap.h"
#include "ip_encryption.h"
#include "cmac.h"
#include "aes_deterministic.h"
#include "utils.h"
#include "hmac.h"
#include "aes_gcm.h"
#include "aes_gcm_hmac_deterministic.h"
#include "ip_utils.h"
#include "crypto_utils.h"
#include "openssl/bio.h"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_sds.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_config.h>
#include <stddef.h>

#include <msgpack.h>
#include "encrypt.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#endif

#if defined(__unix__) || defined(__APPLE__)
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define DO_DEBUG 0

/* Define the configuration directory based on the platform */
#ifdef _WIN32
#define FLUENT_BIT_CONFIG_DIR "C:/Program Files/fluent-bit"
#elif defined(__APPLE__)
#define FLUENT_BIT_CONFIG_DIR "/opt/fluent-bit/etc/fluent-bit"
#else
#define FLUENT_BIT_CONFIG_DIR "/etc/fluent-bit"
#endif

/* Construct the file path for the PII fields cache */
static const char *get_cache_file_path()
{
    static char cache_path[256] = {0};
    snprintf(cache_path, sizeof(cache_path), "%s/pii_cache.json", FLUENT_BIT_CONFIG_DIR);
    return cache_path;
}

/* Construct the file path for the encryption keys cache */
static const char *get_enc_keys_cache_file_path()
{
    static char cache_path[256] = {0};
    snprintf(cache_path, sizeof(cache_path), "%s/enc_keys_cache.json", FLUENT_BIT_CONFIG_DIR);
    return cache_path;
}

/* Reads the cached PII fields from a file */
static flb_sds_t read_cached_pii_fields(const char *cache_file)
{
    FILE *fp = fopen(cache_file, "r");
    if (!fp) {
        flb_error("[filter_encrypt] Failed to open cache file: %s", cache_file);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (filesize <= 0) {
        flb_error("[filter_encrypt] Cache file %s is empty or inaccessible", cache_file);
        fclose(fp);
        return NULL;
    }

    char *buffer = flb_malloc(filesize + 1);
    if (!buffer) {
        fclose(fp);
        flb_error("[filter_encrypt] Failed to allocate memory for reading cache file");
        return NULL;
    }
    size_t read_size = fread(buffer, 1, filesize, fp);
    buffer[read_size] = '\0';
    fclose(fp);

    flb_info("[filter_encrypt] Loaded cached PII fields from file: %s", cache_file);
    return flb_sds_create_len(buffer, read_size);
}

/* Writes the retrieved PII fields to a local cache file with restricted permissions (if desired) */
static int write_cached_pii_fields(const char *cache_file, flb_sds_t response_json)
{
    FILE *fp;
#ifdef __unix__
    mode_t old_umask = umask(0077);
    fp = fopen(cache_file, "w");
    umask(old_umask);
#else
    fp = fopen(cache_file, "w");
#endif
    if (!fp) {
        flb_error("[filter_encrypt] Failed to open cache file for writing: %s", cache_file);
        return -1;
    }
    size_t len = flb_sds_len(response_json);
    size_t written = fwrite(response_json, 1, len, fp);
    fclose(fp);
    if (written != len) {
        flb_error("[filter_encrypt] Failed to write complete data to cache file: %s", cache_file);
        return -1;
    }
    flb_info("[filter_encrypt] Successfully updated cache file: %s with retrieved PII fields", cache_file);
    return 0;
}

/* Reduced timeout HTTP request.
 * Note: In your current Fluent Bit version the HTTP client does not expose a timeout field.
 * If a newer fluent-bit version adds timeout support, you can set it here.
 */
static flb_sds_t make_http_request(struct flb_config *config,
                                   const char* HOST,
                                   const int PORT,
                                   const char* URI_PATH,
                                   const char** headers,
                                   size_t num_headers)
{
    struct flb_upstream *upstream = NULL;
    struct flb_http_client *client = NULL;
    struct flb_tls *tls = NULL;
    int flb_upstream_flag = FLB_IO_TLS; /* using HTTPS (TLS) */
    size_t b_sent;
    int ret;
    struct flb_connection *u_conn = NULL;
    flb_sds_t resp = NULL;

    if (PORT == 443) {
        /* Create TLS context */
        tls = flb_tls_create(FLB_TLS_CLIENT_MODE, /* mode */
                             FLB_FALSE,  /* verify */
                             -1,         /* debug */
                             NULL,       /* vhost */
                             NULL,       /* ca_path */
                             NULL,       /* ca_file */
                             NULL,       /* crt_file */
                             NULL,       /* key_file */
                             NULL);      /* key_passwd */
        if (!tls) {
            flb_error("[filter_encrypt] error initializing TLS context");
            goto cleanup;
        }
    } else {
        /* using HTTP (no HTTPS/TLS) */
        flb_upstream_flag = FLB_IO_TCP;
    }

    /* Create an 'upstream' context */
    upstream = flb_upstream_create(config, HOST, PORT, flb_upstream_flag, tls);
    if (!upstream) {
        flb_error("[filter_encrypt] connection initialization error");
        goto cleanup;
    }
    upstream->base.net.keepalive = FLB_FALSE;

    flb_stream_disable_async_mode(&upstream->base);

    /* Retrieve a TCP connection from the 'upstream' context */
    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_error("[filter_encrypt] connection initialization error");
        goto cleanup;
    }

    /* Create HTTP Client request/context */
    client = flb_http_client(u_conn,
                             FLB_HTTP_GET, URI_PATH,
                             NULL, 0,
                             HOST, PORT,
                             NULL, 0);
    if (!client) {
        flb_error("[filter_encrypt] could not create http client");
        goto cleanup;
    }

    /* If your Fluent Bit version supported setting a timeout, it would be set here.
     * e.g. client->timeout = 2;
     */

    /* Add headers */
    for (size_t i = 0; i < num_headers; i += 2) {
        flb_http_add_header(client, headers[i], strlen(headers[i]),
                            headers[i + 1], strlen(headers[i + 1]));
    }

    /* Perform the HTTP request */
    ret = flb_http_do(client, &b_sent);

    /* Validate return status and HTTP status if set */
    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_trace("[filter_encrypt] Request failed and returned: \n%s",
                      client->resp.payload);
        }
        goto cleanup;
    }

    resp = flb_sds_create_len(client->resp.payload, client->resp.payload_size);
    flb_debug("\nresp: %s\n", resp);

cleanup:
    if (client) {
        flb_http_client_destroy(client);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    if (upstream) {
        flb_upstream_destroy(upstream);
    }

    return resp;
}

/* Updated API retrieval for PII fields to use the cache if the endpoint is unavailable */
flb_sds_t api_retrieve_pii_fields(struct flb_config* config, bool is_startup)
{
    struct HashMapEntry* organization_key_kv = get(FLB_FILTER_ENCRYPT_ORGANIZATION_KEY);
    const char *organization_key = organization_key_kv->data;
    struct HashMapEntry* api_access_kv = get(FLB_FILTER_ENCRYPT_API_ACCESS_KEY);
    const char *api_access_key = api_access_kv->data;
    struct HashMapEntry* api_secret_key_kv = get(FLB_FILTER_ENCRYPT_API_SECRET_KEY);
    const char *api_secret_key = api_secret_key_kv->data;

    struct HashMapEntry* item_backend_host = get(FLB_FILTER_ENCRYPT_HOST);
    const char *backend_server_host_value = item_backend_host->data;
    struct HashMapEntry* item_backend_path = get(FLB_FILTER_ENCRYPT_URI_PII_FIELDS);
    const char *backend_server_path_value = item_backend_path->data;
    struct HashMapEntry* item_backend_port = get(FLB_FILTER_ENCRYPT_PORT);
    const char *backend_server_port_value = item_backend_port->data;

    flb_debug("port = %s", backend_server_port_value);
    const uintmax_t backend_server_port_numeric = strtoumax(backend_server_port_value, NULL, 10);

    const char* headers[] = {
        "User-Agent", "Fluent-Bit",
        FLB_FILTER_ENCRYPT_HEADER_X_ORGANIZATION_KEY, organization_key,
        FLB_FILTER_ENCRYPT_HEADER_X_ACCESS_KEY, api_access_key,
        FLB_FILTER_ENCRYPT_HEADER_X_SECRET_KEY, api_secret_key
    };

    flb_sds_t resp = make_http_request(config,
                                       backend_server_host_value,
                                       backend_server_port_numeric,
                                       backend_server_path_value,
                                       headers,
                                       sizeof(headers) / sizeof(headers[0]));

    const char *cache_file = get_cache_file_path();

    /* Check for a NULL response (i.e. the endpoint is unavailable) */
    if (!resp) {
        flb_error("[filter_encrypt] Unable to connect to the backend server: http(s)://%s:%d",
                  backend_server_host_value, backend_server_port_numeric);
        flb_info("[filter_encrypt] Falling back to cached PII fields from: %s", cache_file);
        /* Attempt to load from cache instead of failing */
        resp = read_cached_pii_fields(cache_file);
        if (resp == NULL) {
            flb_error("[filter_encrypt] No cached PII fields available, and API endpoint http(s)://%s:%d is unreachable",
                      backend_server_host_value, backend_server_port_numeric);
            if (is_startup) {
                exit(EXIT_FAILURE);
            }
        }
    }
    else {
        /* If API request was successful, update the cache file */
        if (write_cached_pii_fields(cache_file, resp) < 0) {
            flb_error("[filter_encrypt] Failed to update cache file: %s", cache_file);
        }
    }
    return resp;
}

/**
 * Helper function to get a cross-platform temporary file path for the encryption keys cache
 */
static flb_sds_t read_cached_enc_keys(const char *cache_file)
{
    FILE *fp = fopen(cache_file, "r");
    if (!fp) {
        flb_error("[filter_encrypt] Failed to open encryption keys cache file: %s", cache_file);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (filesize <= 0) {
        flb_error("[filter_encrypt] Encryption keys cache file %s is empty or inaccessible", cache_file);
        fclose(fp);
        return NULL;
    }

    char *buffer = flb_malloc(filesize + 1);
    if (!buffer) {
        fclose(fp);
        flb_error("[filter_encrypt] Failed to allocate memory for reading encryption keys cache file");
        return NULL;
    }
    size_t read_size = fread(buffer, 1, filesize, fp);
    buffer[read_size] = '\0';
    fclose(fp);

    flb_info("[filter_encrypt] Loaded cached encryption keys from file: %s", cache_file);
    return flb_sds_create_len(buffer, read_size);
}

/**
 * Writes the retrieved encryption keys to a local encryption keys cache file
 * with restricted file permissions (e.g. 0600 on Unix).
 */
static int write_cached_enc_keys(const char *cache_file, flb_sds_t response_json)
{
    FILE *fp;
#ifdef __unix__
    /* Save current umask and set to 0077, so new file gets mode 0600 (rw-------) */
    mode_t old_umask = umask(0077);
    fp = fopen(cache_file, "w");
    umask(old_umask);
#else
    fp = fopen(cache_file, "w");
#endif
    if (!fp) {
        flb_error("[filter_encrypt] Failed to open encryption keys cache file for writing: %s", cache_file);
        return -1;
    }
    size_t len = flb_sds_len(response_json);
    size_t written = fwrite(response_json, 1, len, fp);
    fclose(fp);
    if (written != len) {
        flb_error("[filter_encrypt] Failed to write complete data to encryption keys cache file: %s", cache_file);
        return -1;
    }
    flb_info("[filter_encrypt] Successfully updated encryption keys cache file: %s", cache_file);
    return 0;
}

/**
 * Updated API retrieval for encryption keys to use the cache if the endpoint is unavailable.
 */
flb_sds_t api_retrieve_encryption_keys(struct flb_config* config, bool is_startup)
{
    struct HashMapEntry* organization_key_kv = get(FLB_FILTER_ENCRYPT_ORGANIZATION_KEY);
    const char *organization_key = organization_key_kv->data;
    struct HashMapEntry* api_access_kv = get(FLB_FILTER_ENCRYPT_API_ACCESS_KEY);
    const char *api_access_key = api_access_kv->data;
    struct HashMapEntry* api_secret_key_kv = get(FLB_FILTER_ENCRYPT_API_SECRET_KEY);
    const char *api_secret_key = api_secret_key_kv->data;

    struct HashMapEntry* item_backend_host = get(FLB_FILTER_ENCRYPT_HOST);
    const char *backend_server_host_value = item_backend_host->data;
    struct HashMapEntry* item_backend_path = get(FLB_FILTER_ENCRYPT_URI_ENC_KEYS);
    const char *backend_server_path_value = item_backend_path->data;
    struct HashMapEntry* item_backend_port = get(FLB_FILTER_ENCRYPT_PORT);
    const char *backend_server_port_value = item_backend_port->data;

    flb_debug("port = %s", backend_server_port_value);
    const uintmax_t backend_server_port_numeric = strtoumax(backend_server_port_value, NULL, 10);

    const char* headers[] = {
        "User-Agent", "Fluent-Bit",
        FLB_FILTER_ENCRYPT_HEADER_X_ORGANIZATION_KEY, organization_key,
        FLB_FILTER_ENCRYPT_HEADER_X_ACCESS_KEY, api_access_key,
        FLB_FILTER_ENCRYPT_HEADER_X_SECRET_KEY, api_secret_key
    };

    flb_sds_t resp = make_http_request(config,
                                       backend_server_host_value,
                                       backend_server_port_numeric,
                                       backend_server_path_value,
                                       headers,
                                       sizeof(headers) / sizeof(headers[0]));

    const char *cache_file = get_enc_keys_cache_file_path();

    /* Check for a NULL response (i.e. the endpoint is unavailable) */
    if (!resp) {
        flb_error("[filter_encrypt] Unable to connect to the key server: http(s)://%s:%d",
                  backend_server_host_value, backend_server_port_numeric);
        flb_info("[filter_encrypt] Falling back to cached encryption keys from: %s", cache_file);
        /* Attempt to load from cache instead of failing */
        resp = read_cached_enc_keys(cache_file);
        if (resp == NULL) {
            flb_error("[filter_encrypt] No cached encryption keys available, and API endpoint http(s)://%s:%d is unreachable",
                      backend_server_host_value, backend_server_port_numeric);
            if (is_startup) {
                exit(EXIT_FAILURE);
            }
        }
    }
    else {
        /* If API request was successful, update the cache file */
        if (write_cached_enc_keys(cache_file, resp) < 0) {
            flb_error("[filter_encrypt] Failed to update encryption keys cache file: %s", cache_file);
        }
    }
    return resp;
}

/**
 * Populates http json response in a linked-list structure.
 * @param resp http response (json)
 */
void populate_pii_fields(flb_sds_t response_json) {
    struct mk_list* head;
    struct mk_list* tmp;
    struct pii_kv *an_item;
    int i, status = 0;

    //flb_debug("parsing %s\n", json_inputs);
    status = json_read_object(response_json, pii_fields_json_attrs_items, NULL);
    if (status != 0)
        puts(json_error_string(status));

    flb_debug("Loaded [%d] pii fields\n", pii_obj_count);

    mk_list_init(&items_pii);

    for (i = 0; i < pii_obj_count; i++) {
        flb_debug("id = %d, field_name = %s, masking_technique = %s\n",
                  pii_fields_records_array[i].id,
                  pii_fields_records_array[i].fieldName,
                  pii_fields_records_array[i].maskingTechnique);

        // populating items - need to free this memory
        an_item = flb_malloc(sizeof(struct pii_kv));
        if (!an_item) {
            flb_errno();
        }

        an_item->id = pii_fields_records_array[i].id;

        an_item->key_len = strlen(pii_fields_records_array[i].fieldName);
        snprintf(an_item->key, an_item->key_len + 1, "%s", pii_fields_records_array[i].fieldName);

        an_item->val_len = strlen(pii_fields_records_array[i].maskingTechnique);
        snprintf(an_item->val, an_item->val_len + 1, "%s", pii_fields_records_array[i].maskingTechnique);

        mk_list_add(&an_item->_head, &items_pii);
    }


    /* iterate through the list */
    flb_debug("Iterating through list");
    mk_list_foreach_safe(head, tmp, &items_pii) {
        an_item = mk_list_entry(head, struct pii_kv, _head);
        flb_debug("key=%s,value=%s", an_item->key, an_item->val);
    }
}

/**
 * Populate configuration settings in hashmap for HTTP API requests.
 * @param ctx
 * @param properties
 */
int populate_configurations_in_hashmap(struct flb_filter_encrypt* ctx, struct mk_list* properties) {
    struct mk_list* head;
    struct mk_list* split;
    struct flb_kv* kv;
    int list_size;

    mk_list_foreach(head, properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        split = flb_utils_split(kv->val, ' ', 3);
        list_size = mk_list_size(split);

        if (list_size == 0 || list_size > 3) {
            flb_plg_error(ctx->f_ins, "Invalid config for %s", kv->key);
            flb_utils_split_free(split);
            return -1;
        }
        flb_info("key=%s, value=%s\n", kv->key, kv->val);

        insert(kv->key, kv->val);
        struct HashMapEntry* item = get(kv->key);
        if (item == NULL) {
            flb_debug("Error: key %s not found!?", kv->key);
            flb_utils_split_free(split);
            return -1;
        }

        flb_utils_split_free(split);
    }
    return 0;
}


/**
 * Populates http json response in a linked-list structure.
 * @param resp http response (json)
 */
int populate_encryption_keys(flb_sds_t response_json) {
    struct mk_list* tmp;
    struct dek_kv *an_item;
    int i, status = 0;

    flb_debug("parsing %s\n", response_json);
    status = json_read_object(response_json, dek_fields_json_attrs_items, NULL);
    if (status != 0) {
        flb_error("json_read_object error: %s", json_error_string(status));
        return -1;
    }

    flb_debug("Loaded [%d] encryption key(s)\n", dek_obj_count);

    mk_list_init(&items_dek);

    for (i = 0; i < dek_obj_count; i++) {
        flb_debug("id = %d, created_on = %s, encryption_key = %s, encryption_key_time_start = %s\n",
                  dek_records_array[i].id,
                  dek_records_array[i].created_on,
                  dek_records_array[i].encryption_key,
                  dek_records_array[i].encryption_key_time_start);

        an_item = flb_malloc(sizeof(struct dek_kv));
        if (!an_item) {
            flb_errno();
            return -1;
        }

        an_item->id = dek_records_array[i].id;

        an_item->encryption_key_len = strlen(dek_records_array[i].encryption_key);
        snprintf(an_item->encryption_key, an_item->encryption_key_len + 1, "%s", dek_records_array[i].encryption_key);

        an_item->encryption_key_time_start_len = strlen(dek_records_array[i].encryption_key_time_start);
        snprintf(an_item->encryption_key_time_start, an_item->encryption_key_time_start_len + 1, "%s", dek_records_array[i].encryption_key_time_start);

        an_item->created_on_len = strlen(dek_records_array[i].created_on);
        snprintf(an_item->created_on, an_item->created_on_len + 1, "%s", dek_records_array[i].created_on);

        mk_list_add(&an_item->_head, &items_dek);
    }

    flb_debug("Iterating through list");
    mk_list_foreach_safe(head_dek, tmp, &items_dek) {
        an_item = mk_list_entry(head_dek, struct dek_kv, _head);
        flb_info("encryption_key=%s,encryption_key_time_start=%s", an_item->encryption_key, an_item->encryption_key_time_start);
    }
    return 0;
}

/**
 * Sets the encryption keys
 * @aes_det_key_ptr aes_det_key encryption key
 * @ip_encryption_key_ptr ip encryption key
 */
void set_encryption_keys(char *aes_det_key_ptr, char *ip_encryption_key_ptr) {
    struct mk_list* tmp;
    struct dek_kv *an_item;

    struct HashMapEntry* item_key_master_key = get(FLB_FILTER_ENCRYPT_MASTER_ENC_KEY);
    if (!item_key_master_key) {
        flb_error("Master encryption key not found in hashmap.");
        exit(EXIT_FAILURE);
    }
    const char *key_master_key_value = item_key_master_key->data;
    flb_info("key_master_key_value=%s", key_master_key_value);

    /* Iterate through the encryption keys list */
    flb_debug("Iterating through encryption keys list");
    bool found_ddk = false;
    mk_list_foreach_safe(head_dek, tmp, &items_dek) {
        an_item = mk_list_entry(head_dek, struct dek_kv, _head);
        flb_info("encryption_key=%s,length=%zu,encryption_key_time_start=%s",
                 an_item->encryption_key,
                 strlen(an_item->encryption_key),
                 an_item->encryption_key_time_start);

        size_t size = strlen(an_item->encryption_key);
        flb_info("key length:%zu ", size);

        size_t decoded_size = 0;
        unsigned char* salt_iv_tag_ciphertext_hex = base64decode(an_item->encryption_key,
                                                                 strlen(an_item->encryption_key),
                                                                 &decoded_size);

        if (salt_iv_tag_ciphertext_hex == NULL || decoded_size == 0) {
            flb_error("Failed to decode base64 data");
            continue;
        }

        flb_info("decoded_size: %zu", decoded_size);
        flb_debug("Decoded Base64 data:");
        print_bytes(salt_iv_tag_ciphertext_hex, decoded_size);

        /* Define expected lengths */
        const int salt_len = 64;
        const int iv_len = 16;
        const int tag_len = 16;
        const int tag_position = salt_len + iv_len;
        const int encrypted_position = tag_position + tag_len;

        /* Ensure that the decoded data is long enough */
        if (decoded_size < encrypted_position) {
            flb_error("Decoded data is too short");
            free(salt_iv_tag_ciphertext_hex);
            continue;
        }

        /* Extract different parts of the decoded data */
        char *extracted_salt = substring((char*)salt_iv_tag_ciphertext_hex, 0, salt_len);
        char *extracted_iv = substring((char*)salt_iv_tag_ciphertext_hex, salt_len, iv_len);
        char *extracted_tag = substring((char*)salt_iv_tag_ciphertext_hex, tag_position, tag_len);
        char *extracted_ciphertext = substring((char*)salt_iv_tag_ciphertext_hex, encrypted_position, decoded_size - encrypted_position);

        /* Validate extracted parts */
        if (!extracted_salt || !extracted_iv || !extracted_tag || !extracted_ciphertext) {
            flb_error("Failed to extract parts from decoded data");
            free(salt_iv_tag_ciphertext_hex);
            free(extracted_salt);
            free(extracted_iv);
            free(extracted_tag);
            free(extracted_ciphertext);
            continue;
        }

        /* Debug: Print extracted components */
        flb_debug("Extracted Salt:");
        print_bytes((unsigned char*)extracted_salt, salt_len);
        flb_debug("Extracted IV:");
        print_bytes((unsigned char*)extracted_iv, iv_len);
        flb_debug("Extracted Tag:");
        print_bytes((unsigned char*)extracted_tag, tag_len);
        flb_debug("Extracted Ciphertext:");
        print_bytes((unsigned char*)extracted_ciphertext, decoded_size - encrypted_position);

        /* Generate key using PBKDF2 */
        char key_out[128] = {0x00};
        flb_debug("Generating key using PBKDF2");
        crypto_utils_generate_key_from_pbkdf2(key_master_key_value, extracted_salt, key_out, 100000, 32); // key_length = 32
        flb_debug("Generated key_out: %s", key_out);

        /* Decrypt using AES-GCM */
        unsigned char data_encryption_key[129] = {0x00}; // Increased size to 129 to accommodate null terminator
        unsigned char *additional = (unsigned char *)"";

        flb_debug("Attempting AES-GCM decryption");
        int decryptedtext_len = aes_gcm_256_decrypt(extracted_ciphertext, decoded_size - encrypted_position,
                                                    additional, strlen((char *)additional),
                                                    extracted_tag,
                                                    key_out, extracted_iv, iv_len,
                                                    data_encryption_key);

        if (decryptedtext_len >= 0) {
            /* Ensure decryptedtext_len does not exceed buffer size */
            if ((size_t)decryptedtext_len >= sizeof(data_encryption_key)) {
                flb_error("Decrypted text length exceeds buffer size");
                free(salt_iv_tag_ciphertext_hex);
                free(extracted_salt);
                free(extracted_iv);
                free(extracted_tag);
                free(extracted_ciphertext);
                continue;
            }

            data_encryption_key[decryptedtext_len] = '\0'; // Safe now as buffer is 129 bytes
            flb_debug("Decryption successful. Decrypted text length: %d", decryptedtext_len);
            flb_debug("Decrypted Encryption Key: %s", data_encryption_key);

            /* Copy decrypted key to destination buffers */
            strncpy(aes_det_key_ptr, (char *)data_encryption_key, decryptedtext_len + 1);
            strncpy(ip_encryption_key_ptr, (char *)data_encryption_key, decryptedtext_len + 1);

            flb_debug("AES Deterministic Key: %s", aes_det_key_ptr);
            flb_debug("IP Encryption Key: %s", ip_encryption_key_ptr);

            set_encryption_key(ip_encryption_key_ptr);
            found_ddk = true;
        } else {
            flb_debug("Decryption failed");
        }

        /* Free allocated memory */
        free(salt_iv_tag_ciphertext_hex);
        free(extracted_salt);
        free(extracted_iv);
        free(extracted_tag);
        free(extracted_ciphertext);

        if (found_ddk) {
            break;
        }
    }
    if (!found_ddk) {
        flb_debug("No default data decryption key found.\n");
        exit(EXIT_FAILURE);
    }
}


static int setup(struct flb_filter_encrypt* ctx, struct flb_filter_instance* f_ins, struct flb_config* config)
{
    struct mk_list* head;
    struct mk_list* split;
    struct flb_kv* kv;
    struct modify_rule* rule = NULL;
    struct flb_split_entry* sentry;
    int list_size;
    flb_sds_t response_json;
    int status;

    flb_debug("loading configurations from backend server.\n");

    populate_key_value_delimiters(value_delimiters);

    if (populate_configurations_in_hashmap(ctx, &f_ins->properties) < 0) {
        flb_error("[filter_encrypt] Failed to populate configurations in hashmap");
        return -1;
    }

    response_json = api_retrieve_pii_fields(config, true);
    if (!response_json) {
        flb_error("[filter_encrypt] Failed to retrieve PII fields");
        return -1;
    }

    status = json_read_object(response_json, pii_fields_json_attrs_items, NULL);
    if (status != 0) {
        flb_error("[filter_encrypt] Failed to read PII fields: %s", json_error_string(status));
        flb_sds_destroy(response_json);
        return -1;
    }

    populate_pii_fields(response_json);
    flb_sds_destroy(response_json);

    response_json = api_retrieve_encryption_keys(config, true);
    if (!response_json) {
        flb_error("[filter_encrypt] Failed to retrieve encryption keys");
        return -1;
    }

    if (populate_encryption_keys(response_json) < 0) {
        flb_error("[filter_encrypt] Failed to populate encryption keys");
        flb_sds_destroy(response_json);
        return -1;
    }

    flb_sds_destroy(response_json);

    set_encryption_keys(aes_det_key, ip_encryption_key);
    return 0;
}


static int cb_encrypt_init(struct flb_filter_instance *f_ins,
                           struct flb_config *config, void *data)
{
    int ret;
    struct flb_filter_encrypt *ctx = NULL;
    (void) f_ins;
    (void) config;
    (void) data;

    // Create context
    ctx = flb_calloc(1, sizeof(struct flb_filter_encrypt));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->f_ins = f_ins;

    // Initialize hashmap
    initHashMap();

    /* Read in config values */
    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->upstream = flb_upstream_create(config,
                                        ctx->host,
                                        ctx->port,
                                        FLB_IO_TCP,
                                        NULL);

    if (setup(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    /* Export context */
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static inline bool helper_msgpack_object_matches_str(msgpack_object *obj, char* str, int len) {
    const char* key;
    int klen;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = obj->via.bin.ptr;
        klen = obj->via.bin.size;
    } else if (obj->type == MSGPACK_OBJECT_STR) {
        key = obj->via.str.ptr;
        klen = obj->via.str.size;
    } else {
        return false;
    }
    bool compare = ((len == klen) && (strncmp(str, key, klen) == 0));
    return compare;
}

static inline bool kv_key_matches_str(msgpack_object_kv *kv, char* str, int len)
{
    return helper_msgpack_object_matches_str(&kv->key, str, len);
}

static inline bool kv_val_matches_str(msgpack_object_kv *kv, char* str, int len)
{
    return helper_msgpack_object_matches_str(&kv->val, str, len);
}


static inline bool kv_key_matches_str_field_name_key(msgpack_object_kv* kv,struct pii_kv* entry)
{
    return kv_key_matches_str(kv, entry->key, entry->key_len);
}

static inline bool kv_key_does_not_match_str_field_name_key(msgpack_object_kv* kv, struct pii_kv* entry)
{
    return !kv_key_matches_str_field_name_key(kv, entry);
}

static inline int map_count_keys_matching_str(msgpack_object* map, char* str, int len)
{
    int i;
    int count = 0;

    //flb_trace("map_count_keys_matching_str\n");
    //flb_trace("str:%s (len:%d)\n", str, len);

    //flb_trace("map->via.map.size: %d\n", map->via.map.size);
    for (i = 0; i < map->via.map.size; i++) {

        //flb_trace("map->via.map.ptr[i]->key.via.str.ptr: %s\n", map->via.map.ptr[i].key.via.str.ptr);
        //flb_trace("map->via.map.ptr[i]->key.via.str.size: %d\n", map->via.map.ptr[i].key.via.str.size);
        if (kv_key_matches_str(&map->via.map.ptr[i], str, len)) {
            count++;
        }
    }
    return count;
}

static inline void map_pack_each(msgpack_packer* packer, msgpack_object* map) {
    int i;

    for (i = 0; i<map->via.map.size; i++) {
        msgpack_pack_object(packer, map->via.map.ptr[i].key);
        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }
}

static inline void map_pack_each_fn(msgpack_packer* packer, msgpack_object* map, struct modify_rule* rule, bool(* f)(
        msgpack_object_kv* kv, struct modify_rule* rule)) {
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], rule)) {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline void map_pack_each_fn_kv(msgpack_packer *packer,
                                       msgpack_object *map,
                                       struct pii_kv *field_kv,
                                       bool(* f)(msgpack_object_kv *kv,
                                                 struct pii_kv *field_kv)) {
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], field_kv)) {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}


static void helper_pack_string(struct flb_filter_encrypt *ctx, msgpack_packer *packer, const char* str, int len)
{

    if (str==NULL) {
        flb_plg_error(ctx->f_ins, "helper_pack_string : NULL passed");
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static inline int apply_rule_ENCRYPT(struct flb_filter_encrypt* ctx, msgpack_packer* packer, msgpack_object* map,
                                     struct pii_kv* an_item) {

    int is_modified = FLB_FILTER_NOTOUCH;

    flb_debug("apply_rule_ENCRYPT\n");

    flb_debug("list item data id: %d", an_item->id);
    flb_debug("list item data key: %s, key_len: %d", an_item->key, an_item->key_len);
    flb_debug("list item data value: %s, key_len: %d", an_item->val, an_item->val_len);

    char *pseudonymized_value = "<pseudonymization failed>";

    bool ip_encrypted = false;

    int i;
    int count = 0;

    int matches = map_count_keys_matching_str(map, an_item->key, an_item->key_len);

    flb_debug("matches %d:\n", matches);
    if(matches > 0) {

        for (i = 0; i<map->via.map.size; i++) {

            if (kv_key_matches_str(&map->via.map.ptr[i], an_item->key, an_item->key_len)) {

                char *tmp_field_value = flb_malloc(strlen(map->via.map.ptr[i].val.via.str.ptr) + 1);

                strcpy(tmp_field_value, map->via.map.ptr[i].val.via.str.ptr);

                char *ptr_value = strtok(tmp_field_value, value_delimiters);

                char *tmp_extracted_value = flb_malloc(1024);

                // get end index
                ptrdiff_t index = ptr_value - tmp_field_value;

                strncpy(tmp_extracted_value, tmp_field_value, index);
                tmp_extracted_value[0 + index] = '\0';

                if (flb_log_check(FLB_LOG_DEBUG))
                    BIO_dump_fp(stdout,
                                (const char *) tmp_extracted_value,
                                strlen((char *) tmp_extracted_value));

                flb_debug("tmp_extracted_value:%s\n", tmp_extracted_value);
                flb_debug("encrypting with: %s", an_item->val);
                if (strncmp(an_item->val, "hmac_sha256", an_item->val_len)==0) {
                    unsigned char *result = NULL;
                    unsigned char *hashed_value = NULL;
                    unsigned int resultlen = -1;

                    // hmac-sha256
                    hashed_value = mx_hmac_sha256((const void *) aes_det_key,
                                                  strlen(aes_det_key),
                                                  tmp_extracted_value,
                                                  strlen(tmp_extracted_value),
                                                  result,
                                                  &resultlen);
                    pseudonymized_value = base64encode(hashed_value, resultlen);
                    flb_debug("Encrypted with hmac-sha256: %s\n", pseudonymized_value);
                } else if (strncmp(an_item->val, "aes_gcm", an_item->val_len) == 0) {
                    // encrypt with aes-gcm mode
                    pseudonymized_value =
                            aes_128_gcm_encrypt(tmp_extracted_value, strlen(tmp_extracted_value), aes_det_key);
                    flb_debug("Encrypted with aes-gcm mode: %s\n", pseudonymized_value);
                } else if (strncmp(an_item->val, "aes_gcm_det", an_item->val_len) == 0) {
                    // encrypt with aes-gcm mode deterministic
                    pseudonymized_value = aes_128_gcm_encrypt_deterministic(tmp_extracted_value,
                                                                            strlen(tmp_extracted_value),
                                                                            aes_det_key);
                    flb_debug("Encrypted with aes-gcm mode deterministic: %s\n", pseudonymized_value);
                } else if (strncmp(an_item->val, "cryptopant_ipv4_ipv6", an_item->val_len) == 0) {
                    // encrypt with CrytopANT-HMAC
                    pseudonymized_value = encrypt_ip(tmp_extracted_value);
                    ip_encrypted = true;

                    // tag encrypted IPs with private network ranges.
                    if (ip_encrypted) {
                        flb_debug("IP address: %s\n", tmp_extracted_value);
                        int is_private = is_ip_address_private(tmp_extracted_value);
                        flb_debug("IP address in: %s => out: %s, internal IP:%d\n",
                                  tmp_extracted_value,
                                  pseudonymized_value,
                                  is_private);

                        char new_field_value[128]; // ensure this is large enough to hold the new field value
                        snprintf(new_field_value, sizeof(new_field_value), "#private=%s", (is_private==1 ? "true" : "false"));

                        if (strlen(pseudonymized_value) + strlen(new_field_value) < PSEUDONYMIZED_VALUE_MAX_SIZE) {
                            strncat(pseudonymized_value, new_field_value, sizeof(pseudonymized_value) - strlen(pseudonymized_value) - 1);
                        } else {
                            fprintf(stderr, "Buffer overflow prevented: pseudonymized_value is too large to append new_field_value\n");
                        }

                        if (DO_DEBUG > 0) printf("pseudonymized_value:%s\n", pseudonymized_value);
                    }

                } else {
                    // encryption mechanism not found... we should do something about this.
                    flb_trace("Encryption Mechanism Not found: THIS SHOULD NOT HAPPEN!");
                }

                flb_debug("field %s : %s => %s\n", an_item->key, tmp_extracted_value, pseudonymized_value);

                if (flb_log_check(FLB_LOG_DEBUG))
                    BIO_dump_fp(stdout,
                                (const char *) tmp_extracted_value,
                                strlen((char *) tmp_extracted_value));

                count++;

                flb_free(tmp_extracted_value);
                flb_free(tmp_field_value);

                msgpack_pack_map(packer, map->via.map.size - matches + 1);

                map_pack_each_fn_kv(packer, map, an_item, kv_key_does_not_match_str_field_name_key);
                helper_pack_string(ctx, packer, an_item->key, an_item->key_len);
                helper_pack_string(ctx, packer, pseudonymized_value, strlen(pseudonymized_value));

                is_modified = FLB_FILTER_MODIFIED;

            }

        }

        if (flb_log_check(FLB_LOG_DEBUG)) flb_debug("count: %d\n", count);

        if (flb_log_check(FLB_LOG_DEBUG))
            msgpack_object_print(stderr, *map);
    }

    return is_modified;
}

static inline int apply_modifying_rules(msgpack_packer* packer, msgpack_object* root, struct flb_filter_encrypt* ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    if (flb_log_check(FLB_LOG_DEBUG))
        msgpack_object_print(stderr, map);

    bool has_modifications = false;

    int records_in = map.via.map.size;

    msgpack_sbuffer sbuffer;
    msgpack_packer in_packer;
    msgpack_unpacker unpacker;
    msgpack_unpacked unpacked;

    int initial_buffer_size = 1024*8;
    int new_buffer_size = 0;


    struct pii_kv *an_item;
    struct mk_list* tmp_pii;
    struct mk_list* head_pii;

    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&in_packer, &sbuffer, msgpack_sbuffer_write);
    msgpack_unpacked_init(&unpacked);
    if (!msgpack_unpacker_init(&unpacker, initial_buffer_size)) {
        flb_plg_error(ctx->f_ins, "Unable to allocate memory for unpacker, aborting");
        return -1;
    }

    mk_list_foreach_safe(head_pii, tmp_pii, &items_pii)
    {

        an_item = mk_list_entry(head_pii, struct pii_kv, _head);

        msgpack_sbuffer_clear(&sbuffer);

        if (apply_rule_ENCRYPT(ctx, &in_packer, &map, an_item) != FLB_FILTER_NOTOUCH) {

            if (DO_DEBUG > 0) printf("apply_modifying_rule has_modified set as true.\n");
            has_modifications = true;
            new_buffer_size = sbuffer.size*2;

            if (msgpack_unpacker_buffer_capacity(&unpacker) < new_buffer_size) {
                if (!msgpack_unpacker_reserve_buffer(&unpacker, new_buffer_size)) {
                    flb_plg_error(ctx->f_ins, "Unable to re-allocate memory for "
                                              "unpacker, aborting");
                    return -1;
                }
            }

            memcpy(msgpack_unpacker_buffer(&unpacker), sbuffer.data, sbuffer.size);
            msgpack_unpacker_buffer_consumed(&unpacker, sbuffer.size);

            msgpack_unpacker_next(&unpacker, &unpacked);

            if (unpacked.data.type == MSGPACK_OBJECT_MAP) {
                map = unpacked.data;
            } else {
                flb_plg_error(ctx->f_ins, "Expected MSGPACK_MAP, this is not a "
                                          "valid return value, skipping");
            }
        }

    }

    if (has_modifications) {
        // * Record array init(2)
        msgpack_pack_array(packer, 2);

        // * * Record array item 1/2
        msgpack_pack_object(packer, ts);

        flb_plg_trace(ctx->f_ins, "Input map size %d elements, output map size "
                                  "%d elements", records_in, map.via.map.size);

        // * * Record array item 2/2
        msgpack_pack_object(packer, map);
    }

    msgpack_unpacked_destroy(&unpacked);
    msgpack_unpacker_destroy(&unpacker);
    msgpack_sbuffer_destroy(&sbuffer);

    return has_modifications ? 1 : 0;

}

static int cb_encrypt_filter(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             void **out_buf, size_t *out_size,
                             struct flb_filter_instance *f_ins,
                             struct flb_input_instance *i_ins,
                             void *context,
                             struct flb_config *config)
{

    flb_debug("cb_encrypt_filter");

    struct flb_filter_encrypt *ctx = context;

    // start clock to measure execution time for this function
    clock_t time_cb_encrypt_filter = clock();

    // start clock to check for any updates
    if(start == 0) {
        time(&start);  /* start the timer */

        flb_info("HTTP GET PII fields (every %d secs)\n", interval_seconds);
        flb_sds_t response_json = api_retrieve_pii_fields(config, false);
        flb_info("HTTP GET PII resp %s\n", response_json);
        if(response_json != -1) {
            populate_pii_fields(response_json);
        } else {
            flb_info("HTTP GET PII fields failed..\n");
        }
    }
    time(&end);
    elapsed = difftime(end, start);
    if (elapsed >= interval_seconds) {
        flb_info("HTTP GET PII fields (every %d secs)\n", interval_seconds);
        flb_sds_t response_json = api_retrieve_pii_fields(config, false);
        if(response_json != -1) {
            populate_pii_fields(response_json);
        } else {
            flb_info("HTTP GET PII fields failed..\n");
        }
        time(&start);
    }

    msgpack_unpacked result;
    size_t off = 0;
    (void)f_ins;
    (void)config;
    flb_debug("executing cb_encrypt_filter\n");


    int modifications = 0;
    int total_modifications = 0;

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // Records come in the format,
    //
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ],
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ]
    //
    // Example record,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)==MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type==MSGPACK_OBJECT_ARRAY) {
            modifications = apply_modifying_rules(&packer, &result.data, ctx);

            if (modifications==0) {
                // not matched, so copy original event.
                msgpack_pack_object(&packer, result.data);
            }
            total_modifications += modifications;
        } else {
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);

    if (total_modifications==0) {
        msgpack_sbuffer_destroy(&buffer);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = buffer.data;
    *out_size = buffer.size;

    // Calculate the time taken by cb_encrypt_filter()
    time_cb_encrypt_filter = clock() - time_cb_encrypt_filter;
    double time_taken = ((double)time_cb_encrypt_filter)/CLOCKS_PER_SEC; // in seconds
    flb_debug("apply_modifying_rules() took %f seconds to execute \n", time_taken);

    return FLB_FILTER_MODIFIED;
}


static void flb_filter_encrypt_destroy(struct flb_filter_encrypt *ctx)
{
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }

    if (ctx->host) {
        flb_sds_destroy(ctx->host);
    }

    flb_free(ctx);
}


static int cb_encrypt_exit(void *data, struct flb_config *config)
{
    struct flb_filter_encrypt *ctx = data;

    // Free the hashmap
    freeHashMap();

    if (ctx != NULL) {
        flb_filter_encrypt_destroy(ctx);
    }
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
        {
                FLB_CONFIG_MAP_STR, "host", NULL,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, host),
                "The host of the server where to get the PII fields."
        },
        {
                FLB_CONFIG_MAP_INT, "port", 0,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, port),
                "The port on the server where to get the PII fields."
        },
        {
                FLB_CONFIG_MAP_STR, "uri_pii_fields", NULL,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, uri_pii_fields),
                "The URI on the server where to get the PII fields."
        },
        {
                FLB_CONFIG_MAP_STR, "organization_key", NULL,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, organization_key),
                "The Organization Key part of the API Key."
        },
        {
                FLB_CONFIG_MAP_STR, "api_access_key", NULL,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, api_access_key),
                "The API Access Key."
        },
        {
                FLB_CONFIG_MAP_STR, "api_secret_key", NULL,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, api_secret_key),
                "The API Secret Key."
        },
        {
                FLB_CONFIG_MAP_STR, "tenant_id", NULL,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, tenant_id),
                "The URI on the server where to get the PII fields."
        },
        {
                FLB_CONFIG_MAP_INT, "agent_id", 0,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, agent_id),
                "The URI on the server where to get the PII fields."
        },
        {
                FLB_CONFIG_MAP_STR, "uri_enc_keys", 0,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, uri_enc_keys),
                "The URI on the server where to get the PII fields."
        },
        {
                FLB_CONFIG_MAP_STR, "master_enc_key", 0,
                0, FLB_TRUE, offsetof(struct flb_filter_encrypt, master_enc_key),
                "The URI on the server where to get the PII fields."
        },

        /* EOF */
        {0}
};

struct flb_filter_plugin filter_encrypt_plugin = {
        .name         = "encrypt",
        .description  = "Encrypts PII values by applying based on matching keys."
                        "It takes 2 inputs: the field name and the masking function.",
        .cb_init      = cb_encrypt_init,
        .cb_filter    = cb_encrypt_filter,
        .cb_exit      = cb_encrypt_exit,
        .config_map   = config_map,
        .flags        = 0
};
