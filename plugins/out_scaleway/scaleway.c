/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Fluent Bit
 * ==========
 * Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_thread_storage.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_gzip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_config.h>
#include <msgpack.h>

#include <ctype.h>
#include <sys/stat.h>

#include "scaleway.h"

struct flb_scaleway_dynamic_tenant_id_entry {
    flb_sds_t value;
    struct cfl_list _head;
};

void pack_string(msgpack_packer *pk, const char *key, const char *value)
{
    msgpack_pack_str(pk, strlen(key));
    msgpack_pack_str_body(pk, key, strlen(key));
    msgpack_pack_str(pk, strlen(value));
    msgpack_pack_str_body(pk, value, strlen(value));
}

flb_sds_t msgpack_to_json(struct flb_output_instance *ins, const char *msgpack_data, size_t msgpack_size)
{
    flb_sds_t json_str = NULL;
    json_str = flb_msgpack_raw_to_json_sds(msgpack_data, msgpack_size);
    return json_str;
}

int extract_field_from_json(struct flb_output_instance *ins, const char *json_payload, size_t payload_size, const char *field_name, char **field_value)
{
    char *msgpack_data = NULL;
    size_t msgpack_size = 0;
    int root_type;
    size_t consumed;
    msgpack_object root;

    /* Convert JSON to MsgPack */
    if (flb_pack_json(json_payload, payload_size, &msgpack_data, &msgpack_size, &root_type, &consumed) != 0) {
        flb_plg_error(ins, "Failed to pack JSON to MsgPack");
        return -1;
    }

    /* Unpack MsgPack to get root object */
    msgpack_unpacked result;
    msgpack_unpacked_init(&result);
    if (!msgpack_unpack_next(&result, msgpack_data, msgpack_size, NULL)) {
        flb_plg_error(ins, "Failed to unpack MsgPack data");
        msgpack_unpacked_destroy(&result);
        flb_free(msgpack_data);
        return -1;
    }

    root = result.data;

    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ins, "Root object is not a map");
        msgpack_unpacked_destroy(&result);
        flb_free(msgpack_data);
        return -1;
    }

    msgpack_object_kv *kv = root.via.map.ptr;
    for (size_t i = 0; i < root.via.map.size; i++) {
        if (strncmp(kv[i].key.via.str.ptr, field_name, kv[i].key.via.str.size) == 0) {
            if (kv[i].val.type == MSGPACK_OBJECT_STR) {
                *field_value = strndup(kv[i].val.via.str.ptr, kv[i].val.via.str.size);
                msgpack_unpacked_destroy(&result);
                flb_free(msgpack_data);
                flb_plg_info(ins, "Successfully extracted field '%s'", field_name);
                return 0; /* Successfully extracted field */
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_free(msgpack_data);
    flb_plg_error(ins, "Field '%s' not found in JSON payload", field_name);
    return -1; /* Field not found */
}

int setup_http_client(struct flb_http_client **client, struct flb_upstream_conn **u_conn, struct flb_config *config, struct flb_output_instance *ins, const char *uri, const char *auth_token, const char *method, const flb_sds_t payload)
{
    struct flb_upstream *upstream = flb_upstream_create(config, FLB_SCALEWAY_HOST, FLB_SCALEWAY_PORT, FLB_IO_TLS, ins->tls);
    if (!upstream) {
        flb_plg_error(ins, "Failed to create upstream");
        return -1;
    }

    *u_conn = flb_upstream_conn_get(upstream);
    if (!*u_conn) {
        flb_plg_error(ins, "Failed to get upstream connection");
        flb_upstream_destroy(upstream);
        return -1;
    }

    *client = flb_http_client(*u_conn, strcmp(method, "GET") == 0 ? FLB_HTTP_GET : FLB_HTTP_POST, uri, payload, payload ? flb_sds_len(payload) : 0, FLB_SCALEWAY_HOST, FLB_SCALEWAY_PORT, NULL, 0);
    if (!*client) {
        flb_plg_error(ins, "Failed to create HTTP client");
        flb_upstream_conn_release(*u_conn);
        flb_upstream_destroy(upstream);
        return -1;
    }

    /* Set headers */
    flb_http_add_header(*client, FLB_SCALEWAY_HEADER_AUTH, strlen(FLB_SCALEWAY_HEADER_AUTH), auth_token, strlen(auth_token));
    flb_http_add_header(*client, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE), "application/json", strlen("application/json"));

    return 0;
}

int create_data_source(struct flb_output_instance *ins, const char *uri, const char *auth_token, const char *project_id, const char *name, const char *type, char **created_id)
{
    flb_plg_info(ins, "Creating data source: name=%s, project_id=%s, type=%s", name, project_id, type);
    struct flb_config *config = flb_config_init();
    if (!config) {
        flb_plg_error(ins, "Failed to initialize Fluent Bit configuration");
        return -1;
    }

    /* Pack data into MsgPack and then convert to JSON */
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 3);
    pack_string(&pk, "name", name);
    pack_string(&pk, "project_id", project_id);
    pack_string(&pk, "type", type);

    flb_sds_t json_payload = msgpack_to_json(ins, sbuf.data, sbuf.size);
    if (!json_payload) {
        flb_plg_error(ins, "Failed to convert MsgPack to JSON");
        msgpack_sbuffer_destroy(&sbuf);
        flb_config_exit(config);
        return -1;
    }

    struct flb_http_client *client = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    if (setup_http_client(&client, &u_conn, config, ins, uri, auth_token, "POST", json_payload) != 0) {
        flb_plg_error(ins, "Failed to setup HTTP client for data source creation");
        flb_sds_destroy(json_payload);
        msgpack_sbuffer_destroy(&sbuf);
        flb_config_exit(config);
        return -1;
    }

    /* Perform HTTP request */
    size_t bytes;
    int ret = flb_http_do(client, &bytes);
    if (ret != 0 || client->resp.status != 200) {
        flb_plg_error(ins, "HTTP request failed with status %d", client->resp.status);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(json_payload);
        msgpack_sbuffer_destroy(&sbuf);
        flb_config_exit(config);
        return -1;
    }

    /* Extract the 'id' from the JSON payload */
    if (extract_field_from_json(ins, client->resp.payload, client->resp.payload_size, "id", created_id) != 0) {
        flb_plg_error(ins, "ID field not found in response.");
        ret = -1;
    }

    /* Cleanup */
    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(json_payload);
    msgpack_sbuffer_destroy(&sbuf);
    flb_config_exit(config);

    return ret;
}

int fetch_data(struct flb_output_instance *ins, const char *base_url, const char *data_source_id, const char *auth_token, char **extracted_url)
{
    struct flb_config *config = flb_config_init();
    if (!config) {
        flb_plg_error(ins, "Failed to initialize Fluent Bit configuration");
        return -1;
    }

    int url_length = snprintf(NULL, 0, "%s/%s", base_url, data_source_id) + 1;
    char *full_url = malloc(url_length);
    if (full_url == NULL) {
        flb_plg_error(ins, "Failed to allocate memory for URL");
        flb_config_exit(config);
        return -1;
    }
    snprintf(full_url, url_length, "%s/%s", base_url, data_source_id);

    struct flb_http_client *client = NULL;
    struct flb_upstream_conn *u_conn = NULL;

    if (setup_http_client(&client, &u_conn, config, ins, full_url, auth_token, "GET", NULL) != 0) {
        flb_plg_error(ins, "Failed to setup HTTP client for data fetch");
        free(full_url);
        flb_config_exit(config);
        return -1;
    }

    /* Perform HTTP request */
    size_t bytes;
    int ret = flb_http_do(client, &bytes);
    if (ret != 0 || client->resp.status != 200) {
        flb_plg_error(ins, "HTTP request failed with status %d", client->resp.status);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        free(full_url);
        flb_config_exit(config);
        return -1;
    }

    /* Extract the 'url' from the JSON payload */
    if (extract_field_from_json(ins, client->resp.payload, client->resp.payload_size, "url", extracted_url) != 0) {
        flb_plg_error(ins, "URL field not found in response.");
        ret = -1;
    }

    /* Cleanup */
    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    free(full_url);
    flb_config_exit(config);

    return ret;
}

int create_push_url(struct flb_output_instance *ins, const char *url, char **push_url)
{
    const char *modified_url;
    size_t needed_size;

    flb_plg_info(ins, "Creating push URL from base URL: %s", url);

    /* Check and remove "https://" prefix if present */
    modified_url = url;
    if (strncmp(url, "https://", 8) == 0) {
        modified_url += 8;  /* Move pointer forward to skip "https://" */
    }

    /* Calculate the needed size for the new URL */
    needed_size = strlen(modified_url) + 1;  /* +1 for null-terminator */

    /* Allocate memory for push_url */
    *push_url = malloc(needed_size);
    if (*push_url == NULL) {
        flb_plg_error(ins, "Failed to allocate memory for push_url");
        return -1;
    }

    /* Copy the modified URL to push_url */
    snprintf(*push_url, needed_size, "%s", modified_url);

    flb_plg_info(ins, "Push URL created successfully: %s", *push_url);
    return 0;
}

int fetch_and_create_push_url(struct flb_output_instance *ins, const char *url, const char *data_source_id, const char *auth_token, char **push_url)
{
    char *response_url;
    int ret;

    ret = fetch_data(ins, url, data_source_id, auth_token, &response_url);
    if (ret != 0) {
        return ret;
    }

    ret = create_push_url(ins, response_url, push_url);
    free(response_url);

    return ret;
}

char* generate_unique_name(const char *prefix)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char *name = malloc(100);

    strftime(name, 100, "%Y%m%d%H%M%S", t);
    char *unique_name = malloc(strlen(prefix) + strlen(name) + 2);
    sprintf(unique_name, "%s-%s", prefix, name);
    free(name);

    return unique_name;
}

int setup_data_source(struct flb_output_instance *ins, const char *create_uri, const char *project_id, const char *type, char **push_url,
                      int (*create_data_source)(struct flb_output_instance *, const char *, const char *, const char *, const char *, const char *, char **),
                      int (*fetch_and_create_push_url)(struct flb_output_instance *, const char *, const char *, const char *, char **))
{
    const char *secret_key;
    char *auth_token;
    char *name;
    char *data_source_id = NULL;
    int create_result;
    int fetch_result;

    secret_key = getenv("SCW_SECRET_KEY");
    if (secret_key == NULL) {
        flb_plg_error(ins, "SCW_SECRET_KEY is not defined");
        return -1;
    }

    auth_token = strdup(secret_key);
    name = generate_unique_name("fluent-bit-plugin-scaleway");

    create_result = create_data_source(ins, create_uri, auth_token, project_id, name, type, &data_source_id);
    if (create_result == 0 && data_source_id) {
        fetch_result = fetch_and_create_push_url(ins, create_uri, data_source_id, auth_token, push_url);
        free(data_source_id);
        free(auth_token);
        free(name);
        if (fetch_result == 0) {
            flb_plg_info(ins, "setup_data_source completed successfully");
        } else {
            flb_plg_error(ins, "fetch_and_create_push_url failed");
        }
        return fetch_result;
    }

    free(auth_token);
    free(name);
    flb_plg_error(ins, "create_data_source failed");
    return create_result;
}

// end of scaleway create datasource


pthread_once_t scaleway_initialization_guard = PTHREAD_ONCE_INIT;

static FLB_TLS_DEFINE(struct flb_scaleway_dynamic_tenant_id_entry,
               thread_local_tenant_id);

void scaleway_initialize_thread_local_storage()
{
    FLB_TLS_INIT(thread_local_tenant_id);
}

static struct flb_scaleway_dynamic_tenant_id_entry *dynamic_tenant_id_create() {
    struct flb_scaleway_dynamic_tenant_id_entry *entry;

    entry = (struct flb_scaleway_dynamic_tenant_id_entry *) \
        flb_calloc(1, sizeof(struct flb_scaleway_dynamic_tenant_id_entry));

    if (entry != NULL) {
        entry->value = NULL;

        cfl_list_entry_init(&entry->_head);
    }

    return entry;
}

static void dynamic_tenant_id_destroy(struct flb_scaleway_dynamic_tenant_id_entry *entry) {
    if (entry != NULL) {
        if (entry->value != NULL) {
            flb_sds_destroy(entry->value);

            entry->value = NULL;
        }

        if (!cfl_list_entry_is_orphan(&entry->_head)) {
            cfl_list_del(&entry->_head);
        }

        flb_free(entry);
    }
}

static void flb_scaleway_kv_init(struct mk_list *list)
{
    mk_list_init(list);
}

static inline void safe_sds_cat(flb_sds_t *buf, const char *str, int len)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(*buf, str, len);
    if (tmp) {
        *buf = tmp;
    }
}

static inline void normalize_cat(struct flb_ra_parser *rp, flb_sds_t *name)
{
    int sub;
    int len;
    char tmp[64];
    struct mk_list *s_head;
    struct flb_ra_key *key;
    struct flb_ra_subentry *entry;

    /* Iterate record accessor keys */
    key = rp->key;
    if (rp->type == FLB_RA_PARSER_STRING) {
        safe_sds_cat(name, key->name, flb_sds_len(key->name));
    }
    else if (rp->type == FLB_RA_PARSER_KEYMAP) {
        safe_sds_cat(name, key->name, flb_sds_len(key->name));
        if (mk_list_size(key->subkeys) > 0) {
            safe_sds_cat(name, "_", 1);
        }

        sub = 0;
        mk_list_foreach(s_head, key->subkeys) {
            entry = mk_list_entry(s_head, struct flb_ra_subentry, _head);

            if (sub > 0) {
                safe_sds_cat(name, "_", 1);
            }
            if (entry->type == FLB_RA_PARSER_STRING) {
                safe_sds_cat(name, entry->str, flb_sds_len(entry->str));
            }
            else if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
                len = snprintf(tmp, sizeof(tmp) -1, "%d",
                               entry->array_id);
                safe_sds_cat(name, tmp, len);
            }
            sub++;
        }
    }
}

static flb_sds_t normalize_ra_key_name(struct flb_scaleway *ctx,
                                       struct flb_record_accessor *ra)
{
    int c = 0;
    flb_sds_t name;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    name = flb_sds_create_size(128);
    if (!name) {
        return NULL;
    }

    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (c > 0) {
            flb_sds_cat(name, "_", 1);
        }
        normalize_cat(rp, &name);
        c++;
    }

    return name;
}

void flb_scaleway_kv_destroy(struct flb_scaleway_kv *kv)
{
    /* destroy key and value */
    flb_sds_destroy(kv->key);
    if (kv->val_type == FLB_SCALEWAY_KV_STR) {
        flb_sds_destroy(kv->str_val);
    }
    else if (kv->val_type == FLB_SCALEWAY_KV_RA) {
        flb_ra_destroy(kv->ra_val);
    }

    if (kv->ra_key) {
        flb_ra_destroy(kv->ra_key);
    }

    if (kv->key_normalized) {
        flb_sds_destroy(kv->key_normalized);
    }

    flb_free(kv);
}

int flb_scaleway_kv_append(struct flb_scaleway *ctx, char *key, char *val)
{
    int ra_count = 0;
    int k_len;
    int ret;
    struct flb_scaleway_kv *kv;

    if (!key) {
        return -1;
    }

    if (!val && key[0] != '$') {
        return -1;
    }

    kv = flb_calloc(1, sizeof(struct flb_scaleway_kv));
    if (!kv) {
        flb_errno();
        return -1;
    }

    k_len = strlen(key);
    if (key[0] == '$' && k_len >= 2 && isdigit(key[1])) {
        flb_plg_error(ctx->ins,
                      "key name for record accessor cannot start with a number: %s",
                      key);
        flb_free(kv);
        return -1;
    }

    kv->key = flb_sds_create(key);
    if (!kv->key) {
        flb_free(kv);
        return -1;
    }

    /*
     * If the key starts with a '$', it means its a record accessor pattern and
     * the key value pair will be formed using the key name and it proper value.
     */
    if (key[0] == '$' && val == NULL) {
        kv->ra_key = flb_ra_create(key, FLB_TRUE);
        if (!kv->ra_key) {
            flb_plg_error(ctx->ins,
                          "invalid key record accessor pattern for key '%s'",
                          key);
            flb_scaleway_kv_destroy(kv);
            return -1;
        }

        /* Normalize 'key name' using record accessor pattern */
        kv->key_normalized = normalize_ra_key_name(ctx, kv->ra_key);
        if (!kv->key_normalized) {
            flb_plg_error(ctx->ins,
                          "could not normalize key pattern name '%s'\n",
                          kv->ra_key->pattern);
            flb_scaleway_kv_destroy(kv);
            return -1;
        }
        /* remove record keys placed as stream labels via 'labels' and 'label_keys' */
        ret = flb_slist_add(&ctx->remove_keys_derived, key);
        if (ret < 0) {
            flb_scaleway_kv_destroy(kv);
            return -1;
        }
        ra_count++;
    }
    else if (val[0] == '$') {
        /* create a record accessor context */
        kv->val_type = FLB_SCALEWAY_KV_RA;
        kv->ra_val = flb_ra_create(val, FLB_TRUE);
        if (!kv->ra_val) {
            flb_plg_error(ctx->ins,
                          "invalid record accessor pattern for key '%s': %s",
                          key, val);
            flb_scaleway_kv_destroy(kv);
            return -1;
        }
        ret = flb_slist_add(&ctx->remove_keys_derived, val);
        if (ret < 0) {
            flb_scaleway_kv_destroy(kv);
            return -1;
        }
        ra_count++;
    }
    else {
        kv->val_type = FLB_SCALEWAY_KV_STR;
        kv->str_val = flb_sds_create(val);
        if (!kv->str_val) {
            flb_scaleway_kv_destroy(kv);
            return -1;
        }
    }
    mk_list_add(&kv->_head, &ctx->labels_list);

    /* return the number of record accessor values */
    return ra_count;
}

static void flb_scaleway_kv_exit(struct flb_scaleway *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_scaleway_kv *kv;

    mk_list_foreach_safe(head, tmp, &ctx->labels_list) {
        kv = mk_list_entry(head, struct flb_scaleway_kv, _head);

        /* unlink and destroy */
        mk_list_del(&kv->_head);
        flb_scaleway_kv_destroy(kv);
    }
}

/* Pack a label key, it also perform sanitization of the characters */
static int pack_label_key(msgpack_packer *mp_pck, char *key, int key_len)
{
    int i;
    int k_len = key_len;
    int is_digit = FLB_FALSE;
    char *p;
    size_t prev_size;

    /* Normalize key name using the packed value */
    if (isdigit(*key)) {
        is_digit = FLB_TRUE;
        k_len++;
    }

    /* key: pack the length */
    msgpack_pack_str(mp_pck, k_len);
    if (is_digit) {
        msgpack_pack_str_body(mp_pck, "_", 1);
    }

    /* save the current offset */
    prev_size = ((msgpack_sbuffer *) mp_pck->data)->size;

    /* Pack the key name */
    msgpack_pack_str_body(mp_pck, key, key_len);

    /* 'p' will point to where the key was written */
    p = (char *) (((msgpack_sbuffer*) mp_pck->data)->data + prev_size);

    /* and sanitize the key characters */
    for (i = 0; i < key_len; i++) {
        if (!isalnum(p[i]) && p[i] != '_') {
            p[i] = '_';
        }
    }

    return 0;
}

static flb_sds_t pack_labels(struct flb_scaleway *ctx,
                             msgpack_packer *mp_pck,
                             char *tag, int tag_len,
                             msgpack_object *map)
{
    int i;
    flb_sds_t ra_val;
    struct mk_list *head;
    struct flb_ra_value *rval = NULL;
    struct flb_scaleway_kv *kv;
    msgpack_object k;
    msgpack_object v;
    struct flb_mp_map_header mh;


    /* Initialize dynamic map header */
    flb_mp_map_header_init(&mh, mp_pck);

    mk_list_foreach(head, &ctx->labels_list) {
        kv = mk_list_entry(head, struct flb_scaleway_kv, _head);

        /* record accessor key/value pair */
        if (kv->ra_key != NULL && kv->ra_val == NULL) {
            ra_val = flb_ra_translate(kv->ra_key, tag, tag_len, *(map), NULL);
            if (!ra_val || flb_sds_len(ra_val) == 0) {
                /* if no value is retruned or if it's empty, just skip it */
                flb_plg_info(ctx->ins,
                             "empty record accessor key translation for pattern: %s",
                             kv->ra_key->pattern);
            }
            else {
                /* Pack the key and value */
                flb_mp_map_header_append(&mh);

                /* We skip the first '$' character since it won't be valid in Loki */
                pack_label_key(mp_pck, kv->key_normalized,
                               flb_sds_len(kv->key_normalized));

                msgpack_pack_str(mp_pck, flb_sds_len(ra_val));
                msgpack_pack_str_body(mp_pck, ra_val, flb_sds_len(ra_val));
            }

            if (ra_val) {
                flb_sds_destroy(ra_val);
            }
            continue;
        }

        /*
         * The code is a bit duplicated to be able to manage the exception of an
         * invalid or empty value, on that case the k/v is skipped.
         */
        if (kv->val_type == FLB_SCALEWAY_KV_STR) {
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(mp_pck, flb_sds_len(kv->key));
            msgpack_pack_str_body(mp_pck, kv->key, flb_sds_len(kv->key));
            msgpack_pack_str(mp_pck, flb_sds_len(kv->str_val));
            msgpack_pack_str_body(mp_pck, kv->str_val, flb_sds_len(kv->str_val));
        }
        else if (kv->val_type == FLB_SCALEWAY_KV_RA) {
            /* record accessor type */
            ra_val = flb_ra_translate(kv->ra_val, tag, tag_len, *(map), NULL);
            if (!ra_val || flb_sds_len(ra_val) == 0) {
                flb_plg_info(ctx->ins, "could not translate record accessor");
            }
            else {
                flb_mp_map_header_append(&mh);
                msgpack_pack_str(mp_pck, flb_sds_len(kv->key));
                msgpack_pack_str_body(mp_pck, kv->key, flb_sds_len(kv->key));
                msgpack_pack_str(mp_pck, flb_sds_len(ra_val));
                msgpack_pack_str_body(mp_pck, ra_val, flb_sds_len(ra_val));
            }

            if (ra_val) {
                flb_sds_destroy(ra_val);
            }
        }
    }

    if (ctx->auto_kubernetes_labels == FLB_TRUE) {
        rval = flb_ra_get_value_object(ctx->ra_k8s, *map);
        if (rval && rval->o.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < rval->o.via.map.size; i++) {
                k = rval->o.via.map.ptr[i].key;
                v = rval->o.via.map.ptr[i].val;

                if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* append the key/value pair */
                flb_mp_map_header_append(&mh);

                /* Pack key */
                pack_label_key(mp_pck, (char *) k.via.str.ptr, k.via.str.size);

                /* Pack the value */
                msgpack_pack_str(mp_pck, v.via.str.size);
                msgpack_pack_str_body(mp_pck, v.via.str.ptr,  v.via.str.size);
            }
        }

        if (rval) {
            flb_ra_key_value_destroy(rval);
        }
    }

    /* Check if we added any label, if no one has been set, set the defaul 'job' */
    if (mh.entries == 0) {
        /* pack the default entry */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 3);
        msgpack_pack_str_body(mp_pck, "job", 3);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "fluent-bit", 10);
    }
    flb_mp_map_header_end(&mh);
    return 0;
}

static int create_label_map_entry(struct flb_scaleway *ctx,
                                  struct flb_sds_list *list, msgpack_object *val, int *ra_used)
{
    msgpack_object key;
    flb_sds_t label_key;
    flb_sds_t val_str;
    int i;
    int len;
    int ret;

    if (ctx == NULL || list == NULL || val == NULL || ra_used == NULL) {
        return -1;
    }

    switch (val->type) {
    case MSGPACK_OBJECT_STR:
        label_key = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
        if (label_key == NULL) {
            flb_errno();
            return -1;
        }

        val_str = flb_ra_create_str_from_list(list);
        if (val_str == NULL) {
            flb_plg_error(ctx->ins, "[%s] flb_ra_create_from_list failed", __FUNCTION__);
            flb_sds_destroy(label_key);
            return -1;
        }

        /* for debugging
          printf("label_key=%s val_str=%s\n", label_key, val_str);
         */

        ret = flb_scaleway_kv_append(ctx, label_key, val_str);
        flb_sds_destroy(label_key);
        flb_sds_destroy(val_str);
        if (ret == -1) {
            return -1;
        }
        *ra_used = *ra_used + 1;

        break;
    case MSGPACK_OBJECT_MAP:
        len = val->via.map.size;
        for (i=0; i<len; i++) {
            key = val->via.map.ptr[i].key;
            if (key.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "[%s] key is not string", __FUNCTION__);
                return -1;
            }
            ret = flb_sds_list_add(list, (char*)key.via.str.ptr, key.via.str.size);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_add failed", __FUNCTION__);
                return -1;
            }

            ret = create_label_map_entry(ctx, list, &val->via.map.ptr[i].val, ra_used);
            if (ret < 0) {
                return -1;
            }

            ret = flb_sds_list_del_last_entry(list);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_del_last_entry failed", __FUNCTION__);
                return -1;
            }
        }

        break;
    default:
        flb_plg_error(ctx->ins, "[%s] value type is not str or map. type=%d", __FUNCTION__, val->type);
        return -1;
    }
    return 0;
}

static int create_label_map_entries(struct flb_scaleway *ctx,
                                    char *msgpack_buf, size_t msgpack_size, int *ra_used)
{
    struct flb_sds_list *list = NULL;
    msgpack_unpacked result;
    size_t off = 0;
    int i;
    int len;
    int ret;
    msgpack_object key;

    if (ctx == NULL || msgpack_buf == NULL || ra_used == NULL) {
        return -1;
    }

    msgpack_unpacked_init(&result);
    while(msgpack_unpack_next(&result, msgpack_buf, msgpack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "[%s] data type is not map", __FUNCTION__);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        len = result.data.via.map.size;
        for (i=0; i<len; i++) {
            list = flb_sds_list_create();
            if (list == NULL) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_create failed", __FUNCTION__);
                msgpack_unpacked_destroy(&result);
                return -1;
            }
            key = result.data.via.map.ptr[i].key;
            if (key.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "[%s] key is not string", __FUNCTION__);
                flb_sds_list_destroy(list);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            ret = flb_sds_list_add(list, (char*)key.via.str.ptr, key.via.str.size);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] flb_sds_list_add failed", __FUNCTION__);
                flb_sds_list_destroy(list);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            ret = create_label_map_entry(ctx, list, &result.data.via.map.ptr[i].val, ra_used);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "[%s] create_label_map_entry failed", __FUNCTION__);
                flb_sds_list_destroy(list);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            flb_sds_list_destroy(list);
            list = NULL;
        }
    }

    msgpack_unpacked_destroy(&result);

    return 0;
}

static int read_label_map_path_file(struct flb_output_instance *ins, flb_sds_t path,
                                    char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;
    char *buf = NULL;
    char *msgp_buf = NULL;
    FILE *fp = NULL;
    struct stat st;
    size_t file_size;
    size_t ret_size;

    ret = access(path, R_OK);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ins, "can't access %s", path);
        return -1;
    }

    ret = stat(path, &st);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ins, "stat failed %s", path);
        return -1;
    }
    file_size = st.st_size;

    fp = fopen(path, "r");
    if (fp == NULL) {
        flb_plg_error(ins, "can't open %s", path);
        return -1;
    }

    buf = flb_malloc(file_size);
    if (buf == NULL) {
        flb_plg_error(ins, "malloc failed");
        fclose(fp);
        return -1;
    }

    ret_size = fread(buf, 1, file_size, fp);
    if (ret_size < file_size && feof(fp) != 0) {
        flb_plg_error(ins, "fread failed");
        fclose(fp);
        flb_free(buf);
        return -1;
    }

    ret = flb_pack_json(buf, file_size, &msgp_buf, &ret_size, &root_type, NULL);
    if (ret < 0) {
        flb_plg_error(ins, "flb_pack_json failed");
        fclose(fp);
        flb_free(buf);
        return -1;
    }

    *out_buf = msgp_buf;
    *out_size = ret_size;

    fclose(fp);
    flb_free(buf);
    return 0;
}

static int load_label_map_path(struct flb_scaleway *ctx, flb_sds_t path, int *ra_used)
{
    int ret;
    char *msgpack_buf = NULL;
    size_t msgpack_size;

    ret = read_label_map_path_file(ctx->ins, path, &msgpack_buf, &msgpack_size);
    if (ret < 0) {
        return -1;
    }

    ret = create_label_map_entries(ctx, msgpack_buf, msgpack_size, ra_used);
    if (ret < 0) {
        flb_free(msgpack_buf);
        return -1;
    }

    if (msgpack_buf != NULL) {
        flb_free(msgpack_buf);
    }

    return 0;
}

static int parse_labels(struct flb_scaleway *ctx)
{
    int ret;
    int ra_used = 0;
    char *p;
    flb_sds_t key;
    flb_sds_t val;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    flb_scaleway_kv_init(&ctx->labels_list);

    if (ctx->labels) {
        mk_list_foreach(head, ctx->labels) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            /* record accessor label key ? */
            if (entry->str[0] == '$') {
                ret = flb_scaleway_kv_append(ctx, entry->str, NULL);
                if (ret == -1) {
                    return -1;
                }
                else if (ret > 0) {
                    ra_used++;
                }
                continue;
            }

            p = strchr(entry->str, '=');
            if (!p) {
                flb_plg_error(ctx->ins, "invalid key value pair on '%s'",
                              entry->str);
                return -1;
            }

            key = flb_sds_create_size((p - entry->str) + 1);
            flb_sds_cat(key, entry->str, p - entry->str);
            val = flb_sds_create(p + 1);
            if (!key) {
                flb_plg_error(ctx->ins,
                              "invalid key value pair on '%s'",
                              entry->str);
                return -1;
            }
            if (!val || flb_sds_len(val) == 0) {
                flb_plg_error(ctx->ins,
                              "invalid key value pair on '%s'",
                              entry->str);
                flb_sds_destroy(key);
                return -1;
            }

            ret = flb_scaleway_kv_append(ctx, key, val);
            flb_sds_destroy(key);
            flb_sds_destroy(val);

            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                ra_used++;
            }
        }
    }

    /* Append label keys set in the configuration */
    if (ctx->label_keys) {
        mk_list_foreach(head, ctx->label_keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            if (entry->str[0] != '$') {
                flb_plg_error(ctx->ins,
                              "invalid label key, the name must start with '$'");
                return -1;
            }

            ret = flb_scaleway_kv_append(ctx, entry->str, NULL);
            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                ra_used++;
            }
        }
    }

    /* label_map_path */
    if (ctx->label_map_path) {
        ret = load_label_map_path(ctx, ctx->label_map_path, &ra_used);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to load label_map_path");
        }
    }

    if (ctx->auto_kubernetes_labels == FLB_TRUE) {
        ctx->ra_k8s = flb_ra_create("$kubernetes['labels']", FLB_TRUE);
        if (!ctx->ra_k8s) {
            flb_plg_error(ctx->ins,
                          "could not create record accessor for Kubernetes labels");
            return -1;
        }
    }

    /*
     * If the variable 'ra_used' is greater than zero, means that record accessor is
     * being used to compose the stream labels.
     */
    ctx->ra_used = ra_used;
    return 0;
}

static int key_is_duplicated(struct mk_list *list, char *str, int len)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        if (flb_sds_len(entry->str) == len &&
            strncmp(entry->str, str, len) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int prepare_remove_keys(struct flb_scaleway *ctx)
{
    int ret;
    int len;
    int size;
    char *tmp;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct mk_list *patterns;

    patterns = &ctx->remove_keys_derived;

    /* Add remove keys set in the configuration */
    if (ctx->remove_keys) {
        mk_list_foreach(head, ctx->remove_keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            if (entry->str[0] != '$') {
                tmp = flb_malloc(flb_sds_len(entry->str) + 2);
                if (!tmp) {
                    flb_errno();
                    continue;
                }
                else {
                    tmp[0] = '$';
                    len = flb_sds_len(entry->str);
                    memcpy(tmp + 1, entry->str, len);
                    tmp[len + 1] = '\0';
                    len++;
                }
            }
            else {
                tmp = entry->str;
                len = flb_sds_len(entry->str);
            }

            ret = key_is_duplicated(patterns, tmp, len);
            if (ret == FLB_TRUE) {
                if (entry->str != tmp) {
                    flb_free(tmp);
                }
                continue;
            }

            ret = flb_slist_add_n(patterns, tmp, len);
            if (entry->str != tmp) {
                flb_free(tmp);
            }
            if (ret < 0) {
                return -1;
            }
        }
        size = mk_list_size(patterns);
        flb_plg_info(ctx->ins, "remove_mpa size: %d", size);
        if (size > 0) {
            ctx->remove_mpa = flb_mp_accessor_create(patterns);
            if (ctx->remove_mpa == NULL) {
                return -1;
            }
        }
    }

    return 0;
}

static void loki_config_destroy(struct flb_scaleway *ctx)
{
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->ra_k8s) {
        flb_ra_destroy(ctx->ra_k8s);
    }
    if (ctx->ra_tenant_id_key) {
        flb_ra_destroy(ctx->ra_tenant_id_key);
    }

    if (ctx->remove_mpa) {
        flb_mp_accessor_destroy(ctx->remove_mpa);
    }
    flb_slist_destroy(&ctx->remove_keys_derived);

    flb_scaleway_kv_exit(ctx);
    flb_free(ctx);
}

static struct flb_scaleway *loki_config_create(struct flb_output_instance *ins,
                                               struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    struct flb_scaleway *ctx;
    struct flb_upstream *upstream;
    char *compress;
    const char *project_id;

    flb_plg_info(ins, "Creating Scaleway Loki configuration context");

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_scaleway));
    if (!ctx) {
        flb_plg_error(ins, "Failed to allocate memory for Scaleway context");
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    flb_scaleway_kv_init(&ctx->labels_list);

    flb_plg_info(ins, "Scaleway context created successfully");

    /* Register context with plugin instance */
    flb_output_set_context(ins, ctx);

     /* Initialize project_id */
        project_id = flb_output_get_property("project_id", ins);
        if (project_id) {
            ctx->project_id = strdup(project_id);
        } else {
            flb_plg_error(ins, "Project ID is not set");
            flb_free(ctx);
            return NULL;
        }

        flb_plg_info(ins, "Project ID set to: %s", ctx->project_id);



     // Check if host is empty and set the log URL
       flb_plg_info(ins, "Check if host is empty and set the log URL: %s", ins->host.name);

       if (ins->host.name == NULL || strlen(ins->host.name) == 0) {
           // Call setup_data_source to get the log URL
           char **push_url = malloc(sizeof(char*));
             if (!push_url) {
                 flb_plg_error(ctx->ins, "Failed to allocate memory for push_url");
                 return NULL;
             }

            *push_url = NULL;
           ret = setup_data_source(ins, FLB_SCALEWAY_CREATE_URI, ctx->project_id, "logs", push_url, create_data_source, fetch_and_create_push_url);
           if (ret == 0 && push_url) {
               ins->host.name = strdup(*push_url);
               flb_plg_info(ins, "Log URL set to: %s", ins->host.name);
           } else {
               flb_plg_error(ctx->ins, "Failed to set up data source and obtain logs URL");
               free(push_url);
               return NULL;
           }
           free(push_url);
        }

    /* Set networking defaults */
    flb_output_net_default(FLB_SCALEWAY_HOST, FLB_SCALEWAY_PORT, ins);

    flb_plg_info(ins, "Networking defaults set");

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "Failed to set configuration map");
        return NULL;
    }

    flb_plg_info(ins, "Configuration map loaded successfully");

    /* Initialize final remove_keys list */
    flb_slist_create(&ctx->remove_keys_derived);

    flb_plg_info(ins, "remove_keys list initialized");

    /* Parse labels */
    ret = parse_labels(ctx);
    if (ret == -1) {
        flb_plg_error(ins, "Failed to parse labels");
        return NULL;
    }

    flb_plg_info(ins, "Labels parsed successfully");

    /* Load remove keys */
    ret = prepare_remove_keys(ctx);
    if (ret == -1) {
        flb_plg_error(ins, "Failed to prepare remove keys");
        return NULL;
    }

    flb_plg_info(ins, "Remove keys loaded successfully");

    /* tenant_id_key */
    if (ctx->tenant_id_key_config) {
        ctx->ra_tenant_id_key = flb_ra_create(ctx->tenant_id_key_config, FLB_FALSE);
        if (!ctx->ra_tenant_id_key) {
            flb_plg_error(ctx->ins, "Could not create record accessor for Tenant ID");
        } else {
            flb_plg_info(ctx->ins, "Record accessor for Tenant ID created successfully");
        }
    }

    /* Compress (gzip) */
    compress = (char *) flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (compress) {
        if (strcasecmp(compress, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }

    flb_plg_info(ins, "Compression setting: %s", ctx->compress_gzip ? "gzip" : "none");

    /* Line Format */
    if (strcasecmp(ctx->line_format, "json") == 0) {
        ctx->out_line_format = FLB_SCALEWAY_FMT_JSON;
    }
    else if (strcasecmp(ctx->line_format, "key_value") == 0) {
        ctx->out_line_format = FLB_SCALEWAY_FMT_KV;
    }
    else {
        flb_plg_error(ctx->ins, "Invalid 'line_format' value: %s", ctx->line_format);
        return NULL;
    }

    flb_plg_info(ins, "Line format set to: %s", ctx->out_line_format == FLB_SCALEWAY_FMT_JSON ? "json" : "key_value");

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create Upstream connection context */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   ins->tls);
    if (!upstream) {
        flb_plg_error(ins, "Failed to create upstream connection context");
        return NULL;
    }
    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);
    ctx->tcp_port = ins->host.port;
    ctx->tcp_host = ins->host.name;

    flb_plg_info(ins, "Upstream connection context created successfully: %s:%d", ctx->tcp_host, ctx->tcp_port);

    return ctx;
}

/*
 * Convert struct flb_tm timestamp value to nanoseconds and then it pack it as
 * a string.
 */

static void pack_timestamp(msgpack_packer *mp_pck, struct flb_time *tms)
{
    int len;
    char buf[64];
    uint64_t nanosecs;

    /* convert to nanoseconds */
    nanosecs = flb_time_to_nanosec(tms);

    /* format as a string */
    len = snprintf(buf, sizeof(buf) - 1, "%" PRIu64, nanosecs);

    /* pack the value */
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, buf, len);
}


static void pack_format_line_value(flb_sds_t *buf, msgpack_object *val)
{
    int i;
    int len;
    char temp[512];
    msgpack_object k;
    msgpack_object v;

    if (val->type == MSGPACK_OBJECT_STR) {
        safe_sds_cat(buf, "\"", 1);
        safe_sds_cat(buf, val->via.str.ptr, val->via.str.size);
        safe_sds_cat(buf, "\"", 1);
    }
    else if (val->type == MSGPACK_OBJECT_NIL) {
        safe_sds_cat(buf, "null", 4);
    }
    else if (val->type == MSGPACK_OBJECT_BOOLEAN) {
        if (val->via.boolean) {
            safe_sds_cat(buf, "true", 4);
        }
        else {
            safe_sds_cat(buf, "false", 5);
        }
    }
    else if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        len = snprintf(temp, sizeof(temp)-1, "%"PRIu64, val->via.u64);
        safe_sds_cat(buf, temp, len);
    }
    else if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        len = snprintf(temp, sizeof(temp)-1, "%"PRId64, val->via.i64);
        safe_sds_cat(buf, temp, len);
    }
    else if (val->type == MSGPACK_OBJECT_FLOAT32 ||
             val->type == MSGPACK_OBJECT_FLOAT64) {
        if (val->via.f64 == (double)(long long int) val->via.f64) {
            len = snprintf(temp, sizeof(temp)-1, "%.1f", val->via.f64);
        }
        else {
            len = snprintf(temp, sizeof(temp)-1, "%.16g", val->via.f64);
        }
        safe_sds_cat(buf, temp, len);
    }
    else if (val->type == MSGPACK_OBJECT_ARRAY) {
        safe_sds_cat(buf, "\"[", 2);
        for (i = 0; i < val->via.array.size; i++) {
            v = val->via.array.ptr[i];
            if (i > 0) {
                safe_sds_cat(buf, " ", 1);
            }
            pack_format_line_value(buf, &v);
        }
        safe_sds_cat(buf, "]\"", 2);
    }
    else if (val->type == MSGPACK_OBJECT_MAP) {
        safe_sds_cat(buf, "\"map[", 5);

        for (i = 0; i < val->via.map.size; i++) {
            k = val->via.map.ptr[i].key;
            v = val->via.map.ptr[i].val;

            if (k.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (i > 0) {
                safe_sds_cat(buf, " ", 1);
            }

            safe_sds_cat(buf, k.via.str.ptr, k.via.str.size);
            safe_sds_cat(buf, ":", 1);
            pack_format_line_value(buf, &v);
        }
        safe_sds_cat(buf, "]\"", 2);
    }
    else {

        return;
    }
}

// seek tenant id from map and set it to dynamic_tenant_id
static int get_tenant_id_from_record(struct flb_scaleway *ctx, msgpack_object *map,
                                     flb_sds_t *dynamic_tenant_id)
{
    struct flb_ra_value *rval = NULL;
    flb_sds_t tmp_str;
    int cmp_len;

    rval = flb_ra_get_value_object(ctx->ra_tenant_id_key, *map);

    if (rval == NULL) {
        flb_plg_warn(ctx->ins, "the value of %s is missing",
                     ctx->tenant_id_key_config);
        return -1;
    }
    else if (rval->o.type != MSGPACK_OBJECT_STR) {
        flb_plg_warn(ctx->ins, "the value of %s is not string",
                     ctx->tenant_id_key_config);
        flb_ra_key_value_destroy(rval);
        return -1;
    }

    tmp_str = flb_sds_create_len(rval->o.via.str.ptr,
                                 rval->o.via.str.size);
    if (tmp_str == NULL) {
        flb_plg_warn(ctx->ins, "cannot create tenant ID string from record");
        flb_ra_key_value_destroy(rval);
        return -1;
    }

    // check if already dynamic_tenant_id is set.
    if (*dynamic_tenant_id != NULL) {
        cmp_len = flb_sds_len(*dynamic_tenant_id);

        if ((rval->o.via.str.size == cmp_len) &&
            flb_sds_cmp(tmp_str, *dynamic_tenant_id, cmp_len) == 0) {
            // tenant_id is same. nothing to do.
            flb_ra_key_value_destroy(rval);
            flb_sds_destroy(tmp_str);

            return 0;
        }

        flb_plg_warn(ctx->ins, "Tenant ID is overwritten %s -> %s",
                     *dynamic_tenant_id, tmp_str);

        flb_sds_destroy(*dynamic_tenant_id);
    }

    // this sds will be released after setting http header.
    *dynamic_tenant_id = tmp_str;
    flb_plg_info(ctx->ins, "Tenant ID is %s", *dynamic_tenant_id);

    flb_ra_key_value_destroy(rval);
    return 0;
}

static int pack_record(struct flb_scaleway *ctx,
                       msgpack_packer *mp_pck, msgpack_object *rec,
                       flb_sds_t *dynamic_tenant_id)
{
    int i;
    int skip = 0;
    int len;
    int ret;
    int size_hint = 1024;
    char *line;
    flb_sds_t buf;
    msgpack_object key;
    msgpack_object val;
    char *tmp_sbuf_data = NULL;
    size_t tmp_sbuf_size;
    msgpack_unpacked mp_buffer;
    size_t off = 0;

    /*
     * Get tenant id from record before removing keys.
     * https://github.com/fluent/fluent-bit/issues/6207
     */
    if (ctx->ra_tenant_id_key && rec->type == MSGPACK_OBJECT_MAP) {
        get_tenant_id_from_record(ctx, rec, dynamic_tenant_id);
    }

    /* Remove keys in remove_keys */
    msgpack_unpacked_init(&mp_buffer);
    if (ctx->remove_mpa) {
        ret = flb_mp_accessor_keys_remove(ctx->remove_mpa, rec,
                                          (void *) &tmp_sbuf_data, &tmp_sbuf_size);
        if (ret == FLB_TRUE) {
            ret = msgpack_unpack_next(&mp_buffer, tmp_sbuf_data, tmp_sbuf_size, &off);
            if (ret != MSGPACK_UNPACK_SUCCESS) {
                flb_free(tmp_sbuf_data);
                msgpack_unpacked_destroy(&mp_buffer);
                return -1;
            }
            rec = &mp_buffer.data;
        }
    }

    /* Drop single key */
    if (ctx->drop_single_key == FLB_TRUE && rec->type == MSGPACK_OBJECT_MAP && rec->via.map.size == 1) {
        if (ctx->out_line_format == FLB_SCALEWAY_FMT_JSON) {
            rec = &rec->via.map.ptr[0].val;
        } else if (ctx->out_line_format == FLB_SCALEWAY_FMT_KV) {
            val = rec->via.map.ptr[0].val;

            if (val.type == MSGPACK_OBJECT_STR) {
                msgpack_pack_str(mp_pck, val.via.str.size);
                msgpack_pack_str_body(mp_pck, val.via.str.ptr, val.via.str.size);
            } else {
                buf = flb_sds_create_size(size_hint);
                if (!buf) {
                    msgpack_unpacked_destroy(&mp_buffer);
                    if (tmp_sbuf_data) {
                        flb_free(tmp_sbuf_data);
                    }
                    return -1;
                }
                pack_format_line_value(&buf, &val);
                msgpack_pack_str(mp_pck, flb_sds_len(buf));
                msgpack_pack_str_body(mp_pck, buf, flb_sds_len(buf));
                flb_sds_destroy(buf);
            }

            msgpack_unpacked_destroy(&mp_buffer);
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }

            return 0;
        }
    }

    if (ctx->out_line_format == FLB_SCALEWAY_FMT_JSON) {
        line = flb_msgpack_to_json_str(size_hint, rec);
        if (!line) {
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }
            msgpack_unpacked_destroy(&mp_buffer);
            return -1;
        }
        len = strlen(line);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, line, len);
        flb_free(line);
    }
    else if (ctx->out_line_format == FLB_SCALEWAY_FMT_KV) {
        if (rec->type != MSGPACK_OBJECT_MAP) {
            msgpack_unpacked_destroy(&mp_buffer);
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }
            return -1;
        }

        buf = flb_sds_create_size(size_hint);
        if (!buf) {
            msgpack_unpacked_destroy(&mp_buffer);
            if (tmp_sbuf_data) {
                flb_free(tmp_sbuf_data);
            }
            return -1;
        }

        for (i = 0; i < rec->via.map.size; i++) {
            key = rec->via.map.ptr[i].key;
            val = rec->via.map.ptr[i].val;

            if (key.type != MSGPACK_OBJECT_STR) {
                skip++;
                continue;
            }

            if (i > skip) {
                safe_sds_cat(&buf, " ", 1);
            }

            safe_sds_cat(&buf, key.via.str.ptr, key.via.str.size);
            safe_sds_cat(&buf, "=", 1);
            pack_format_line_value(&buf, &val);
        }

        msgpack_pack_str(mp_pck, flb_sds_len(buf));
        msgpack_pack_str_body(mp_pck, buf, flb_sds_len(buf));
        flb_sds_destroy(buf);
    }

    msgpack_unpacked_destroy(&mp_buffer);
    if (tmp_sbuf_data) {
        flb_free(tmp_sbuf_data);
    }

    return 0;
}

/* Initialization callback */
static int cb_scaleway_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    int              result;
    struct flb_scaleway *ctx;

    /* Create plugin context */
    ctx = loki_config_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize configuration");
        return -1;
    }

    result = pthread_mutex_init(&ctx->dynamic_tenant_list_lock, NULL);

    if (result != 0) {
        flb_errno();

        flb_plg_error(ins, "cannot initialize dynamic tenant id list lock");

        loki_config_destroy(ctx);

        return -1;
    }

    result = pthread_once(&scaleway_initialization_guard,
                          scaleway_initialize_thread_local_storage);

    if (result != 0) {
        flb_errno();

        flb_plg_error(ins, "cannot initialize thread local storage");

        loki_config_destroy(ctx);

        return -1;
    }

    cfl_list_init(&ctx->dynamic_tenant_list);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins,
                 "configured, hostname=%s:%i",
                 ctx->tcp_host, ctx->tcp_port);
    return 0;
}

static flb_sds_t loki_compose_payload(struct flb_scaleway *ctx,
                                      int total_records,
                                      char *tag, int tag_len,
                                      const void *data, size_t bytes,
                                      flb_sds_t *dynamic_tenant_id)
{
    // int mp_ok = MSGPACK_UNPACK_SUCCESS;
    // size_t off = 0;
    flb_sds_t json;
    // struct flb_time tms;
    // msgpack_unpacked result;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    // msgpack_object *obj;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    /*
     * Fluent Bit uses Loki API v1 to push records in JSON format, this
     * is the expected structure:
     *
     * {
     *   "streams": [
     *     {
     *       "stream": {
     *         "label": "value"
     *       },
     *       "values": [
     *         [ "<unix epoch in nanoseconds>", "<log line>" ],
     *         [ "<unix epoch in nanoseconds>", "<log line>" ]
     *       ]
     *     }
     *   ]
     * }
     */

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Main map */
    msgpack_pack_map(&mp_pck, 1);

    /* streams */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "streams", 7);

    if (ctx->ra_used == 0 && ctx->auto_kubernetes_labels == FLB_FALSE) {
        /*
         * If labels are cached, there is no record accessor or custom
         * keys, so it's safe to put one main stream and attach all the
         * values.
         */
        msgpack_pack_array(&mp_pck, 1);

        /* map content: streams['stream'] & streams['values'] */
        msgpack_pack_map(&mp_pck, 2);

        /* streams['stream'] */
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "stream", 6);

        /* Pack stream labels */
        pack_labels(ctx, &mp_pck, tag, tag_len, NULL);

        /* streams['values'] */
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "values", 6);
        msgpack_pack_array(&mp_pck, total_records);

        while ((ret = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
            msgpack_pack_array(&mp_pck, 2);

            /* Append the timestamp */
            pack_timestamp(&mp_pck, &log_event.timestamp);
            pack_record(ctx, &mp_pck, log_event.body, dynamic_tenant_id);
        }
    }
    else {
        /*
         * Here there are no cached labels and the labels are composed by
         * each record content. To simplify the operation just create
         * one stream per record.
         */
        msgpack_pack_array(&mp_pck, total_records);

        while ((ret = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
            /* map content: streams['stream'] & streams['values'] */
            msgpack_pack_map(&mp_pck, 2);

            /* streams['stream'] */
            msgpack_pack_str(&mp_pck, 6);
            msgpack_pack_str_body(&mp_pck, "stream", 6);

            /* Pack stream labels */
            pack_labels(ctx, &mp_pck, tag, tag_len, log_event.body);

            /* streams['values'] */
            msgpack_pack_str(&mp_pck, 6);
            msgpack_pack_str_body(&mp_pck, "values", 6);
            msgpack_pack_array(&mp_pck, 1);

            msgpack_pack_array(&mp_pck, 2);

            /* Append the timestamp */
            pack_timestamp(&mp_pck, &log_event.timestamp);
            pack_record(ctx, &mp_pck, log_event.body, dynamic_tenant_id);
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;
}

static void payload_release(void *payload, int compressed)
{
    if (compressed) {
        flb_free(payload);
    }
    else {
        flb_sds_destroy(payload);
    }
}

static void cb_scaleway_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    flb_sds_t payload = NULL;
    flb_sds_t out_buf = NULL;
    size_t out_size;
    int compressed = FLB_FALSE;
    struct flb_scaleway *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_scaleway_dynamic_tenant_id_entry *dynamic_tenant_id;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    dynamic_tenant_id = FLB_TLS_GET(thread_local_tenant_id);

    if (dynamic_tenant_id == NULL) {
        dynamic_tenant_id = dynamic_tenant_id_create();

        if (dynamic_tenant_id == NULL) {
            flb_errno();
            flb_plg_error(ctx->ins, "cannot allocate dynamic tenant id");

            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        FLB_TLS_SET(thread_local_tenant_id, dynamic_tenant_id);

        pthread_mutex_lock(&ctx->dynamic_tenant_list_lock);

        cfl_list_add(&dynamic_tenant_id->_head, &ctx->dynamic_tenant_list);

        pthread_mutex_unlock(&ctx->dynamic_tenant_list_lock);
    }

    /* Format the data to the expected Newrelic Payload */
    payload = loki_compose_payload(ctx,
                                   event_chunk->total_events,
                                   (char *) event_chunk->tag,
                                   flb_sds_len(event_chunk->tag),
                                   event_chunk->data, event_chunk->size,
                                   &dynamic_tenant_id->value);

    if (!payload) {
        flb_plg_error(ctx->ins, "cannot compose request payload");

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Map buffer */
    out_buf = payload;
    out_size = flb_sds_len(payload);

    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) payload, flb_sds_len(payload), (void **) &out_buf, &out_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        } else {
            compressed = FLB_TRUE;
            /* payload is not longer needed */
            flb_sds_destroy(payload);
        }
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");

        payload_release(out_buf, compressed);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        out_buf, out_size,
                        ctx->tcp_host, ctx->tcp_port,
                        NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");

        payload_release(out_buf, compressed);
        flb_upstream_conn_release(u_conn);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Set callback context to the HTTP client context */
    flb_http_set_callback_context(c, ctx->ins->callback);

    /* User Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Auth headers */
    if (ctx->http_user && ctx->http_passwd) { /* Basic */
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    } else if (ctx->bearer_token) { /* Bearer token */
        flb_http_bearer_auth(c, ctx->bearer_token);
    }

    /* Arbitrary additional headers */
    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    /* Add Content-Type header */
    flb_http_add_header(c,
                        FLB_SCALEWAY_CT, sizeof(FLB_SCALEWAY_CT) - 1,
                        FLB_SCALEWAY_CT_JSON, sizeof(FLB_SCALEWAY_CT_JSON) - 1);

    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Add X-Scope-OrgID header */
    if (dynamic_tenant_id->value != NULL) {
        flb_http_add_header(c,
                            FLB_SCALEWAY_HEADER_SCOPE, sizeof(FLB_SCALEWAY_HEADER_SCOPE) - 1,
                            dynamic_tenant_id->value,
                            flb_sds_len(dynamic_tenant_id->value));
    }
    else if (ctx->tenant_id) {
        flb_http_add_header(c,
                            FLB_SCALEWAY_HEADER_SCOPE, sizeof(FLB_SCALEWAY_HEADER_SCOPE) - 1,
                            ctx->tenant_id, flb_sds_len(ctx->tenant_id));
    }

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    payload_release(out_buf, compressed);

    /* Validate HTTP client return status */
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status == 400) {
            /*
             * Loki will return 400 if incoming data is out of order.
             * We should not retry such data.
             */
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i Not retrying.\n%s",
                          ctx->tcp_host, ctx->tcp_port, c->resp.status,
                          c->resp.payload);
            out_ret = FLB_ERROR;
        }
        else if (c->resp.status < 200 || c->resp.status > 205) {
            if (c->resp.payload) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->tcp_host, ctx->tcp_port, c->resp.status,
                              c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->tcp_host, ctx->tcp_port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->tcp_host, ctx->tcp_port,
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->tcp_host, ctx->tcp_port,
                              c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->tcp_host, ctx->tcp_port, ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(out_ret);
}

static void release_dynamic_tenant_ids(struct cfl_list *dynamic_tenant_list)
{
    struct cfl_list                         *iterator;
    struct cfl_list                         *backup;
    struct flb_scaleway_dynamic_tenant_id_entry *entry;

    cfl_list_foreach_safe(iterator, backup, dynamic_tenant_list) {
        entry = cfl_list_entry(iterator,
                               struct flb_scaleway_dynamic_tenant_id_entry,
                               _head);

        dynamic_tenant_id_destroy(entry);
    }
}

static int cb_scaleway_exit(void *data, struct flb_config *config)
{
    struct flb_scaleway *ctx = data;

    if (!ctx) {
        return 0;
    }

    pthread_mutex_lock(&ctx->dynamic_tenant_list_lock);

    release_dynamic_tenant_ids(&ctx->dynamic_tenant_list);

    pthread_mutex_unlock(&ctx->dynamic_tenant_list_lock);

    loki_config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "uri", FLB_SCALEWAY_URI,
     0, FLB_TRUE, offsetof(struct flb_scaleway, uri),
     "Specify a custom HTTP URI. It must start with forward slash."
    },

    {
     FLB_CONFIG_MAP_STR, "tenant_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, tenant_id),
     "Tenant ID used by default to push logs to Loki. If omitted or empty "
     "it assumes Loki is running in single-tenant mode and no X-Scope-OrgID "
     "header is sent."
    },

    {
     FLB_CONFIG_MAP_STR, "tenant_id_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, tenant_id_key_config),
     "If set, X-Scope-OrgID will be the value of the key from incoming record. "
     "It is useful to set X-Scode-OrgID dynamically."
    },

    {
     FLB_CONFIG_MAP_CLIST, "labels", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, labels),
     "labels for API requests. If no value is set, the default label is 'job=fluent-bit'"
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_kubernetes_labels", "false",
     0, FLB_TRUE, offsetof(struct flb_scaleway, auto_kubernetes_labels),
     "If set to true, it will add all Kubernetes labels to Loki labels.",
    },

    {
     FLB_CONFIG_MAP_BOOL, "drop_single_key", "false",
     0, FLB_TRUE, offsetof(struct flb_scaleway, drop_single_key),
     "If set to true and only a single key remains, the log line sent to Loki "
     "will be the value of that key.",
    },

    {
     FLB_CONFIG_MAP_CLIST, "label_keys", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, label_keys),
     "Comma separated list of keys to use as stream labels."
    },

    {
     FLB_CONFIG_MAP_CLIST, "remove_keys", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, remove_keys),
     "Comma separated list of keys to remove."
    },

    {
     FLB_CONFIG_MAP_STR, "line_format", "json",
     0, FLB_TRUE, offsetof(struct flb_scaleway, line_format),
     "Format to use when flattening the record to a log line. Valid values are "
     "'json' or 'key_value'. If set to 'json' the log line sent to Loki will be "
     "the Fluent Bit record dumped as json. If set to 'key_value', the log line "
     "will be each item in the record concatenated together (separated by a "
     "single space) in the format '='."
    },

    {
     FLB_CONFIG_MAP_STR, "label_map_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, label_map_path),
     "A label map file path"
    },

    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, http_user),
     "Set HTTP auth user"
    },

    // must be a call api to cockpit create token with credential
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_scaleway, http_passwd),
     "Set HTTP auth password"
    },

    {
     FLB_CONFIG_MAP_STR, "bearer_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_scaleway, bearer_token),
     "Set bearer token auth"
    },

     // must be a call api to cockpit create token with credential
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_scaleway, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },

    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression in network transfer. Option available is 'gzip'"
    },

    {
      FLB_CONFIG_MAP_STR, "project_id", NULL,
      0, FLB_TRUE, offsetof(struct flb_scaleway, project_id),
      "Scaleway project ID"
    },

    /* EOF */
    {0}
};

/* for testing */
static int cb_scaleway_format_test(struct flb_config *config,
                               struct flb_input_instance *ins,
                               void *plugin_context,
                               void *flush_ctx,
                               int event_type,
                               const char *tag, int tag_len,
                               const void *data, size_t bytes,
                               void **out_data, size_t *out_size)
{
    int total_records;
    flb_sds_t payload = NULL;
    flb_sds_t dynamic_tenant_id;
    struct flb_scaleway *ctx = plugin_context;

    dynamic_tenant_id = NULL;

    /* Count number of records */
    total_records = flb_mp_count(data, bytes);

    payload = loki_compose_payload(ctx, total_records,
                                   (char *) tag, tag_len, data, bytes,
                                   &dynamic_tenant_id);
    if (payload == NULL) {
        if (dynamic_tenant_id != NULL) {
            flb_sds_destroy(dynamic_tenant_id);
        }

        return -1;
    }

    *out_data = payload;
    *out_size = flb_sds_len(payload);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_scaleway_plugin = {
    .name        = "scaleway",
    .description = "Scaleway",
    .cb_init     = cb_scaleway_init,
    .cb_flush    = cb_scaleway_flush,
    .cb_exit     = cb_scaleway_exit,
    .config_map  = config_map,

    /* for testing */
    .test_formatter.callback = cb_scaleway_format_test,

    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
