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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_gzip.h>

#include <msgpack.h>

#include "gce_metadata.h"
#include "stackdriver.h"
#include "stackdriver_conf.h"
#include "stackdriver_operation.h"
#include "stackdriver_source_location.h"
#include "stackdriver_http_request.h"
#include "stackdriver_timestamp.h"
#include "stackdriver_helper.h"
#include "stackdriver_resource_types.h"

pthread_key_t oauth2_type;
pthread_key_t oauth2_token;
pthread_key_t oauth2_token_expires;

static void oauth2_cache_exit(void *ptr)
{
    if (ptr) {
        flb_sds_destroy(ptr);
    }
}

static void oauth2_cache_free_expiration(void *ptr)
{
    if (ptr) {
        flb_free(ptr);
    }
}

static void oauth2_cache_init()
{
    /* oauth2 pthread key */
    pthread_key_create(&oauth2_type, oauth2_cache_exit);
    pthread_key_create(&oauth2_token, oauth2_cache_exit);
    pthread_key_create(&oauth2_token_expires, oauth2_cache_free_expiration);
}

/* Set oauth2 type and token in pthread keys */
static void oauth2_cache_set(char *type, char *token, time_t expires)
{
    flb_sds_t tmp;
    time_t *tmp_expires;

    /* oauth2 type */
    tmp = pthread_getspecific(oauth2_type);
    if (tmp) {
        flb_sds_destroy(tmp);
    }
    tmp = flb_sds_create(type);
    pthread_setspecific(oauth2_type, tmp);

    /* oauth2 access token */
    tmp = pthread_getspecific(oauth2_token);
    if (tmp) {
        flb_sds_destroy(tmp);
    }
    tmp = flb_sds_create(token);
    pthread_setspecific(oauth2_token, tmp);

    /* oauth2 access token expiration */
    tmp_expires = pthread_getspecific(oauth2_token_expires);
    if (tmp_expires) {
        flb_free(tmp_expires);
    }
    tmp_expires = flb_calloc(1, sizeof(time_t));
    if (!tmp_expires) {
        flb_errno();
        return;
    }
    *tmp_expires = expires;
    pthread_setspecific(oauth2_token_expires, tmp_expires);
}

/* By using pthread keys cached values, compose the authorizatoin token */
static time_t oauth2_cache_get_expiration()
{
    time_t *expires = pthread_getspecific(oauth2_token_expires);
    if (expires) {
        return *expires;
    }
    return 0;
}

/* By using pthread keys cached values, compose the authorizatoin token */
static flb_sds_t oauth2_cache_to_token()
{
    flb_sds_t type;
    flb_sds_t token;
    flb_sds_t output;

    type = pthread_getspecific(oauth2_type);
    if (!type) {
        return NULL;
    }

    output = flb_sds_create(type);
    if (!output) {
        return NULL;
    }

    token = pthread_getspecific(oauth2_token);
    flb_sds_printf(&output, " %s", token);
    return output;
}

/*
 * Base64 Encoding in JWT must:
 *
 * - remove any trailing padding '=' character
 * - replace '+' with '-'
 * - replace '/' with '_'
 *
 * ref: https://www.rfc-editor.org/rfc/rfc7515.txt Appendix C
 */
int jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
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

static int jwt_encode(char *payload, char *secret,
                      char **out_signature, size_t *out_size,
                      struct flb_stackdriver *ctx)
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
    flb_sds_cat(out, buf, olen);
    flb_sds_cat(out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    jwt_base64_url_encode((unsigned char *) buf, buf_size,
                          (unsigned char *) payload, len, &olen);

    /* Append Payload */
    flb_sds_cat(out, buf, olen);

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

    len = strlen(secret);
    sig_len = sizeof(sig);

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

    jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    flb_sds_cat(out, ".", 1);
    flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);

    return 0;
}

/* Create a new oauth2 context and get a oauth2 token */
static int get_oauth2_token(struct flb_stackdriver *ctx)
{
    int ret;
    char *token;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    flb_oauth2_payload_clear(ctx->o);

    /* In case of using metadata server, fetch token from there */
    if (ctx->metadata_server_auth) {
        return gce_metadata_read_token(ctx);
    }

    /* JWT encode for oauth2 */
    issued = time(NULL);
    expires = issued + FLB_STD_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->client_email, FLB_STD_SCOPE,
             FLB_STD_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = jwt_encode(payload, ctx->private_key, &sig_data, &sig_size, ctx);
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

static flb_sds_t get_google_token(struct flb_stackdriver *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;
    time_t cached_expiration = 0;
    time_t current_timestamp = 0;

    ret = pthread_mutex_trylock(&ctx->token_mutex);
    if (ret == EBUSY) {
        /*
         * If the routine is locked we just use our pre-cached values and
         * compose the expected authorization value.
         *
         * If the routine fails it will return NULL and the caller will just
         * issue a FLB_RETRY.
         */
        output = oauth2_cache_to_token();
        cached_expiration = oauth2_cache_get_expiration();
        current_timestamp = time(NULL);

        if (current_timestamp < cached_expiration) {
            return output;
        } else {
            /*
             * Cached token is expired. Wait on lock to use up-to-date token
             * by either waiting for it to be refreshed or refresh it ourselves.
             */
            flb_plg_info(ctx->ins, "Cached token is expired. Waiting on lock.");
            ret = pthread_mutex_lock(&ctx->token_mutex);
        }
    }

    if (ret != 0) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        ret = get_oauth2_token(ctx);
    }

    /* Copy string to prevent race conditions (get_oauth2 can free the string) */
    if (ret == 0) {
        /* Update pthread keys cached values */
        oauth2_cache_set(ctx->o->token_type, ctx->o->access_token, ctx->o->expires_at);

        /* Compose outgoing buffer using cached values */
        output = oauth2_cache_to_token();
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

void replace_prefix_dot(flb_sds_t s, int tag_prefix_len)
{
    int i;
    int str_len;
    char c;

    if (!s) {
        return;
    }

    str_len = flb_sds_len(s);
    if (tag_prefix_len > str_len) {
        flb_error("[output] tag_prefix shouldn't be longer than local_resource_id");
        return;
    }

    for (i = 0; i < tag_prefix_len; i++) {
        c = s[i];

        if (c == '.') {
            s[i] = '_';
        }
    }
}
static int extract_msgpack_obj_from_msgpack_map(msgpack_object_map *root,
                                                char *name, int size,
                                                msgpack_object_type object_type,
                                                msgpack_object *val)
{
    int i;
    msgpack_object key;

    if (root == NULL) {
      return -1;
    }
    for (i = 0; i < root->size; i++) {
        key = root->ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            continue;
        }
        if (key.via.str.size == size
            && strncmp(key.via.str.ptr, name, size) == 0) {
            *val = root->ptr[i].val;
            if (val->type != object_type) {
                return -1;
            }
            return 0;
        }
    }
    return -1;
}


static flb_sds_t get_str_value_from_msgpack_map(msgpack_object_map map,
                                                const char *key, int key_size)
{
    int ret;
    msgpack_object v;
    flb_sds_t ptr = NULL;

    /* convert msgpack_object_map to msgpack_object */
    ret = extract_msgpack_obj_from_msgpack_map(&map, (char*) key, key_size,
                                               MSGPACK_OBJECT_STR, &v);
    if (ret == 0) {
        ptr = flb_sds_create_len(v.via.str.ptr, v.via.str.size);
    }
    return ptr;
}

/* parse_monitored_resource is to extract the monitoired resource labels
 * from "logging.googleapis.com/monitored_resource" in log data
 * and append to 'resource'/'labels' in log entry.
 * Monitored resource type is already read from resource field in stackdriver
 * output plugin configuration parameters.
 *
 * The structure of monitored_resource is:
 * {
 *   "logging.googleapis.com/monitored_resource": {
 *      "labels": {
 *         "resource_label": <label_value>,
 *      }
 *    }
 * }
 * See https://cloud.google.com/logging/docs/api/v2/resource-list#resource-types
 * for required labels for each monitored resource.
 */

static int parse_monitored_resource(struct flb_stackdriver *ctx, const void *data, size_t bytes, msgpack_packer *mp_pck)
{
    int ret = -1;
    msgpack_object *obj;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        obj = log_event.body;

        msgpack_object_kv *kv = obj->via.map.ptr;
        msgpack_object_kv *const kvend = obj->via.map.ptr + obj->via.map.size;
        for (; kv < kvend; ++kv) {
          if (kv->val.type == MSGPACK_OBJECT_MAP && kv->key.type == MSGPACK_OBJECT_STR
          && strncmp (MONITORED_RESOURCE_KEY, kv->key.via.str.ptr, kv->key.via.str.size) == 0) {
            msgpack_object subobj = kv->val;
            msgpack_object_kv *p = subobj.via.map.ptr;
            msgpack_object_kv *pend = subobj.via.map.ptr + subobj.via.map.size;
            for (; p < pend; ++p) {
              if (p->key.type != MSGPACK_OBJECT_STR || p->val.type != MSGPACK_OBJECT_MAP) {
                continue;
              }
              if (strncmp("labels", p->key.via.str.ptr, p->key.via.str.size) == 0) {
                  msgpack_object labels = p->val;
                  msgpack_object_kv *q = labels.via.map.ptr;
                  msgpack_object_kv *qend = labels.via.map.ptr + labels.via.map.size;
                  int fields = 0;
                  for (; q < qend; ++q) {
                    if (q->key.type != MSGPACK_OBJECT_STR || q->val.type != MSGPACK_OBJECT_STR) {
                        flb_plg_error(ctx->ins, "Key and value should be string in the %s/labels", MONITORED_RESOURCE_KEY);
                    }
                    ++fields;
                  }
                  if (fields > 0) {
                    msgpack_pack_map(mp_pck, fields);
                    q = labels.via.map.ptr;
                    for (; q < qend; ++q) {
                      if (q->key.type != MSGPACK_OBJECT_STR || q->val.type != MSGPACK_OBJECT_STR) {
                          continue;
                      }
                      flb_plg_debug(ctx->ins, "[%s] found in the payload", MONITORED_RESOURCE_KEY);
                      msgpack_pack_str(mp_pck, q->key.via.str.size);
                      msgpack_pack_str_body(mp_pck, q->key.via.str.ptr, q->key.via.str.size);
                      msgpack_pack_str(mp_pck, q->val.via.str.size);
                      msgpack_pack_str_body(mp_pck, q->val.via.str.ptr, q->val.via.str.size);
                    }

                    flb_log_event_decoder_destroy(&log_decoder);

                    return 0;
                  }
              }
            }
          }
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    flb_plg_debug(ctx->ins, "[%s] not found in the payload", MONITORED_RESOURCE_KEY);

    return ret;
}

/*
 * Given a local_resource_id, split the content using the proper separator generating
 * a linked list to store the spliited string
 */
static struct mk_list *parse_local_resource_id_to_list(char *local_resource_id, char *type)
{
    int ret = -1;
    int max_split = -1;
    int len_k8s_container;
    int len_k8s_node;
    int len_k8s_pod;
    struct mk_list *list;

    len_k8s_container = sizeof(K8S_CONTAINER) - 1;
    len_k8s_node = sizeof(K8S_NODE) - 1;
    len_k8s_pod = sizeof(K8S_POD) - 1;

    /* Allocate list head */
    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    /* Determinate the max split value based on type */
    if (strncmp(type, K8S_CONTAINER, len_k8s_container) == 0) {
        /* including the prefix of tag */
        max_split = 4;
    }
    else if (strncmp(type, K8S_NODE, len_k8s_node) == 0) {
        max_split = 2;
    }
    else if (strncmp(type, K8S_POD, len_k8s_pod) == 0) {
        max_split = 3;
    }

    /* The local_resource_id is splitted by '.' */
    ret = flb_slist_split_string(list, local_resource_id, '.', max_split);

    if (ret == -1 || mk_list_size(list) != max_split) {
        flb_error("error parsing local_resource_id [%s] for type %s", local_resource_id, type);
        flb_slist_destroy(list);
        flb_free(list);
        return NULL;
    }

    return list;
}

/*
 *    extract_local_resource_id():
 *  - extract the value from "logging.googleapis.com/local_resource_id" field
 *  - if local_resource_id is missing from the payLoad, use the tag of the log
 */
static int extract_local_resource_id(const void *data, size_t bytes,
                                     struct flb_stackdriver *ctx, const char *tag) {
    msgpack_object_map map;
    flb_sds_t local_resource_id;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    if ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = log_event.body->via.map;
        local_resource_id = get_str_value_from_msgpack_map(map, LOCAL_RESOURCE_ID_KEY,
                                                           LEN_LOCAL_RESOURCE_ID_KEY);

        if (local_resource_id == NULL) {
            /* if local_resource_id is not found, use the tag of the log */
            flb_plg_debug(ctx->ins, "local_resource_id not found, "
                                    "tag [%s] is assigned for local_resource_id", tag);
            local_resource_id = flb_sds_create(tag);
        }

        /* we need to create up the local_resource_id from previous log */
        if (ctx->local_resource_id) {
            flb_sds_destroy(ctx->local_resource_id);
        }

        ctx->local_resource_id = flb_sds_create(local_resource_id);

        flb_sds_destroy(local_resource_id);

        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "failed to unpack data");

        ret = -1;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    return ret;
}

/*
 *    set_monitored_resource_labels():
 *  - use the extracted local_resource_id to assign the label keys for different
 *    resource types that are specified in the configuration of stackdriver_out plugin
 */
static int set_monitored_resource_labels(struct flb_stackdriver *ctx, char *type)
{
    int ret = -1;
    int first = FLB_TRUE;
    int counter = 0;
    int len_k8s_container;
    int len_k8s_node;
    int len_k8s_pod;
    size_t prefix_len = 0;
    struct local_resource_id_list *ptr;
    struct mk_list *list = NULL;
    struct mk_list *head;
    flb_sds_t new_local_resource_id;

    if (!ctx->local_resource_id) {
        flb_plg_error(ctx->ins, "local_resource_is is not assigned");
        return -1;
    }

    len_k8s_container = sizeof(K8S_CONTAINER) - 1;
    len_k8s_node = sizeof(K8S_NODE) - 1;
    len_k8s_pod = sizeof(K8S_POD) - 1;

    prefix_len = flb_sds_len(ctx->tag_prefix);
    if (flb_sds_casecmp(ctx->tag_prefix, ctx->local_resource_id, prefix_len) != 0) {
        flb_plg_error(ctx->ins, "tag_prefix [%s] doesn't match the prefix of"
                      " local_resource_id [%s]", ctx->tag_prefix,
                      ctx->local_resource_id);
        return -1;
    }

    new_local_resource_id = flb_sds_create_len(ctx->local_resource_id,
                                               flb_sds_len(ctx->local_resource_id));
    replace_prefix_dot(new_local_resource_id, prefix_len - 1);

    if (strncmp(type, K8S_CONTAINER, len_k8s_container) == 0) {
        list = parse_local_resource_id_to_list(new_local_resource_id, K8S_CONTAINER);
        if (!list) {
            goto error;
        }

        /* iterate through the list */
        mk_list_foreach(head, list) {
            ptr = mk_list_entry(head, struct local_resource_id_list, _head);
            if (first) {
                first = FLB_FALSE;
                continue;
            }

            /* Follow the order of fields in local_resource_id */
            if (counter == 0) {
                if (ctx->namespace_name) {
                    flb_sds_destroy(ctx->namespace_name);
                }
                ctx->namespace_name = flb_sds_create(ptr->val);
            }
            else if (counter == 1) {
                if (ctx->pod_name) {
                    flb_sds_destroy(ctx->pod_name);
                }
                ctx->pod_name = flb_sds_create(ptr->val);
            }
            else if (counter == 2) {
                if (ctx->container_name) {
                    flb_sds_destroy(ctx->container_name);
                }
                ctx->container_name = flb_sds_create(ptr->val);
            }

            counter++;
        }

        if (!ctx->namespace_name || !ctx->pod_name || !ctx->container_name) {
            goto error;
        }
    }
    else if (strncmp(type, K8S_NODE, len_k8s_node) == 0) {
        list = parse_local_resource_id_to_list(new_local_resource_id, K8S_NODE);
        if (!list) {
            goto error;
        }

        mk_list_foreach(head, list) {
            ptr = mk_list_entry(head, struct local_resource_id_list, _head);
            if (first) {
                first = FLB_FALSE;
                continue;
            }

            if (ptr != NULL) {
                if (ctx->node_name) {
                    flb_sds_destroy(ctx->node_name);
                }
                ctx->node_name = flb_sds_create(ptr->val);
            }
        }

        if (!ctx->node_name) {
            goto error;
        }
    }
    else if (strncmp(type, K8S_POD, len_k8s_pod) == 0) {
        list = parse_local_resource_id_to_list(new_local_resource_id, K8S_POD);
        if (!list) {
            goto error;
        }

        mk_list_foreach(head, list) {
            ptr = mk_list_entry(head, struct local_resource_id_list, _head);
            if (first) {
                first = FLB_FALSE;
                continue;
            }

            /* Follow the order of fields in local_resource_id */
            if (counter == 0) {
                if (ctx->namespace_name) {
                    flb_sds_destroy(ctx->namespace_name);
                }
                ctx->namespace_name = flb_sds_create(ptr->val);
            }
            else if (counter == 1) {
                if (ctx->pod_name) {
                    flb_sds_destroy(ctx->pod_name);
                }
                ctx->pod_name = flb_sds_create(ptr->val);
            }

            counter++;
        }

        if (!ctx->namespace_name || !ctx->pod_name) {
            goto error;
        }
    }

    ret = 0;

    if (list) {
        flb_slist_destroy(list);
        flb_free(list);
    }
    flb_sds_destroy(new_local_resource_id);

    return ret;

 error:
    if (list) {
        flb_slist_destroy(list);
        flb_free(list);
    }

    if (strncmp(type, K8S_CONTAINER, len_k8s_container) == 0) {
        if (ctx->namespace_name) {
            flb_sds_destroy(ctx->namespace_name);
        }

        if (ctx->pod_name) {
            flb_sds_destroy(ctx->pod_name);
        }

        if (ctx->container_name) {
            flb_sds_destroy(ctx->container_name);
        }
    }
    else if (strncmp(type, K8S_NODE, len_k8s_node) == 0) {
        if (ctx->node_name) {
            flb_sds_destroy(ctx->node_name);
        }
    }
    else if (strncmp(type, K8S_POD, len_k8s_pod) == 0) {
        if (ctx->namespace_name) {
            flb_sds_destroy(ctx->namespace_name);
        }

        if (ctx->pod_name) {
            flb_sds_destroy(ctx->pod_name);
        }
    }

    flb_sds_destroy(new_local_resource_id);
    return -1;
}

static int is_tag_match_regex(struct flb_stackdriver *ctx,
                              const char *tag, int tag_len)
{
    int ret;
    int tag_prefix_len;
    int len_to_be_matched;
    const char *tag_str_to_be_matcheds;

    tag_prefix_len = flb_sds_len(ctx->tag_prefix);
    if (tag_len > tag_prefix_len &&
        flb_sds_cmp(ctx->tag_prefix, tag, tag_prefix_len) != 0) {
        return 0;
    }

    tag_str_to_be_matcheds = tag + tag_prefix_len;
    len_to_be_matched = tag_len - tag_prefix_len;
    ret = flb_regex_match(ctx->regex,
                          (unsigned char *) tag_str_to_be_matcheds,
                          len_to_be_matched);

    /* 1 -> match;  0 -> doesn't match;  < 0 -> error */
    return ret;
}

static int is_local_resource_id_match_regex(struct flb_stackdriver *ctx)
{
    int ret;
    int prefix_len;
    int len_to_be_matched;
    const char *str_to_be_matcheds;

    if (!ctx->local_resource_id) {
        flb_plg_warn(ctx->ins, "local_resource_id not found in the payload");
        return -1;
    }

    prefix_len = flb_sds_len(ctx->tag_prefix);
    str_to_be_matcheds = ctx->local_resource_id + prefix_len;
    len_to_be_matched = flb_sds_len(ctx->local_resource_id) - prefix_len;

    ret = flb_regex_match(ctx->regex,
                          (unsigned char *) str_to_be_matcheds,
                          len_to_be_matched);

    /* 1 -> match;  0 -> doesn't match;  < 0 -> error */
    return ret;
}

static void cb_results(const char *name, const char *value,
                       size_t vlen, void *data);
/*
 * extract_resource_labels_from_regex(4) will only be called if the
 * tag or local_resource_id field matches the regex rule
 */
static int extract_resource_labels_from_regex(struct flb_stackdriver *ctx,
                                              const char *tag, int tag_len,
                                              int from_tag)
{
    int ret = 1;
    int prefix_len;
    int len_to_be_matched;
    int local_resource_id_len;
    const char *str_to_be_matcheds;
    struct flb_regex_search result;

    prefix_len = flb_sds_len(ctx->tag_prefix);
    if (from_tag == FLB_TRUE) {
        local_resource_id_len = tag_len;
        str_to_be_matcheds = tag + prefix_len;
    }
    else {
        // this will be called only if the payload contains local_resource_id
        local_resource_id_len = flb_sds_len(ctx->local_resource_id);
        str_to_be_matcheds = ctx->local_resource_id + prefix_len;
    }

    len_to_be_matched = local_resource_id_len - prefix_len;
    ret = flb_regex_do(ctx->regex, str_to_be_matcheds, len_to_be_matched, &result);
    if (ret <= 0) {
        flb_plg_warn(ctx->ins, "invalid pattern for given value %s when"
                     " extracting resource labels", str_to_be_matcheds);
        return -1;
    }

    flb_regex_parse(ctx->regex, &result, cb_results, ctx);

    return ret;
}

static int process_local_resource_id(struct flb_stackdriver *ctx,
                                     const char *tag, int tag_len, char *type)
{
    int ret;

    // parsing local_resource_id from tag takes higher priority
    if (is_tag_match_regex(ctx, tag, tag_len) > 0) {
        ret = extract_resource_labels_from_regex(ctx, tag, tag_len, FLB_TRUE);
    }
    else if (is_local_resource_id_match_regex(ctx) > 0) {
        ret = extract_resource_labels_from_regex(ctx, tag, tag_len, FLB_FALSE);
    }
    else {
        ret = set_monitored_resource_labels(ctx, type);
    }

    return ret;
}

/*
 * get_payload_labels
 * - Iterate throught the original payload (obj) and find out the entry that matches
 *   the labels_key
 * - Used to convert all labels under labels_key to root-level `labels` field
 */
static msgpack_object *get_payload_labels(struct flb_stackdriver *ctx, msgpack_object *obj)
{
    int i;
    int len;
    msgpack_object_kv *kv = NULL;

    if (!obj || obj->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    len = flb_sds_len(ctx->labels_key);
    for (i = 0; i < obj->via.map.size; i++) {
        kv = &obj->via.map.ptr[i];
        if (flb_sds_casecmp(ctx->labels_key, kv->key.via.str.ptr, len) == 0) {
            /* only the first matching entry will be returned */
            return &kv->val;
        }
    }

    //flb_plg_debug(ctx->ins, "labels_key [%s] not found in the payload",
    //              ctx->labels_key);
    return NULL;
}

/*
 *    pack_resource_labels():
 *  - Looks through the resource_labels parameter and appends new key value
 *    pair to the log entry.
 *  - Supports field access, plaintext assignment and environment variables.
 */
static int pack_resource_labels(struct flb_stackdriver *ctx,
                                struct flb_mp_map_header *mh,
                                msgpack_packer *mp_pck,
                                const void *data,
                                size_t bytes)
{
    struct mk_list *head;
    struct flb_kv *label_kv;
    struct flb_record_accessor *ra;
    struct flb_ra_value *rval;
    int len;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    if (ctx->should_skip_resource_labels_api == FLB_TRUE) {
        return -1;
    }

    len = mk_list_size(&ctx->resource_labels_kvs);
    if (len == 0) {
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    if ((ret = flb_log_event_decoder_next(
                &log_decoder,
                &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        flb_mp_map_header_init(mh, mp_pck);
        mk_list_foreach(head, &ctx->resource_labels_kvs) {
            label_kv = mk_list_entry(head, struct flb_kv, _head);
            /*
             * KVs have the form destination=original, so the original key is the value.
             * If the value starts with '$', it will be processed using record accessor.
             * Otherwise, it will be treated as a plaintext assignment.
             */
            if (label_kv->val[0] == '$') {
                ra = flb_ra_create(label_kv->val, FLB_TRUE);
                rval = flb_ra_get_value_object(ra, *log_event.body);

                if (rval != NULL && rval->o.type == MSGPACK_OBJECT_STR) {
                    flb_mp_map_header_append(mh);
                    msgpack_pack_str(mp_pck, flb_sds_len(label_kv->key));
                    msgpack_pack_str_body(mp_pck, label_kv->key,
                        flb_sds_len(label_kv->key));
                    msgpack_pack_str(mp_pck, flb_sds_len(rval->val.string));
                    msgpack_pack_str_body(mp_pck, rval->val.string,
                        flb_sds_len(rval->val.string));
                    flb_ra_key_value_destroy(rval);
                } else {
                    flb_plg_warn(ctx->ins, "failed to find a corresponding entry for "
                        "resource label entry [%s=%s]", label_kv->key, label_kv->val);
                }
                flb_ra_destroy(ra);
            } else {
                flb_mp_map_header_append(mh);
                msgpack_pack_str(mp_pck, flb_sds_len(label_kv->key));
                msgpack_pack_str_body(mp_pck, label_kv->key,
                    flb_sds_len(label_kv->key));
                msgpack_pack_str(mp_pck, flb_sds_len(label_kv->val));
                msgpack_pack_str_body(mp_pck, label_kv->val,
                    flb_sds_len(label_kv->val));
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "failed to unpack data");

        flb_log_event_decoder_destroy(&log_decoder);

        return -1;
    }

    /* project_id should always be packed from config parameter */
    flb_mp_map_header_append(mh);
    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "project_id", 10);
    msgpack_pack_str(mp_pck, flb_sds_len(ctx->project_id));
    msgpack_pack_str_body(mp_pck,
                        ctx->project_id, flb_sds_len(ctx->project_id));

    flb_log_event_decoder_destroy(&log_decoder);
    flb_mp_map_header_end(mh);

    return 0;
}

static void pack_labels(struct flb_stackdriver *ctx,
                        msgpack_packer *mp_pck,
                        msgpack_object *payload_labels_ptr)
{
    int i;
    int labels_size = 0;
    struct mk_list *head;
    struct flb_kv *list_kv;
    msgpack_object_kv *obj_kv = NULL;

    /* Determine size of labels map */
    labels_size = mk_list_size(&ctx->config_labels);
    if (payload_labels_ptr != NULL &&
        payload_labels_ptr->type == MSGPACK_OBJECT_MAP) {
        labels_size += payload_labels_ptr->via.map.size;
    }

    msgpack_pack_map(mp_pck, labels_size);

    /* pack labels from the payload */
    if (payload_labels_ptr != NULL &&
        payload_labels_ptr->type == MSGPACK_OBJECT_MAP) {

        for (i = 0; i < payload_labels_ptr->via.map.size; i++) {
            obj_kv = &payload_labels_ptr->via.map.ptr[i];
            msgpack_pack_object(mp_pck, obj_kv->key);
            msgpack_pack_object(mp_pck, obj_kv->val);
        }
    }

    /* pack labels set in configuration */
    /* in msgpack duplicate keys are overriden by the last set */
    /* static label keys override payload labels */
    mk_list_foreach(head, &ctx->config_labels){
        list_kv = mk_list_entry(head, struct flb_kv, _head);
        msgpack_pack_str(mp_pck, flb_sds_len(list_kv->key));
        msgpack_pack_str_body(mp_pck, list_kv->key, flb_sds_len(list_kv->key));
        msgpack_pack_str(mp_pck, flb_sds_len(list_kv->val));
        msgpack_pack_str_body(mp_pck, list_kv->val, flb_sds_len(list_kv->val));
    }
}

static void cb_results(const char *name, const char *value,
                       size_t vlen, void *data)
{
    struct flb_stackdriver *ctx = data;

    if (vlen == 0) {
        return;
    }

    if (strcmp(name, "pod_name") == 0) {
        if (ctx->pod_name != NULL) {
            flb_sds_destroy(ctx->pod_name);
        }
        ctx->pod_name = flb_sds_create_len(value, vlen);
    }
    else if (strcmp(name, "namespace_name") == 0) {
        if (ctx->namespace_name != NULL) {
            flb_sds_destroy(ctx->namespace_name);
        }
        ctx->namespace_name = flb_sds_create_len(value, vlen);
    }
    else if (strcmp(name, "container_name") == 0) {
        if (ctx->container_name != NULL) {
            flb_sds_destroy(ctx->container_name);
        }
        ctx->container_name = flb_sds_create_len(value, vlen);
    }
    else if (strcmp(name, "node_name") == 0) {
        if (ctx->node_name != NULL) {
            flb_sds_destroy(ctx->node_name);
        }
        ctx->node_name = flb_sds_create_len(value, vlen);
    }

    return;
}

int flb_stackdriver_regex_init(struct flb_stackdriver *ctx)
{
    /* If a custom regex is not set, use the defaults */
    ctx->regex = flb_regex_create(ctx->custom_k8s_regex);
    if (!ctx->regex) {
        return -1;
    }

    return 0;
}

static int cb_stackdriver_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    int io_flags = FLB_IO_TLS;
    char *token;
    struct flb_stackdriver *ctx;

    /* Create config context */
    ctx = flb_stackdriver_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Set context */
    flb_output_set_context(ins, ctx);

    if (ctx->test_log_entry_format) {
        return 0;
    }

    /* Network mode IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Initialize oauth2 cache pthread keys */
    oauth2_cache_init();

    /* Create mutex for acquiring oauth tokens (they are shared across flush coroutines) */
    pthread_mutex_init(&ctx->token_mutex, NULL);

    /* Create Upstream context for Stackdriver Logging (no oauth2 service) */
    ctx->u = flb_upstream_create_url(config, ctx->cloud_logging_write_url,
                                     io_flags, ins->tls);
    ctx->metadata_u = flb_upstream_create_url(config, ctx->metadata_server,
                                              FLB_IO_TCP, NULL);

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(ctx->config, FLB_STD_AUTH_URL, 3000);

    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }
    if (!ctx->metadata_u) {
        flb_plg_error(ctx->ins, "metadata upstream creation failed");
        return -1;
    }
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

    /* Metadata Upstream Sync flags */
    flb_stream_disable_async_mode(&ctx->metadata_u->base);

    if (ins->test_mode == FLB_FALSE) {
        /* Retrieve oauth2 token */
        token = get_google_token(ctx);
        if (!token) {
            flb_plg_warn(ctx->ins, "token retrieval failed");
        }
        else {
            flb_sds_destroy(token);
        }
    }

    if (ctx->metadata_server_auth) {
        ret = gce_metadata_read_project_id(ctx);
        if (ret == -1) {
            return -1;
        }

        if (ctx->resource_type != RESOURCE_TYPE_GENERIC_NODE
            && ctx->resource_type != RESOURCE_TYPE_GENERIC_TASK) {
            ret = gce_metadata_read_zone(ctx);
            if (ret == -1) {
                return -1;
            }

            ret = gce_metadata_read_instance_id(ctx);
            if (ret == -1) {
                return -1;
            }
        }
    }

    /* Validate project_id */
    if (!ctx->project_id) {
        flb_plg_error(ctx->ins, "property 'project_id' is not set");
        return -1;
    }

    if (!ctx->export_to_project_id) {
        ctx->export_to_project_id = ctx->project_id;
    }

    ret = flb_stackdriver_regex_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to init stackdriver custom regex");
        return -1;
    }

    return 0;
}

static int validate_severity_level(severity_t * s,
                                   const char * str,
                                   const unsigned int str_size)
{
    int i = 0;

    const static struct {
        severity_t s;
        const unsigned int str_size;
        const char * str;
    }   enum_mapping[] = {
        {FLB_STD_EMERGENCY, 9, "EMERGENCY"},
        {FLB_STD_EMERGENCY, 5, "EMERG"    },

        {FLB_STD_ALERT    , 1, "A"        },
        {FLB_STD_ALERT    , 5, "ALERT"    },

        {FLB_STD_CRITICAL , 1, "C"        },
        {FLB_STD_CRITICAL , 1, "F"        },
        {FLB_STD_CRITICAL , 4, "CRIT"     },
        {FLB_STD_CRITICAL , 5, "FATAL"    },
        {FLB_STD_CRITICAL , 8, "CRITICAL" },

        {FLB_STD_ERROR    , 1, "E"        },
        {FLB_STD_ERROR    , 3, "ERR"      },
        {FLB_STD_ERROR    , 5, "ERROR"    },
        {FLB_STD_ERROR    , 6, "SEVERE"   },

        {FLB_STD_WARNING  , 1, "W"        },
        {FLB_STD_WARNING  , 4, "WARN"     },
        {FLB_STD_WARNING  , 7, "WARNING"  },

        {FLB_STD_NOTICE   , 1, "N"        },
        {FLB_STD_NOTICE   , 6, "NOTICE"   },

        {FLB_STD_INFO     , 1, "I"        },
        {FLB_STD_INFO     , 4, "INFO"     },

        {FLB_STD_DEBUG    , 1, "D"        },
        {FLB_STD_DEBUG    , 5, "DEBUG"    },
        {FLB_STD_DEBUG    , 5, "TRACE"    },
        {FLB_STD_DEBUG    , 9, "TRACE_INT"},
        {FLB_STD_DEBUG    , 4, "FINE"     },
        {FLB_STD_DEBUG    , 5, "FINER"    },
        {FLB_STD_DEBUG    , 6, "FINEST"   },
        {FLB_STD_DEBUG    , 6, "CONFIG"   },

        {FLB_STD_DEFAULT  , 7, "DEFAULT"  }
    };

    for (i = 0; i < sizeof (enum_mapping) / sizeof (enum_mapping[0]); ++i) {
        if (enum_mapping[i].str_size != str_size) {
            continue;
        }

        if (strncasecmp(str, enum_mapping[i].str, str_size) == 0) {
            *s = enum_mapping[i].s;
            return 0;
        }
    }
    return -1;
}

static int get_msgpack_obj(msgpack_object * subobj, const msgpack_object * o,
                           const flb_sds_t key, const int key_size,
                           msgpack_object_type type)
{
    int i = 0;
    msgpack_object_kv * p = NULL;

    if (o == NULL || subobj == NULL) {
        return -1;
    }

    for (i = 0; i < o->via.map.size; i++) {
        p = &o->via.map.ptr[i];
        if (p->val.type != type) {
            continue;
        }

        if (flb_sds_cmp(key, p->key.via.str.ptr, p->key.via.str.size) == 0) {
            *subobj = p->val;
            return 0;
        }
    }
    return -1;
}

static int get_string(flb_sds_t * s, const msgpack_object * o, const flb_sds_t key)
{
    msgpack_object tmp;
    if (get_msgpack_obj(&tmp, o, key, flb_sds_len(key), MSGPACK_OBJECT_STR) == 0) {
        *s = flb_sds_create_len(tmp.via.str.ptr, tmp.via.str.size);
        return 0;
    }

    *s = 0;
    return -1;
}

static int get_severity_level(severity_t * s, const msgpack_object * o,
                              const flb_sds_t key)
{
    msgpack_object tmp;
    if (get_msgpack_obj(&tmp, o, key, flb_sds_len(key), MSGPACK_OBJECT_STR) == 0
        && validate_severity_level(s, tmp.via.str.ptr, tmp.via.str.size) == 0) {
        return 0;
    }
    *s = 0;
    return -1;
}

static int get_trace_sampled(int * trace_sampled_value, const msgpack_object * src_obj,
                             const flb_sds_t key)
{
    msgpack_object tmp;
    int ret = get_msgpack_obj(&tmp, src_obj, key, flb_sds_len(key), MSGPACK_OBJECT_BOOLEAN);

    if (ret == 0 && tmp.via.boolean == true) {
        *trace_sampled_value = FLB_TRUE;
        return 0;
    } else if (ret == 0 && tmp.via.boolean == false) {
        *trace_sampled_value = FLB_FALSE;
        return 0;
    }

    return -1;
}

static insert_id_status validate_insert_id(msgpack_object * insert_id_value,
                                           const msgpack_object * obj)
{
    int i = 0;
    msgpack_object_kv * p = NULL;
    insert_id_status ret = INSERTID_NOT_PRESENT;

    if (obj == NULL) {
        return ret;
    }

    for (i = 0; i < obj->via.map.size; i++) {
        p = &obj->via.map.ptr[i];
        if (p->key.type != MSGPACK_OBJECT_STR) {
            continue;
        }
        if (validate_key(p->key, DEFAULT_INSERT_ID_KEY, INSERT_ID_SIZE)) {
            if (p->val.type == MSGPACK_OBJECT_STR && p->val.via.str.size > 0) {
                *insert_id_value = p->val;
                ret = INSERTID_VALID;
            }
            else {
                ret = INSERTID_INVALID;
            }
            break;
        }
    }
    return ret;
}

static int pack_payload(int insert_id_extracted,
                        int operation_extracted,
                        int operation_extra_size,
                        int source_location_extracted,
                        int source_location_extra_size,
                        int http_request_extracted,
                        int http_request_extra_size,
                        timestamp_status tms_status,
                        msgpack_packer *mp_pck, msgpack_object *obj,
                        struct flb_stackdriver *ctx)
{
    /* Specified fields include local_resource_id, operation, sourceLocation ... */
    int i, j;
    int to_remove = 0;
    int ret;
    int map_size;
    int new_map_size;
    int len;
    int len_to_be_removed;
    int key_not_found;
    int text_payload_len = 0;
    int is_string_text_payload = FLB_FALSE;
    int write_to_textpayload_field = FLB_FALSE;
    flb_sds_t removed;
    flb_sds_t monitored_resource_key;
    flb_sds_t local_resource_id_key;
    flb_sds_t stream;
    flb_sds_t text_payload = NULL;
    msgpack_object_kv *kv = obj->via.map.ptr;
    msgpack_object_kv *const kvend = obj->via.map.ptr + obj->via.map.size;

    monitored_resource_key = flb_sds_create(MONITORED_RESOURCE_KEY);
    local_resource_id_key = flb_sds_create(LOCAL_RESOURCE_ID_KEY);
    stream = flb_sds_create("stream");
    /*
     * array of elements that need to be removed from payload,
     * special field 'operation' will be processed individually
     */
    flb_sds_t to_be_removed[] =
    {
        monitored_resource_key,
        local_resource_id_key,
        ctx->project_id_key,
        ctx->labels_key,
        ctx->severity_key,
        ctx->trace_key,
        ctx->span_id_key,
        ctx->trace_sampled_key,
        ctx->log_name_key,
        stream
        /* more special fields are required to be added, but, if this grows with more
           than a few records, it might need to be converted to flb_hash
         */
    };

    if (insert_id_extracted == FLB_TRUE) {
        to_remove += 1;
    }
    if (operation_extracted == FLB_TRUE && operation_extra_size == 0) {
        to_remove += 1;
    }
    if (source_location_extracted == FLB_TRUE && source_location_extra_size == 0) {
        to_remove += 1;
    }
    if (http_request_extracted == FLB_TRUE && http_request_extra_size == 0) {
        to_remove += 1;
    }
    if (tms_status == FORMAT_TIMESTAMP_OBJECT) {
        to_remove += 1;
    }
    if (tms_status == FORMAT_TIMESTAMP_DUO_FIELDS) {
        to_remove += 2;
    }

    map_size = obj->via.map.size;
    len_to_be_removed = sizeof(to_be_removed) / sizeof(to_be_removed[0]);
    for (i = 0; i < map_size; i++) {
        kv = &obj->via.map.ptr[i];
        len = kv->key.via.str.size;
        for (j = 0; j < len_to_be_removed; j++) {
            removed = to_be_removed[j];
            /*
             * check length of key to avoid partial matching
             * e.g. labels key = labels && kv->key = labelss
             */
            if (removed && flb_sds_cmp(removed, kv->key.via.str.ptr, len) == 0) {
                to_remove += 1;
                break;
            }
        }
    }

    new_map_size = map_size - to_remove;

    if (ctx->text_payload_key && get_string(&text_payload, obj, ctx->text_payload_key) == 0) {
        is_string_text_payload = FLB_TRUE;
    }

    /* write to textPayload if text_payload_key is the only residual string field*/
    if ((new_map_size == 1) && is_string_text_payload) {
      write_to_textpayload_field = FLB_TRUE;
    }

    if (write_to_textpayload_field) {
        msgpack_pack_str(mp_pck, 11);
        msgpack_pack_str_body(mp_pck, "textPayload", 11);

        text_payload_len = flb_sds_len(text_payload);
        msgpack_pack_str(mp_pck, text_payload_len);
        msgpack_pack_str_body(mp_pck, text_payload, text_payload_len);
    } else {
      /* jsonPayload */
      msgpack_pack_str(mp_pck, 11);
      msgpack_pack_str_body(mp_pck, "jsonPayload", 11);

      ret = msgpack_pack_map(mp_pck, new_map_size);
      if (ret < 0) {
          goto error;
      }
    }

    /* points back to the beginning of map */
    kv = obj->via.map.ptr;
    for(; kv != kvend; ++kv) {
        key_not_found = 1;

        /* processing logging.googleapis.com/insertId */
        if (insert_id_extracted == FLB_TRUE
            && validate_key(kv->key, DEFAULT_INSERT_ID_KEY, INSERT_ID_SIZE)) {
            continue;
        }

        /* processing logging.googleapis.com/operation */
        if (validate_key(kv->key, OPERATION_FIELD_IN_JSON,
                         OPERATION_KEY_SIZE)
            && kv->val.type == MSGPACK_OBJECT_MAP) {
            if (operation_extra_size > 0) {
                msgpack_pack_object(mp_pck, kv->key);
                pack_extra_operation_subfields(mp_pck, &kv->val, operation_extra_size);
            }
            continue;
        }

        if (validate_key(kv->key, SOURCELOCATION_FIELD_IN_JSON,
                         SOURCE_LOCATION_SIZE)
            && kv->val.type == MSGPACK_OBJECT_MAP) {

            if (source_location_extra_size > 0) {
                msgpack_pack_object(mp_pck, kv->key);
                pack_extra_source_location_subfields(mp_pck, &kv->val,
                                                     source_location_extra_size);
            }
            continue;
        }

        if (validate_key(kv->key, ctx->http_request_key,
                         ctx->http_request_key_size)
            && kv->val.type == MSGPACK_OBJECT_MAP) {

            if(http_request_extra_size > 0) {
                msgpack_pack_object(mp_pck, kv->key);
                pack_extra_http_request_subfields(mp_pck, &kv->val,
                                                  http_request_extra_size);
            }
            continue;
        }

        if (validate_key(kv->key, "timestamp", 9)
            && tms_status == FORMAT_TIMESTAMP_OBJECT) {
            continue;
        }

        if (validate_key(kv->key, "timestampSeconds", 16)
            && tms_status == FORMAT_TIMESTAMP_DUO_FIELDS) {
            continue;
        }
        if (validate_key(kv->key, "timestampNanos", 14)
            && tms_status == FORMAT_TIMESTAMP_DUO_FIELDS) {
            continue;
        }

        len = kv->key.via.str.size;
        for (j = 0; j < len_to_be_removed; j++) {
            removed = to_be_removed[j];
            if (removed && flb_sds_cmp(removed, kv->key.via.str.ptr, len) == 0) {
                key_not_found = 0;
                break;
            }
        }

        /* write residual log fields to jsonPayload */
        if (key_not_found && !write_to_textpayload_field) {
            ret = msgpack_pack_object(mp_pck, kv->key);
            if (ret < 0) {
                goto error;
            }
            ret = msgpack_pack_object(mp_pck, kv->val);
            if (ret < 0) {
                goto error;
            }
        }
    }

    flb_sds_destroy(monitored_resource_key);
    flb_sds_destroy(local_resource_id_key);
    flb_sds_destroy(stream);
    flb_sds_destroy(text_payload);
    return 0;

    error:
        flb_sds_destroy(monitored_resource_key);
        flb_sds_destroy(local_resource_id_key);
        flb_sds_destroy(stream);
        flb_sds_destroy(text_payload);
        return ret;
}

static flb_sds_t stackdriver_format(struct flb_stackdriver *ctx,
                                    int total_records,
                                    const char *tag, int tag_len,
                                    const void *data, size_t bytes,
                                    struct flb_config *config)
{
    int len;
    int ret;
    int array_size = 0;
    /* The default value is 3: timestamp, jsonPayload, logName. */
    int entry_size = 3;
    size_t s;
    // size_t off = 0;
    char path[PATH_MAX];
    char time_formatted[255];
    const char *newtag;
    const char *new_log_name;
    msgpack_object *obj;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    flb_sds_t out_buf;
    struct flb_mp_map_header mh;

    /* Parameters for project_id_key */
    int project_id_extracted = FLB_FALSE;
    flb_sds_t project_id_key;

    /* Parameters for severity */
    int severity_extracted = FLB_FALSE;
    severity_t severity;

    /* Parameters for trace */
    int trace_extracted = FLB_FALSE;
    flb_sds_t trace = NULL;
    char stackdriver_trace[PATH_MAX];
    const char *new_trace;

    /* Parameters for span id */
    int span_id_extracted = FLB_FALSE;
    flb_sds_t span_id;

    /* Parameters for trace sampled */
    int trace_sampled_extracted = FLB_FALSE;
    int trace_sampled = FLB_FALSE;

    /* Parameters for log name */
    int log_name_extracted = FLB_FALSE;
    flb_sds_t log_name = NULL;
    flb_sds_t stream = NULL;
    flb_sds_t stream_key;

    /* Parameters for insertId */
    msgpack_object insert_id_obj;
    insert_id_status in_status;
    int insert_id_extracted;

    /* Parameters in Operation */
    flb_sds_t operation_id;
    flb_sds_t operation_producer;
    int operation_first = FLB_FALSE;
    int operation_last = FLB_FALSE;
    int operation_extracted = FLB_FALSE;
    int operation_extra_size = 0;

    /* Parameters for sourceLocation */
    flb_sds_t source_location_file;
    int64_t source_location_line = 0;
    flb_sds_t source_location_function;
    int source_location_extracted = FLB_FALSE;
    int source_location_extra_size = 0;

    /* Parameters for httpRequest */
    struct http_request_field http_request;
    int http_request_extracted = FLB_FALSE;
    int http_request_extra_size = 0;

    /* Parameters for Timestamp */
    struct tm tm;
    // struct flb_time tms;
    timestamp_status tms_status;
    /* Count number of records */
    array_size = total_records;

    /* Parameters for labels */
    msgpack_object *payload_labels_ptr;
    int labels_size = 0;

    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    /*
     * Search each entry and validate insertId.
     * Reject the entry if insertId is invalid.
     * If all the entries are rejected, stop formatting.
     *
     */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        /* Extract insertId */
        in_status = validate_insert_id(&insert_id_obj, log_event.body);

        if (in_status == INSERTID_INVALID) {
            flb_plg_error(ctx->ins,
                          "Incorrect insertId received. InsertId should be non-empty string.");
            array_size -= 1;
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Sounds like this should compare to -1 instead of zero */
    if (array_size == 0) {
        return NULL;
    }

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Pack root map (resource & entries):
     *
     * {"resource": {"type": "...", "labels": {...},
     *  "entries": []
     */
    msgpack_pack_map(&mp_pck, 3);

    /* Set partialSuccess to true */
    msgpack_pack_str(&mp_pck, 14);
    msgpack_pack_str_body(&mp_pck, "partialSuccess", 14);
    msgpack_pack_true(&mp_pck);

    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "resource", 8);

    /* type & labels */
    msgpack_pack_map(&mp_pck, 2);

    /* type */
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "type", 4);
    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->resource));
    msgpack_pack_str_body(&mp_pck, ctx->resource,
                          flb_sds_len(ctx->resource));

    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "labels", 6);

    ret = pack_resource_labels(ctx, &mh, &mp_pck, data, bytes);
    if (ret != 0) {
        if (ctx->resource_type == RESOURCE_TYPE_K8S) {
            ret = extract_local_resource_id(data, bytes, ctx, tag);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "fail to construct local_resource_id");
                msgpack_sbuffer_destroy(&mp_sbuf);
                return NULL;
            }
        }
        ret = parse_monitored_resource(ctx, data, bytes, &mp_pck);
        if (ret != 0) {
            if (strcmp(ctx->resource, "global") == 0) {
                /* global resource has field project_id */
                msgpack_pack_map(&mp_pck, 1);
                msgpack_pack_str(&mp_pck, 10);
                msgpack_pack_str_body(&mp_pck, "project_id", 10);
                msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                msgpack_pack_str_body(&mp_pck,
                                    ctx->project_id, flb_sds_len(ctx->project_id));
            }
            else if (ctx->resource_type == RESOURCE_TYPE_GENERIC_NODE
                || ctx->resource_type == RESOURCE_TYPE_GENERIC_TASK) {
                flb_mp_map_header_init(&mh, &mp_pck);

                if (ctx->resource_type == RESOURCE_TYPE_GENERIC_NODE && ctx->node_id) {
                    /* generic_node has fields project_id, location, namespace, node_id */
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 7);
                    msgpack_pack_str_body(&mp_pck, "node_id", 7);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->node_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->node_id, flb_sds_len(ctx->node_id));
                }
                else {
                    /* generic_task has fields project_id, location, namespace, job, task_id */
                    if (ctx->job) {
                        flb_mp_map_header_append(&mh);
                        msgpack_pack_str(&mp_pck, 3);
                        msgpack_pack_str_body(&mp_pck, "job", 3);
                        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->job));
                        msgpack_pack_str_body(&mp_pck,
                                            ctx->job, flb_sds_len(ctx->job));
                    }

                    if (ctx->task_id) {
                        flb_mp_map_header_append(&mh);
                        msgpack_pack_str(&mp_pck, 7);
                        msgpack_pack_str_body(&mp_pck, "task_id", 7);
                        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->task_id));
                        msgpack_pack_str_body(&mp_pck,
                                            ctx->task_id, flb_sds_len(ctx->task_id));
                    }
                }

                if (ctx->project_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "project_id", 10);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->project_id, flb_sds_len(ctx->project_id));
                }

                if (ctx->location) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "location", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->location));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->location, flb_sds_len(ctx->location));
                }

                if (ctx->namespace_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 9);
                    msgpack_pack_str_body(&mp_pck, "namespace", 9);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->namespace_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->namespace_id, flb_sds_len(ctx->namespace_id));
                }

                flb_mp_map_header_end(&mh);
            }
            else if (strcmp(ctx->resource, "gce_instance") == 0) {
                /* gce_instance resource has fields project_id, zone, instance_id */
                flb_mp_map_header_init(&mh, &mp_pck);

                if (ctx->project_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "project_id", 10);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->project_id, flb_sds_len(ctx->project_id));
                }

                if (ctx->zone) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 4);
                    msgpack_pack_str_body(&mp_pck, "zone", 4);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->zone));
                    msgpack_pack_str_body(&mp_pck, ctx->zone, flb_sds_len(ctx->zone));
                }

                if (ctx->instance_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 11);
                    msgpack_pack_str_body(&mp_pck, "instance_id", 11);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->instance_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->instance_id, flb_sds_len(ctx->instance_id));
                }
                flb_mp_map_header_end(&mh);
            }
            else if (strcmp(ctx->resource, K8S_CONTAINER) == 0) {
                /* k8s_container resource has fields project_id, location, cluster_name,
                *                                   namespace_name, pod_name, container_name
                *
                * The local_resource_id for k8s_container is in format:
                *    k8s_container.<namespace_name>.<pod_name>.<container_name>
                */

                ret = process_local_resource_id(ctx, tag, tag_len, K8S_CONTAINER);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "fail to extract resource labels "
                                "for k8s_container resource type");
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    return NULL;
                }

                flb_mp_map_header_init(&mh, &mp_pck);

                if (ctx->project_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "project_id", 10);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->project_id, flb_sds_len(ctx->project_id));
                }

                if (ctx->cluster_location) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "location", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_location,
                                        flb_sds_len(ctx->cluster_location));
                }

                if (ctx->cluster_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 12);
                    msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_name, flb_sds_len(ctx->cluster_name));
                }

                if (ctx->namespace_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 14);
                    msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->namespace_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->namespace_name,
                                        flb_sds_len(ctx->namespace_name));
                }

                if (ctx->pod_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "pod_name", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->pod_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->pod_name, flb_sds_len(ctx->pod_name));
                }

                if (ctx->container_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 14);
                    msgpack_pack_str_body(&mp_pck, "container_name", 14);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->container_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->container_name,
                                        flb_sds_len(ctx->container_name));
                }

                flb_mp_map_header_end(&mh);
            }
            else if (strcmp(ctx->resource, K8S_NODE) == 0) {
                /* k8s_node resource has fields project_id, location, cluster_name, node_name
                *
                * The local_resource_id for k8s_node is in format:
                *      k8s_node.<node_name>
                */

                ret = process_local_resource_id(ctx, tag, tag_len, K8S_NODE);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "fail to process local_resource_id from "
                                "log entry for k8s_node");
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    return NULL;
                }

                flb_mp_map_header_init(&mh, &mp_pck);

                if (ctx->project_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "project_id", 10);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->project_id, flb_sds_len(ctx->project_id));
                }

                if (ctx->cluster_location) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "location", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_location,
                                        flb_sds_len(ctx->cluster_location));
                }

                if (ctx->cluster_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 12);
                    msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_name, flb_sds_len(ctx->cluster_name));
                }

                if (ctx->node_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 9);
                    msgpack_pack_str_body(&mp_pck, "node_name", 9);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->node_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->node_name, flb_sds_len(ctx->node_name));
                }

                flb_mp_map_header_end(&mh);
            }
            else if (strcmp(ctx->resource, K8S_POD) == 0) {
                /* k8s_pod resource has fields project_id, location, cluster_name,
                *                             namespace_name, pod_name.
                *
                * The local_resource_id for k8s_pod is in format:
                *      k8s_pod.<namespace_name>.<pod_name>
                */

                ret = process_local_resource_id(ctx, tag, tag_len, K8S_POD);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "fail to process local_resource_id from "
                                "log entry for k8s_pod");
                    msgpack_sbuffer_destroy(&mp_sbuf);
                    return NULL;
                }

                flb_mp_map_header_init(&mh, &mp_pck);

                if (ctx->project_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "project_id", 10);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->project_id, flb_sds_len(ctx->project_id));
                }

                if (ctx->cluster_location) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "location", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_location,
                                        flb_sds_len(ctx->cluster_location));
                }

                if (ctx->cluster_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 12);
                    msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_name, flb_sds_len(ctx->cluster_name));
                }

                if (ctx->namespace_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 14);
                    msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->namespace_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->namespace_name,
                                        flb_sds_len(ctx->namespace_name));
                }

                if (ctx->pod_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "pod_name", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->pod_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->pod_name, flb_sds_len(ctx->pod_name));
                }

                flb_mp_map_header_end(&mh);
            }
            else if (strcmp(ctx->resource, K8S_CLUSTER) == 0) {
                /* k8s_cluster resource has fields project_id, location, cluster_name
                *
                * There is no local_resource_id for k8s_cluster as we get all info
                *      from plugin config
                */

                flb_mp_map_header_init(&mh, &mp_pck);

                if (ctx->project_id) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "project_id", 10);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->project_id, flb_sds_len(ctx->project_id));
                }

                if (ctx->cluster_location) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 8);
                    msgpack_pack_str_body(&mp_pck, "location", 8);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_location,
                                        flb_sds_len(ctx->cluster_location));
                }

                if (ctx->cluster_name) {
                    flb_mp_map_header_append(&mh);
                    msgpack_pack_str(&mp_pck, 12);
                    msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
                    msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
                    msgpack_pack_str_body(&mp_pck,
                                        ctx->cluster_name, flb_sds_len(ctx->cluster_name));
                }

                flb_mp_map_header_end(&mh);
            }
            else {
                flb_plg_error(ctx->ins, "unsupported resource type '%s'",
                            ctx->resource);
                msgpack_sbuffer_destroy(&mp_sbuf);
                return NULL;
            }
        }
    }
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "entries", 7);

    /* Append entries */
    msgpack_pack_array(&mp_pck, array_size);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);
        msgpack_sbuffer_destroy(&mp_sbuf);

        return NULL;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        obj = log_event.body;
        tms_status = extract_timestamp(obj, &log_event.timestamp);

        /*
         * Pack entry
         *
         * {
         *  "severity": "...",
         *  "labels": "...",
         *  "logName": "...",
         *  "jsonPayload": {...},
         *  "timestamp": "...",
         *  "spanId": "...",
         *  "traceSampled": <true or false>,
         *  "trace": "..."
         * }
         */
        entry_size = 3;

        /* Extract severity */
        severity_extracted = FLB_FALSE;
        if (ctx->severity_key
            && get_severity_level(&severity, obj, ctx->severity_key) == 0) {
            severity_extracted = FLB_TRUE;
            entry_size += 1;
        }

        /* Extract trace */
        trace_extracted = FLB_FALSE;
        if (ctx->trace_key
            && get_string(&trace, obj, ctx->trace_key) == 0) {
            trace_extracted = FLB_TRUE;
            entry_size += 1;
        }

        /* Extract span id */
        span_id_extracted = FLB_FALSE;
        if (ctx->span_id_key
            && get_string(&span_id, obj, ctx->span_id_key) == 0) {
            span_id_extracted = FLB_TRUE;
            entry_size += 1;
        }

        /* Extract trace sampled */
        trace_sampled_extracted = FLB_FALSE;
        if (ctx->trace_sampled_key
            && get_trace_sampled(&trace_sampled, obj, ctx->trace_sampled_key) == 0) {
            trace_sampled_extracted = FLB_TRUE;
            entry_size += 1;
        }

        /* Extract project id */
        project_id_extracted = FLB_FALSE;
        if (ctx->project_id_key
            && get_string(&project_id_key, obj, ctx->project_id_key) == 0) {
            project_id_extracted = FLB_TRUE;
        }

        /* Extract log name */
        log_name_extracted = FLB_FALSE;
        if (ctx->log_name_key
            && get_string(&log_name, obj, ctx->log_name_key) == 0) {
            log_name_extracted = FLB_TRUE;
        }

        /* Extract insertId */
        in_status = validate_insert_id(&insert_id_obj, obj);
        if (in_status == INSERTID_VALID) {
            insert_id_extracted = FLB_TRUE;
            entry_size += 1;
        }
        else if (in_status == INSERTID_NOT_PRESENT) {
            insert_id_extracted = FLB_FALSE;
        }
        else {
            if (trace_extracted == FLB_TRUE) {
                flb_sds_destroy(trace);
            }

            if (span_id_extracted == FLB_TRUE) {
                flb_sds_destroy(span_id);
            }

            if (project_id_extracted == FLB_TRUE) {
                flb_sds_destroy(project_id_key);
            }

            if (log_name_extracted == FLB_TRUE) {
                flb_sds_destroy(log_name);
            }

            continue;
        }

        /* Extract operation */
        operation_id = flb_sds_create("");
        operation_producer = flb_sds_create("");
        operation_first = FLB_FALSE;
        operation_last = FLB_FALSE;
        operation_extra_size = 0;
        operation_extracted = extract_operation(&operation_id, &operation_producer,
                                                &operation_first, &operation_last, obj,
                                                &operation_extra_size);

        if (operation_extracted == FLB_TRUE) {
            entry_size += 1;
        }

        /* Extract sourceLocation */
        source_location_file = flb_sds_create("");
        source_location_line = 0;
        source_location_function = flb_sds_create("");
        source_location_extra_size = 0;
        source_location_extracted = extract_source_location(&source_location_file,
                                                            &source_location_line,
                                                            &source_location_function,
                                                            obj,
                                                            &source_location_extra_size);

        if (source_location_extracted == FLB_TRUE) {
            entry_size += 1;
        }

        /* Extract httpRequest */
        init_http_request(&http_request);
        http_request_extra_size = 0;
        http_request_extracted = extract_http_request(&http_request,
                                                      ctx->http_request_key,
                                                      ctx->http_request_key_size,
                                                      obj, &http_request_extra_size);
        if (http_request_extracted == FLB_TRUE) {
            entry_size += 1;
        }

        /* Extract payload labels */
        payload_labels_ptr = get_payload_labels(ctx, obj);
        if (payload_labels_ptr != NULL &&
            payload_labels_ptr->type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "the type of payload labels should be map");
            flb_sds_destroy(operation_id);
            flb_sds_destroy(operation_producer);
            flb_sds_destroy(source_location_file);
            flb_sds_destroy(source_location_function);

            if (trace_extracted == FLB_TRUE) {
                flb_sds_destroy(trace);
            }

            if (span_id_extracted == FLB_TRUE) {
                flb_sds_destroy(span_id);
            }

            if (project_id_extracted == FLB_TRUE) {
                flb_sds_destroy(project_id_key);
            }

            if (log_name_extracted == FLB_TRUE) {
                flb_sds_destroy(log_name);
            }

            flb_log_event_decoder_destroy(&log_decoder);
            msgpack_sbuffer_destroy(&mp_sbuf);

            return NULL;
        }

        /* Number of parsed labels */
        labels_size = mk_list_size(&ctx->config_labels);
        if (payload_labels_ptr != NULL &&
            payload_labels_ptr->type == MSGPACK_OBJECT_MAP) {
            labels_size += payload_labels_ptr->via.map.size;
        }

        if (labels_size > 0) {
            entry_size += 1;
        }

        msgpack_pack_map(&mp_pck, entry_size);

        /* Add severity into the log entry */
        if (severity_extracted == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, 8);
            msgpack_pack_str_body(&mp_pck, "severity", 8);
            msgpack_pack_int(&mp_pck, severity);
        }

        /* Add trace into the log entry */
        if (trace_extracted == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, 5);
            msgpack_pack_str_body(&mp_pck, "trace", 5);

            if (ctx->autoformat_stackdriver_trace) {
                len = snprintf(stackdriver_trace, sizeof(stackdriver_trace) - 1,
                    "projects/%s/traces/%s", ctx->project_id, trace);
                new_trace = stackdriver_trace;
            }
            else {
                len = flb_sds_len(trace);
                new_trace = trace;
            }

            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, new_trace, len);
            flb_sds_destroy(trace);
        }

        /* Add spanId field into the log entry */
        if (span_id_extracted == FLB_TRUE) {
            msgpack_pack_str_with_body(&mp_pck, "spanId", 6);
            len = flb_sds_len(span_id);
            msgpack_pack_str_with_body(&mp_pck, span_id, len);
            flb_sds_destroy(span_id);
        }

        /* Add traceSampled field into the log entry */
        if (trace_sampled_extracted == FLB_TRUE) {
            msgpack_pack_str_with_body(&mp_pck, "traceSampled", 12);

            if (trace_sampled == FLB_TRUE) {
                msgpack_pack_true(&mp_pck);
            } else {
                msgpack_pack_false(&mp_pck);
            }

        }

        /* Add insertId field into the log entry */
        if (insert_id_extracted == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, 8);
            msgpack_pack_str_body(&mp_pck, "insertId", 8);
            msgpack_pack_object(&mp_pck, insert_id_obj);
        }

        /* Add operation field into the log entry */
        if (operation_extracted == FLB_TRUE) {
            add_operation_field(&operation_id, &operation_producer,
                                &operation_first, &operation_last, &mp_pck);
        }

        /* Add sourceLocation field into the log entry */
        if (source_location_extracted == FLB_TRUE) {
            add_source_location_field(&source_location_file, source_location_line,
                                      &source_location_function, &mp_pck);
        }

        /* Add httpRequest field into the log entry */
        if (http_request_extracted == FLB_TRUE) {
            add_http_request_field(&http_request, &mp_pck);
        }

        /* labels */
        if (labels_size > 0) {
            msgpack_pack_str(&mp_pck, 6);
            msgpack_pack_str_body(&mp_pck, "labels", 6);
            pack_labels(ctx, &mp_pck, payload_labels_ptr);
        }

        /* Clean up id and producer if operation extracted */
        flb_sds_destroy(operation_id);
        flb_sds_destroy(operation_producer);
        flb_sds_destroy(source_location_file);
        flb_sds_destroy(source_location_function);
        destroy_http_request(&http_request);

        /* both textPayload and jsonPayload are supported */
        pack_payload(insert_id_extracted,
                     operation_extracted,
                     operation_extra_size,
                     source_location_extracted,
                     source_location_extra_size,
                     http_request_extracted,
                     http_request_extra_size,
                     tms_status,
                     &mp_pck, obj, ctx);

        /* avoid modifying the original tag */
        newtag = tag;
        stream_key = flb_sds_create("stream");
        if (ctx->resource_type == RESOURCE_TYPE_K8S
            && get_string(&stream, obj, stream_key) == 0) {
            if (flb_sds_cmp(stream, STDOUT, flb_sds_len(stream)) == 0) {
                newtag = "stdout";
            }
            else if (flb_sds_cmp(stream, STDERR, flb_sds_len(stream)) == 0) {
                newtag = "stderr";
            }
        }

        if (log_name_extracted == FLB_FALSE) {
            new_log_name = newtag;
        }
        else {
            new_log_name = log_name;
        }

        if (project_id_extracted == FLB_TRUE) {
            len = snprintf(path, sizeof(path) - 1,
                       "projects/%s/logs/%s", project_id_key, new_log_name);
            flb_sds_destroy(project_id_key);
        } else {
            len = snprintf(path, sizeof(path) - 1,
                       "projects/%s/logs/%s", ctx->export_to_project_id, new_log_name);
        }

        /* logName */
        if (log_name_extracted == FLB_TRUE) {
            flb_sds_destroy(log_name);
        }

        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "logName", 7);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, path, len);
        flb_sds_destroy(stream_key);
        flb_sds_destroy(stream);

        /* timestamp */
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "timestamp", 9);

        /* Format the time */
        /*
         * If format is timestamp_object or timestamp_duo_fields,
         * tms has been updated.
         *
         * If timestamp is not presen,
         * use the default tms(current time).
         */

        gmtime_r(&log_event.timestamp.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                        FLB_STD_TIME_FMT, &tm);
        len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                       ".%09" PRIu64 "Z",
                       (uint64_t) log_event.timestamp.tm.tv_nsec);
        s += len;

        msgpack_pack_str(&mp_pck, s);
        msgpack_pack_str_body(&mp_pck, time_formatted, s);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                          config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        return NULL;
    }

    return out_buf;
}

static int stackdriver_format_test(struct flb_config *config,
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
    struct flb_stackdriver *ctx = plugin_context;

    /* Count number of records */
    total_records = flb_mp_count(data, bytes);

    payload = stackdriver_format(ctx, total_records,
                                (char *) tag, tag_len, data, bytes, config);
    if (payload == NULL) {
        return -1;
    }

    *out_data = payload;
    *out_size = flb_sds_len(payload);

    return 0;

}
#ifdef FLB_HAVE_METRICS
static void add_record_metrics(struct flb_stackdriver* ctx,
                               uint64_t ts,
                               int val,
                               int response_code,
                               int grpc_code)
{
  char grpc_code_label[32];
  char response_code_label[32];
  char* name = (char*) flb_output_name(ctx->ins);
  /* convert status to string format */
  snprintf(response_code_label, sizeof(response_code_label) - 1, "%i",
           response_code);
  /* convert grpc_code to string format */
  snprintf(grpc_code_label, sizeof(grpc_code_label) - 1, "%i", grpc_code);

  /* processed records total */
  cmt_counter_add(ctx->cmt_proc_records_total, ts, val, 3,
                  (char* []) {grpc_code_label, response_code_label, name});
}

static void update_http_metrics(struct flb_stackdriver* ctx,
                                struct flb_event_chunk* event_chunk,
                                uint64_t ts,
                                int http_status)
{
    char response_code_label[32];

    /* convert status to string format */
    snprintf(response_code_label, sizeof(response_code_label) - 1, "%i",
             http_status);
    char* name = (char*) flb_output_name(ctx->ins);

    cmt_counter_inc(ctx->cmt_requests_total, ts, 2,
                    (char* []) {response_code_label, name});
}

static void update_retry_metric(struct flb_stackdriver *ctx,
                                 struct flb_event_chunk *event_chunk,
                                 uint64_t ts,
                                 int http_status)
{
    char tmp[32];
    char *name = (char *) flb_output_name(ctx->ins);

    /* convert status to string format */
    snprintf(tmp, sizeof(tmp) - 1, "%i", http_status);
    cmt_counter_add(ctx->cmt_retried_records_total,
                    ts, event_chunk->total_events, 2, (char *[]) {tmp, name});

}
#endif

static int parse_partial_success_response(struct flb_http_client* c,
                                          struct flb_stackdriver* ctx,
                                          uint64_t ts,
                                          int total_events,
                                          int* grpc_status_codes)
{
    int ret;
    int root_type;
    int i;
    int log_entry_ret;
    int code_ret;
    char* buffer;
    char at_type_str[PARTIAL_SUCCESS_GRPC_TYPE_SIZE];
    size_t size;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object error_map;
    msgpack_object details_arr;
    msgpack_object details_map;
    msgpack_object logEntryErrors_map;
    msgpack_object logEntryError_key;
    msgpack_object logEntryError_map;
    msgpack_object logEntryCode;
    msgpack_object at_type;

    if (c->resp.status != 400 && c->resp.status != 403) {
        return -1;
    }

    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &buffer, &size, &root_type, NULL);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "failed to parse json into msgpack: %s",
                      c->resp.payload);
        return -1;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buffer, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "Cannot unpack response: %s",
                          c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "Cannot unpack response");
        }
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "response parsing failed, msgpack_type=%i",
                      root.type);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }
/*  Sample error response
{
  "error": {
    "code": 400,
    "message": "Log entry with size 293.1K exceeds maximum size of 256.0K",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.logging.v2.WriteLogEntriesPartialErrors",
        "logEntryErrors": {
          "2": {
            "code": 3,
            "message": "Log entry with size 293.1K exceeds maximum size of 256.0K"
          },
          "4": {
            "code": 3,
            "message": "Log entry with size 293.1K exceeds maximum size of 256.0K"
          }
        }
      }
    ]
  }
}
*/
    ret = extract_msgpack_obj_from_msgpack_map(&root.via.map, "error", 5,
                                               MSGPACK_OBJECT_MAP, &error_map);
    if (ret == -1) {
        flb_plg_debug(ctx->ins, "response does not have key: \"error\"");
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    ret = extract_msgpack_obj_from_msgpack_map(&error_map.via.map, "details", 7,
                                               MSGPACK_OBJECT_ARRAY,
                                               &details_arr);
    if (ret == -1) {
        flb_plg_debug(ctx->ins, "response does not have key: \"details\"");
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    for (i = 0; i < details_arr.via.array.size; i++) {
        details_map = details_arr.via.array.ptr[i];
        if (details_map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }


        ret = extract_msgpack_obj_from_msgpack_map(&details_map.via.map,
                                                   "@type", 5,
                                                   MSGPACK_OBJECT_STR,
                                                   &at_type);
        strncpy(at_type_str, at_type.via.str.ptr,
                PARTIAL_SUCCESS_GRPC_TYPE_SIZE);
        if (ret != 0 ||
            at_type.via.str.size != PARTIAL_SUCCESS_GRPC_TYPE_SIZE ||
            strncmp(at_type_str, PARTIAL_SUCCESS_GRPC_TYPE,
                           PARTIAL_SUCCESS_GRPC_TYPE_SIZE) != 0) {
            continue;
        }

        ret = extract_msgpack_obj_from_msgpack_map(&details_map.via.map,
                                                   "logEntryErrors", 14,
                                                   MSGPACK_OBJECT_MAP,
                                                   &logEntryErrors_map);
        if (ret != 0) {
            continue;
        }

        for (i = 0; i < logEntryErrors_map.via.map.size; i++) {
            logEntryError_key = logEntryErrors_map.via.map.ptr[i].key;
            if (logEntryError_key.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            log_entry_ret = extract_msgpack_obj_from_msgpack_map(
                &logEntryErrors_map.via.map,
                (char *) logEntryError_key.via.str.ptr,
                logEntryError_key.via.str.size,
                MSGPACK_OBJECT_MAP,
                &logEntryError_map);

            if (log_entry_ret != 0) {
                continue;
            }

            code_ret = extract_msgpack_obj_from_msgpack_map(
                &logEntryError_map.via.map,
                "code",
                4,
                MSGPACK_OBJECT_POSITIVE_INTEGER,
                &logEntryCode);

            if (code_ret == 0) {
                if (logEntryCode.via.i64 < 0
                    || logEntryCode.via.i64 >= GRPC_STATUS_CODES_SIZE) {
                    // TODO: fallback on a different data structure
                    flb_plg_error(ctx->ins,
                                  "internal error unexpected status code: %i",
                                  (int) logEntryCode.via.i64);
                    return -1;
                }
                grpc_status_codes[(int) logEntryCode.via.i64]++;
#ifdef FLB_HAVE_METRICS
                add_record_metrics(ctx, ts, 1, c->resp.status,
                                   (int) logEntryCode.via.i64);
#endif
            }
        }
    }
    flb_free(buffer);
    msgpack_unpacked_destroy(&result);
    return 0;
}
static void cb_stackdriver_flush(struct flb_event_chunk *event_chunk,
                                 struct flb_output_flush *out_flush,
                                 struct flb_input_instance *i_ins,
                                 void *out_context,
                                 struct flb_config *config)
{
    (void) i_ins;
    (void) config;
    int ret;
    int code;
    int ret_partial_success;
    int ret_code = FLB_RETRY;
    int grpc_status_counts[GRPC_STATUS_CODES_SIZE] = {0};
    size_t b_sent;
    flb_sds_t token;
    flb_sds_t payload_buf;
    void *compressed_payload_buffer = NULL;
    size_t compressed_payload_size;
    struct flb_stackdriver *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    int compressed = FLB_FALSE;
    uint64_t write_entries_start = 0;
    uint64_t write_entries_end = 0;
    float write_entries_latency = 0.0;
#ifdef FLB_HAVE_METRICS
    char *name = (char *) flb_output_name(ctx->ins);
    uint64_t ts = cfl_time_now();
#endif

    /* Reformat msgpack to stackdriver JSON payload */
    payload_buf = stackdriver_format(ctx,
                                     event_chunk->total_events,
                                     event_chunk->tag, flb_sds_len(event_chunk->tag),
                                     event_chunk->data, event_chunk->size,
                                     config);
    if (!payload_buf) {
#ifdef FLB_HAVE_METRICS
        cmt_counter_inc(ctx->cmt_failed_requests,
                        ts, 1, (char *[]) {name});

        /* OLD api */
        flb_metrics_sum(FLB_STACKDRIVER_FAILED_REQUESTS, 1, ctx->ins->metrics);
#endif
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (ctx->test_log_entry_format) {
        printf("%s\n", payload_buf);
        flb_sds_destroy(payload_buf);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
#ifdef FLB_HAVE_METRICS
        cmt_counter_inc(ctx->cmt_failed_requests,
                        ts, 1, (char *[]) {name});

        /* OLD api */
        flb_metrics_sum(FLB_STACKDRIVER_FAILED_REQUESTS, 1, ctx->ins->metrics);

        update_retry_metric(ctx, event_chunk, ts, STACKDRIVER_NET_ERROR);
#endif
        flb_sds_destroy(payload_buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get or renew Token */
    token = get_google_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(payload_buf);
#ifdef FLB_HAVE_METRICS
        cmt_counter_inc(ctx->cmt_failed_requests,
                        ts, 1, (char *[]) {name});

        /* OLD api */
        flb_metrics_sum(FLB_STACKDRIVER_FAILED_REQUESTS, 1, ctx->ins->metrics);
#endif
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    compressed_payload_buffer = payload_buf;
    compressed_payload_size = flb_sds_len(payload_buf);
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) payload_buf, flb_sds_len(payload_buf),
                                &compressed_payload_buffer, &compressed_payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot gzip payload, disabling compression");
        } else {
            compressed = FLB_TRUE;
            flb_sds_destroy(payload_buf);
        }
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_STD_WRITE_URI,
                        compressed_payload_buffer, compressed_payload_size, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, 4192);

    if (ctx->stackdriver_agent) {
        flb_http_add_header(c, "User-Agent", 10,
                            ctx->stackdriver_agent,
                            flb_sds_len(ctx->stackdriver_agent));
    }
    else {
        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    }

    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));
    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    write_entries_start = cfl_time_now();

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    write_entries_end = cfl_time_now();
    write_entries_latency = (float)(write_entries_end - write_entries_start) / 1000000000.0;

    /* validate response */
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        ret_code = FLB_RETRY;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
        if (c->resp.status == 200) {
            ret_code = FLB_OK;
        }
        else {
#ifdef FLB_HAVE_METRICS
          /* check partial success */
          ret_partial_success =
                parse_partial_success_response(c,
                                               ctx,
                                               ts,
                                               (int) event_chunk->total_events,
                                               grpc_status_counts);

            int failed_records = 0;
            if (ret_partial_success == 0) {
              for (code = 0; code < GRPC_STATUS_CODES_SIZE; code++) {
                if (grpc_status_counts[code] != 0) {
                  failed_records += grpc_status_counts[code];
                }
              }
              cmt_counter_add(ctx->ins->cmt_dropped_records, ts,
                              failed_records, 1, (char* []) {name});
              int successful_records =
                  (int) event_chunk->total_events - failed_records;
              if (successful_records != 0) {
                add_record_metrics(ctx, ts, successful_records, 200, 0);
              }
            }
            else {
              add_record_metrics(ctx, ts, (int) event_chunk->total_events,
                                 c->resp.status, -1);
              cmt_counter_add(ctx->ins->cmt_dropped_records, ts,
                              (int) event_chunk->total_events, 1,
                              (char* []) {name});
            }
#endif
          if (c->resp.status >= 400 && c->resp.status < 500) {
            ret_code = FLB_ERROR;
            flb_plg_warn(ctx->ins, "tag=%s error sending to Cloud Logging: %s", event_chunk->tag,
                         c->resp.payload);
          }
          else {
            if (c->resp.payload_size > 0) {
              /* we got an error */
              flb_plg_warn(ctx->ins, "tag=%s error sending to Cloud Logging: %s", event_chunk->tag,
                           c->resp.payload);
            }
            else {
              flb_plg_debug(ctx->ins, "tag=%s response from Cloud Logging: %s", event_chunk->tag,
                            c->resp.payload);
            }
            ret_code = FLB_RETRY;
          }
        }
    }

    /* Update specific stackdriver metrics */
#ifdef FLB_HAVE_METRICS
    if (ret_code == FLB_OK) {
        cmt_counter_inc(ctx->cmt_successful_requests, ts, 1, (char *[]) {name});
        if (write_entries_latency > 0.0) {
          cmt_histogram_observe(ctx->cmt_write_entries_latency, ts, write_entries_latency, 1, (char *[]) {name});
        }
        add_record_metrics(ctx, ts, (int) event_chunk->total_events, 200, 0);

        /* OLD api */
        flb_metrics_sum(FLB_STACKDRIVER_SUCCESSFUL_REQUESTS, 1, ctx->ins->metrics);
    }
    else if (ret_code == FLB_ERROR) {
        cmt_counter_inc(ctx->cmt_failed_requests, ts, 1, (char* []) {name});

        /* OLD api */
        flb_metrics_sum(FLB_STACKDRIVER_FAILED_REQUESTS, 1, ctx->ins->metrics);
    }

    if (ret_code == FLB_RETRY) {
        update_retry_metric(ctx, event_chunk, ts, c->resp.status);
    }

    /* Update metrics counter by using labels/http status code */
    update_http_metrics(ctx, event_chunk, ts, c->resp.status);
#endif

    /* Cleanup */
    if (compressed == FLB_TRUE) {
        flb_free(compressed_payload_buffer);
    }
    else {
        flb_sds_destroy(payload_buf);
    }
    flb_sds_destroy(token);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    /* Done */
    FLB_OUTPUT_RETURN(ret_code);
}

static int cb_stackdriver_exit(void *data, struct flb_config *config)
{
    struct flb_stackdriver *ctx = data;

    if (!ctx) {
        return -1;
    }

    flb_stackdriver_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_stackdriver, credentials_file),
     "Set the path for the google service credentials file"
    },
    {
     FLB_CONFIG_MAP_STR, "metadata_server", (char *)NULL,
     0, FLB_FALSE, 0,
     "Set the metadata server"
    },
    {
      FLB_CONFIG_MAP_STR, "service_account_email", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, client_email),
      "Set the service account email"
    },
    // set in flb_bigquery_oauth_credentials
    {
      FLB_CONFIG_MAP_STR, "service_account_secret", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, private_key),
      "Set the service account secret"
    },
    {
      FLB_CONFIG_MAP_STR, "export_to_project_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, export_to_project_id),
      "Export to project id"
    },
    {
      FLB_CONFIG_MAP_STR, "project_id_key", DEFAULT_PROJECT_ID_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, project_id_key),
      "Set the gcp project id key"
    },
    {
      FLB_CONFIG_MAP_STR, "resource", FLB_SDS_RESOURCE_TYPE,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, resource),
      "Set the resource"
    },
    {
      FLB_CONFIG_MAP_STR, "severity_key", DEFAULT_SEVERITY_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, severity_key),
      "Set the severity key"
    },
    {
      FLB_CONFIG_MAP_BOOL, "autoformat_stackdriver_trace", "false",
      0, FLB_TRUE, offsetof(struct flb_stackdriver, autoformat_stackdriver_trace),
      "Autoformat the stackdriver trace"
    },
    {
      FLB_CONFIG_MAP_STR, "trace_key", DEFAULT_TRACE_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, trace_key),
      "Set the trace key"
    },
    {
      FLB_CONFIG_MAP_STR, "span_id_key", DEFAULT_SPAN_ID_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, span_id_key),
      "Set the span id key"
    },
    {
      FLB_CONFIG_MAP_STR, "trace_sampled_key", DEFAULT_TRACE_SAMPLED_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, trace_sampled_key),
      "Set the trace sampled key"
    },
    {
      FLB_CONFIG_MAP_STR, "log_name_key", DEFAULT_LOG_NAME_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, log_name_key),
      "Set the logname key"
    },
    {
      FLB_CONFIG_MAP_STR, "http_request_key", HTTPREQUEST_FIELD_IN_JSON,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, http_request_key),
      "Set the http request key"
    },
    {
      FLB_CONFIG_MAP_STR, "k8s_cluster_name", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, cluster_name),
      "Set the kubernetes cluster name"
    },
    {
      FLB_CONFIG_MAP_STR, "k8s_cluster_location", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, cluster_location),
      "Set the kubernetes cluster location"
    },
    {
      FLB_CONFIG_MAP_STR, "location", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, location),
      "Set the resource location"
    },
    {
      FLB_CONFIG_MAP_STR, "namespace", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, namespace_id),
      "Set the resource namespace"
    },
    {
      FLB_CONFIG_MAP_STR, "node_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, node_id),
      "Set the resource node id"
    },
    {
      FLB_CONFIG_MAP_STR, "job", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, job),
      "Set the resource job"
    },
    {
      FLB_CONFIG_MAP_STR, "task_id", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, task_id),
      "Set the resource task id"
    },
    {
      FLB_CONFIG_MAP_STR, "compress", NULL,
      0, FLB_FALSE, 0,
      "Set log payload compression method. Option available is 'gzip'"
    },
    {
      FLB_CONFIG_MAP_CLIST, "labels", NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, labels),
      "Set the labels"
    },
    {
      FLB_CONFIG_MAP_STR, "labels_key", DEFAULT_LABELS_KEY,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, labels_key),
      "Set the labels key"
    },
    {
      FLB_CONFIG_MAP_STR, "tag_prefix", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, tag_prefix),
      "Set the tag prefix"
    },
    {
      FLB_CONFIG_MAP_STR, "stackdriver_agent", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, stackdriver_agent),
      "Set the stackdriver agent"
    },
    /* Custom Regex */
    {
      FLB_CONFIG_MAP_STR, "custom_k8s_regex", DEFAULT_TAG_REGEX,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, custom_k8s_regex),
      "Set a custom kubernetes regex filter"
    },
    {
      FLB_CONFIG_MAP_CLIST, "resource_labels", NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, resource_labels),
      "Set the resource labels"
    },
    {
      FLB_CONFIG_MAP_STR, "text_payload_key", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, text_payload_key),
      "Set key for extracting text payload"
    },
    {
      FLB_CONFIG_MAP_BOOL, "test_log_entry_format", "false",
      0, FLB_TRUE, offsetof(struct flb_stackdriver, test_log_entry_format),
      "Test log entry format"
    },
    {
      FLB_CONFIG_MAP_STR, "cloud_logging_base_url", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_stackdriver, cloud_logging_base_url),
      "The base Cloud Logging API URL to use for the /v2/entries:write API request. Default: https://logging.googleapis.com"
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_stackdriver_plugin = {
    .name         = "stackdriver",
    .description  = "Send events to Google Stackdriver Logging",
    .cb_init      = cb_stackdriver_init,
    .cb_flush     = cb_stackdriver_flush,
    .cb_exit      = cb_stackdriver_exit,
    .workers      = 1,
    .config_map   = config_map,

    /* Test */
    .test_formatter.callback = stackdriver_format_test,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
