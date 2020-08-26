/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <msgpack.h>

#include "gce_metadata.h"
#include "stackdriver.h"
#include "stackdriver_conf.h"
#include "stackdriver_operation.h"
#include "stackdriver_source_location.h"
#include "stackdriver_http_request.h"
#include "stackdriver_timestamp.h"
#include "stackdriver_helper.h"
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

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

    /* do normal base64 encoding */
    mbedtls_base64_encode(out_buf, out_size - 1,
                          &len, in_buf, in_size);

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
    mbedtls_sha256_context sha256_ctx;
    mbedtls_rsa_context *rsa;
    flb_sds_t out;
    mbedtls_pk_context pk_ctx;
    unsigned char sig[256] = {0};

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* Encode header */
    len = strlen(headers);
    mbedtls_base64_encode((unsigned char *) buf, buf_size - 1,
                          &olen, (unsigned char *) headers, len);

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
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) out,
                          flb_sds_len(out));
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    /* In mbedTLS cert length must include the null byte */
    len = strlen(secret) + 1;

    /* Load Private Key */
    mbedtls_pk_init(&pk_ctx);
    ret = mbedtls_pk_parse_key(&pk_ctx,
                               (unsigned char *) secret, len, NULL, 0);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error loading private key");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    /* Create RSA context */
    rsa = mbedtls_pk_rsa(pk_ctx);
    if (!rsa) {
        flb_plg_error(ctx->ins, "error creating RSA context");
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL,
                                 MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                 0, (unsigned char *) sha256_buf, sig);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error signing SHA256");
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_errno();
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    flb_sds_cat(out, ".", 1);
    flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);
    mbedtls_pk_free(&pk_ctx);

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

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(ctx->config, FLB_STD_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }

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
                                    "urn:ietf:params:oauth:"
                                    "grant-type:jwt-bearer", -1);
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

static char *get_google_token(struct flb_stackdriver *ctx)
{
    int ret = 0;

    if (!ctx->o) {
        ret = get_oauth2_token(ctx);
    }
    else if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        flb_oauth2_destroy(ctx->o);
        ret = get_oauth2_token(ctx);
    }

    if (ret != 0) {
        return NULL;
    }

    return ctx->o->access_token;
}

static bool validate_msgpack_unpacked_data(msgpack_object root)
{
    return root.type == MSGPACK_OBJECT_ARRAY &&
           root.via.array.size == 2 &&
           root.via.array.ptr[1].type == MSGPACK_OBJECT_MAP;
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

static flb_sds_t get_str_value_from_msgpack_map(msgpack_object_map map,
                                                const char *key, int key_size)
{
    int i;
    msgpack_object k;
    msgpack_object v;
    flb_sds_t ptr = NULL;

    for (i = 0; i < map.size; i++) {
        k = map.ptr[i].key;
        v = map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (k.via.str.size == key_size &&
            strncmp(key, (char *) k.via.str.ptr, k.via.str.size) == 0) {
            /* make sure to free it after use */
            ptr =  flb_sds_create_len(v.via.str.ptr, v.via.str.size);
            break;
        }
    }

    return ptr;
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
        flb_error("error parsing local_resource_id for type %s", type);
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
    msgpack_object root;
    msgpack_object_map map;
    msgpack_unpacked result;
    flb_sds_t local_resource_id;
    size_t off = 0;

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        if (!validate_msgpack_unpacked_data(root)) {
            msgpack_unpacked_destroy(&result);
            flb_plg_error(ctx->ins, "unexpected record format");
            return -1;
        }

        map = root.via.array.ptr[1].via.map;
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
    }
    else {
        msgpack_unpacked_destroy(&result);
        flb_plg_error(ctx->ins, "failed to unpack data");
        return -1;
    }

    flb_sds_destroy(local_resource_id);
    msgpack_unpacked_destroy(&result);
    return 0;
}

/*
 *    process_local_resource_id():
 *  - use the extracted local_resource_id to assign the label keys for different
 *    resource types that are specified in the configuration of stackdriver_out plugin
 */
static int process_local_resource_id(struct flb_stackdriver *ctx, char *type)
{
    int ret = -1;
    int first = FLB_TRUE;
    int counter = 0;
    int len_k8s_container;
    int len_k8s_node;
    int len_k8s_pod;
    int prefix_len;
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

/*
 * parse_labels
 * - Iterate throught the original payload (obj) and find out the entry that matches
 *   the labels_key
 * - Used to convert all labels under labels_key to root-level `labels` field
 */
static msgpack_object *parse_labels(struct flb_stackdriver *ctx, msgpack_object *obj)
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

    return;
}

int is_tag_match_regex(struct flb_stackdriver *ctx, const char *tag, int tag_len)
{
    int ret;
    int tag_prefix_len;
    int len_to_be_matched;
    const char *tag_str_to_be_matcheds;
    struct flb_regex *regex;

    tag_prefix_len = flb_sds_len(ctx->tag_prefix);
    tag_str_to_be_matcheds = tag + tag_prefix_len;
    len_to_be_matched = tag_len - tag_prefix_len;

    regex = flb_regex_create(DEFAULT_TAG_REGEX);
    ret = flb_regex_match(regex, tag_str_to_be_matcheds, len_to_be_matched);
    flb_regex_destroy(regex);

    /* 1 -> match;  0 -> doesn't match;  < 0 -> error */
    return ret;
}

/* extract_resource_labels_from_regex(3) will only be called if the
 * tag matches the regex rule
 */
int extract_resource_labels_from_regex(struct flb_stackdriver *ctx,
                                       const char *tag, int tag_len)
{
    int ret = 1;
    int tag_prefix_len;
    int len_to_be_matched;
    const char *tag_str_to_be_matcheds;
    struct flb_regex *regex;
    struct flb_regex_search result;

    tag_prefix_len = flb_sds_len(ctx->tag_prefix);
    tag_str_to_be_matcheds = tag + tag_prefix_len;
    len_to_be_matched = tag_len - tag_prefix_len;

    regex = flb_regex_create(DEFAULT_TAG_REGEX);
    ret = flb_regex_do(regex, tag_str_to_be_matcheds, len_to_be_matched, &result);
    if (ret <= 0) {
        flb_plg_warn(ctx->ins, "invalid pattern for given tag %s", tag);
        return -1;
    }

    flb_regex_parse(regex, &result, cb_results, ctx);
    flb_regex_destroy(regex);

    return ret;
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

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Network mode IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create Upstream context for Stackdriver Logging (no oauth2 service) */
    ctx->u = flb_upstream_create_url(config, FLB_STD_WRITE_URL,
                                     io_flags, &ins->tls);
    ctx->metadata_u = flb_upstream_create_url(config, "http://metadata.google.internal",
                                     FLB_IO_TCP, NULL);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }
    if (!ctx->metadata_u) {
        flb_plg_error(ctx->ins, "metadata upstream creation failed");
        return -1;
    }

    /* Metadata Upstream Sync flags */
    ctx->metadata_u->flags &= ~FLB_IO_ASYNC;

    if (ins->test_mode == FLB_FALSE) {
        /* Retrieve oauth2 token */
        token = get_google_token(ctx);
        if (!token) {
            flb_plg_warn(ctx->ins, "token retrieval failed");
        }
    }

    if (ctx->metadata_server_auth) {
        ret = gce_metadata_read_project_id(ctx);
        if (ret == -1) {
            return -1;
        }

        ret = gce_metadata_read_zone(ctx);
        if (ret == -1) {
            return -1;
        }

        ret = gce_metadata_read_instance_id(ctx);
        if (ret == -1) {
            return -1;
        }
    }

    /* Validate project_id */
    if (!ctx->project_id) {
        flb_plg_error(ctx->ins, "property 'project_id' is not set");
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

static int get_stream(msgpack_object_map map)
{
    int i;
    int len_stdout;
    int val_size;
    msgpack_object k;
    msgpack_object v;

    /* len(stdout) == len(stderr) */
    len_stdout = sizeof(STDOUT) - 1;
    for (i = 0; i < map.size; i++) {
        k = map.ptr[i].key;
        v = map.ptr[i].val;
        if (k.type == MSGPACK_OBJECT_STR &&
            strncmp(k.via.str.ptr, "stream", k.via.str.size) == 0) {
            val_size = v.via.str.size;
            if (val_size == len_stdout) {
                if (strncmp(v.via.str.ptr, STDOUT, val_size) == 0) {
                    return STREAM_STDOUT;
                }
                else if (strncmp(v.via.str.ptr, STDERR, val_size) == 0) {
                    return STREAM_STDERR;
                }
            }
        }
    }

    return STREAM_UNKNOWN;
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

static int pack_json_payload(int insert_id_extracted,
                             int operation_extracted, int operation_extra_size,
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
    flb_sds_t removed;
    flb_sds_t local_resource_id_key;
    flb_sds_t stream;
    msgpack_object_kv *kv = obj->via.map.ptr;
    msgpack_object_kv *const kvend = obj->via.map.ptr + obj->via.map.size;

    local_resource_id_key = flb_sds_create(LOCAL_RESOURCE_ID_KEY);
    stream = flb_sds_create("stream");
    /*
     * array of elements that need to be removed from payload,
     * special field 'operation' will be processed individually
     */
    flb_sds_t to_be_removed[] =
    {
        local_resource_id_key,
        ctx->labels_key,
        stream
        /* more special fields are required to be added */
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
            if (flb_sds_cmp(removed, kv->key.via.str.ptr, len) == 0) {
                to_remove += 1;
                break;
            }
        }
    }

    new_map_size = map_size - to_remove;

    ret = msgpack_pack_map(mp_pck, new_map_size);
    if (ret < 0) {
        goto error;
    }

    /* points back to the beginning of map */
    kv = obj->via.map.ptr;
    for(; kv != kvend; ++kv	) {
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

        if (validate_key(kv->key, HTTPREQUEST_FIELD_IN_JSON,
                         HTTP_REQUEST_KEY_SIZE)
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
            if (flb_sds_cmp(removed, kv->key.via.str.ptr, len) == 0) {
                key_not_found = 0;
                break;
            }
        }

        if (key_not_found) {
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

    flb_sds_destroy(local_resource_id_key);
    flb_sds_destroy(stream);
    return 0;

    error:
        flb_sds_destroy(local_resource_id_key);
        flb_sds_destroy(stream);
        return ret;
}

static int stackdriver_format(struct flb_config *config,
                              struct flb_input_instance *ins,
                              void *plugin_context,
                              void *flush_ctx,
                              const char *tag, int tag_len,
                              const void *data, size_t bytes,
                              void **out_data, size_t *out_size)
{
    int len;
    int ret;
    int array_size = 0;
    /* The default value is 3: timestamp, jsonPayload, logName. */
    int entry_size = 3;
    int stream;
    size_t s;
    size_t off = 0;
    char path[PATH_MAX];
    char time_formatted[255];
    const char *newtag;
    msgpack_object *obj;
    msgpack_object *labels_ptr;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    flb_sds_t out_buf;
    struct flb_stackdriver *ctx = plugin_context;

    /* Parameters for severity */
    int severity_extracted = FLB_FALSE;
    severity_t severity;

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
    struct flb_time tms;
    timestamp_status tms_status;

    /* Count number of records */
    array_size = flb_mp_count(data, bytes);

    /*
     * Search each entry and validate insertId.
     * Reject the entry if insertId is invalid.
     * If all the entries are rejected, stop formatting.
     *
     */
    off = 0;
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* Extract insertId */
        in_status = validate_insert_id(&insert_id_obj, obj);
        if (in_status == INSERTID_INVALID) {
            flb_plg_error(ctx->ins,
                          "Incorrect insertId received. InsertId should be non-empty string.");
            array_size -= 1;
        }
    }
    msgpack_unpacked_destroy(&result);

    if (array_size == 0) {
        *out_size = 0;
        return -1;
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
    msgpack_pack_map(&mp_pck, 2);

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

    if (ctx->k8s_resource_type) {
        ret = extract_local_resource_id(data, bytes, ctx, tag);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "fail to construct local_resource_id");
            return -1;
        }
    }

    if (strcmp(ctx->resource, "global") == 0) {
      /* global resource has field project_id */
      msgpack_pack_map(&mp_pck, 1);
      msgpack_pack_str(&mp_pck, 10);
      msgpack_pack_str_body(&mp_pck, "project_id", 10);
      msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
      msgpack_pack_str_body(&mp_pck,
                            ctx->project_id, flb_sds_len(ctx->project_id));
    }
    else if (strcmp(ctx->resource, "gce_instance") == 0) {
      /* gce_instance resource has fields project_id, zone, instance_id */
      msgpack_pack_map(&mp_pck, 3);

      msgpack_pack_str(&mp_pck, 10);
      msgpack_pack_str_body(&mp_pck, "project_id", 10);
      msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
      msgpack_pack_str_body(&mp_pck,
                            ctx->project_id, flb_sds_len(ctx->project_id));

      msgpack_pack_str(&mp_pck, 4);
      msgpack_pack_str_body(&mp_pck, "zone", 4);
      msgpack_pack_str(&mp_pck, flb_sds_len(ctx->zone));
      msgpack_pack_str_body(&mp_pck, ctx->zone, flb_sds_len(ctx->zone));

      msgpack_pack_str(&mp_pck, 11);
      msgpack_pack_str_body(&mp_pck, "instance_id", 11);
      msgpack_pack_str(&mp_pck, flb_sds_len(ctx->instance_id));
      msgpack_pack_str_body(&mp_pck,
                            ctx->instance_id, flb_sds_len(ctx->instance_id));
    }
    else if (strcmp(ctx->resource, K8S_CONTAINER) == 0) {
        /* k8s_container resource has fields project_id, location, cluster_name,
         *                                   namespace_name, pod_name, container_name
         *
         * The local_resource_id for k8s_container is in format:
         *    k8s_container.<namespace_name>.<pod_name>.<container_name>
         */

        if (is_tag_match_regex(ctx, tag, tag_len) > 0) {
            ret = extract_resource_labels_from_regex(ctx, tag, tag_len);
        }
        else {
            ret = process_local_resource_id(ctx, K8S_CONTAINER);
        }

        if (ret == -1) {
            flb_plg_error(ctx->ins, "fail to extract resource labels "
                          "for k8s_container resource type");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return -1;
        }

        msgpack_pack_map(&mp_pck, 6);

        msgpack_pack_str(&mp_pck, 10);
        msgpack_pack_str_body(&mp_pck, "project_id", 10);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
        msgpack_pack_str_body(&mp_pck,
                              ctx->project_id, flb_sds_len(ctx->project_id));

        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "location", 8);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
        msgpack_pack_str_body(&mp_pck,
                              ctx->cluster_location, flb_sds_len(ctx->cluster_location));

        msgpack_pack_str(&mp_pck, 12);
        msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->cluster_name, flb_sds_len(ctx->cluster_name));

        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->namespace_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->namespace_name, flb_sds_len(ctx->namespace_name));

        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "pod_name", 8);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->pod_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->pod_name, flb_sds_len(ctx->pod_name));

        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "container_name", 14);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->container_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->container_name, flb_sds_len(ctx->container_name));
    }
    else if (strcmp(ctx->resource, K8S_NODE) == 0) {
        /* k8s_node resource has fields project_id, location, cluster_name, node_name
         *
         * The local_resource_id for k8s_node is in format:
         *      k8s_node.<node_name>
         */

        ret = process_local_resource_id(ctx, K8S_NODE);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "fail to process local_resource_id from "
                          "log entry for k8s_node");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return -1;
        }

        msgpack_pack_map(&mp_pck, 4);

        msgpack_pack_str(&mp_pck, 10);
        msgpack_pack_str_body(&mp_pck, "project_id", 10);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
        msgpack_pack_str_body(&mp_pck,
                              ctx->project_id, flb_sds_len(ctx->project_id));

        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "location", 8);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
        msgpack_pack_str_body(&mp_pck,
                              ctx->cluster_location, flb_sds_len(ctx->cluster_location));

        msgpack_pack_str(&mp_pck, 12);
        msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->cluster_name, flb_sds_len(ctx->cluster_name));

        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "node_name", 9);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->node_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->node_name, flb_sds_len(ctx->node_name));
    }
    else if (strcmp(ctx->resource, K8S_POD) == 0) {
        /* k8s_pod resource has fields project_id, location, cluster_name,
         *                             namespace_name, pod_name.
         *
         * The local_resource_id for k8s_pod is in format:
         *      k8s_pod.<namespace_name>.<pod_name>
         */

        ret = process_local_resource_id(ctx, K8S_POD);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "fail to process local_resource_id from "
                          "log entry for k8s_pod");
            msgpack_sbuffer_destroy(&mp_sbuf);
            return -1;
        }

        msgpack_pack_map(&mp_pck, 5);

        msgpack_pack_str(&mp_pck, 10);
        msgpack_pack_str_body(&mp_pck, "project_id", 10);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->project_id));
        msgpack_pack_str_body(&mp_pck,
                              ctx->project_id, flb_sds_len(ctx->project_id));

        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "location", 8);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_location));
        msgpack_pack_str_body(&mp_pck,
                              ctx->cluster_location, flb_sds_len(ctx->cluster_location));

        msgpack_pack_str(&mp_pck, 12);
        msgpack_pack_str_body(&mp_pck, "cluster_name", 12);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->cluster_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->cluster_name, flb_sds_len(ctx->cluster_name));

        msgpack_pack_str(&mp_pck, 14);
        msgpack_pack_str_body(&mp_pck, "namespace_name", 14);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->namespace_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->namespace_name, flb_sds_len(ctx->namespace_name));

        msgpack_pack_str(&mp_pck, 8);
        msgpack_pack_str_body(&mp_pck, "pod_name", 8);
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->pod_name));
        msgpack_pack_str_body(&mp_pck,
                              ctx->pod_name, flb_sds_len(ctx->pod_name));
    }

    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "entries", 7);

    /* Append entries */
    msgpack_pack_array(&mp_pck, array_size);

    off = 0;
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Get timestamp */
        flb_time_pop_from_msgpack(&tms, &result, &obj);
        tms_status = extract_timestamp(obj, &tms);

        /*
         * Pack entry
         *
         * {
         *  "severity": "...",
         *  "labels": "...",
         *  "logName": "...",
         *  "jsonPayload": {...},
         *  "timestamp": "..."
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
        http_request_extracted = extract_http_request(&http_request, obj,
                                                      &http_request_extra_size);
        if (http_request_extracted == FLB_TRUE) {
            entry_size += 1;
        }

        /* Extract labels */
        labels_ptr = parse_labels(ctx, obj);
        if (labels_ptr != NULL) {
            if (labels_ptr->type != MSGPACK_OBJECT_MAP) {
                flb_plg_error(ctx->ins, "the type of labels should be map");
                flb_sds_destroy(operation_id);
                flb_sds_destroy(operation_producer);
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&mp_sbuf);
                return -1;
            }
            entry_size += 1;
        }

        msgpack_pack_map(&mp_pck, entry_size);

        /* Add severity into the log entry */
        if (severity_extracted == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, 8);
            msgpack_pack_str_body(&mp_pck, "severity", 8);
            msgpack_pack_int(&mp_pck, severity);
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
        if (labels_ptr != NULL) {
            msgpack_pack_str(&mp_pck, 6);
            msgpack_pack_str_body(&mp_pck, "labels", 6);
            msgpack_pack_object(&mp_pck, *labels_ptr);
        }

        /* Clean up id and producer if operation extracted */
        flb_sds_destroy(operation_id);
        flb_sds_destroy(operation_producer);
        flb_sds_destroy(source_location_file);
        flb_sds_destroy(source_location_function);
        destroy_http_request(&http_request);

        /* jsonPayload */
        msgpack_pack_str(&mp_pck, 11);
        msgpack_pack_str_body(&mp_pck, "jsonPayload", 11);
        pack_json_payload(insert_id_extracted,
                          operation_extracted, operation_extra_size,
                          source_location_extracted,
                          source_location_extra_size,
                          http_request_extracted,
                          http_request_extra_size,
                          tms_status,
                          &mp_pck, obj, ctx);

        /* avoid modifying the original tag */
        newtag = tag;
        if (ctx->k8s_resource_type) {
            stream = get_stream(result.data.via.array.ptr[1].via.map);
            if (stream == STREAM_STDOUT) {
                newtag = "stdout";
            }
            else if (stream == STREAM_STDERR) {
                newtag = "stderr";
            }
        }
        /* logName */
        len = snprintf(path, sizeof(path) - 1,
                       "projects/%s/logs/%s", ctx->project_id, newtag);

        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "logName", 7);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, path, len);

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

        gmtime_r(&tms.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                        FLB_STD_TIME_FMT, &tm);
        len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                        ".%09" PRIu64 "Z", (uint64_t) tms.tm.tv_nsec);
        s += len;

        msgpack_pack_str(&mp_pck, s);
        msgpack_pack_str_body(&mp_pck, time_formatted, s);

    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static void set_authorization_header(struct flb_http_client *c,
                                     char *token)
{
    int len;
    char header[512];

    len = snprintf(header, sizeof(header) - 1,
                   "Bearer %s", token);
    flb_http_add_header(c, "Authorization", 13, header, len);
}

static void cb_stackdriver_flush(const void *data, size_t bytes,
                                 const char *tag, int tag_len,
                                 struct flb_input_instance *i_ins,
                                 void *out_context,
                                 struct flb_config *config)
{
    (void) i_ins;
    (void) config;
    int ret;
    int ret_code = FLB_RETRY;
    size_t b_sent;
    char *token;
    flb_sds_t payload_buf;
    size_t payload_size;
    void *out_buf;
    size_t out_size;
    struct flb_stackdriver *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Reformat msgpack to stackdriver JSON payload */
    ret = stackdriver_format(config, i_ins,
                             ctx, NULL,
                             tag, tag_len,
                             data, bytes,
                             &out_buf, &out_size);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    payload_buf = (flb_sds_t) out_buf;
    payload_size = out_size;

    /* Get or renew Token */
    token = get_google_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(payload_buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_STD_WRITE_URI,
                        payload_buf, payload_size, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, 4192);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);

    /* Compose and append Authorization header */
    set_authorization_header(c, token);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

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
            if (c->resp.payload_size > 0) {
                /* we got an error */
                flb_plg_warn(ctx->ins, "error\n%s",
                             c->resp.payload);
            }
            else {
                flb_plg_debug(ctx->ins, "response\n%s",
                              c->resp.payload);
            }
            ret_code = FLB_RETRY;
        }
    }

    /* Cleanup */
    flb_sds_destroy(payload_buf);
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

struct flb_output_plugin out_stackdriver_plugin = {
    .name         = "stackdriver",
    .description  = "Send events to Google Stackdriver Logging",
    .cb_init      = cb_stackdriver_init,
    .cb_flush     = cb_stackdriver_flush,
    .cb_exit      = cb_stackdriver_exit,

    /* Test */
    .test_formatter.callback = stackdriver_format,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
