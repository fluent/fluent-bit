/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_oauth2_jwt.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/tls/flb_tls.h>

#include <monkey/mk_core/mk_list.h>

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <time.h>



struct flb_oauth2_jwks_key {
    flb_sds_t kid;
    flb_sds_t modulus;
    flb_sds_t exponent;
    time_t loaded_at;
};

struct flb_oauth2_jwks_cache {
    struct flb_hash_table *entries;
    time_t last_refresh;
    int refresh_interval;
};

struct flb_oauth2_jwt_ctx {
    struct flb_config *config;
    struct flb_oauth2_jwt_cfg cfg;
    struct flb_oauth2_jwks_cache jwks_cache;
};

const char *flb_oauth2_jwt_status_message(int status)
{
    switch (status) {
    case FLB_OAUTH2_JWT_OK:
        return "ok";
    case FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT:
        return "jwt must contain 3 segments";
    case FLB_OAUTH2_JWT_ERR_BASE64_HEADER:
        return "unable to decode header";
    case FLB_OAUTH2_JWT_ERR_BASE64_PAYLOAD:
        return "unable to decode payload";
    case FLB_OAUTH2_JWT_ERR_BASE64_SIGNATURE:
        return "unable to decode signature";
    case FLB_OAUTH2_JWT_ERR_JSON_HEADER:
        return "invalid header json";
    case FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD:
        return "invalid payload json";
    case FLB_OAUTH2_JWT_ERR_MISSING_KID:
        return "missing kid in header";
    case FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED:
        return "unsupported alg";
    case FLB_OAUTH2_JWT_ERR_MISSING_EXP:
        return "missing exp claim";
    case FLB_OAUTH2_JWT_ERR_MISSING_ISS:
        return "missing iss claim";
    case FLB_OAUTH2_JWT_ERR_MISSING_AUD:
        return "missing aud claim";
    case FLB_OAUTH2_JWT_ERR_MISSING_BEARER_TOKEN:
        return "missing bearer token";
    case FLB_OAUTH2_JWT_ERR_MISSING_AUTH_HEADER:
        return "missing authorization header";
    case FLB_OAUTH2_JWT_ERR_VALIDATION_UNAVAILABLE:
        return "validation not implemented";
    default:
        return "unknown error";
    }
}

static void oauth2_jwks_key_destroy(struct flb_oauth2_jwks_key *key)
{
    if (!key) {
        return;
    }

    if (key->kid) {
        flb_sds_destroy(key->kid);
    }

    if (key->modulus) {
        flb_sds_destroy(key->modulus);
    }

    if (key->exponent) {
        flb_sds_destroy(key->exponent);
    }

    flb_free(key);
}

static void oauth2_jwks_cache_destroy(struct flb_oauth2_jwks_cache *cache)
{
    int i;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_hash_table_entry *entry;
    struct flb_hash_table_chain *table;

    if (!cache || !cache->entries) {
        return;
    }

    /* Iterate through all hash table chains and destroy keys */
    for (i = 0; i < cache->entries->size; i++) {
        table = &cache->entries->table[i];
        mk_list_foreach_safe(head, tmp, &table->chains) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
            if (entry->val) {
                oauth2_jwks_key_destroy((struct flb_oauth2_jwks_key *)entry->val);
                entry->val = NULL; /* Prevent double-free */
            }
        }
    }

    flb_hash_table_destroy(cache->entries);
    cache->entries = NULL;
}

static int oauth2_jwks_cache_init(struct flb_oauth2_jwks_cache *cache,
                                  int refresh_interval)
{
    if (!cache) {
        return -1;
    }

    cache->entries = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 64, 0);
    if (!cache->entries) {
        return -1;
    }

    cache->last_refresh = 0;
    cache->refresh_interval = refresh_interval;

    return 0;
}

static void oauth2_jwt_destroy_claims(struct flb_oauth2_jwt_claims *claims)
{
    if (!claims) {
        return;
    }

    if (claims->kid) {
        flb_sds_destroy(claims->kid);
    }

    if (claims->alg) {
        flb_sds_destroy(claims->alg);
    }

    if (claims->issuer) {
        flb_sds_destroy(claims->issuer);
    }

    if (claims->audience) {
        flb_sds_destroy(claims->audience);
    }

    if (claims->client_id) {
        flb_sds_destroy(claims->client_id);
    }
}

void flb_oauth2_jwt_destroy(struct flb_oauth2_jwt *jwt)
{
    if (!jwt) {
        return;
    }

    oauth2_jwt_destroy_claims(&jwt->claims);

    if (jwt->header_json) {
        flb_sds_destroy(jwt->header_json);
    }

    if (jwt->payload_json) {
        flb_sds_destroy(jwt->payload_json);
    }

    if (jwt->signing_input) {
        flb_sds_destroy(jwt->signing_input);
    }

    if (jwt->signature) {
        flb_free(jwt->signature);
    }
}

static int oauth2_jwt_token_strcmp(const char *json, jsmntok_t *tok, const char *cmp)
{
    int len = (tok->end - tok->start);

    if (len != (int) strlen(cmp)) {
        return -1;
    }

    return strncmp(json + tok->start, cmp, len);
}

static int oauth2_jwt_parse_json_tokens(const char *json,
                                        size_t json_len,
                                        jsmntok_t **tokens_out,
                                        int *tokens_size_out,
                                        int invalid_error)
{
    int ret;
    jsmn_parser parser;
    int tokens_size = 32;
    jsmntok_t *tokens = NULL;
    int max_iterations = 20; /* Prevent infinite loop */
    int iteration = 0;

    while (iteration < max_iterations) {
        flb_free(tokens);
        tokens = flb_calloc(1, sizeof(jsmntok_t) * tokens_size);
        if (!tokens) {
            flb_errno();
            return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
        }

        /* Reinitialize parser for each attempt */
        jsmn_init(&parser);
        ret = jsmn_parse(&parser, json, json_len, tokens, tokens_size);

        if (ret != JSMN_ERROR_NOMEM) {
            break;
        }

        /* Double the token size for next iteration */
        tokens_size *= 2;
        iteration++;
    }

    if (iteration >= max_iterations) {
        flb_free(tokens);
        return invalid_error;
    }

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_free(tokens);
        return invalid_error;
    }

    if (ret < 1 || tokens[0].type != JSMN_OBJECT) {
        flb_free(tokens);
        return invalid_error;
    }

    *tokens_out = tokens;
    *tokens_size_out = ret;
    return FLB_OAUTH2_JWT_OK;
}

static int oauth2_jwt_base64url_decode(const char *segment,
                                       size_t segment_len,
                                       unsigned char **decoded,
                                       size_t *decoded_len,
                                       int base64_error_code)
{
    int ret;
    size_t i;
    size_t j = 0;
    size_t padding = 0;
    size_t padded_len;
    size_t clean_len = 0;
    char *padded;
    unsigned char c;

    if (!segment || !decoded || !decoded_len) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    /* First, count non-whitespace characters */
    for (i = 0; i < segment_len; i++) {
        if (!isspace((unsigned char)segment[i])) {
            clean_len++;
        }
    }

    if (clean_len == 0) {
        return base64_error_code;
    }

    padding = (4 - (clean_len % 4)) % 4;
    padded_len = clean_len + padding;

    padded = flb_malloc(padded_len + 1);
    if (!padded) {
        flb_errno();
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    /* Copy and convert base64url to base64, skipping whitespace */
    for (i = 0; i < segment_len && j < clean_len; i++) {
        c = (unsigned char)segment[i];

        if (isspace(c)) {
            continue; /* Skip whitespace */
        }

        /* Validate base64url character */
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            flb_free(padded);
            return base64_error_code;
        }

        if (c == '-') {
            padded[j] = '+';
        }
        else if (c == '_') {
            padded[j] = '/';
        }
        else {
            padded[j] = c;
        }
        j++;
    }

    if (j != clean_len) {
        flb_free(padded);
        return base64_error_code;
    }

    /* Add padding */
    for (i = 0; i < padding; i++) {
        padded[clean_len + i] = '=';
    }
    padded[padded_len] = '\0';

    /* First pass: get required buffer size */
    ret = flb_base64_decode(NULL, 0, decoded_len,
                            (unsigned char *) padded, padded_len);
    /* Note: ret will be FLB_BASE64_ERR_BUFFER_TOO_SMALL (-42) on first pass, this is expected */
    if (ret != 0 && ret != FLB_BASE64_ERR_BUFFER_TOO_SMALL) {
        flb_free(padded);
        return base64_error_code;
    }

    if (*decoded_len == 0) {
        flb_free(padded);
        return base64_error_code;
    }

    *decoded = flb_malloc(*decoded_len + 1);
    if (!*decoded) {
        flb_errno();
        flb_free(padded);
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    ret = flb_base64_decode(*decoded, *decoded_len, decoded_len,
                            (unsigned char *) padded, padded_len);
    flb_free(padded);

    if (ret != 0) {
        flb_free(*decoded);
        *decoded = NULL;
        return base64_error_code;
    }

    (*decoded)[*decoded_len] = '\0';
    return FLB_OAUTH2_JWT_OK;
}

static flb_sds_t oauth2_jwt_token_to_sds(const char *json, jsmntok_t *tok)
{
    return flb_sds_create_len(json + tok->start, tok->end - tok->start);
}

static int oauth2_jwt_parse_header(const char *json, size_t json_len,
                                   struct flb_oauth2_jwt_claims *claims)
{
    int ret;
    int root_type;
    char *mp_buf = NULL;
    size_t mp_size;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object *k;
    msgpack_object *v;
    size_t i;
    size_t map_size;
    size_t key_len;
    size_t val_len;
    const char *key_str;
    const char *val_str;

    /* Convert JSON to msgpack */
    ret = flb_pack_json_yyjson(json, json_len, &mp_buf, &mp_size,
                               &root_type, NULL);
    if (ret != 0 || root_type != JSMN_OBJECT) {
        if (mp_buf) {
            flb_free(mp_buf);
        }
        return FLB_OAUTH2_JWT_ERR_JSON_HEADER;
    }

    /* Unpack msgpack */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, mp_buf, mp_size, &off) != MSGPACK_UNPACK_SUCCESS) {
        flb_free(mp_buf);
        msgpack_unpacked_destroy(&result);
        return FLB_OAUTH2_JWT_ERR_JSON_HEADER;
    }

    map = result.data;
    if (map.type != MSGPACK_OBJECT_MAP) {
        flb_free(mp_buf);
        msgpack_unpacked_destroy(&result);
        return FLB_OAUTH2_JWT_ERR_JSON_HEADER;
    }

    /* Extract fields from msgpack map */
    map_size = map.via.map.size;
    for (i = 0; i < map_size; i++) {
        k = &map.via.map.ptr[i].key;
        v = &map.via.map.ptr[i].val;

        if (k->type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (v->type == MSGPACK_OBJECT_STR) {
            key_len = k->via.str.size;
            val_len = v->via.str.size;
            key_str = (const char *)k->via.str.ptr;
            val_str = (const char *)v->via.str.ptr;

            if (key_len == 3 && strncmp(key_str, "kid", 3) == 0) {
                claims->kid = flb_sds_create_len(val_str, val_len);
            }
            else if (key_len == 3 && strncmp(key_str, "alg", 3) == 0) {
                claims->alg = flb_sds_create_len(val_str, val_len);
            }
        }
    }

    flb_free(mp_buf);
    msgpack_unpacked_destroy(&result);

    if (!claims->kid) {
        return FLB_OAUTH2_JWT_ERR_MISSING_KID;
    }

    if (!claims->alg || strcmp(claims->alg, "RS256") != 0) {
        return FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED;
    }

    return FLB_OAUTH2_JWT_OK;
}

static int oauth2_jwt_parse_payload(const char *json, size_t json_len,
                                    struct flb_oauth2_jwt_claims *claims)
{
    int ret;
    int root_type;
    char *mp_buf = NULL;
    size_t mp_size;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object *k;
    msgpack_object *v;
    size_t i;
    size_t map_size;
    size_t key_len;
    const char *key_str;
    msgpack_object *first;

    /* Convert JSON to msgpack */
    ret = flb_pack_json_yyjson(json, json_len, &mp_buf, &mp_size,
                               &root_type, NULL);
    if (ret != 0 || root_type != JSMN_OBJECT) {
        if (mp_buf) {
            flb_free(mp_buf);
        }
        return FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD;
    }

    /* Unpack msgpack */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, mp_buf, mp_size, &off) != MSGPACK_UNPACK_SUCCESS) {
        flb_free(mp_buf);
        msgpack_unpacked_destroy(&result);
        return FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD;
    }

    map = result.data;
    if (map.type != MSGPACK_OBJECT_MAP) {
        flb_free(mp_buf);
        msgpack_unpacked_destroy(&result);
        return FLB_OAUTH2_JWT_ERR_JSON_PAYLOAD;
    }

    /* Extract fields from msgpack map */
    map_size = map.via.map.size;
    for (i = 0; i < map_size; i++) {
        k = &map.via.map.ptr[i].key;
        v = &map.via.map.ptr[i].val;

        if (k->type != MSGPACK_OBJECT_STR) {
            continue;
        }

        key_len = k->via.str.size;
        key_str = (const char *)k->via.str.ptr;

        if (key_len == 3 && strncmp(key_str, "exp", 3) == 0) {
            if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                claims->expiration = v->via.u64;
            }
            else if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                /* Negative integers are not valid for exp */
                continue;
            }
        }
        else if (key_len == 3 && strncmp(key_str, "iss", 3) == 0) {
            if (v->type == MSGPACK_OBJECT_STR) {
                if (claims->issuer) {
                    flb_sds_destroy(claims->issuer);
                }
                claims->issuer = flb_sds_create_len((const char *)v->via.str.ptr,
                                                     v->via.str.size);
            }
        }
        else if (key_len == 3 && strncmp(key_str, "aud", 3) == 0) {
            if (v->type == MSGPACK_OBJECT_STR) {
                if (claims->audience) {
                    flb_sds_destroy(claims->audience);
                }
                claims->audience = flb_sds_create_len((const char *)v->via.str.ptr,
                                                      v->via.str.size);
            }
            else if (v->type == MSGPACK_OBJECT_ARRAY && v->via.array.size > 0) {
                /* Take first element of array */
                first = &v->via.array.ptr[0];
                if (first->type == MSGPACK_OBJECT_STR) {
                    if (claims->audience) {
                        flb_sds_destroy(claims->audience);
                    }
                    claims->audience = flb_sds_create_len((const char *)first->via.str.ptr,
                                                          first->via.str.size);
                }
            }
        }
        else if (key_len == 3 && strncmp(key_str, "azp", 3) == 0) {
            if (v->type == MSGPACK_OBJECT_STR) {
                if (claims->client_id) {
                    flb_sds_destroy(claims->client_id);
                }
                claims->client_id = flb_sds_create_len((const char *)v->via.str.ptr,
                                                       v->via.str.size);
            }
        }
        else if (key_len == 9 && strncmp(key_str, "client_id", 9) == 0) {
            if (v->type == MSGPACK_OBJECT_STR) {
                if (claims->client_id) {
                    flb_sds_destroy(claims->client_id);
                }
                claims->client_id = flb_sds_create_len((const char *)v->via.str.ptr,
                                                       v->via.str.size);
            }
        }
    }

    flb_free(mp_buf);
    msgpack_unpacked_destroy(&result);

    if (claims->expiration == 0) {
        return FLB_OAUTH2_JWT_ERR_MISSING_EXP;
    }

    if (!claims->issuer) {
        return FLB_OAUTH2_JWT_ERR_MISSING_ISS;
    }

    if (!claims->audience) {
        return FLB_OAUTH2_JWT_ERR_MISSING_AUD;
    }

    return FLB_OAUTH2_JWT_OK;
}

int flb_oauth2_jwt_parse(const char *token, size_t token_len,
                         struct flb_oauth2_jwt *jwt)
{
    int ret;
    int segment = 0;
    size_t i;
    size_t start = 0;
    const char *parts[3] = {0};
    size_t parts_len[3] = {0};
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;

    if (!token || token_len == 0 || !jwt) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    memset(jwt, 0, sizeof(struct flb_oauth2_jwt));

    for (i = 0; i <= token_len; i++) {
        if (i == token_len || token[i] == '.') {
            if (segment >= 3) {
                return FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT;
            }

            parts[segment] = token + start;
            parts_len[segment] = i - start;
            segment++;
            start = i + 1;
        }
    }

    if (segment != 3) {
        return FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT;
    }

    jwt->signing_input = flb_sds_create_len(token, parts_len[0] + parts_len[1] + 1);
    if (!jwt->signing_input) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    memcpy(jwt->signing_input, parts[0], parts_len[0]);
    jwt->signing_input[parts_len[0]] = '.';
    memcpy(jwt->signing_input + parts_len[0] + 1, parts[1], parts_len[1]);
    jwt->signing_input[parts_len[0] + parts_len[1] + 1] = '\0';

    ret = oauth2_jwt_base64url_decode(parts[0], parts_len[0], &decoded, &decoded_len,
                                      FLB_OAUTH2_JWT_ERR_BASE64_HEADER);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    jwt->header_json = flb_sds_create_len((const char *) decoded, decoded_len);
    flb_free(decoded);
    decoded = NULL;
    decoded_len = 0;
    if (!jwt->header_json) {
        flb_oauth2_jwt_destroy(jwt);
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    ret = oauth2_jwt_parse_header(jwt->header_json, flb_sds_len(jwt->header_json),
                                  &jwt->claims);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    ret = oauth2_jwt_base64url_decode(parts[1], parts_len[1], &decoded, &decoded_len,
                                      FLB_OAUTH2_JWT_ERR_BASE64_PAYLOAD);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    jwt->payload_json = flb_sds_create_len((const char *) decoded, decoded_len);
    flb_free(decoded);
    decoded = NULL;
    decoded_len = 0;
    if (!jwt->payload_json) {
        flb_oauth2_jwt_destroy(jwt);
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    ret = oauth2_jwt_parse_payload(jwt->payload_json,
                                   flb_sds_len(jwt->payload_json),
                                   &jwt->claims);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    ret = oauth2_jwt_base64url_decode(parts[2], parts_len[2], &decoded, &decoded_len,
                                      FLB_OAUTH2_JWT_ERR_BASE64_SIGNATURE);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_oauth2_jwt_destroy(jwt);
        return ret;
    }

    jwt->signature = decoded;
    jwt->signature_len = decoded_len;

    return FLB_OAUTH2_JWT_OK;
}

static int oauth2_jwks_parse_key(const char *json, jsmntok_t *tokens, int tokens_size, int key_obj_idx,
                                 struct flb_oauth2_jwks_key **key_out)
{
    int i;
    flb_sds_t kid = NULL;
    flb_sds_t n = NULL;
    flb_sds_t e = NULL;
    struct flb_oauth2_jwks_key *key = NULL;
    jsmntok_t *key_obj;

    if (!json || !tokens || key_obj_idx < 0 || key_obj_idx >= tokens_size || !key_out) {
        return -1;
    }

    key_obj = &tokens[key_obj_idx];
    if (key_obj->type != JSMN_OBJECT) {
        return -1;
    }

    /* Find kty, kid, n, e in the key object */
    /* JSMN stores objects as: [object_token, key1, value1, key2, value2, ...] */
    for (i = key_obj_idx + 1; i < tokens_size && i < key_obj_idx + 1 + (key_obj->size * 2); i += 2) {
        jsmntok_t *tok = &tokens[i];
        jsmntok_t *val;

        if (i + 1 >= tokens_size) {
            break;
        }

        val = &tokens[i + 1];

        if (tok->type != JSMN_STRING) {
            continue;
        }

        if (oauth2_jwt_token_strcmp(json, tok, "kty") == 0) {
            flb_sds_t kty = oauth2_jwt_token_to_sds(json, val);
            if (kty && strcmp(kty, "RSA") != 0) {
                flb_sds_destroy(kty);
                if (kid) flb_sds_destroy(kid);
                if (n) flb_sds_destroy(n);
                if (e) flb_sds_destroy(e);
                return -1; /* Not an RSA key */
            }
            if (kty) {
                flb_sds_destroy(kty);
            }
        }
        else if (oauth2_jwt_token_strcmp(json, tok, "kid") == 0) {
            kid = oauth2_jwt_token_to_sds(json, val);
        }
        else if (oauth2_jwt_token_strcmp(json, tok, "n") == 0) {
            n = oauth2_jwt_token_to_sds(json, val);
        }
        else if (oauth2_jwt_token_strcmp(json, tok, "e") == 0) {
            e = oauth2_jwt_token_to_sds(json, val);
        }
    }

    if (!kid || !n || !e) {
        if (kid) flb_sds_destroy(kid);
        if (n) flb_sds_destroy(n);
        if (e) flb_sds_destroy(e);
        return -1;
    }

    key = flb_calloc(1, sizeof(struct flb_oauth2_jwks_key));
    if (!key) {
        flb_sds_destroy(kid);
        flb_sds_destroy(n);
        flb_sds_destroy(e);
        return -1;
    }

    key->kid = kid;
    key->modulus = n;
    key->exponent = e;
    key->loaded_at = time(NULL);

    *key_out = key;
    return 0;
}

static int oauth2_jwks_parse_json(flb_sds_t jwks_json, struct flb_oauth2_jwks_cache *cache)
{
    int ret;
    int tokens_size;
    jsmntok_t *tokens = NULL;
    int i;
    int keys_found = 0;

    ret = oauth2_jwt_parse_json_tokens(jwks_json, flb_sds_len(jwks_json),
                                       &tokens, &tokens_size,
                                       FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT);
    if (ret != FLB_OAUTH2_JWT_OK) {
        flb_error("[oauth2_jwt] failed to parse JWKS JSON tokens");
        return -1;
    }


    /* Find "keys" array in the JWKS */
    for (i = 1; i < tokens_size; i++) {
        jsmntok_t *key = &tokens[i];
        jsmntok_t *val;

        if (key->type != JSMN_STRING) {
            continue;
        }

        i++;
        if (i >= tokens_size) {
            break;
        }

        val = &tokens[i];

        if (oauth2_jwt_token_strcmp(jwks_json, key, "keys") == 0 &&
            val->type == JSMN_ARRAY) {
            int j;
            int keys_count = val->size;
            int key_idx = i + 1;
            int key_obj_end;
            jsmntok_t *key_obj;
            struct flb_oauth2_jwks_key *jwks_key;

            /* Parse each key in the array */
            for (j = 0; j < keys_count && key_idx < tokens_size; j++) {
                key_obj = &tokens[key_idx];
                jwks_key = NULL;

                if (key_obj->type != JSMN_OBJECT) {
                    break;
                }

                /* For JSMN, an object with size N has N key-value pairs
                 * Each pair occupies 2 tokens (key + value)
                 * So total tokens = 1 (object) + N*2 (pairs)
                 * Since JWKS keys have simple string values (no nested objects),
                 * we can use this simple calculation */
                key_obj_end = key_idx + 1 + (key_obj->size * 2);

                /* Ensure we don't go beyond tokens_size */
                if (key_obj_end > tokens_size) {
                    key_obj_end = tokens_size;
                }

                ret = oauth2_jwks_parse_key(jwks_json, tokens, tokens_size, key_idx, &jwks_key);
                if (ret == 0 && jwks_key) {
                    /* Store key in cache using kid as hash key */
                    flb_hash_table_add(cache->entries, jwks_key->kid,
                                      flb_sds_len(jwks_key->kid),
                                      jwks_key, 0);
                    keys_found++;
                }

                /* Move to next key object */
                key_idx = key_obj_end;
            }
            break;
        }
    }

    flb_free(tokens);

    if (keys_found == 0) {
        flb_error("[oauth2_jwt] No valid keys found in JWKS");
        return -1;
    }

    return 0;
}


static int oauth2_jwt_verify_signature_rsa(const char *signing_input,
                                           size_t signing_input_len,
                                           const unsigned char *signature,
                                           size_t signature_len,
                                           flb_sds_t modulus_b64,
                                           flb_sds_t exponent_b64)
{
    int ret;
    unsigned char *modulus_bytes = NULL;
    unsigned char *exponent_bytes = NULL;
    size_t modulus_len = 0;
    size_t exponent_len = 0;

    /* Decode base64url modulus and exponent */
    ret = oauth2_jwt_base64url_decode(modulus_b64, flb_sds_len(modulus_b64),
                                      (unsigned char **)&modulus_bytes, &modulus_len,
                                      FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT);
    if (ret != FLB_OAUTH2_JWT_OK) {
        goto cleanup;
    }

    ret = oauth2_jwt_base64url_decode(exponent_b64, flb_sds_len(exponent_b64),
                                      (unsigned char **)&exponent_bytes, &exponent_len,
                                      FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT);
    if (ret != FLB_OAUTH2_JWT_OK) {
        goto cleanup;
    }

    /* Use flb_crypto abstraction for signature verification */
    /* This handles OpenSSL 1.1.1 and 3.x compatibility internally */
    ret = flb_crypto_verify_simple(FLB_CRYPTO_PADDING_PKCS1,
                                   FLB_HASH_SHA256,
                                   modulus_bytes, modulus_len,
                                   exponent_bytes, exponent_len,
                                   (unsigned char *) signing_input, signing_input_len,
                                   (unsigned char *) signature, signature_len);

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_debug("[oauth2_jwt] Signature verification failed: ret=%d", ret);
    }

cleanup:
    if (modulus_bytes) {
        flb_free(modulus_bytes);
    }
    if (exponent_bytes) {
        flb_free(exponent_bytes);
    }

    return (ret == FLB_CRYPTO_SUCCESS) ? 0 : -1;
}

static int oauth2_jwks_fetch_keys(struct flb_oauth2_jwt_ctx *ctx)
{
    int ret;
    int port;
    size_t b_sent;
    char *protocol = NULL;
    char *host = NULL;
    char *port_str = NULL;
    char *uri = NULL;
    int io_flags = FLB_IO_TCP;
    struct flb_upstream *u = NULL;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;
    struct flb_tls *tls = NULL;
    flb_sds_t jwks_json = NULL;

    if (!ctx || !ctx->cfg.jwks_url || !ctx->config) {
        return -1;
    }


    ret = flb_utils_url_split(ctx->cfg.jwks_url, &protocol, &host, &port_str, &uri);
    if (ret != 0) {
        flb_error("[oauth2_jwt] invalid JWKS URL: %s", ctx->cfg.jwks_url);
        return -1;
    }

    if (!host || !port_str || !uri) {
        flb_error("[oauth2_jwt] invalid JWKS URL components");
        goto cleanup;
    }

    port = atoi(port_str);
    if (port <= 0) {
        flb_error("[oauth2_jwt] invalid port in JWKS URL");
        goto cleanup;
    }

    if (protocol && strcasecmp(protocol, "https") == 0) {
        io_flags = FLB_IO_TLS;
        flb_tls_init();
        tls = flb_tls_create(FLB_TLS_CLIENT_MODE, FLB_TRUE, 0,
                            host, NULL, NULL, NULL, NULL, NULL);
        if (!tls) {
            flb_error("[oauth2_jwt] failed to create TLS context");
            goto cleanup;
        }
        flb_tls_set_verify_hostname(tls, FLB_TRUE);
        ret = flb_tls_load_system_certificates(tls);
        if (ret != 0) {
            flb_error("[oauth2_jwt] failed to load system certificates");
            goto cleanup;
        }
    }

    u = flb_upstream_create(ctx->config, host, port, io_flags, tls);
    if (!u) {
        flb_error("[oauth2_jwt] failed to create upstream");
        goto cleanup;
    }

    flb_stream_disable_async_mode(&u->base);

    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_error("[oauth2_jwt] failed to get upstream connection");
        goto cleanup;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, uri, NULL, 0, host, port, NULL, 0);
    if (!c) {
        flb_error("[oauth2_jwt] failed to create HTTP client");
        goto cleanup;
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_error("[oauth2_jwt] HTTP request failed");
        goto cleanup;
    }

    if (c->resp.status != 200) {
        flb_error("[oauth2_jwt] JWKS endpoint returned status %d", c->resp.status);
        goto cleanup;
    }

    if (c->resp.payload_size <= 0) {
        flb_error("[oauth2_jwt] empty JWKS response");
        goto cleanup;
    }

    jwks_json = flb_sds_create_len(c->resp.payload, c->resp.payload_size);
    if (!jwks_json) {
        flb_error("[oauth2_jwt] failed to create JWKS JSON buffer");
        goto cleanup;
    }

    /* Parse JWKS JSON and store keys in cache */
    ret = oauth2_jwks_parse_json(jwks_json, &ctx->jwks_cache);
    if (ret != 0) {
        flb_error("[oauth2_jwt] failed to parse JWKS JSON");
        flb_sds_destroy(jwks_json);
        jwks_json = NULL;
    }
    else {
        ctx->jwks_cache.last_refresh = time(NULL);
    }

cleanup:
    if (jwks_json) {
        flb_sds_destroy(jwks_json);
    }
    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    if (u) {
        flb_upstream_destroy(u);
    }
    if (tls) {
        flb_tls_destroy(tls);
    }
    if (protocol) {
        flb_free(protocol);
    }
    if (host) {
        flb_free(host);
    }
    if (port_str) {
        flb_free(port_str);
    }
    if (uri) {
        flb_free(uri);
    }

    return (jwks_json != NULL) ? 0 : -1;
}

static void oauth2_jwt_free_cfg(struct flb_oauth2_jwt_cfg *cfg)
{
    /* Note: cfg->issuer, cfg->jwks_url, and cfg->allowed_audience are pointers
     * to strings owned by the Fluent Bit configuration system (flb_kv).
     * They will be freed automatically when the input instance properties are
     * destroyed, so we should NOT free them here to avoid double-free errors.
     */
    (void) cfg;
}

struct flb_oauth2_jwt_ctx *flb_oauth2_jwt_context_create(struct flb_config *config,
                                                         struct flb_oauth2_jwt_cfg *cfg)
{
    struct flb_oauth2_jwt_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_oauth2_jwt_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->config = config;

    if (cfg != NULL) {
        memcpy(&ctx->cfg, cfg, sizeof(struct flb_oauth2_jwt_cfg));
    }

    if (oauth2_jwks_cache_init(&ctx->jwks_cache,
                               ctx->cfg.jwks_refresh_interval) != 0) {
        flb_free(ctx);
        return NULL;
    }

    /* Don't download JWKS during initialization - do it lazily on first validation */
    /* This avoids blocking the initialization thread */

    return ctx;
}

void flb_oauth2_jwt_context_destroy(struct flb_oauth2_jwt_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    oauth2_jwks_cache_destroy(&ctx->jwks_cache);
    oauth2_jwt_free_cfg(&ctx->cfg);
    flb_free(ctx);
}

int flb_oauth2_jwt_validate(struct flb_oauth2_jwt_ctx *ctx,
                            const char *authorization_header,
                            size_t authorization_header_len)
{
    int ret;
    int status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    int verify_ret;
    int allowed_client_authorized;
    int dot_count;
    size_t token_start = 0;
    size_t token_len;
    size_t i;
    time_t now;
    uint64_t exp;
    struct flb_oauth2_jwt jwt;
    struct flb_oauth2_jwks_key *jwks_key;
    struct mk_list *allowed_client_head;
    struct flb_config_map_val *map_val;
    struct mk_list *client_list_head;
    struct flb_slist_entry *client_entry;

    verify_ret = 0;
    allowed_client_authorized = FLB_FALSE;
    dot_count = 0;
    jwks_key = NULL;
    allowed_client_head = NULL;
    map_val = NULL;
    client_list_head = NULL;
    client_entry = NULL;

    if (!ctx) {
        return FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
    }

    if (!ctx->cfg.validate) {
        return FLB_OAUTH2_JWT_OK;
    }

    if (!authorization_header || authorization_header_len == 0) {
        return FLB_OAUTH2_JWT_ERR_MISSING_AUTH_HEADER;
    }

    while (token_start < authorization_header_len &&
           isspace((unsigned char) authorization_header[token_start])) {
        token_start++;
    }

    if (authorization_header_len - token_start < sizeof("Bearer ") - 1 ||
        strncasecmp(&authorization_header[token_start], "Bearer ", sizeof("Bearer ") - 1) != 0) {
        return FLB_OAUTH2_JWT_ERR_MISSING_BEARER_TOKEN;
    }

    token_start += sizeof("Bearer ") - 1;
    token_len = authorization_header_len - token_start;

    while (token_len > 0 &&
           isspace((unsigned char) authorization_header[token_start + token_len - 1])) {
        token_len--;
    }

    /* Check if token looks like a JWT (has dots) */
    if (token_len > 0) {
        dot_count = 0;
        for (i = 0; i < token_len; i++) {
            if (authorization_header[token_start + i] == '.') {
                dot_count++;
            }
        }
        if (dot_count != 2) {
            flb_debug("[oauth2_jwt] Token does not appear to be a JWT (expected 2 dots, found %d). "
                     "Keycloak may be returning opaque tokens instead of JWT access tokens.", dot_count);
            return FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT;
        }
    }

    memset(&jwt, 0, sizeof(struct flb_oauth2_jwt));

    status = flb_oauth2_jwt_parse(&authorization_header[token_start], token_len, &jwt);
    if (status != FLB_OAUTH2_JWT_OK) {
        flb_debug("[oauth2_jwt] failed to parse token: %s",
                  flb_oauth2_jwt_status_message(status));
        return status;
    }

    /* Verify signature using JWKS */
    if (jwt.claims.kid) {
        now = time(NULL);

        /* Check if cache needs refresh or is empty */
        if (ctx->jwks_cache.last_refresh == 0 ||
            (now - ctx->jwks_cache.last_refresh) >= ctx->cfg.jwks_refresh_interval) {
            ret = oauth2_jwks_fetch_keys(ctx);
            if (ret != 0) {
                flb_debug("[oauth2_jwt] Failed to fetch JWKS: %d", ret);
        status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
        goto jwt_end;
            }
        }

        /* Lookup key by kid */
        jwks_key = (struct flb_oauth2_jwks_key *)flb_hash_table_get_ptr(ctx->jwks_cache.entries,
                                         jwt.claims.kid,
                                         flb_sds_len(jwt.claims.kid));
        if (!jwks_key) {
            /* Try to refresh JWKS and lookup again */
            ret = oauth2_jwks_fetch_keys(ctx);
            if (ret != 0) {
                flb_debug("[oauth2_jwt] Failed to refresh JWKS: %d", ret);
        status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
        goto jwt_end;
            }
            jwks_key = (struct flb_oauth2_jwks_key *)flb_hash_table_get_ptr(ctx->jwks_cache.entries,
                                                 jwt.claims.kid,
                                                 flb_sds_len(jwt.claims.kid));
    }

        if (!jwks_key) {
            flb_debug("[oauth2_jwt] Key with kid '%s' not found in JWKS", jwt.claims.kid);
        status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
        goto jwt_end;
    }

        /* Verify RSA signature */
        verify_ret = oauth2_jwt_verify_signature_rsa(
            jwt.signing_input, flb_sds_len(jwt.signing_input),
            jwt.signature, jwt.signature_len,
            jwks_key->modulus, jwks_key->exponent);
        if (verify_ret != 0) {
            flb_debug("[oauth2_jwt] Signature verification failed: ret=%d", verify_ret);
            status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
            goto jwt_end;
        }
    }

    /* Check expiration */
    now = time(NULL);
    exp = jwt.claims.expiration;
    if (exp <= (uint64_t) now) {
        flb_debug("[oauth2_jwt] Token expired: exp=%llu <= now=%ld", (unsigned long long)exp, (long)now);
        status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
        goto jwt_end;
    }

    /* Check issuer */
    if (ctx->cfg.issuer) {
        if (!jwt.claims.issuer || strcmp(ctx->cfg.issuer, jwt.claims.issuer) != 0) {
            flb_debug("[oauth2_jwt] Issuer mismatch: expected='%s', actual='%s'",
                     ctx->cfg.issuer, jwt.claims.issuer ? jwt.claims.issuer : "(null)");
            status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
            goto jwt_end;
        }
    }

    /* Check audience */
    if (ctx->cfg.allowed_audience) {
        if (!jwt.claims.audience || strcmp(ctx->cfg.allowed_audience, jwt.claims.audience) != 0) {
            flb_debug("[oauth2_jwt] Audience mismatch: expected='%s', actual='%s'",
                     ctx->cfg.allowed_audience, jwt.claims.audience ? jwt.claims.audience : "(null)");
            status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
            goto jwt_end;
        }
    }

    /* Check allowed clients */
    if (ctx->cfg.allowed_clients && mk_list_size(ctx->cfg.allowed_clients) > 0) {
        allowed_client_authorized = FLB_FALSE;

        /* Iterate over flb_config_map_val entries (each contains a list of flb_slist_entry) */
        mk_list_foreach(allowed_client_head, ctx->cfg.allowed_clients) {
            map_val = mk_list_entry(allowed_client_head, struct flb_config_map_val, _head);
            if (!map_val || !map_val->val.list) {
                continue;
            }

            /* Iterate over flb_slist_entry in this map_val's list */
            mk_list_foreach(client_list_head, map_val->val.list) {
                client_entry = mk_list_entry(client_list_head, struct flb_slist_entry, _head);
                if (jwt.claims.client_id && client_entry && client_entry->str &&
                    strcmp(client_entry->str, jwt.claims.client_id) == 0) {
                allowed_client_authorized = FLB_TRUE;
                    goto client_check_done;
                }
            }
        }

    client_check_done:
        if (allowed_client_authorized == FLB_FALSE) {
            flb_error("[oauth2_jwt] Client ID '%s' not in allowed list (rejecting request)",
                     jwt.claims.client_id ? jwt.claims.client_id : "(null)");
            status = FLB_OAUTH2_JWT_ERR_INVALID_ARGUMENT;
            goto jwt_end;
        }
    }

    status = FLB_OAUTH2_JWT_OK;

jwt_end:
    flb_oauth2_jwt_destroy(&jwt);

    return status;
}

/* OAuth2 JWT config map for input plugins */
static struct flb_config_map oauth2_jwt_config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "oauth2.validate", "false",
     0, FLB_TRUE, offsetof(struct flb_oauth2_jwt_cfg, validate),
     "Enable OAuth2 JWT validation for incoming requests"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.issuer", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_jwt_cfg, issuer),
     "Expected issuer claim for OAuth2 JWT validation"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.jwks_url", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_jwt_cfg, jwks_url),
     "JWKS endpoint URL for OAuth2 JWT validation"
    },
    {
     FLB_CONFIG_MAP_STR, "oauth2.allowed_audience", NULL,
     0, FLB_TRUE, offsetof(struct flb_oauth2_jwt_cfg, allowed_audience),
     "Audience claim to enforce for OAuth2 JWT validation"
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "oauth2.allowed_clients", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_oauth2_jwt_cfg, allowed_clients),
     "Authorized client_id/azp values for OAuth2 JWT validation"
    },
    {
     FLB_CONFIG_MAP_INT, "oauth2.jwks_refresh_interval", "300",
     0, FLB_TRUE, offsetof(struct flb_oauth2_jwt_cfg, jwks_refresh_interval),
     "JWKS cache refresh interval in seconds for OAuth2 JWT validation"
    },

    /* EOF */
    {0}
};

struct mk_list *flb_oauth2_jwt_get_config_map(struct flb_config *config)
{
    struct mk_list *config_map;

    config_map = flb_config_map_create(config, oauth2_jwt_config_map);

    return config_map;
}

