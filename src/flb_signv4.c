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

/*
 *
 * AWS Signv4 documentation
 *
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <mbedtls/sha256.h>

#include <stdlib.h>
#include <ctype.h>

static flb_sds_t sha256_to_hex(unsigned char *sha256)
{
    int i;
    flb_sds_t hex;
    flb_sds_t tmp;

    hex = flb_sds_create_size(64);
    if (!hex) {
        flb_error("[signv4] cannot allocate buffer to convert sha256 to hex");
        return NULL;
    }

    for (i = 0; i < 32; i++) {
        tmp = flb_sds_printf(&hex, "%02x", sha256[i]);
        if (!tmp) {
            flb_error("[signedv4] error formatting sha256 -> hex");
            flb_sds_destroy(hex);
            return NULL;
        }
        hex = tmp;
    }

    return hex;
}

static int hmac_sha256_sign(unsigned char out[32],
                            unsigned char *key, size_t key_len,
                            unsigned char *msg, size_t msg_len)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);

    /* Start with the key */
    mbedtls_md_hmac_starts(&ctx, key, key_len);

    /* Update message */
    mbedtls_md_hmac_update(&ctx, msg, msg_len);

    /* Write digest to output buffer */
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);

    return 0;
}

static int kv_key_cmp(const void *a_arg, const void *b_arg)
{
    int ret;
    struct flb_kv *kv_a = *(struct flb_kv **) a_arg;
    struct flb_kv *kv_b = *(struct flb_kv **) b_arg;

    ret = strcmp(kv_a->key, kv_b->key);
    if (ret == 0) {
        ret = strcmp(kv_a->val, kv_b->val);
    }

    return ret;
}

static inline int to_encode(char c)
{
    if ((c >= 48 && c <= 57)  ||  /* 0-9 */
        (c >= 65 && c <= 90)  ||  /* A-Z */
        (c >= 97 && c <= 122) ||  /* a-z */
        (c == '-' || c == '_' || c == '.' || c == '~' || c == '/' ||
         c == '=')) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

flb_sds_t flb_signv4_uri_normalize_path(char *uri, size_t len)
{
    char *p;
    int end_slash = FLB_FALSE;
    struct mk_list *tmp;
    struct mk_list *prev;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *entry;
    flb_sds_t out;

    out = flb_sds_create_len(uri, len);
    if (!out) {
        return NULL;
    }

    if (uri[len - 1] == '/') {
        end_slash = FLB_TRUE;
    }

    split = flb_utils_split(out, '/', -1);
    if (!split) {
        flb_sds_destroy(out);
        return NULL;
    }

    p = out;
    *p++ = '/';

    mk_list_foreach_safe(head, tmp, split) {
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        if (entry->len == 1 && *entry->value == '.') {
            flb_utils_split_free_entry(entry);
        }
        else if (entry->len == 2 && memcmp(entry->value, "..", 2) == 0) {
            prev = head->prev;
            if (prev != split) {
                entry = mk_list_entry(prev, struct flb_split_entry, _head);
                flb_utils_split_free_entry(entry);
            }
            entry = mk_list_entry(head, struct flb_split_entry, _head);
            flb_utils_split_free_entry(entry);
        }
    }

    mk_list_foreach(head, split) {
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        memcpy(p, entry->value, entry->len);
        p += entry->len;

        if (head->next != split) {
            *p++ = '/';
        }
    }

    len = (p - out);
    if (end_slash == FLB_TRUE && out[len - 1] != '/') {
        *p++ = '/';
    }

    flb_utils_split_free(split);

    flb_sds_len_set(out, p - out);
    out[p - out] = '\0';

    return out;
}

static flb_sds_t uri_encode(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[signv4] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE) {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) *(uri + i));
            if (!tmp) {
                flb_error("[signv4] error formatting special character");
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_error("[signv4] error composing outgoing buffer");
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
        }
    }

    return buf;
}

/*
 * Encodes URI parameters, which can not have "/" characters in them
 * (This happens in an STS request, the role ARN has a slash and is
 * given as a query parameter).
 */
static flb_sds_t uri_encode_params(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[signv4] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE || uri[i] == '/') {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) *(uri + i));
            if (!tmp) {
                flb_error("[signv4] error formatting special character");
                flb_sds_destroy(buf);
                return NULL;
            }
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_error("[signv4] error composing outgoing buffer");
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
        }
    }

    return buf;
}

/*
 * Convert URL encoded params (query string or POST payload) to a sorted
 * key/value linked list
 */
static flb_sds_t url_params_format(char *params)
{
    int i;
    int ret;
    int len;
    int items;
    char *p;
    struct mk_list list;
    struct mk_list split;
    struct mk_list *h_tmp;
    struct mk_list *head;
    struct flb_slist_entry *e;
    flb_sds_t key;
    flb_sds_t val;
    flb_sds_t tmp;
    flb_sds_t buf = NULL;
    struct flb_kv *kv;
    struct flb_kv **arr;

    mk_list_init(&list);
    mk_list_init(&split);

    ret = flb_slist_split_string(&split, params, '&', -1);
    if (ret == -1) {
        flb_error("[signv4] error processing given query string");
        return NULL;
    }

    mk_list_foreach_safe(head, h_tmp, &split) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        p = strchr(e->str, '=');
        if (!p) {
            continue;
        }

        len = (p - e->str);
        p++;

        /* URI encode every key and value */
        key = uri_encode_params(e->str, len);
        len++;
        val = uri_encode_params(p, flb_sds_len(e->str) - len);
        if (!key || !val) {
            flb_error("[signv4] error encoding uri for query string");
            if (key) {
                flb_sds_destroy(key);
            }
            if (val) {
                flb_sds_destroy(val);
            }
            flb_slist_destroy(&split);
            flb_kv_release(&list);
            return NULL;
        }

        kv = flb_kv_item_create_len(&list,
                                    key, flb_sds_len(key),
                                    val, flb_sds_len(val));
        flb_sds_destroy(key);
        flb_sds_destroy(val);

        if (!kv) {
            flb_error("[signv4] error processing key/value from query string");
            flb_slist_destroy(&split);
            flb_kv_release(&list);
            return NULL;
        }
    }
    flb_slist_destroy(&split);

    /* Sort the kv list of parameters */
    items = mk_list_size(&list);
    if (items == 0) {
        flb_kv_release(&list);
        return flb_sds_create("");
    }

    arr = flb_malloc(sizeof(struct flb_kv *) * items);
    if (!arr) {
        flb_errno();
        flb_kv_release(&list);
        return NULL;
    }

    i = 0;
    mk_list_foreach(head, &list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        arr[i] = kv;
        i++;
    }
    /* sort headers by key */
    qsort(arr, items, sizeof(struct flb_kv *), kv_key_cmp);

    /* Format query string parameters */
    buf = flb_sds_create_size(items * 64);
    if (!buf) {
        flb_kv_release(&list);
        flb_free(arr);
        return NULL;
    }

    for (i = 0; i < items; i++) {
        kv = (struct flb_kv *) arr[i];
        if (i + 1 < items) {
            tmp = flb_sds_printf(&buf, "%s=%s&",
                                 kv->key, kv->val);
        }
        else {
            tmp = flb_sds_printf(&buf, "%s=%s",
                                 kv->key, kv->val);
        }
        if (!tmp) {
            flb_error("[signv4] error allocating value");

        }
        buf = tmp;
    }

    flb_kv_release(&list);
    flb_free(arr);

    return buf;
}

/*
 * Given an original list of kv headers with 'in_list' as the list headed,
 * generate new entries on 'out_list' considering lower case headers key,
 * sorted by keys and values and merged duplicates.
 */
void headers_sanitize(struct mk_list *in_list, struct mk_list *out_list)
{
    int x;
    char *v_start;
    char *v_end;
    char *val;
    struct mk_list *head;
    struct mk_list *c_head;
    struct mk_list *tmp;
    struct mk_list out_tmp;
    struct flb_kv *kv;
    struct flb_kv *c_kv;
    flb_sds_t t;

    mk_list_init(&out_tmp);

    /* Create lowercase key headers in the temporal list */
    mk_list_foreach(head, in_list) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Sanitize value */
        v_start = kv->val;
        v_end = kv->val + flb_sds_len(kv->val);
        while (*v_start == ' ' || *v_start == '\t') {
            v_start++;
        }
        while (*v_end == ' ' || *v_end == '\t') {
            v_end--;
        }

        /*
         * The original headers might have upper case characters, for safety just
         * make a copy of them so we can lowercase them if required.
         */
        kv = flb_kv_item_create_len(&out_tmp,
                                    kv->key, flb_sds_len(kv->key),
                                    v_start, v_end - v_start);
        for (x = 0; x < flb_sds_len(kv->key); x++) {
            kv->key[x] = tolower(kv->key[x]);
        }

        /*
         * trim: kv->val alreay have a copy of the original value, now we need
         * to look for double empty spaces in the middle of the value and do
         * proper adjustments.
         */
        val = kv->val;
        while (v_start < v_end) {
            if (*v_start == ' ') {
                if (v_start < v_end && *(v_start + 1) == ' ') {
                    v_start++;
                    continue;
                }
            }
            *val = *v_start;
            v_start++;
            val++;
        }
        *val = '\0';
        flb_sds_len_set(kv->val, val - kv->val);
    }

    /* Find and merge duplicates */
    mk_list_foreach_safe(head, tmp, &out_tmp) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Check if this kv exists in out_list */
        c_kv = NULL;
        mk_list_foreach(c_head, out_list) {
            c_kv = mk_list_entry(c_head, struct flb_kv, _head);
            if (strcmp(kv->key, c_kv->key) == 0) {
                break;
            }
            c_kv = NULL;
        }

        /* if c_kv is set, means the key already exists in the outgoing list */
        if (c_kv) {
            t = flb_sds_printf(&c_kv->val, ",%s", kv->val);
            c_kv->val = t;
            flb_kv_item_destroy(kv);
        }
        else {
            mk_list_del(&kv->_head);
            mk_list_add(&kv->_head, out_list);
        }
    }
}

/*
 * Task 1: Create a canonical request
 * ==================================
 *
 *  https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 *  CanonicalRequest =
 *  HTTPRequestMethod + '\n' +
 *  CanonicalURI + '\n' +
 *  CanonicalQueryString + '\n' +
 *  CanonicalHeaders + '\n' +
 *  SignedHeaders + '\n' +
 *  HexEncode(Hash(RequestPayload))
 */
static flb_sds_t flb_signv4_canonical_request(struct flb_http_client *c,
                                              int normalize_uri,
                                              int amz_date_header,
                                              char *amzdate,
                                              char *security_token,
                                              flb_sds_t *signed_headers)
{
    int i;
    int len;
    int items;
    int post_params = FLB_FALSE;
    size_t size;
    char *val;
    struct flb_kv **arr;
    flb_sds_t cr;
    flb_sds_t uri;
    flb_sds_t tmp = NULL;
    flb_sds_t params;
    struct flb_kv *kv;
    struct mk_list list_tmp;
    struct mk_list *head;
    unsigned char sha256_buf[64] = {0};
    mbedtls_sha256_context sha256_ctx;

    /* Size hint */
    size = strlen(c->uri) + (mk_list_size(&c->headers) * 64) + 256;

    cr = flb_sds_create_size(size);
    if (!cr) {
        flb_error("[signv4] cannot allocate buffer");
        return NULL;
    }

    switch (c->method) {
    case FLB_HTTP_GET:
        tmp = flb_sds_cat(cr, "GET\n", 4);
        break;
    case FLB_HTTP_POST:
        tmp = flb_sds_cat(cr, "POST\n", 5);
        break;
    case FLB_HTTP_PUT:
        tmp = flb_sds_cat(cr, "PUT\n", 4);
        break;
    case FLB_HTTP_HEAD:
        tmp = flb_sds_cat(cr, "HEAD\n", 5);
        break;
    };

    if (!tmp) {
        flb_error("[signv4] invalid processing of HTTP method");
        flb_sds_destroy(cr);
        return NULL;
    }

    cr = tmp;

    /* Our URI already contains the query string, so do the proper adjustments */
    if (c->query_string) {
        len = (c->query_string - c->uri) - 1;
    }
    else {
        len = strlen(c->uri);
    }

    /*
     * URI normalization is required by certain AWS service, for hence the caller
     * plugin is responsible to enable/disable this flag. If set the URI in the
     * canonical request will be normalized.
     */
    if (normalize_uri == FLB_TRUE) {
        tmp = flb_signv4_uri_normalize_path((char *) c->uri, len);
        if (!tmp) {
            flb_error("[signv4] error normalizing path");
            flb_sds_destroy(cr);
            return NULL;
        }
        len = flb_sds_len(tmp);
    }
    else {
        tmp = (char *) c->uri;
    }

    /* Do URI encoding (rfc3986) */
    uri = uri_encode(tmp, len);
    if (tmp != c->uri) {
        flb_sds_destroy(tmp);
    }
    if (!uri) {
        /* error composing outgoing buffer */
        flb_sds_destroy(cr);
        return NULL;
    }

    tmp = flb_sds_cat(cr, uri, flb_sds_len(uri));
    if (!tmp) {
        flb_error("[signv4] error concatenating encoded URI");
        flb_sds_destroy(uri);
        flb_sds_destroy(cr);
        return NULL;
    }
    cr = tmp;
    flb_sds_destroy(uri);

    tmp = flb_sds_cat(cr, "\n", 1);
    if (!tmp) {
        flb_error("[signv4] error concatenating encoded URI break line");
        flb_sds_destroy(cr);
        return NULL;
    }
    cr = tmp;

    /* Canonical Query String */
    tmp = NULL;
    if (c->query_string) {
        params = url_params_format((char *) c->query_string);
        if (!params) {
            flb_sds_destroy(cr);
            return NULL;
        }
        tmp = flb_sds_cat(cr, params, flb_sds_len(params));
        if (!tmp) {
            flb_error("[signv4] error concatenating query string");
            flb_sds_destroy(params);
            flb_sds_destroy(cr);
            return NULL;
        }
        flb_sds_destroy(params);
        cr = tmp;
    }

    /*
     * If the original HTTP method is POST and we have some urlencoded parameters
     * as payload, we must handle them as we did for the query string.
     */
    if (c->method == FLB_HTTP_POST && c->body_len > 0) {
        val = (char *) flb_kv_get_key_value("Content-Type", &c->headers);
        if (val) {
            if (strstr(val, "application/x-www-form-urlencoded")) {
                params = url_params_format((char *) c->body_buf);
                if (!params) {
                    flb_error("[signv4] error processing POST payload params");
                    flb_sds_destroy(cr);
                    return NULL;
                }
                tmp = flb_sds_cat(cr, params, flb_sds_len(params));
                if (!tmp) {
                    flb_error("[signv4] error concatenating POST payload params");
                    flb_sds_destroy(params);
                    flb_sds_destroy(cr);
                    return NULL;
                }
                cr = tmp;
                flb_sds_destroy(params);
                post_params = FLB_TRUE;
            }
        }
    }

    /* query string / POST separator */
    tmp = flb_sds_cat(cr, "\n", 1);
    if (!tmp) {
        flb_error("[signv4] error adding params breakline separator");
        flb_sds_destroy(cr);
        return NULL;
    }
    cr = tmp;

    /*
     * Canonical Headers
     *
     * Add the required custom headers:
     *
     * - x-amz-date
     * - x-amz-security-token (if set)
     */
    mk_list_init(&list_tmp);

    /* include x-amz-date header ? */
    if (amz_date_header == FLB_TRUE) {
        len = strlen(amzdate);
        flb_http_add_header(c, "x-amz-date", 10, amzdate, len);
    }

    /* x-amz-security_token */
    if (security_token) {
        len = strlen(security_token);
        flb_http_add_header(c, "x-amz-security-token", 20, security_token, len);
    }

    headers_sanitize(&c->headers, &list_tmp);

    /*
     * For every header registered, append it to the temporal array so we can sort them
     * later.
     */
    items = mk_list_size(&list_tmp);
    size = (sizeof(struct flb_kv *) * items);
    arr = flb_malloc(size);
    if (!arr) {
        flb_errno();
        flb_kv_release(&list_tmp);
        flb_sds_destroy(cr);
        return NULL;
    }

    /* Compose temporal array to sort headers */
    i = 0;
    mk_list_foreach(head, &list_tmp) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        arr[i] = kv;
        i++;
    }

    /* Sort the headers from the temporal array */
    qsort(arr, items, sizeof(struct flb_kv *), kv_key_cmp);

    /* Iterate sorted headers and append them to the outgoing buffer */
    for (i = 0; i < items; i++) {
        kv = (struct flb_kv *) arr[i];
        tmp = flb_sds_printf(&cr, "%s:%s\n", kv->key, kv->val);
        if (!tmp) {
            flb_error("[signv4] error composing canonical headers");
            flb_free(arr);
            flb_kv_release(&list_tmp);
            flb_sds_destroy(cr);
            return NULL;
        }
        cr = tmp;
    }

    /* Add required breakline */
    tmp = flb_sds_printf(&cr, "\n");
    if (!tmp) {
        flb_error("[signv4] error adding extra breakline separator");
        flb_free(arr);
        flb_kv_release(&list_tmp);
        flb_sds_destroy(cr);
        return NULL;
    }
    cr = tmp;

    /* Signed Headers for canonical request context */
    for (i = 0; i < items; i++) {
        kv = (struct flb_kv *) arr[i];

        /* Check if this is the last header, if so add breakline separator */
        if (i + 1 == items) {
            tmp = flb_sds_printf(&cr, "%s\n", kv->key);
        }
        else {
            tmp = flb_sds_printf(&cr, "%s;", kv->key);
        }
        if (!tmp) {
            flb_error("[signv4] error composing canonical signed headers");
            flb_free(arr);
            flb_kv_release(&list_tmp);
            flb_sds_destroy(cr);
            return NULL;
        }
        cr = tmp;
    }

    /* Signed Headers for authorization header (Task 4) */
    for (i = 0; i < items; i++) {
        kv = (struct flb_kv *) arr[i];

        /* Check if this is the last header, if so add breakline separator */
        if (i + 1 == items) {
            tmp = flb_sds_printf(signed_headers, "%s", kv->key);
        }
        else {
            tmp = flb_sds_printf(signed_headers, "%s;", kv->key);
        }
        if (!tmp) {
            flb_error("[signv4] error composing auth signed headers");
            flb_free(arr);
            flb_kv_release(&list_tmp);
            flb_sds_destroy(cr);
            return NULL;
        }
        *signed_headers = tmp;
    }

    flb_free(arr);
    flb_kv_release(&list_tmp);

    /* Hashed Payload */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    if (c->body_len > 0 && post_params == FLB_FALSE) {
        mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) c->body_buf,
                              c->body_len);
    }
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    for (i = 0; i < 32; i++) {
        tmp = flb_sds_printf(&cr, "%02x", (unsigned char) sha256_buf[i]);
        if (!tmp) {
            flb_error("[signedv4] error formatting hashed payload");
            flb_sds_destroy(cr);
            return NULL;
        }
        cr = tmp;
    }

    return cr;
}

/*
 * Task 2
 * ======
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
 */
static flb_sds_t flb_signv4_string_to_sign(struct flb_http_client *c,
                                           flb_sds_t cr, char *amzdate,
                                           char *datestamp, char *service,
                                           char *region)
{
    int i;
    flb_sds_t tmp;
    flb_sds_t sign;
    unsigned char sha256_buf[64] = {0};
    mbedtls_sha256_context sha256_ctx;

    sign = flb_sds_create_size(256);
    if (!sign) {
        flb_error("[signv4] cannot create buffer for signature");
        return NULL;
    }

    /* Hashing Algorithm */
    tmp = flb_sds_cat(sign, "AWS4-HMAC-SHA256\n", 17);
    if (!tmp) {
        flb_error("[signv4] cannot add algorithm to signature");
        flb_sds_destroy(sign);
        return NULL;
    }
    sign = tmp;

    /* Amazon date */
    tmp = flb_sds_printf(&sign, "%s\n", amzdate);
    if (!tmp) {
        flb_error("[signv4] cannot add amz-date to signature");
        flb_sds_destroy(sign);
        return NULL;
    }
    sign = tmp;

    /* Credentials Scope */
    tmp = flb_sds_printf(&sign, "%s/%s/%s/aws4_request\n",
                         datestamp, region, service);
    if (!tmp) {
        flb_error("[signv4] cannot add credentials scope  to signature");
        flb_sds_destroy(sign);
        return NULL;
    }

    /* Hash of Canonical Request */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (unsigned char *) cr, flb_sds_len(cr));
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    for (i = 0; i < 32; i++) {
        tmp = flb_sds_printf(&sign, "%02x", (unsigned char) sha256_buf[i]);
        if (!tmp) {
            flb_error("[signv4] error formatting hashed canonical request");
            flb_sds_destroy(sign);
            return NULL;
        }
        sign = tmp;
    }

    return sign;
}

/*
 * Task 3
 * ======
 *
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
 */
static flb_sds_t flb_signv4_calculate_signature(flb_sds_t string_to_sign,
                                                char *datestamp, char *service,
                                                char *region, char *secret_key)
{
    int len;
    int klen = 32;
    flb_sds_t tmp;
    flb_sds_t key;
    unsigned char key_date[32];
    unsigned char key_region[32];
    unsigned char key_service[32];
    unsigned char key_signing[32];
    unsigned char signature[32];

    /* Compose initial key */
    key = flb_sds_create_size(256);
    if (!key) {
        flb_error("[signv4] cannot create buffer for signature calculation");
        return NULL;
    }

    tmp = flb_sds_printf(&key, "AWS4%s", secret_key);
    if (!tmp) {
        flb_error("[signv4] error formatting initial key");
        flb_sds_destroy(key);
        return NULL;
    }
    key = tmp;

    /* key_date */
    len = strlen(datestamp);
    hmac_sha256_sign(key_date, (unsigned char *) key, flb_sds_len(key),
                     (unsigned char *) datestamp, len);
    flb_sds_destroy(key);

    /* key_region */
    len = strlen(region);
    hmac_sha256_sign(key_region, key_date, klen, (unsigned char *) region, len);

    /* key_service */
    len = strlen(service);
    hmac_sha256_sign(key_service, key_region, klen, (unsigned char *) service, len);

    /* key_signing */
    hmac_sha256_sign(key_signing, key_service, klen,
                     (unsigned char *) "aws4_request", 12);

    /* Signature */
    hmac_sha256_sign(signature, key_signing, klen,
                     (unsigned char *) string_to_sign, flb_sds_len(string_to_sign));

    return sha256_to_hex(signature);
}

/*
 * Task 4
 * ======
 *
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
 */
static flb_sds_t flb_signv4_add_authorization(struct flb_http_client *c,
                                              char *access_key,
                                              char *datestamp,
                                              char *region, char *service,
                                              flb_sds_t signed_headers,
                                              flb_sds_t signature)
{
    int ret;
    int len;
    flb_sds_t tmp;
    flb_sds_t header_value;

    header_value = flb_sds_create_size(512);
    if (!header_value) {
        flb_error("[signv4] cannot allocate buffer for authorization header");
        return NULL;
    }

    tmp = flb_sds_printf(&header_value,
                         "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, "
                         "SignedHeaders=%s, Signature=%s",
                         access_key, datestamp, region, service,
                         signed_headers, signature);
    if (!tmp) {
        flb_error("[signv4] error composing authorization header");
        flb_sds_destroy(header_value);
        return NULL;
    }
    header_value = tmp;

    len = flb_sds_len(header_value);
    ret = flb_http_add_header(c, "Authorization", 13, header_value, len);
    if (ret == -1) {
        flb_error("[signv4] could not add authorization header");
        flb_sds_destroy(header_value);
        return NULL;

    }
    header_value = tmp;

    /* Return the composed final header for testing if required */
    return header_value;
}

flb_sds_t flb_signv4_do(struct flb_http_client *c, int normalize_uri,
                        int amz_date_header,
                        time_t t_now,
                        char *access_key,
                        char *region, char *service,
                        char *secret_key, char *security_token)
{
    char amzdate[32];
    char datestamp[32];
    struct tm *gmt;
    flb_sds_t cr;
    flb_sds_t string_to_sign;
    flb_sds_t signature;
    flb_sds_t signed_headers;
    flb_sds_t auth_header;

    gmt = flb_malloc(sizeof(struct tm));
    if (!gmt) {
        flb_errno();
        return NULL;
    }

    if (!gmtime_r(&t_now, gmt)) {
        flb_error("[signv4] error converting given unix timestamp");
        flb_free(gmt);
        return NULL;
    }

    strftime(amzdate, sizeof(amzdate) - 1, "%Y%m%dT%H%M%SZ", gmt);
    strftime(datestamp, sizeof(datestamp) - 1, "%Y%m%d", gmt);
    flb_free(gmt);

    /* Task 1: canonical request */
    signed_headers = flb_sds_create_size(256);
    if (!signed_headers) {
        flb_error("[signedv4] cannot allocate buffer for auth signed headers");
        return NULL;
    }

    cr = flb_signv4_canonical_request(c, normalize_uri,
                                      amz_date_header, amzdate,
                                      security_token, &signed_headers);
    if (!cr) {
        flb_error("[signv4] failed canonical request");
        flb_sds_destroy(signed_headers);
        return NULL;
    }

    /* Task 2: string to sign */
    string_to_sign = flb_signv4_string_to_sign(c, cr, amzdate,
                                               datestamp, service, region);
    if (!string_to_sign) {
        flb_error("[signv4] failed string to sign");
        flb_sds_destroy(cr);
        flb_sds_destroy(signed_headers);
        return NULL;
    }
    flb_sds_destroy(cr);

    /* Task 3: calculate the signature */
    signature = flb_signv4_calculate_signature(string_to_sign, datestamp, service,
                                               region, secret_key);
    if (!signature) {
        flb_error("[signv4] failed calculate_string");
        flb_sds_destroy(signed_headers);
        flb_sds_destroy(string_to_sign);
        return NULL;
    }
    flb_sds_destroy(string_to_sign);

    /* Task 4: add signature to HTTP request */
    auth_header = flb_signv4_add_authorization(c,
                                               access_key,
                                               datestamp, region, service,
                                               signed_headers, signature);
    flb_sds_destroy(signed_headers);
    flb_sds_destroy(signature);

    if (!auth_header) {
        flb_error("[signv4] error creating authorization header");
        return NULL;
    }

    return auth_header;
}
