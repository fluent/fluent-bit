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



#include "oci_client.h"

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output_plugin.h>

#include <fluent-bit/flb_crypto.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <fluent-bit/flb_jsmn.h>

flb_sds_t create_base64_sha256_signature(flb_sds_t private_key,
                                         flb_sds_t signing_string)
{
    int len = 0, ret;
    size_t outlen;
    flb_sds_t signature;
    unsigned char sha256_buf[32] = { 0 };
    unsigned char sig[256] = { 0 };
    size_t sig_len = sizeof(sig);

    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) signing_string,
                          flb_sds_len(signing_string),
                          sha256_buf, sizeof(sha256_buf));

    if(ret != FLB_CRYPTO_SUCCESS) {
        // flb_plg_error(ctx->ins, "error generating hash buffer");
        return NULL;
    }

    ret =   flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                   FLB_CRYPTO_PADDING_PKCS1,
                                   FLB_HASH_SHA256,
                                   (unsigned char *) private_key,
                                   flb_sds_len(private_key),
                                   sha256_buf, sizeof(sha256_buf),
                                   sig, &sig_len);


    if (ret != FLB_CRYPTO_SUCCESS) {
        // flb_plg_error(ctx->ins, "error signing SHA256");
        return NULL;
    }

    signature = flb_sds_create_size(512);
    if (!signature) {
        flb_errno();
        return NULL;
    }

    /* base 64 encode */
    len = flb_sds_alloc(signature) - 1;
    flb_base64_encode((unsigned char*) signature, len, &outlen, sig,
                      sizeof(sig));
    signature[outlen] = '\0';
    flb_sds_len_set(signature, outlen);

    return signature;
}

flb_sds_t get_date(void)
{

    flb_sds_t rfc1123date;
    time_t t;
    size_t size;
    struct tm tm = { 0 };

    /* Format Date */
    rfc1123date = flb_sds_create_size(32);
    if (!rfc1123date) {
        flb_errno();
        return NULL;
    }

    t = time(NULL);
    if (!gmtime_r(&t, &tm)) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return NULL;
    }
    size = strftime(rfc1123date, flb_sds_alloc(rfc1123date) - 1,
                    "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (size <= 0) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return NULL;
    }
    flb_sds_len_set(rfc1123date, size);
    return rfc1123date;
}

flb_sds_t add_header_and_signing(struct flb_http_client *c,
                                 flb_sds_t signing_str,
                                 const char *header,
                                 int headersize,
                                 const char *val, int val_size)
{
    if (!signing_str) {
        return NULL;
    }

    flb_http_add_header(c, header, headersize, val, val_size);

    signing_str = flb_sds_cat(signing_str, "\n", 1);
    signing_str = flb_sds_cat(signing_str, header, headersize);
    signing_str = flb_sds_cat(signing_str, ": ", 2);
    signing_str = flb_sds_cat(signing_str, val, val_size);

    return signing_str;
}

/*
 * Authorization: Signature version="1",keyId="<tenancy_ocid>/<user_ocid>/<key_fingerprint>",
 * algorithm="rsa-sha256",headers="(request-target) date x-content-sha256 content-type content-length",
 * signature="signature"
 */
flb_sds_t create_authorization_header_content(flb_sds_t signature,
                                              flb_sds_t key_id)
{
    flb_sds_t content;

    content = flb_sds_create_size(1024*10);
    content = flb_sds_cat(content, FLB_OCI_SIGN_SIGNATURE_VERSION,
                          sizeof(FLB_OCI_SIGN_SIGNATURE_VERSION) - 1);
    content = flb_sds_cat(content, ",", 1);
    content = flb_sds_cat(content, FLB_OCI_SIGN_KEYID,
                          sizeof(FLB_OCI_SIGN_KEYID) - 1);
    content = flb_sds_cat(content, "=\"", 2);
    content = flb_sds_cat(content, key_id, flb_sds_len(key_id));
    content = flb_sds_cat(content, "\",", 2);
    content = flb_sds_cat(content, FLB_OCI_SIGN_ALGORITHM,
                          sizeof(FLB_OCI_SIGN_ALGORITHM) - 1);
    content = flb_sds_cat(content, ",", 1);
    content = flb_sds_cat(content, FLB_OCI_SIGN_HEADERS,
                          sizeof(FLB_OCI_SIGN_HEADERS) - 1);
    content = flb_sds_cat(content, ",", 1);
    content = flb_sds_cat(content, FLB_OCI_SIGN_SIGNATURE,
                          sizeof(FLB_OCI_SIGN_SIGNATURE) - 1);
    content = flb_sds_cat(content, "=\"", 2);
    content = flb_sds_cat(content, signature, flb_sds_len(signature));
    content = flb_sds_cat(content, "\"", 1);

    return content;
}

flb_sds_t create_fed_authorization_header_content(flb_sds_t signature,
                                                  flb_sds_t key_id)
{
    flb_sds_t content;

    content = flb_sds_create_size(512);
    content = flb_sds_cat(content, FLB_OCI_SIGN_SIGNATURE_VERSION,
                          sizeof(FLB_OCI_SIGN_SIGNATURE_VERSION) - 1);
    content = flb_sds_cat(content, ",", 1);
    content = flb_sds_cat(content, FLB_OCI_SIGN_KEYID,
                          sizeof(FLB_OCI_SIGN_KEYID) - 1);
    content = flb_sds_cat(content, "=\"", 2);
    content = flb_sds_cat(content, key_id, flb_sds_len(key_id));
    content = flb_sds_cat(content, "\",", 2);
    content = flb_sds_cat(content, FLB_OCI_SIGN_ALGORITHM,
                          sizeof(FLB_OCI_SIGN_ALGORITHM) - 1);
    content = flb_sds_cat(content, ",", 1);
    content = flb_sds_cat(content, FLB_OCI_FED_SIGN_HEADERS,
                          sizeof(FLB_OCI_FED_SIGN_HEADERS) - 1);
    content = flb_sds_cat(content, ",", 1);
    content = flb_sds_cat(content, FLB_OCI_SIGN_SIGNATURE,
                          sizeof(FLB_OCI_SIGN_SIGNATURE) - 1);
    content = flb_sds_cat(content, "=\"", 2);
    content = flb_sds_cat(content, signature, flb_sds_len(signature));
    content = flb_sds_cat(content, "\"", 1);

    return content;
}

flb_sds_t refresh_cert(struct flb_upstream *u,
                       flb_sds_t cert_url,
                       struct flb_output_instance *ins)
{
    flb_sds_t cert = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    int ret = 0;
    size_t b_sent;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_errno();
        return NULL;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, cert_url, NULL, 0,
                        NULL, 0, NULL, 0);

    if (!c) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        return NULL;
    }

    flb_http_strip_port_from_host(c);
    flb_http_buffer_size(c, 0);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Accept", 6, "*/*", 3);
    flb_http_add_header(c, "Authorization", 13, "Bearer Oracle", 13);

    ret = flb_http_do(c, &b_sent);

    if (ret != 0) {
        flb_errno();
        flb_plg_error(ins, "http do error");
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    if (c->resp.status != 200 && c->resp.status != 204 && c->resp.status != 201) {
        flb_errno();
        flb_plg_info(ins, "request header = %s", c->header_buf);
        flb_plg_error(ins, "request was not successful with status = %d payload = %s url = %s",
                      c->resp.status, c->resp.payload, cert_url);
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    cert = flb_sds_create_len(c->resp.payload, c->resp.payload_size);

    if (!cert) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);
    return cert;
}

// finish this func
flb_sds_t get_tenancy_id_from_certificate(X509 *cert)
{
    flb_sds_t t_id = NULL;
    int i;
    const unsigned char *str;
    char* x;

    X509_NAME *subj = X509_get_subject_name(cert);

    for (i = 0; i < X509_NAME_entry_count(subj); i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        str = ASN1_STRING_get0_data(d);
        x = strstr((const char *) str, "opc-tenant:");
        if (x) {
            break;
        }
    }

    t_id = flb_sds_create((const char*) str + 11);

    return t_id;
}

char* sanitize_certificate_string(flb_sds_t cert_pem)
{
    // i2d_X509()
    char sanitized[strlen(cert_pem) + 1];
    strcpy(sanitized, cert_pem);
    char c_start[] = "-----BEGIN CERTIFICATE-----";
    size_t c_st_len = strlen(c_start);
    char c_end[] = "-----END CERTIFICATE-----";
    char k_start[] = "-----BEGIN PUBLIC KEY-----";
    size_t k_st_len = strlen(k_start);
    char k_end[] = "-----END PUBLIC KEY-----";
    char *p = NULL, *q = NULL, *ans, *tmp, *a;

    p = strstr(sanitized, c_start);
    q = strstr(sanitized, c_end);
    if (p && q) {
        *q = '\0';
        tmp = p + c_st_len + 1;
    }
    else {
        p = strstr(sanitized, k_start);
        q = strstr(sanitized, k_end);
        *q = '\0';
        tmp = p + k_st_len;
    }
    ans = flb_malloc(strlen(sanitized) + sizeof(char));
    a = ans;
    while(*tmp != '\0')
    {
        if(*tmp != '\t' && *tmp != '\n') {
            *a++ = *tmp++;
        }
        else {
            ++tmp;
        }
    }
    *a = '\0';

    return ans;

}

void colon_separated_fingerprint(unsigned char* readbuf, void *writebuf, size_t len)
{
    char *l;
    size_t i;
    for(i=0; i < len-1; i++) {
        l = (char*) (3*i + ((intptr_t) writebuf));
        sprintf(l, "%02x:", readbuf[i]);
    }

    l = (char*) (3*(len - 1) + ((intptr_t) writebuf));
    sprintf(l, "%02x", readbuf[len - 1]);
}

flb_sds_t fingerprint(X509 *cert)
{
    // i2d_X509()
    flb_sds_t fingerprint = NULL;
    const EVP_MD *digest;
    unsigned char md[SHA_DIGEST_LENGTH];
    char buf[3*SHA_DIGEST_LENGTH+1];
    unsigned int n;

    digest = EVP_get_digestbyname("sha1");
    X509_digest(cert, digest, md, &n);

    colon_separated_fingerprint(md, (void *) buf, (size_t) SHA_DIGEST_LENGTH);

    fingerprint = flb_sds_create_len(buf, 3*SHA_DIGEST_LENGTH);
    return fingerprint;
}

int session_key_supplier(flb_sds_t *priv_key,
                         flb_sds_t *pub_key,
                         struct flb_output_instance *ins)
{
    // Key generation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY* key = NULL;
    BIO *pri, *pub;
    int priKeyLen;
    int pubKeyLen;
    char* priKeyStr;
    char* pubKeyStr;
    int ret;
    BIGNUM *bne = NULL;

    bne = BN_new();
    ret = BN_set_word(bne, RSA_EXP);
    if (ret != 1) {
        return -1;
    }
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bne);
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);

    // Serialize to string
    pri = BIO_new(BIO_s_mem());
    pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey_traditional(pri, key, NULL, NULL, 0, 0, NULL);
    PEM_write_bio_PUBKEY(pub, key);

    priKeyLen = BIO_pending(pri);
    pubKeyLen = BIO_pending(pub);
    priKeyStr = flb_malloc(priKeyLen);
    pubKeyStr = flb_malloc(pubKeyLen);
    BIO_read(pri, priKeyStr, priKeyLen);
    BIO_read(pub, pubKeyStr, pubKeyLen);
    priKeyStr[priKeyLen] = '\0';
    pubKeyStr[pubKeyLen] = '\0';
    // flb_plg_info(ins, "private_key = %s", priKeyStr);
    // flb_plg_info(ins, "pub_key = %s", pubKeyStr);

    *priv_key = flb_sds_create_len((const char *) priKeyStr, priKeyLen);
    *pub_key = flb_sds_create_len((const char *)pubKeyStr, pubKeyLen);

    BIO_free(pri);
    BIO_free(pub);
    flb_free(priKeyStr);
    flb_free(pubKeyStr);
    BN_free(bne);

    return 0;
}

X509 *get_cert_from_string(flb_sds_t cert_pem)
{
    X509 *cert;
    BIO* certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, cert_pem, (int) flb_sds_len(cert_pem));
    cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);

    BIO_free(certBio);
    return cert;
}

flb_sds_t get_region(struct flb_upstream *u,
                     flb_sds_t region_url,
                     struct flb_hash_table *ht)
{
    flb_sds_t region;
    char* temp_region = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    size_t b_sent, temp_sz;
    int ret;

    // TODO: construct region uri
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_errno();
        return NULL;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, region_url,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_errno();
        return NULL;
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Accept", 6, "*/*", 3);
    flb_http_add_header(c, "Authorization", 13, "Bearer Oracle", 13);

    ret = flb_http_do(c, &b_sent);

    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    if (c->resp.status != 200 && c->resp.status != 201 &&
        c->resp.status != 204) {
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    ret = flb_hash_table_get(ht, mk_string_tolower(c->resp.payload),
                             (int)c->resp.payload_size,
                             (void *)&temp_region,
                             &temp_sz);
    if (ret < 0) {
        temp_region = c->resp.payload;
        temp_sz = c->resp.payload_size;
    }

    region = flb_sds_create_len(temp_region,
                                (int) temp_sz);

    return region;
}

flb_sds_t parse_token(char *response,
                      size_t response_len)
{
    int tok_size = 32, ret, i;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    char *key;
    char *val;
    int key_len;
    int val_len;
    flb_sds_t token = NULL;

    jsmn_init(&parser);

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    ret = jsmn_parse(&parser, response, response_len, tokens, tok_size);

    if (ret<=0) {
        flb_free(tokens);
        return NULL;
    }
    tok_size = ret;

    /* Parse JSON tokens */
    for (i = 0; i < tok_size; i++) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type != JSMN_STRING) {
            continue;
        }

        key = response + t->start;
        key_len = (t->end - t->start);

        i++;
        t = &tokens[i];
        val = response + t->start;
        val_len = (t->end - t->start);

        if (val_len < 1) {
            continue;
        }

        if ((key_len == sizeof(FLB_OCI_TOKEN) - 1)
            && strncasecmp(key, FLB_OCI_TOKEN,
                           sizeof(FLB_OCI_TOKEN) - 1) == 0) {
            // code
            token = flb_sds_create_len(val, val_len);
            if (!token) {
                flb_free(tokens);
                return NULL;
            }
            break;
        }
    }

    flb_free(tokens);
    return token;
}

static const char *jwt_decode_payload(const char *src,
                                      char **bufplainp) {
    char *converted_src;
    char *payload = NULL;

    const char *errstr = NULL;

    int i, padding, len;

    int payload_len;
    int nbytesdecoded;

    int payloads_start = 0;
    int payloads_end   = 0;

    len           = (int)strlen(src);
    converted_src = flb_malloc(len + 4);

    for (i = 0; i < len; i++) {
        switch (src[i]) {
            case '-':
                converted_src[i] = '+';
                break;

            case '_':
                converted_src[i] = '/';
                break;

            case '.':
                if (payloads_start == 0)
                    payloads_start = i + 1;
                else {
                    if (payloads_end > 0) {
                        errstr =
                            "The token is invalid with more "
                            "than 2 delimiters";
                        goto done;
                    }
                    payloads_end = i;
                }
                /* FALLTHRU */

            default:
                converted_src[i] = src[i];
        }
    }

    if (payloads_start == 0 || payloads_end == 0) {
        errstr = "The token is invalid with less than 2 delimiters";
        goto done;
    }

    payload_len = payloads_end - payloads_start;
    payload     = flb_malloc(payload_len + 4);
    strncpy(payload, (converted_src + payloads_start), payload_len);

    padding = 4 - (payload_len % 4);
    if (padding < 4) {
        while (padding--)
            payload[payload_len++] = '=';
    }

    nbytesdecoded = ((payload_len + 3) / 4) * 3;
    *bufplainp    = flb_malloc(nbytesdecoded + 1);

    if (EVP_DecodeBlock((uint8_t *)(*bufplainp), (uint8_t *)payload,
                        (int)payload_len) == -1) {
        errstr = "Failed to decode base64 payload";
    }

    done:
    flb_free(payload);
    flb_free(converted_src);
    return errstr;
}

const char* get_token_exp(flb_sds_t token_string,
                          time_t *exp,
                          struct flb_output_instance *ins)
{
    char *payload = NULL;
    const char* err_str = NULL;

    err_str = jwt_decode_payload(token_string, &payload);
    // flb_plg_info(ins, "jwt payload = %s", payload);

    if (err_str != NULL) {
        return err_str;
    }

    int tok_size = 256, ret, i;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    char *key;
    char *val;
    int key_len;
    int val_len;

    jsmn_init(&parser);

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    ret = jsmn_parse(&parser, payload, strlen(payload), tokens, tok_size);

    if (ret<=0) {
        flb_free(tokens);
        return NULL;
    }
    tok_size = ret;

    /* Parse JSON tokens */
    for (i = 0; i < tok_size; i++) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type != JSMN_STRING) {
            continue;
        }

        key = payload + t->start;
        key_len = (t->end - t->start);

        i++;
        t = &tokens[i];
        val = payload + t->start;
        val_len = (t->end - t->start);

        if (val_len < 1) {
            continue;
        }

        // flb_plg_info(ins, "sectoken %s: %s", key, val);
        if ((key_len == 3)
            && strncasecmp(key, "exp",
                           3) == 0) {
            // code
            flb_plg_info(ins, "fetched exp time = %s", val);
            *exp = atol(val);
            break;
        }
    }

    flb_free(tokens);
    return err_str;
}
