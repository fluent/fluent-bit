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

#include <sys/stat.h>
#include <fluent-bit/oracle/flb_oracle_client.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <fluent-bit/flb_jsmn.h>

char* short_names[] = {
    "yny\0",
    "hyd\0",
    "mel\0",
    "bom\0",
    "kix\0",
    "icn\0",
    "syd\0",
    "nrt\0",
    "yul\0",
    "yyz\0",
    "ams\0",
    "fra\0",
    "zrh\0",
    "jed\0",
    "dxb\0",
    "gru\0",
    "cwl\0",
    "lhr\0",
    "iad\0",
    "phx\0",
    "sjc\0",
    "vcp\0",
    "scl\0",
    "mtz\0",
    "mrs\0",
    "sin\0",
    "auh\0",
    "lin\0",
    "arn\0",
    "jnb\0",
    "cdg\0",
    "qro\0",
    "mad\0",
    "ord\0",
    "lfi\0",
    "luf\0",
    "ric\0",
    "pia\0",
    "tus\0",
    "ltn\0",
    "brs\0",
    "nja\0",
    "ukb\0",
    "mct\0",
    "wga\0",
    "bgy\0",
    "mxp\0",
    "snn\0",
    "dtm\0",
    "dus\0",
    "ork\0",
    "vll\0",
    "str\0",
    "beg\0",
    NULL
};

char *long_names[] = {
    "ap-chuncheon-1\0",
    "ap-hyderabad-1\0",
    "ap-melbourne-1\0",
    "ap-mumbai-1\0",
    "ap-osaka-1\0",
    "ap-seoul-1\0",
    "ap-sydney-1\0",
    "ap-tokyo-1\0",
    "ca-montreal-1\0",
    "ca-toronto-1\0",
    "eu-amsterdam-1\0",
    "eu-frankfurt-1\0",
    "eu-zurich-1\0",
    "me-jeddah-1\0",
    "me-dubai-1\0",
    "sa-saopaulo-1\0",
    "uk-cardiff-1\0",
    "uk-london-1\0",
    "us-ashburn-1\0",
    "us-phoenix-1\0",
    "us-sanjose-1\0",
    "sa-vinhedo-1\0",
    "sa-santiago-1\0",
    "il-jerusalem-1\0",
    "eu-marseille-1\0",
    "ap-singapore-1\0",
    "me-abudhabi-1\0",
    "eu-milan-1\0",
    "eu-stockholm-1\0",
    "af-johannesburg-1\0",
    "eu-paris-1\0",
    "mx-queretaro-1\0",
    "eu-madrid-1\0",
    "us-chicago-1\0",
    "us-langley-1\0",
    "us-luke-1\0",
    "us-gov-ashburn-1\0",
    "us-gov-chicago-1\0",
    "us-gov-phoenix-1\0",
    "uk-gov-london-1\0",
    "uk-gov-cardiff-1\0",
    "ap-chiyoda-1\0",
    "ap-ibaraki-1\0",
    "me-dcc-muscat-1\0",
    "ap-dcc-canberra-1\0",
    "eu-dcc-milan-1\0",
    "eu-dcc-milan-2\0",
    "eu-dcc-dublin-2\0",
    "eu-dcc-rating-2\0",
    "eu-dcc-rating-1\0",
    "eu-dcc-dublin-1\0",
    "eu-madrid-2\0",
    "eu-frankfurt-2\0",
    "eu-jovanovac-1\0",
    NULL
};

int create_pk_context(flb_sds_t filepath,
                      const char *key_passphrase,
                      struct flb_output_instance *ins,
                      flb_sds_t *p_key)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ins, "error to open key file: %s", filepath);
        return -1;
    }

    kbuffer = flb_sds_create_size(finfo.size + 1);
    if (!kbuffer) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    ret = fread(kbuffer, finfo.size, 1, fp);
    if (ret < 1) {
        flb_sds_destroy(kbuffer);
        fclose(fp);
        flb_plg_error(ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    *p_key = kbuffer;

    return 0;
}

int load_oci_credentials(struct flb_output_instance *ins,
                         flb_sds_t config_file_location,
                         flb_sds_t profile_name,
                         flb_sds_t *user, flb_sds_t *tenancy,
                         flb_sds_t *key_file, flb_sds_t *key_fingerprint,
                         flb_sds_t *region)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char* key = NULL;
    char* val;

    content = flb_file_read(config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_debug(ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        /* process line */
        flb_plg_debug(ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, profile_name)) {
                flb_plg_info(ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
        }
        if(found_profile) {
            if(line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_debug(ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
                res = -1;
                break;
            }
            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                *user = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                *tenancy = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                *key_file = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                *key_fingerprint = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                *region = flb_sds_create(val);
            }
            else {
                goto iterate;
            }
        }
        iterate:
        if (profile) {
            mk_mem_free(profile);
            profile = NULL;
        }
        if (key) {
            mk_mem_free(key);
            key = NULL;
        }
        line = strtok(NULL, "\n");
    }
    if (!found_profile) {
        flb_errno();
        res = -1;
    }

    flb_sds_destroy(content);
    if (profile) {
        mk_mem_free(profile);
    }
    if (key) {
        mk_mem_free(key);
    }
    return res;
}

/*
 * Authorization: Signature version="1",keyId="<tenancy_ocid>/<user_ocid>/<key_fingerprint>",
 * algorithm="rsa-sha256",headers="(request-target) date x-content-sha256 content-type content-length",
 * signature="signature"
 */
flb_sds_t create_authorization_header_content(flb_sds_t key_id,
                                              flb_sds_t signature,
                                              char* sign_header)
{
    flb_sds_t content;

    content = flb_sds_create_size(512);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_SIGNATURE_VERSION,
                     sizeof(FLB_OCI_SIGN_SIGNATURE_VERSION) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_KEYID,
                     sizeof(FLB_OCI_SIGN_KEYID) - 1);
    flb_sds_cat_safe(&content, "=\"", 2);
    flb_sds_cat_safe(&content, key_id, flb_sds_len(key_id));
    flb_sds_cat_safe(&content, "\",", 2);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_ALGORITHM,
                     sizeof(FLB_OCI_SIGN_ALGORITHM) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, sign_header,
                     sizeof(sign_header) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_SIGNATURE,
                     sizeof(FLB_OCI_SIGN_SIGNATURE) - 1);
    flb_sds_cat_safe(&content, "=\"", 2);
    flb_sds_cat_safe(&content, signature, flb_sds_len(signature));
    flb_sds_cat_safe(&content, "\"", 1);

    return content;
}

flb_sds_t create_base64_sha256_signature(flb_sds_t private_key,
                                         flb_sds_t signing_string,
                                         struct flb_output_instance *ins)
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
        flb_plg_error(ins, "error generating hash buffer");
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
        flb_plg_error(ins, "error signing SHA256");
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
                                 flb_sds_t signing_str, const char *header, int headersize,
                                 const char *val, int val_size)
{
    if (!signing_str) {
        return NULL;
    }

    flb_http_add_header(c, header, headersize, val, val_size);

    flb_sds_cat_safe(&signing_str, "\n", 1);
    flb_sds_cat_safe(&signing_str, header, headersize);
    flb_sds_cat_safe(&signing_str, ": ", 2);
    flb_sds_cat_safe(&signing_str, val, val_size);

    return signing_str;
}

int build_federation_client_headers(struct flb_http_client *c, flb_sds_t private_key,
                                    flb_sds_t key_id, flb_sds_t json,
                                    flb_sds_t uri, struct flb_output_instance *ins)
{
    int ret = -1;
    flb_sds_t tmp_sds = NULL;
    flb_sds_t signing_str = NULL;
    flb_sds_t rfc1123date = NULL;
    flb_sds_t encoded_uri = NULL;
    flb_sds_t signature = NULL;
    flb_sds_t auth_header_str = NULL;

    size_t tmp_len = 0;

    unsigned char sha256_buf[32] = { 0 };

    tmp_sds = flb_sds_create_size(512);
    if (!tmp_sds) {
        flb_errno();
        goto error_label;
    }

    signing_str = flb_sds_create_size(1024);
    if (!signing_str) {
        flb_errno();
        goto error_label;
    }

    // Add (requeset-target) to signing string
    encoded_uri = flb_uri_encode(uri, flb_sds_len(uri));
    if (!encoded_uri) {
        flb_errno();
        goto error_label;
    }
    signing_str = flb_sds_cat(signing_str, FLB_OCI_HEADER_REQUEST_TARGET,
                              sizeof(FLB_OCI_HEADER_REQUEST_TARGET) - 1);
    signing_str = flb_sds_cat(signing_str, ": post ", sizeof(": post ") - 1);
    signing_str = flb_sds_cat(signing_str, encoded_uri,
                              flb_sds_len(encoded_uri));

    // Add Date header
    rfc1123date = get_date();
    if (!rfc1123date) {
        flb_plg_error(ins, "cannot compose temporary date header");
        goto error_label;
    }
    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_DATE,
                                         sizeof(FLB_OCI_HEADER_DATE) - 1, rfc1123date,
                                         flb_sds_len(rfc1123date));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    // Add x-content-sha256 Header
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) json,
                          flb_sds_len(json),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ins, "error forming hash buffer for x-content-sha256 Header");
        goto error_label;
    }

    flb_base64_encode((unsigned char*) tmp_sds, flb_sds_len(tmp_sds) - 1,
                      &tmp_len, sha256_buf, sizeof(sha256_buf));

    tmp_sds[tmp_len] = '\0';
    flb_sds_len_set(tmp_sds, tmp_len);

    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_X_CONTENT_SHA256,
                                         sizeof(FLB_OCI_HEADER_X_CONTENT_SHA256) - 1, tmp_sds,
                                         flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    // Add content-Type
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_TYPE, sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                                         FLB_OCI_HEADER_CONTENT_TYPE_JSON,
                                         sizeof(FLB_OCI_HEADER_CONTENT_TYPE_JSON) - 1);
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    // Add content-Length
    tmp_len = snprintf(tmp_sds, flb_sds_alloc(tmp_sds) - 1, "%i",
                       (int) strlen(json));
    flb_sds_len_set(tmp_sds, tmp_len);
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_LENGTH, sizeof(FLB_OCI_HEADER_CONTENT_LENGTH) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    // Add Authorization header
    signature = create_base64_sha256_signature(private_key,
                                               signing_str,ins);
    if (!signature) {
        flb_plg_error(ins, "cannot compose signing signature");
        goto error_label;
    }

    auth_header_str = create_authorization_header_content(signature, key_id,
                                                          FLB_OCI_FED_SIGN_HEADERS);
    if (!auth_header_str) {
        flb_plg_error(ins, "cannot compose authorization header");
        goto error_label;
    }

    flb_http_add_header(c, FLB_OCI_HEADER_AUTH, sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header_str, flb_sds_len(auth_header_str));

    // User-Agent
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        FLB_OCI_HEADER_USER_AGENT_VAL,
                        sizeof(FLB_OCI_HEADER_USER_AGENT_VAL) - 1);

    // Accept
    flb_http_add_header(c, "Accept", 6, "*/*", 3);

    ret = 0;

    error_label:
    if (tmp_sds) {
        flb_sds_destroy(tmp_sds);
    }
    if (signing_str) {
        flb_sds_destroy(signing_str);
    }
    if (rfc1123date) {
        flb_sds_destroy(rfc1123date);
    }
    if (encoded_uri) {
        flb_sds_destroy(encoded_uri);
    }
    if (signature) {
        flb_sds_destroy(signature);
    }
    if (auth_header_str) {
        flb_sds_destroy(auth_header_str);
    }
    return ret;

}

int build_headers(struct flb_http_client *c, flb_sds_t private_key,
                  flb_sds_t key_id, flb_sds_t json,
                  flb_sds_t uri, struct flb_output_instance *ins,
                  char *content_type)
{
    int ret = -1;
    flb_sds_t tmp_sds = NULL;
    flb_sds_t signing_str = NULL;
    flb_sds_t rfc1123date = NULL;
    flb_sds_t encoded_uri = NULL;
    flb_sds_t signature = NULL;
    flb_sds_t auth_header_str = NULL;

    flb_sds_t tmp_ref = NULL;

    size_t tmp_len = 0;

    unsigned char sha256_buf[32] = { 0 };

    tmp_sds = flb_sds_create_size(512);
    if (!tmp_sds) {
        flb_errno();
        goto error_label;
    }

    signing_str = flb_sds_create_size(1024);
    if (!signing_str) {
        flb_errno();
        goto error_label;
    }

    /* Add (requeset-target) to signing string */
    encoded_uri = flb_uri_encode(uri, flb_sds_len(uri));
    if (!encoded_uri) {
        flb_errno();
        goto error_label;
    }
    flb_sds_cat_safe(&signing_str, FLB_OCI_HEADER_REQUEST_TARGET,
                     sizeof(FLB_OCI_HEADER_REQUEST_TARGET) - 1);
    flb_sds_cat_safe(&signing_str, ": post ", sizeof(": post ") - 1);
    flb_sds_cat_safe(&signing_str, encoded_uri,
                     flb_sds_len(encoded_uri));

    /* Add Host to Header */
    if (((c->flags & FLB_IO_TLS) && c->port == 443)
        || (!(c->flags & FLB_IO_TLS) && c->port == 80)) {
        /* default port */
        tmp_ref = flb_sds_copy(tmp_sds, c->host, strlen(c->host));
    }
    else {
        tmp_ref = flb_sds_printf(&tmp_sds, "%s:%i", c->host, c->port);
    }
    if (!tmp_ref) {
        flb_plg_error(ins, "cannot compose temporary host header");
        goto error_label;
    }
    tmp_sds = tmp_ref;
    tmp_ref = NULL;

    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_HOST,
                                         sizeof(FLB_OCI_HEADER_HOST) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add Date header */
    rfc1123date = get_date();
    if (!rfc1123date) {
        flb_plg_error(ins, "cannot compose temporary date header");
        goto error_label;
    }
    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_DATE,
                                         sizeof(FLB_OCI_HEADER_DATE) - 1, rfc1123date,
                                         flb_sds_len(rfc1123date));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add x-content-sha256 Header */
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) json,
                          flb_sds_len(json),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ins, "error forming hash buffer for x-content-sha256 Header");
        goto error_label;
    }

    flb_base64_encode((unsigned char*) tmp_sds, flb_sds_len(tmp_sds) - 1,
                      &tmp_len, sha256_buf, sizeof(sha256_buf));

    tmp_sds[tmp_len] = '\0';
    flb_sds_len_set(tmp_sds, tmp_len);

    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_X_CONTENT_SHA256,
                                         sizeof(FLB_OCI_HEADER_X_CONTENT_SHA256) - 1, tmp_sds,
                                         flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add content-Type */
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_TYPE, sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                                         content_type,
                                         sizeof(content_type) - 1);
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add content-Length */
    tmp_len = snprintf(tmp_sds, flb_sds_alloc(tmp_sds) - 1, "%i",
                       (int) flb_sds_len(json));
    flb_sds_len_set(tmp_sds, tmp_len);
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_LENGTH, sizeof(FLB_OCI_HEADER_CONTENT_LENGTH) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add Authorization header */
    signature = create_base64_sha256_signature(private_key, signing_str, ins);
    if (!signature) {
        flb_plg_error(ins, "cannot compose signing signature");
        goto error_label;
    }

    auth_header_str = create_authorization_header_content(key_id, signature, FLB_OCI_SIGN_HEADERS);
    if (!auth_header_str) {
        flb_plg_error(ins, "cannot compose authorization header");
        goto error_label;
    }

    flb_http_add_header(c, FLB_OCI_HEADER_AUTH, sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header_str, flb_sds_len(auth_header_str));

    /* User-Agent */
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        FLB_OCI_HEADER_USER_AGENT_VAL,
                        sizeof(FLB_OCI_HEADER_USER_AGENT_VAL) - 1);

    /* Accept */
    flb_http_add_header(c, "Accept", 6, "*/*", 3);

    ret = 0;

    error_label:
    if (tmp_sds) {
        flb_sds_destroy(tmp_sds);
    }
    if (signing_str) {
        flb_sds_destroy(signing_str);
    }
    if (rfc1123date) {
        flb_sds_destroy(rfc1123date);
    }
    if (encoded_uri) {
        flb_sds_destroy(encoded_uri);
    }
    if (signature) {
        flb_sds_destroy(signature);
    }
    if (auth_header_str) {
        flb_sds_destroy(auth_header_str);
    }
    return ret;
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
    const unsigned char *str;
    char* x;

    X509_NAME *subj = X509_get_subject_name(cert);

    for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
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
    for(size_t i=0; i < len-1; i++) {
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
    flb_sds_t token = NULL;

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

void build_region_table(struct flb_hash_table **region_table) {
    *region_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 100, 0);
    int i;
    for(i = 0; short_names[i] != NULL; i++) {
        flb_hash_table_add(*region_table,
                           short_names[i],
                           strlen(short_names[i]),
                           long_names[i],
                           strlen(long_names[i]));
    }

}

int refresh_security_token(struct federation_client *fed_client,
                           struct flb_config *config,
                           struct flb_output_instance *ins,
                           struct flb_upstream *fed_u,
                           struct flb_upstream *cert_u,
                           struct flb_hash_table *region_table)
{
    flb_sds_t region;
    flb_sds_t host;
    flb_sds_t fed_uri;
    char* err;
    struct flb_upstream *upstream;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;
    char *s_leaf_cert, *s_inter_cert, *s_pub_key;
    int ret = -1, sz;
    time_t now;
    size_t b_sent;
    flb_sds_t json;
    if (fed_client && fed_client->expire) {
        now = time(NULL);
        if (fed_client->expire > now) {
            return 0;
        }
    }
    if (!fed_client) {
        fed_client = flb_calloc(1, sizeof(struct federation_client));
    }
    if (!fed_client->leaf_cert_ret) {
        fed_client->leaf_cert_ret = flb_calloc(1, sizeof(struct cert_retriever));
    }
    if (!fed_client->intermediate_cert_ret) {
        fed_client->intermediate_cert_ret = flb_calloc(1, sizeof(struct cert_retriever));
    }

    fed_client->leaf_cert_ret->cert_pem = refresh_cert(cert_u,
                                                            LEAF_CERTIFICATE_URL,
                                                            ins);
    if (!fed_client->leaf_cert_ret->cert_pem) {
        return -1;
    }
    fed_client->leaf_cert_ret->private_key_pem = refresh_cert(cert_u,
                                                                   LEAF_CERTIFICATE_PRIVATE_KEY_URL,
                                                                   ins);
    if (!fed_client->leaf_cert_ret->private_key_pem) {
        return -1;
    }
    fed_client->leaf_cert_ret->cert = get_cert_from_string(fed_client->leaf_cert_ret->cert_pem);

    fed_client->intermediate_cert_ret->cert_pem = refresh_cert(cert_u,
                                                                    INTERMEDIATE_CERTIFICATE_URL,
                                                                    ins);
    if (!fed_client->intermediate_cert_ret->cert_pem) {
        return -1;
    }

    region = get_region(cert_u, GET_REGION_URL, region_table);
    flb_plg_info(ins, "region = %s", region);
    fed_client->region = region;
    host = flb_sds_create_size(512);
    flb_sds_snprintf(&host, flb_sds_alloc(host), "auth.%s.oci.oraclecloud.com", region);
    if (!fed_u) {
        upstream = flb_upstream_create(config, host, 443,
                                       FLB_IO_TLS, ins->tls);
        if (!upstream) {
            return -1;
        }

        fed_u = upstream;
    }
    fed_client->tenancy_id = get_tenancy_id_from_certificate(fed_client->leaf_cert_ret->cert);
    ret = session_key_supplier(&fed_client->private_key,
                               &fed_client->public_key,
                               ins);
    if (ret != 0) {
        flb_plg_error(ins, "failed to create session key pair");
        return -1;
    }

    fed_client->key_id = flb_sds_create_size(512);
    flb_sds_snprintf(&fed_client->key_id, flb_sds_alloc(fed_client->key_id),
                     "%s/fed-x509/%s", fed_client->tenancy_id, fingerprint(fed_client->leaf_cert_ret->cert));
    // flb_plg_info(ctx->ins, "fed client key_id = %s", ctx->fed_client->key_id);

    // TODO: build headers
    u_conn = flb_upstream_conn_get(fed_u);
    if (!u_conn) {
        return -1;
    }

    s_leaf_cert = sanitize_certificate_string(fed_client->leaf_cert_ret->cert_pem);
    // flb_plg_info(ctx->ins, "sanitized leaf cert: %s", s_leaf_cert);
    s_pub_key = sanitize_certificate_string(fed_client->public_key);
    // flb_plg_info(ctx->ins, "pub key: %s", s_pub_key);
    s_inter_cert = sanitize_certificate_string(fed_client->intermediate_cert_ret->cert_pem);
    // flb_plg_info(ctx->ins, "sanitized inter cert: %s", s_inter_cert);
    sz = strlen(s_leaf_cert) + strlen(s_pub_key) + strlen(s_inter_cert);
    json = flb_sds_create_size(sz + 1000);
    flb_sds_snprintf(&json, flb_sds_alloc(json),
                     OCI_FEDERATION_REQUEST_PAYLOAD,
                     s_leaf_cert,
                     s_pub_key,
                     s_inter_cert);
    // flb_plg_info(ctx->ins, "fed client payload = %s", json);

    fed_uri = flb_sds_create_len("/v1/x509", 8);
    c = flb_http_client(u_conn, FLB_HTTP_POST, fed_uri,
                        json, flb_sds_len(json),
                        NULL, 0, NULL, 0);
    c->allow_dup_headers = FLB_FALSE;

    build_federation_client_headers(c, fed_client->leaf_cert_ret->private_key_pem,
                  fed_client->key_id, json,
                  fed_uri, ins);
    /*
    mk_list_foreach_safe(head, tmp, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_casecmp(kv->key, "host", 4) == 0) {
            flb_kv_item_destroy(kv);
            break;
        }
    }
     */


    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        flb_sds_destroy(json);
        flb_free(fed_uri);
        flb_free(s_leaf_cert);
        flb_free(s_pub_key);
        flb_free(s_inter_cert);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    if (c->resp.status != 200) {
        flb_plg_error(ins, "http status = %d, response = %s, header = %s",
                      c->resp.status, c->resp.payload, c->header_buf);
        flb_sds_destroy(json);
        flb_free(fed_uri);
        flb_free(s_leaf_cert);
        flb_free(s_pub_key);
        flb_free(s_inter_cert);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    fed_client->security_token = parse_token(c->resp.payload,
                                                  c->resp.payload_size);
    flb_plg_info(ins, "security token = %s", fed_client->security_token);

    err = get_token_exp(fed_client->security_token, &fed_client->expire, ins);
    if (err) {
        flb_plg_error(ins, "token error = %s",err);
        flb_free(s_leaf_cert);
        flb_free(s_pub_key);
        flb_free(s_inter_cert);
        flb_free(fed_uri);
        flb_sds_destroy(json);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    flb_plg_info(ins, "token expiration time = %ld", fed_client->expire);
    flb_free(json);
    flb_free(fed_uri);
    flb_free(s_leaf_cert);
    flb_free(s_pub_key);
    flb_free(s_inter_cert);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return 0;

}

static int file_to_buffer(const char *path,
                          char **out_buf, size_t *out_size)
{
    int ret;
    char *buf;
    ssize_t bytes;
    FILE *fp;
    struct stat st;

    if (!(fp = fopen(path, "r"))) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, (st.st_size + 1));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

int refresh_oke_workload_security_token(struct federation_client *fed_client,
                                        struct flb_config *config,
                                        struct flb_output_instance *ins,
                                        struct flb_upstream *fed_u,
                                        flb_sds_t oke_sa_ca_file,
                                        flb_sds_t oke_sa_token_file,
                                        flb_sds_t *key_id)
{
    char* tmp, *host;
    const char* err = NULL;
    char buf[1024*8] = {0};
    size_t o_len;
    int port = 12250, ret;
    struct flb_tls *tls;
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    flb_sds_t auth_header;
    char *token = NULL;
    size_t tk_size;
    flb_sds_t json;
    flb_sds_t uri;
    size_t b_sent;
    time_t now;

    if (fed_client && fed_client->expire) {
        now = time(NULL);
        if (fed_client->expire > now) {
            return 0;
        }
    }

    if (fed_client) {
        fed_client = flb_calloc(1, sizeof(struct federation_client));
    }

    /*
    tmp = getenv("OCI_RESOURCE_PRINCIPAL_REGION");
    if (!tmp) {
        flb_plg_error(ctx->ins, "Not a valid region");
        flb_sds_destroy(sa_cert_path);
        return -1;
    }
    ctx->fed_client->region = flb_sds_create_len(tmp, strlen(tmp));
     */
    session_key_supplier(&fed_client->private_key,
                         &fed_client->public_key,
                         ins);
    host = getenv("KUBERNETES_SERVICE_HOST");
    if (!host) {
        flb_plg_error(ins, "Host not found");
        return -1;
    }
    if (!fed_u) {
        tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                             0,
                             1,
                             NULL,
                             NULL,
                             oke_sa_ca_file,
                             NULL,
                             NULL,
                             NULL);
        fed_u = flb_upstream_create(config, host, port, FLB_IO_TLS, tls);
    }

    ret = file_to_buffer(oke_sa_token_file, &token, &tk_size);
    if (ret != 0) {
        flb_errno();
        flb_plg_error(ins, "failed to load kubernetes service account token");
        return -1;
    }

    char *s_pub_key = sanitize_certificate_string(fed_client->public_key);
    json = flb_sds_create_size(1024*4);
    flb_sds_snprintf(&json, flb_sds_alloc(json),
                     OCI_OKE_PROXYMUX_PAYLOAD, s_pub_key);
    uri = flb_sds_create_len("/resourcePrincipalSessionTokens",
                             sizeof("/resourcePrincipalSessionTokens") - 1);

    u_conn = flb_upstream_conn_get(fed_u);
    if (!u_conn) {
        flb_errno();
        flb_plg_error(ins,
                      "failed to establish connection with kubernetes upstream");
        return -1;
    }
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri, json, flb_sds_len(json), NULL, 0, NULL, 0);
    if (!c) {
        flb_errno();
        flb_plg_error(ins,
                      "failed to create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    auth_header = flb_sds_create_size(1024*4);
    ret = flb_sds_snprintf(&auth_header, flb_sds_alloc(auth_header), "Bearer %s", token);
    flb_http_add_header(c, FLB_OCI_HEADER_AUTH,
                        sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header,
                        ret);
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        "Fluent-Bit", 10);
    flb_http_add_header(c, FLB_OCI_HEADER_CONTENT_TYPE,
                        sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                        FLB_OCI_HEADER_CONTENT_TYPE_JSON,
                        sizeof(FLB_OCI_HEADER_CONTENT_TYPE_JSON) - 1);
    flb_http_add_header(c, "Accept", 6, "*/*", 3);
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    if (c->resp.status != 200) {
        flb_plg_info(ins, "request body = %s", json);
        flb_plg_info(ins, "request header = %s", c->header_buf);
        flb_plg_error(ins,
                      "HTTP Status = %d, payload = %s",
                      c->resp.status, c->resp.payload);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    c->resp.payload++;
    c->resp.payload[strlen(c->resp.payload) - 1] = '\0';
    flb_base64_decode((unsigned char*)buf,
                      sizeof(buf),
                      &o_len,
                      (unsigned char*) c->resp.payload,
                      strlen(c->resp.payload));
    *key_id = parse_token(buf, strlen(buf));
    err = get_token_exp(*key_id + 3, &fed_client->expire, ins);

    if (err != NULL) {
        flb_plg_error(ins,
                      "failed to extract token expiration time");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    flb_plg_info(ins, "token expiration time = %ld", fed_client->expire);
    // decode jwt token stored in buf
    // Make the request and fetch the security token

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return 0;
}

