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


#include <sys/stat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_file.h>

#include <monkey/mk_core/mk_list.h>
#include <monkey/mk_core/mk_string.h>
#include <fluent-bit/flb_utils.h>

#include "oci_logan.h"
#include "oci_logan_conf.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define ASN1_STRING_get0_data(x) ASN1_STRING_data(x)

static inline EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return EVP_MD_CTX_create();
}

static inline void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_destroy(ctx);
}

#endif

static int is_test_mode(void);
static flb_sds_t mock_imds_request(struct flb_oci_logan *ctx,
                                   const char *path);
static flb_sds_t mock_federation_response(struct flb_oci_logan *ctx);

static int create_pk_context(flb_sds_t filepath, const char *key_passphrase,
                             struct flb_oci_logan *ctx)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ctx->ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ctx->ins, "error to open key file: %s", filepath);
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
        flb_plg_error(ctx->ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    ctx->private_key = kbuffer;

    return 0;
}

static char *trim_whitespace(const char *str)
{
    const char *start = str;
    const char *end;
    char *trimmed;
    size_t len;

    if (!str || *str == '\0') {
        return NULL;
    }
    while (*start
           && (*start == ' ' || *start == '\t' || *start == '\n'
               || *start == '\r')) {
        start++;
    }
    if (*start == '\0') {
        return NULL;
    }
    end = start + strlen(start) - 1;
    while (end > start
           && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        end--;
    }

    len = end - start + 1;
    trimmed = flb_malloc(len + 1);
    if (!trimmed) {
        return NULL;
    }

    strncpy(trimmed, start, len);
    trimmed[len] = '\0';

    return trimmed;
}

static int load_oci_credentials(struct flb_oci_logan *ctx)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char *key = NULL;
    char *val = NULL;
    char *orig_key = NULL;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0) {
        return -1;
    }

    flb_plg_debug(ctx->ins, "content = %s", content);
    line = strtok(content, "\r\n");

    while (line != NULL) {
        /* process line */
        flb_plg_debug(ctx->ins, "line = %s", line);

        if (!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if (!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
            profile = NULL;
        }

        if (found_profile) {
            if (line[0] == '[') {
                break;
            }

            eq_pos = mk_string_char_search(line, '=', strlen(line));
            if (eq_pos < 0) {
                goto iterate;
            }

            flb_plg_debug(ctx->ins, "eq_pos %d", eq_pos);

            orig_key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ctx->ins, "key = %s", orig_key);

            key = trim_whitespace(orig_key);
            mk_mem_free(orig_key);

            val = trim_whitespace(line + eq_pos + 1);

            if (!key || !val) {
                if (key)
                    flb_free(key);
                if (val)
                    flb_free(val);
                res = -1;
                break;
            }

            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                ctx->user = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                ctx->tenancy = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                ctx->key_file = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                ctx->key_fingerprint = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                ctx->region = flb_sds_create(val);
            }

            flb_free(val);
            val = NULL;
            flb_free(key);
            key = NULL;
        }

      iterate:
        if (profile) {
            mk_mem_free(profile);
            profile = NULL;
        }

        line = strtok(NULL, "\r\n");
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
        flb_free(key);
    }
    if (val) {
        flb_free(val);
    }

    return res;
}

static int global_metadata_fields_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_global_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_global_metadata) {
        kname =
            mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_sds_destroy(f->key);
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->global_metadata_fields);
    }

    return 0;
}

static int log_event_metadata_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_metadata) {
        kname =
            mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_sds_destroy(f->key);
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->log_event_metadata_fields);
    }

    return 0;
}

/* Creates and send HTTP request to oracle IMDS endpoint */
static flb_sds_t make_imds_request(struct flb_oci_logan *ctx,
                                   struct flb_connection *u_conn,
                                   const char *path)
{
    struct flb_http_client *client;
    flb_sds_t response = NULL;
    size_t b_sent;
    int ret;

    if (is_test_mode()) {
        if (getenv("TEST_IMDS_SUCCESS")) {
            return mock_imds_request(ctx, path);
        }
        else if (getenv("TEST_IMDS_FAILURE")) {
            return NULL;
        }
    }

    flb_plg_debug(ctx->ins, "path->%s", path);
    client = flb_http_client(u_conn, FLB_HTTP_GET, path, NULL, 0,
                             ORACLE_IMDS_HOST, 80, NULL, 0);
    if (!client) {
        return NULL;
    }

    flb_http_add_header(client, "Authorization", 13, "Bearer Oracle", 13);
    ret = flb_http_do(client, &b_sent);
    if (ret != 0 || client->resp.status != 200) {
        flb_http_client_destroy(client);
        return NULL;
    }

    response = flb_sds_create_len(client->resp.data, client->resp.data_len);
    flb_http_client_destroy(client);
    return response;
}

/* constructs the complete OCI service hostname */
static flb_sds_t construct_oci_host(const char *service,
                                    struct flb_oci_logan *ctx)
{
    flb_sds_t region = (ctx->imds.region ? ctx->imds.region : ctx->region);
    const char *realm = NULL;
    const char *domain_suffix = NULL;
    flb_sds_t host;

    if (!service || !region) {
        return NULL;
    }

    if (ctx->domain_suffix) {
        domain_suffix = ctx->domain_suffix;
        goto CONSTRUCT_HOST;
    }

    realm = determine_realm_from_region(region);
    domain_suffix = get_domain_suffix_for_realm(realm);

  CONSTRUCT_HOST:;
    host = flb_sds_create_size(256);
    if (!host) {
        return NULL;
    }
    flb_sds_snprintf(&host, flb_sds_alloc(host), "%s.%s.oci.%s",
                     service, region, domain_suffix);
    return host;
}

/* extracts region information from IMDS HTTP response */
flb_sds_t extract_region(const char *response)
{
    const char *body_start;
    size_t len;
    char *region;
    const char *long_name;
    const char *region_value;
    flb_sds_t lregion;

    body_start = strstr(response, "\r\n\r\n");
    if (!body_start) {
        return NULL;
    }

    body_start += 4;

    while (*body_start == '\n' || *body_start == '\r' || *body_start == ' ') {
        body_start++;
    }

    len = strlen(body_start);
    while (len > 0
           && (body_start[len - 1] == '\n' || body_start[len - 1] == '\r'
               || body_start[len - 1] == ' ')) {
        len--;
    }

    region = malloc(len + 1);
    if (!region) {
        return NULL;
    }

    strncpy(region, body_start, len);
    region[len] = '\0';
    long_name = long_region_name(region);
    region_value = long_name ? long_name : region;
    lregion = flb_sds_create(region_value);
    if (!lregion) {
        free(region);
        return NULL;
    }
    return lregion;
}

/* extracts PEM-formatted content from HTTP response */
char *extract_pem_content(const char *response, const char *begin_marker,
                          const char *end_marker)
{
    const char *start, *end;
    size_t pem_length;
    char *pem_content;

    start = strstr(response, begin_marker);
    if (!start) {
        return NULL;
    }

    end = strstr(start, end_marker);
    if (!end) {
        return NULL;
    }

    end += strlen(end_marker);

    pem_length = end - start;
    pem_content = flb_calloc(pem_length + 1, 1);
    if (!pem_content) {
        return NULL;
    }

    strncpy(pem_content, start, pem_length);

    return pem_content;
}

/* calculates fingerprint sha1 of X.509 certificate */
flb_sds_t calculate_certificate_fingerprint(struct flb_oci_logan *ctx,
                                            const char *cert_pem)
{
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    X509 *cert = NULL;
    BIO *bio = NULL;
    flb_sds_t fingerprint = NULL;
    unsigned char *der_cert;
    int der_len, i;
    char hex_fingerprint[SHA_DIGEST_LENGTH * 3 + 1];
    char *p;

    if (is_test_mode() && getenv("TEST_IMDS_SUCCESS")) {
        return
            flb_sds_create
            ("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD");
    }

    bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) {
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        return NULL;
    }

    der_cert = NULL;
    der_len = i2d_X509(cert, &der_cert);
    if (der_len <= 0 || !der_cert) {
        X509_free(cert);
        BIO_free(bio);
        return NULL;
    }

    SHA1(der_cert, der_len, sha1_hash);
    OPENSSL_free(der_cert);

    p = hex_fingerprint;

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        p += sprintf(p, "%02x:", sha1_hash[i]);
    }

    if (p > hex_fingerprint) {
        *(p - 1) = '\0';
    }

    fingerprint = flb_sds_create(hex_fingerprint);

    for (i = 0; i < flb_sds_len(fingerprint); i++) {
        if (islower(fingerprint[i])) {
            fingerprint[i] = toupper(fingerprint[i]);
        }

    }
    X509_free(cert);
    BIO_free(bio);

    return fingerprint;
}

/* extracts tenancy OCID from x509 certificate subject */
bool extract_tenancy_ocid(struct flb_oci_logan *ctx, const char *cert_pem)
{
    BIO *bio;
    X509 *cert;
    flb_sds_t tenancy_ocid = NULL;
    X509_NAME *subject;
    int entry_count, ou_len, i;
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *obj;
    ASN1_STRING *data;
    const unsigned char *ou, *colon;
    const char *prefix;
    size_t prefix_len, ocid_len;

    if (is_test_mode() && getenv("TEST_IMDS_SUCCESS")) {
        ctx->imds.tenancy_ocid = flb_sds_create("ocid1.tenancy.oc1.phx.test");
        return 1;
    }

    bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) {
        return 0;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        return 0;
    }

    subject = X509_get_subject_name(cert);
    if (!subject) {
        X509_free(cert);
        return 0;
    }

    entry_count = X509_NAME_entry_count(subject);
    for (i = 0; i < entry_count; i++) {
        entry = X509_NAME_get_entry(subject, i);
        obj = X509_NAME_ENTRY_get_object(entry);
        if (OBJ_obj2nid(obj) == NID_organizationalUnitName) {
            data = X509_NAME_ENTRY_get_data(entry);
            ou = ASN1_STRING_get0_data(data);
            ou_len = ASN1_STRING_length(data);
            prefix = "opc-tenant:ocid1.tenancy";
            prefix_len = strlen(prefix);

            if (ou && ou_len > (int) prefix_len
                && memcmp(ou, prefix, prefix_len) == 0) {
                colon = memchr(ou, ':', ou_len);
                if (colon && (colon + 1) < (ou + ou_len)) {
                    ocid_len = (ou + ou_len) - (colon + 1);
                    tenancy_ocid =
                        flb_sds_create_len((const char *) (colon + 1),
                                           ocid_len);
                    break;
                }
            }
        }
    }

    X509_free(cert);

    if (!tenancy_ocid) {
        return 0;
    }

    ctx->imds.tenancy_ocid = tenancy_ocid;
    return 1;
}

/* retrieves region, certificates, and keys from IMDS */
int get_keys_and_certs(struct flb_oci_logan *ctx, struct flb_config *config)
{
    flb_sds_t region_resp = NULL;
    flb_sds_t clean_region_resp = NULL;
    flb_sds_t cert_resp = NULL;
    flb_sds_t key_resp = NULL;
    flb_sds_t int_cert_resp = NULL;
    struct flb_connection *u_conn = NULL;
    char *clean_cert_resp, *pem_start, *pem_end;
    size_t pem_len;

    if (is_test_mode() && getenv("TEST_IMDS_SUCCESS")) {
        ctx->imds.region = flb_sds_create("us-phoenix-1");
        ctx->imds.leaf_cert =
            flb_sds_create
            ("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----");
        ctx->imds.intermediate_cert = flb_sds_create("");
        ctx->imds.leaf_key =
            flb_sds_create
            ("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----");
        ctx->imds.tenancy_ocid = flb_sds_create("ocid1.tenancy.oc1.phx.test");
        ctx->imds.fingerprint =
            flb_sds_create
            ("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD");
        return 1;
    }

    if (!is_test_mode()) {
        ctx->u =
            flb_upstream_create(config, ORACLE_IMDS_HOST, 80, FLB_IO_TCP,
                                NULL);
        if (!ctx->u) {
            flb_plg_error(ctx->ins,
                          "failed to create imds upstream connection");
            return 0;
        }

        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "failed to get imds upstream connection");
            return 0;
        }
    }

    region_resp =
        make_imds_request(ctx, u_conn,
                          ORACLE_IMDS_BASE_URL ORACLE_IMDS_REGION_PATH);
    if (!region_resp) {
        flb_plg_error(ctx->ins, "failed to get region from IMDS");
        goto error;
    }
    cert_resp =
        make_imds_request(ctx, u_conn,
                          ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_CERT_PATH);
    if (!cert_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf certificate from IMDS");
        goto error;
    }
    key_resp =
        make_imds_request(ctx, u_conn,
                          ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_KEY_PATH);
    if (!key_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf key from IMDS");
        goto error;
    }
    int_cert_resp =
        make_imds_request(ctx, u_conn,
                          ORACLE_IMDS_BASE_URL
                          ORACLE_IMDS_INTERMEDIATE_CERT_PATH);
    if (!int_cert_resp) {
        flb_plg_error(ctx->ins,
                      "failed to get intermediate certificate from IMDS");
        goto error;
    }
    clean_region_resp = extract_region(region_resp);
    flb_sds_destroy(region_resp);

    clean_cert_resp =
        extract_pem_content(cert_resp, "-----BEGIN CERTIFICATE-----",
                            "-----END CERTIFICATE-----");
    flb_sds_destroy(cert_resp);

    ctx->imds.region = clean_region_resp;
    ctx->imds.leaf_cert = clean_cert_resp;
    ctx->imds.intermediate_cert = int_cert_resp;
    pem_start = strstr(key_resp, "-----BEGIN");
    pem_end = strstr(key_resp, "-----END");
    if (!pem_start || !pem_end) {
        flb_plg_error(ctx->ins, "No valid PEM block found");
        goto error;
    }
    pem_len =
        (pem_end - pem_start) + strlen("-----END RSA PRIVATE KEY-----") + 1;
    ctx->imds.leaf_key = flb_sds_create_len(pem_start, pem_len);

    /* extract tenancy ocid from leaf certificate */
    if (!extract_tenancy_ocid(ctx, clean_cert_resp)) {
        flb_plg_error(ctx->ins, "extract_tenancy_ocid failed");
        goto error;
    }

    /* calculate certificate fingerprint for signing */
    ctx->imds.fingerprint =
        calculate_certificate_fingerprint(ctx, clean_cert_resp);
    if (!ctx->imds.fingerprint) {
        flb_plg_error(ctx->ins, "calculate_certificate_fingerprint failed");
        goto error;
    }

    if (!is_test_mode()) {
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(ctx->u);
    }
    ctx->u = NULL;

    return 1;

  error:
    if (!is_test_mode()) {
        if (region_resp) {
            flb_sds_destroy(region_resp);
        }
        if (cert_resp) {
            flb_sds_destroy(cert_resp);;
        }
        if (key_resp) {
            flb_sds_destroy(key_resp);
        }
        if (int_cert_resp) {
            flb_sds_destroy(int_cert_resp);
        }

        ctx->imds.fingerprint = NULL;
        ctx->imds.intermediate_cert = NULL;
        ctx->imds.leaf_cert = NULL;
        ctx->imds.leaf_key = NULL;
        ctx->imds.region = NULL;
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(ctx->u);
        ctx->u = NULL;
    }
    return 0;
}

/* Generates RSA key pair for session based authentication */
static EVP_PKEY *generate_session_key_pair(struct flb_oci_logan *ctx)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EVP_PKEY *pkey;
    BIGNUM *bn;
    RSA *rsa;
    int rc;

    pkey = EVP_PKEY_new();
    bn = BN_new();
    rsa = RSA_new();
    BN_set_word(bn, RSA_F4);
    rc = RSA_generate_key_ex(rsa, 2048, bn, NULL);
    if (rc != 1) {
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);
    return pkey;
#else
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    return pkey;
#endif
}


char *extract_public_key_pem(EVP_PKEY *pkey)
{
    BIO *bio;
    char *pem_data, *public_key_pem;
    long pem_length;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return NULL;
    }
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return NULL;
    }


    pem_data = NULL;
    pem_length = BIO_get_mem_data(bio, &pem_data);


    public_key_pem = malloc(pem_length + 1);
    if (!public_key_pem) {
        BIO_free(bio);
        return NULL;
    }

    strncpy(public_key_pem, pem_data, pem_length);
    public_key_pem[pem_length] = '\0';

    BIO_free(bio);
    return public_key_pem;
}

char *extract_private_key_pem(EVP_PKEY *pkey)
{
    BIO *bio;
    char *pem_data, *private_key_pem;
    long pem_length;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return NULL;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        return NULL;
    }


    pem_data = NULL;
    pem_length = BIO_get_mem_data(bio, &pem_data);


    private_key_pem = malloc(pem_length + 1);
    if (!private_key_pem) {
        BIO_free(bio);
        return NULL;
    }

    strncpy(private_key_pem, pem_data, pem_length);
    private_key_pem[pem_length] = '\0';

    BIO_free(bio);
    return private_key_pem;
}

static flb_sds_t sanitize_certificate(const char *cert_str)
{
    const char *start;
    const char *end;
    flb_sds_t clean;
    size_t j;
    size_t i;

    if (!cert_str)
        return NULL;

    start = strstr(cert_str, "-----BEGIN");
    if (!start)
        return NULL;

    start = strchr(start, '\n');
    if (!start)
        return NULL;
    start++;

    end = strstr(cert_str, "-----END");
    if (!end || end <= start)
        return NULL;

    clean = flb_sds_create_len(start, end - start);
    if (!clean)
        return NULL;

    j = 0;
    i = 0;
    for (i = 0; i < flb_sds_len(clean); i++) {
        if (!isspace(clean[i])) {
            clean[j++] = clean[i];
        }
    }
    clean[j] = '\0';
    flb_sds_len_set(clean, j);

    return clean;
}

/* Creates federation payload for OCI security token */
flb_sds_t create_federation_payload(struct flb_oci_logan *ctx)
{
    flb_sds_t payload = NULL;
    flb_sds_t leaf_cert;
    flb_sds_t session_pubkey;
    flb_sds_t intermediate_certs;

    payload = NULL;
    leaf_cert = sanitize_certificate(ctx->imds.leaf_cert);
    session_pubkey = sanitize_certificate(ctx->imds.session_pubkey);
    intermediate_certs = NULL;
    if (ctx->imds.intermediate_cert) {
        intermediate_certs =
            sanitize_certificate(ctx->imds.intermediate_cert);
    }

    payload = flb_sds_create_size(8192);
    if (!payload) {
        goto cleanup;
    }

    if (!leaf_cert || !session_pubkey) {
        goto cleanup;
    }
    if (intermediate_certs && flb_sds_len(intermediate_certs) > 0) {
        flb_sds_printf(&payload,
                       "{\"certificate\":\"%s\",\"publicKey\":\"%s\","
                       "\"intermediateCertificates\":[\"%s\"]}",
                       leaf_cert, session_pubkey, intermediate_certs);
    }
    else {
        flb_sds_printf(&payload,
                       "{\"certificate\":\"%s\",\"publicKey\":\"%s\","
                       "\"intermediateCertificates\":[]}",
                       leaf_cert, session_pubkey);
    }


  cleanup:
    flb_sds_destroy(leaf_cert);
    flb_sds_destroy(session_pubkey);
    flb_sds_destroy(intermediate_certs);
    return payload;
}

/* sign federation request with leaf key */
static flb_sds_t sign_request_with_key(struct flb_oci_logan *ctx,
                                       const char *method,
                                       flb_sds_t url_path,
                                       flb_sds_t payload,
                                       flb_sds_t date, const char *host)
{
    flb_sds_t auth_header = NULL;
    flb_sds_t string_to_sign = NULL;
    flb_sds_t lowercase_method = NULL;
    unsigned char *signature = NULL;
    unsigned char *b64_out = NULL;
    size_t sig_len = 0;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int i;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *b64_hash = NULL;
    size_t b64_len = 0;
    size_t b64_size, olen;

    string_to_sign = flb_sds_create_size(1024);
    if (!string_to_sign) {
        return NULL;
    }

    lowercase_method = flb_sds_create(method);
    if (!lowercase_method) {
        flb_sds_destroy(string_to_sign);
        return NULL;
    }
    for (i = 0; i < flb_sds_len(lowercase_method); i++) {
        lowercase_method[i] = tolower(method[i]);
    }

    flb_sds_printf(&string_to_sign, "date: %s\n", date);
    flb_sds_printf(&string_to_sign, "(request-target): %s %s\n",
                   lowercase_method, url_path);
    /* flb_sds_printf(&string_to_sign, "host: %s\n", host); */
    flb_sds_printf(&string_to_sign, "content-length: %zu\n",
                   (payload) ? strlen(payload) : 0);
    flb_sds_printf(&string_to_sign, "content-type: application/json\n");

    SHA256((unsigned char *) payload, (payload) ? flb_sds_len(payload) : 0,
           hash);

    b64_len = 4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1;
    b64_hash = flb_malloc(b64_len);
    if (!b64_hash) {
        goto cleanup;
    }
    if (flb_base64_encode
        ((unsigned char *) b64_hash, b64_len, &b64_len, hash,
         SHA256_DIGEST_LENGTH) != 0) {
        flb_free(b64_hash);
        goto cleanup;
    }
    b64_hash[b64_len] = '\0';

    flb_sds_printf(&string_to_sign, "x-content-sha256: %s", b64_hash);

    if (b64_hash) {
        flb_free(b64_hash);
    }
    flb_plg_debug(ctx->ins, "string to sign: [%s]", string_to_sign);

    bio = BIO_new_mem_buf((void *) ctx->imds.leaf_key, -1);
    if (!bio) {
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate
        (md_ctx, string_to_sign, flb_sds_len(string_to_sign)) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
        goto cleanup;
    }

    signature = flb_malloc(sig_len);
    if (!signature) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(md_ctx, signature, &sig_len) <= 0) {
        goto cleanup;
    }

    b64_size = ((sig_len + 2) / 3) * 4 + 1;
    olen = 0;
    b64_out = flb_malloc(b64_size);

    if (!b64_out) {
        goto cleanup;
    }

    if (flb_base64_encode(b64_out, b64_size, &olen, signature, sig_len) != 0) {
        goto cleanup;
    }

    b64_out[olen] = '\0';

    auth_header = flb_sds_create_size(2048);
    if (!auth_header) {
        goto cleanup;
    }

    flb_sds_printf(&auth_header,
                   "Signature version=\"1\",keyId=\"%s/fed-x509/%s\",algorithm=\"rsa-sha256\","
                   "signature=\"%s\",headers=\"date (request-target) content-length content-type x-content-sha256\"",
                   ctx->imds.tenancy_ocid, ctx->imds.fingerprint, b64_out);

  cleanup:
    if (bio) {
        BIO_free(bio);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (signature) {
        flb_free(signature);
    }
    if (b64_out) {
        flb_free(b64_out);
    }
    if (string_to_sign) {
        flb_sds_destroy(string_to_sign);
    }
    if (lowercase_method) {
        flb_sds_destroy(lowercase_method);
    }
    flb_plg_debug(ctx->ins, "auth header: %s", auth_header);

    return auth_header;
}

static flb_sds_t clean_token_string(flb_sds_t input)
{
    size_t len;
    size_t read_pos;
    size_t write_pos = 0;

    if (!input)
        return NULL;
    len = flb_sds_len(input);
    for (read_pos = 0; read_pos < len; read_pos++) {
        if (input[read_pos] >= 32 && input[read_pos] <= 126) {
            input[write_pos++] = input[read_pos];
        }
    }

    input[write_pos] = '\0';
    flb_sds_len_set(input, write_pos);

    return input;
}

static int parse_federation_response(flb_sds_t response,
                                     struct oci_security_token *token)
{
    jsmn_parser parser;
    jsmntok_t *tokens;
    int tok_size = 32;
    int ret, i;
    char *key;
    char *val;
    int key_len;
    int val_len;
    flb_sds_t raw_token;

    if (!response || !token) {
        return -1;
    }

    jsmn_init(&parser);

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        return -1;
    }

    ret =
        jsmn_parse(&parser, response, flb_sds_len(response), tokens,
                   tok_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_free(tokens);
        return -1;
    }
    tok_size = ret;
    for (i = 1; i < tok_size; i++) {
        if (tokens[i].type != JSMN_STRING) {
            continue;
        }

        key = response + tokens[i].start;
        key_len = tokens[i].end - tokens[i].start;

        if (key_len == 5 && strncmp(key, "token", 5) == 0) {
            i++;
            if (i >= tok_size || tokens[i].type != JSMN_STRING) {
                flb_free(tokens);
                return -1;
            }

            val = response + tokens[i].start;
            val_len = tokens[i].end - tokens[i].start;

            raw_token = flb_sds_create_len(val, val_len);
            if (!raw_token) {
                flb_free(tokens);
                return -1;
            }

            if (!clean_token_string(raw_token)) {
                flb_sds_destroy(raw_token);
                flb_free(tokens);
                return -1;
            }

            if (token->token) {
                flb_sds_destroy(token->token);
            }
            token->token = raw_token;

            flb_free(tokens);
            return 0;
        }
    }

    flb_free(tokens);
    return -1;
}

/* extract jwt and its expiration time */
static int decode_jwt_and_set_expires(struct flb_oci_logan *ctx)
{
    jsmn_parser parser;
    jsmntok_t *tokens;
    int tok_size = 32;
    int ret, i, j, padding, exp_len;
    char *key, *token, *dot1, *dot2, *payload_b64url, *payload_b64,
        *decoded_payload, *exp_str;
    int key_len;
    size_t payload_b64url_len, b64_len, decoded_len;
    time_t exp_value;
    char exp_buf[32];

    if (!ctx || !ctx->security_token.token) {
        flb_plg_error(ctx->ins, "Invalid context or token");
        return -1;
    }

    token = ctx->security_token.token;
    dot1 = strchr(token, '.');
    dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;

    if (!dot1 || !dot2) {
        flb_plg_error(ctx->ins, "Invalid JWT format");
        return -1;
    }

    payload_b64url_len = dot2 - (dot1 + 1);
    payload_b64url = flb_malloc(payload_b64url_len + 1);
    if (!payload_b64url) {
        return -1;
    }

    memcpy(payload_b64url, dot1 + 1, payload_b64url_len);
    payload_b64url[payload_b64url_len] = '\0';

    for (j = 0; j < payload_b64url_len; j++) {
        if (payload_b64url[j] == '-')
            payload_b64url[j] = '+';
        else if (payload_b64url[j] == '_')
            payload_b64url[j] = '/';
    }


    padding = (4 - (payload_b64url_len % 4)) % 4;
    b64_len = payload_b64url_len + padding;
    payload_b64 = flb_malloc(b64_len + 1);
    if (!payload_b64) {
        flb_free(payload_b64url);
        return -1;
    }

    strncpy(payload_b64, payload_b64url, payload_b64url_len);
    memset(payload_b64 + payload_b64url_len, '=', padding);
    payload_b64[b64_len] = '\0';

    decoded_len = (b64_len * 3) / 4 + 1;
    decoded_payload = flb_malloc(decoded_len);
    if (!decoded_payload) {
        flb_free(payload_b64url);
        flb_free(payload_b64);
        return -1;
    }

    ret = flb_base64_decode((unsigned char *) decoded_payload, decoded_len,
                            &decoded_len, (unsigned char *) payload_b64,
                            b64_len);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Base64 decode failed");
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    decoded_payload[decoded_len] = '\0';

    jsmn_init(&parser);

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    ret = jsmn_parse(&parser, decoded_payload, decoded_len, tokens, tok_size);

    if (ret == JSMN_ERROR_INVAL || ret == JSMN_ERROR_PART) {
        flb_plg_error(ctx->ins, "JSON parse error");
        flb_free(tokens);
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    tok_size = ret;

    /* Find "exp" key */
    exp_value = 0;
    for (i = 1; i < tok_size; i++) {
        if (tokens[i].type != JSMN_STRING) {
            continue;
        }

        key = decoded_payload + tokens[i].start;
        key_len = tokens[i].end - tokens[i].start;

        if (key_len == 3 && strncmp(key, "exp", 3) == 0) {
            i++;
            if (i >= tok_size || tokens[i].type != JSMN_PRIMITIVE) {
                flb_plg_error(ctx->ins, "Missing or invalid 'exp' in JWT");
                flb_free(tokens);
                flb_free(payload_b64url);
                flb_free(payload_b64);
                flb_free(decoded_payload);
                return -1;
            }

            /* Extract numeric value */
            exp_str = decoded_payload + tokens[i].start;
            exp_len = tokens[i].end - tokens[i].start;

            if (exp_len >= sizeof(exp_buf)) {
                exp_len = sizeof(exp_buf) - 1;
            }

            strncpy(exp_buf, exp_str, exp_len);
            exp_buf[exp_len] = '\0';

            exp_value = (time_t) atoll(exp_buf);
            break;
        }
    }

    if (exp_value == 0) {
        flb_free(tokens);
        flb_free(payload_b64url);
        flb_free(payload_b64);
        flb_free(decoded_payload);
        return -1;
    }

    ctx->security_token.expires_at = exp_value;

    flb_free(tokens);
    flb_free(payload_b64url);
    flb_free(payload_b64);
    flb_free(decoded_payload);

    return 0;
}

/* signs and sends federation request to OCI authentication endpoint */
flb_sds_t sign_and_send_federation_request(struct flb_oci_logan *ctx,
                                           flb_sds_t payload)
{
    struct flb_upstream *upstream;
    struct flb_http_client *client;
    size_t b_sent, b64_len;
    int ret;
    struct flb_connection *u_conn;
    flb_sds_t resp = NULL;
    int port = 443;
    flb_sds_t url_path, tmp_host;
    flb_sds_t auth_header = NULL;
    flb_sds_t date_header = NULL;
    char *host;
    time_t now;
    struct tm *tm_info;
    char date_buf[128], user_agent[256];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *b64_hash = NULL;

    if (is_test_mode()) {
        return mock_federation_response(ctx);
    }
    url_path = flb_sds_create("/v1/x509");
    tmp_host = construct_oci_host("auth", ctx);
    if (!tmp_host) {
        flb_sds_destroy(url_path);
        return NULL;
    }
    host = flb_calloc(flb_sds_len(tmp_host) + 1, 1);
    if (!host) {
        flb_sds_destroy(tmp_host);
        flb_sds_destroy(url_path);
        return NULL;
    }

    strcpy(host, tmp_host);
    flb_sds_destroy(tmp_host);
    flb_plg_debug(ctx->ins, "host -> %s", host);
    time(&now);
    tm_info = gmtime(&now);
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT",
             tm_info);
    date_header = flb_sds_create(date_buf);

    if (!date_header) {
        flb_free(host);
        flb_sds_destroy(url_path);
        return NULL;
    }

    upstream = flb_upstream_create(ctx->ins->config, host, port,
                                   FLB_IO_TLS, ctx->ins->tls);
    if (!upstream) {
        flb_free(host);
        flb_sds_destroy(url_path);
        return NULL;
    }

    u_conn = flb_upstream_conn_get(upstream);
    if (!u_conn) {
        flb_upstream_destroy(upstream);
        flb_free(host);
        flb_sds_destroy(url_path);
        return NULL;
    }
    client = flb_http_client(u_conn, FLB_HTTP_POST, url_path,
                             payload, strlen(payload), host, port, NULL, 0);

    if (!client) {
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(upstream);
        flb_free(host);
        flb_sds_destroy(url_path);
        flb_sds_destroy(date_header);
        return NULL;
    }

    snprintf(user_agent, sizeof(user_agent),
             "fluent-bit-oci-plugin/%s", ctx->ins->p->name);
    flb_http_add_header(client, "Date", 4, date_header,
                        flb_sds_len(date_header));
    flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
    flb_http_add_header(client, "Content-Length", 14, NULL, 0);

    SHA256((unsigned char *) payload, flb_sds_len(payload), hash);

    b64_len = 4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1;
    b64_hash = flb_malloc(b64_len);
    if (!b64_hash) {
        goto cleanup;
    }
    if (flb_base64_encode
        ((unsigned char *) b64_hash, b64_len, &b64_len, hash,
         SHA256_DIGEST_LENGTH) != 0) {
        flb_free(b64_hash);
        goto cleanup;
    }
    b64_hash[b64_len] = '\0';
    flb_http_add_header(client, "x-content-sha256", 16, b64_hash, b64_len);
    flb_http_add_header(client, "User-Agent", 10, user_agent,
                        strlen(user_agent));
    /* sign request using the leaf key */
    flb_plg_debug(ctx->ins, "signing with tenancy: %s, fingerprint: %s",
                  ctx->imds.tenancy_ocid, ctx->imds.fingerprint);
    auth_header = sign_request_with_key(ctx, "POST", url_path,
                                        payload, date_header, host);
    if (!auth_header) {
        flb_plg_error(ctx->ins, "failed to get authorization header");
        goto cleanup;
    }
    flb_http_add_header(client, "Authorization", 13,
                        auth_header, flb_sds_len(auth_header));
    ret = flb_http_do(client, &b_sent);

    if (ret != 0 || client->resp.status != 200) {
        flb_plg_error(ctx->ins,
                      "federation request failed with status %d: %s",
                      client->resp.status, client->resp.payload);
        flb_plg_error(ctx->ins, "authentication failed with status %d",
                      client->resp.status);

        flb_plg_debug(ctx->ins, "request headers:");
        flb_plg_debug(ctx->ins, "  Authorization: %s", auth_header);
        flb_plg_debug(ctx->ins, "  Date: %s", date_header);
        flb_plg_debug(ctx->ins, "  Content-Type: application/json");
        flb_plg_debug(ctx->ins, "  x-content-sha256: %s", b64_hash);
        flb_plg_debug(ctx->ins, "request body: %s", payload);
        goto cleanup;
    }

    if (client->resp.payload && client->resp.payload_size > 0) {
        resp = flb_sds_create_len(client->resp.payload,
                               client->resp.payload_size);

        if (parse_federation_response(resp, &ctx->security_token) < 0) {
            flb_plg_error(ctx->ins, "failed to parse federation response");
            flb_sds_destroy(resp);
            resp = NULL;
            goto cleanup;
        }

        decode_jwt_and_set_expires(ctx);
    }
  cleanup:
    if (auth_header) {
        flb_sds_destroy(auth_header);
    }
    flb_sds_destroy(date_header);
    flb_sds_destroy(url_path);
    flb_free(b64_hash);
    flb_free(host);
    if (client) {
        flb_http_client_destroy(client);
    }
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(upstream);

    return resp;
}

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance
                                                *ins,
                                                struct flb_config *config)
{
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp = NULL;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;
    flb_sds_t json_payload, response;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logan));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&ctx->global_metadata_fields);
    mk_list_init(&ctx->log_event_metadata_fields);

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    if (strcmp(ctx->auth_type, "instance_principal") == 0) {
        flb_plg_info(ctx->ins, "Using instance principal authentication");

        if (get_keys_and_certs(ctx, config) != 1) {
            flb_plg_error(ctx->ins, "failed to get keys from imds");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->session_key_pair = generate_session_key_pair(ctx);
        if (!ctx->session_key_pair) {
            flb_plg_error(ctx->ins, "failed to generate session keypair");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->imds.session_pubkey = extract_public_key_pem(ctx->session_key_pair);
        ctx->imds.session_privkey = extract_private_key_pem(ctx->session_key_pair);

        if (!ctx->imds.session_pubkey || !ctx->imds.session_privkey) {
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->security_token.token = NULL;
        ctx->security_token.expires_at = 0;
        json_payload = create_federation_payload(ctx);
        if (!json_payload) {
            flb_plg_error(ctx->ins, "failed to create federation payload");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        response = sign_and_send_federation_request(ctx, json_payload);
        if (!response) {
            flb_plg_error(ctx->ins,
                          "failed to get security token from federation endpoint");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        flb_sds_destroy(json_payload);
        flb_sds_destroy(response);

        if (ctx->imds.region) {
            ctx->region = flb_sds_create(ctx->imds.region);
        }
    }
    else {
        if (!ctx->config_file_location) {
            flb_plg_error(ctx->ins,
                          "config file location i's required for config_file auth mode");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ret = load_oci_credentials(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
            flb_plg_error(ctx->ins, "failed to create pk context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->key_id = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                         "%s/%s/%s", ctx->tenancy, ctx->user,
                         ctx->key_fingerprint);
    }

    if (ctx->oci_config_in_record == FLB_FALSE) {
        if (ctx->oci_la_log_source_name == NULL ||
            ctx->oci_la_log_group_id == NULL) {
            flb_plg_error(ctx->ins,
                          "log source name and log group id are required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_global_metadata != NULL) {
        ret = global_metadata_fields_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_metadata != NULL) {
        ret = log_event_metadata_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Setup host and URI */
    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region) {
            flb_plg_error(ctx->ins, "Region is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        host = construct_oci_host("loganalytics", ctx);
        if (!host) {
            flb_plg_error(ctx->ins, "failed to construct oci host");
            return NULL;
        }
    }
    if (!ctx->uri) {
        if (!ctx->namespace) {
            flb_plg_error(ctx->ins, "Namespace is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->uri = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                         "/20200601/namespaces/%s/actions/uploadLogEventsFile",
                         ctx->namespace);
    }

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        default_port = 443;
    }
    else {
        flb_plg_error(ctx->ins, "TLS must be enabled for OCI");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }
#else
    flb_plg_error(ctx->ins, "TLS support required for OCI");
    flb_oci_logan_conf_destroy(ctx);
    return NULL;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    flb_output_net_default(host, default_port, ins);

    if (host != ins->host.name) {
        flb_sds_destroy(host);
    }

    /* Setup proxy if configured */
    if (ctx->proxy) {
        tmp = ctx->proxy;
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'",
                          ctx->proxy);
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->proxy_host = p_host;
        ctx->proxy_port = atoi(p_port);
        flb_free(protocol);
        flb_free(p_port);
        flb_free(p_uri);
    }

    /* Create upstream connection */
    if (ctx->proxy) {
        upstream =
            flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
                                io_flags, ins->tls);
    }
    else {
        upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create upstream context");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

static void metadata_fields_destroy(struct flb_oci_logan *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct metadata_obj *f;

    mk_list_foreach_safe(head, tmp, &ctx->global_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        if (f->key) {
            flb_sds_destroy(f->key);
        }
        if (f->val) {
            flb_sds_destroy(f->val);
        }
        mk_list_del(&f->_head);
        flb_free(f);
    }

    mk_list_foreach_safe(head, tmp, &ctx->log_event_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        if (f->key) {
            flb_sds_destroy(f->key);
        }
        if (f->val) {
            flb_sds_destroy(f->val);
        }
        mk_list_del(&f->_head);
        flb_free(f);
    }

}

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    if (ctx->imds.region) {
        flb_sds_destroy(ctx->imds.region);
    }
    if (ctx->imds.leaf_key) {
        flb_sds_destroy(ctx->imds.leaf_key);
    }
    if (ctx->imds.intermediate_cert) {
        flb_sds_destroy(ctx->imds.intermediate_cert);
    }
    if (ctx->imds.fingerprint) {
        flb_sds_destroy(ctx->imds.fingerprint);
    }
    if (ctx->imds.tenancy_ocid) {
        flb_sds_destroy(ctx->imds.tenancy_ocid);
    }
    if (ctx->imds.leaf_cert) {
        if (is_test_mode()) {
            flb_sds_destroy(ctx->imds.leaf_cert);
        }
        else {
            flb_free(ctx->imds.leaf_cert);
        }
    }
    if (ctx->imds.session_pubkey) {
        free(ctx->imds.session_pubkey);
    }
    if (ctx->imds.session_privkey) {
        free(ctx->imds.session_privkey);
    }
    if (ctx->session_key_pair) {
        EVP_PKEY_free(ctx->session_key_pair);
    }

    if (ctx->security_token.token) {
        flb_sds_destroy(ctx->security_token.token);
    }

    if (ctx->private_key) {
        flb_sds_destroy(ctx->private_key);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->key_id) {
        flb_sds_destroy(ctx->key_id);
    }
    if (ctx->key_file) {
        flb_sds_destroy(ctx->key_file);
    }
    if (ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if (ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if (ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if (ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    if (ctx->oci_la_timezone) {
        flb_sds_destroy(ctx->oci_la_timezone);
    }

    metadata_fields_destroy(ctx);

    flb_free(ctx);
    return 0;
}

static int is_test_mode(void)
{
    return getenv("FLB_OCI_PLUGIN_UNDER_TEST") != NULL;
}

static flb_sds_t mock_imds_request(struct flb_oci_logan *ctx,
                                   const char *path)
{
    if (strstr(path, "/instance/region")) {
        return flb_sds_create("us-phoenix-1");
    }

    else if (strstr(path, "/identity/cert.pem")) {
        return flb_sds_create("-----BEGIN CERTIFICATE-----\n"
                              "MIIC0TCCAbmgAwIBAgIJAKxHjMcXpyEUMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n"
                              "BAoMCW9yYWNsZS5jb20wHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBc\n"
                              "MRIwEAYDVQQKDAlvcmFjbGUuY29tMUYwRAYDVQQLDD1vcGMtdGVuYW50Om9jaWQx\n"
                              "LnRlbmFuY3kub2MxLnBoeC50ZXN0YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n"
                              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
                              "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXWUId1eJsCMFtgKhXFMS\n"
                              "p6/8RkLcYMrFoAWKpILYdSrvJ0R66u+zR1EpqQvk8TDrNMVzfv/jDPPG2BHYkp7R\n"
                              "WE7pWQv8vZGnU6p3SJGvTwKdgnjGjNvCsXI8Dx7ePLxLZhX0Vg8bqXFfVVN3FlWK\n"
                              "VfPy4jLQfQhWVx7dL1EfJL2YiEXI1Oj2DQKLVxPHHcNRVJKXhUHJ2F6PVYqMfAJ9\n"
                              "bJnTHhOGZfYWO7pQQQv2eFaInp6s6LfDZ/P9l5T7PiNJvWNGnJZpVQqEXdqTxXrC\n"
                              "MQIDAQABoyMwITAfBgNVHSMEGDAWgBQxFw2xL6XqYqJSKhyAC/8qBkRCLTANBgkq\n"
                              "hkiG9w0BAQsFAAOCAQEAr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxe\n"
                              "nIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQ\n"
                              "-----END CERTIFICATE-----");
    }


    else if (strstr(path, "/identity/key.pem")) {
        return flb_sds_create("-----BEGIN RSA PRIVATE KEY-----\n"
                              "MIIEpAIBAAKCAQEAr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQ\n"
                              "r3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3Ee\n"
                              "MxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQQIDAQAB\n"
                              "AoIBAEr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenI\n"
                              "RQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3\n"
                              "-----END RSA PRIVATE KEY-----");
    }

    else if (strstr(path, "/identity/intermediate.pem")) {
        return flb_sds_create("-----BEGIN CERTIFICATE-----\n"
                              "MIIDHTCCAgWgAwIBAgIJAKxHjMcXpyE1MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n"
                              "BAoMCW9yYWNsZS5jb20wHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAU\n"
                              "MRIwEAYDVQQKDAlvcmFjbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
                              "CgKCAQEAr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxe\n"
                              "nIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQr3EeMxxenIRQ\n"
                              "QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCvMR4zHF6chFCvMR4zHF6chFCvMR4z\n"
                              "-----END CERTIFICATE-----");
    }
    return NULL;
}

static flb_sds_t mock_federation_response(struct flb_oci_logan *ctx)
{
    const char *header;
    time_t now;
    time_t exp;
    char payload_json[512];
    unsigned char b64_payload[1024];
    size_t b64_len;
    int i;
    const char *signature;
    flb_sds_t jwt;
    flb_sds_t response;

    header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    now = time(NULL);
    exp = now + 3600;
    snprintf(payload_json, sizeof(payload_json),
             "{\"sub\":\"ocid1.instance.oc1.phx.test\","
             "\"opc-instance\":\"ocid1.instance.oc1.phx.test\","
             "\"exp\":%ld,"
             "\"iat\":%ld," "\"jti\":\"test-token-id\"}", exp, now);


    b64_len = sizeof(b64_payload);
    flb_base64_encode(b64_payload, sizeof(b64_payload), &b64_len,
                      (unsigned char *) payload_json, strlen(payload_json));
    b64_payload[b64_len] = '\0';

    for (i = 0; i < b64_len; i++) {
        if (b64_payload[i] == '+')
            b64_payload[i] = '-';
        if (b64_payload[i] == '/')
            b64_payload[i] = '_';
        if (b64_payload[i] == '=') {
            b64_payload[i] = '\0';
            break;
        }
    }

    signature = "ths_signature_is_for_test";

    jwt = flb_sds_create_size(1024);
    flb_sds_printf(&jwt, "%s.%s.%s", header, b64_payload, signature);

    response = flb_sds_create_size(2048);
    flb_sds_printf(&response, "{\"token\":\"%s\"}", jwt);

    flb_sds_destroy(jwt);

    flb_plg_info(ctx->ins, "[mock]created federation response");

    if (parse_federation_response(response, &ctx->security_token) < 0) {
        flb_plg_error(ctx->ins, "failed to parse mock federation response");
        flb_sds_destroy(response);
        return NULL;
    }

    ctx->security_token.expires_at = exp;

    flb_plg_info(ctx->ins, "security token expir e in %ld", exp);

    return response;
}
