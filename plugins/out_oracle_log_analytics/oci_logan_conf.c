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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>


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

static int load_oci_credentials(struct flb_oci_logan *ctx)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char* key = NULL;
    char* val;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_debug(ctx->ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        /* process line */
        flb_plg_debug(ctx->ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
            profile = NULL;
        }
        if(found_profile) {
            if(line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_debug(ctx->ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ctx->ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
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
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
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
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
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


// added by @rghouzra

static flb_sds_t make_imds_request(struct flb_oci_logan *ctx, struct flb_connection *u_conn, const char *path)
{
    struct flb_http_client *client;
    flb_sds_t response = NULL;
    size_t b_sent;
    int ret;

    client = flb_http_client(u_conn, FLB_HTTP_GET, path, NULL, 0,
                             ORACLE_IMDS_HOST, 80, NULL, 0);
    if (!client) {
        flb_plg_error(ctx->ins, "failed to create http client for path: %s", path);
        return NULL;
    }

    flb_http_add_header(client, "Authorization", 13, "Bearer Oracle", 13);
    ret = flb_http_do(client, &b_sent);
    if (ret != 0 || client->resp.status != 200) {
        flb_plg_error(ctx->ins, "HTTP request failed for path: %s, status: %d", path, client->resp.status);
        flb_http_client_destroy(client);
        return NULL;
    }

    response = flb_sds_create_len(client->resp.data, client->resp.data_len);
    flb_http_client_destroy(client);
    return response;
}



flb_sds_t extract_tenancy_ocid_from_cert(struct flb_oci_logan *ctx, const char *cert_pem)
{
    BIO *bio = BIO_new_mem_buf(cert_pem, -1);
    if (!bio) {
        flb_plg_error(ctx->ins, "failed to create BIO for certificate");
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        flb_plg_error(ctx->ins, "failed to parse certificate");
        return NULL;
    }

    flb_sds_t tenancy_ocid = NULL;

    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        char buf[1024];
        X509_NAME_oneline(subject, buf, sizeof(buf));
        flb_plg_debug(ctx->ins, "Certificate subject: %s", buf);
    }

    int entry_count = X509_NAME_entry_count(subject);
    for (int i = 0; i < entry_count; i++) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        if (OBJ_obj2nid(obj) == NID_organizationalUnitName) {
            ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
            const char *ou_str = (const char *)ASN1_STRING_get0_data(data);

            flb_plg_debug(ctx->ins, "OU field: %s", ou_str);

            if (strstr(ou_str, "opc-tenant:ocid1.tenancy") == ou_str) {
                const char *ocid = strchr(ou_str, ':');
                if (ocid && strlen(ocid + 1) > 0) {
                    tenancy_ocid = flb_sds_create(ocid + 1);
                    break;
                }
            }
        }
    }
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        flb_plg_error(ctx->ins, "failed to create BIO for printing certificate");
        X509_free(cert);
        return NULL;
    }

    //just for debugging should be removed after
    X509_print(out, cert);

    char *cert_info = NULL;
    long len = BIO_get_mem_data(out, &cert_info);
    char *copy = malloc(len + 1);
    if (copy) {
        memcpy(copy, cert_info, len);
        copy[len] = '\0';
        flb_plg_debug(ctx->ins, "full cert:\n%s", copy);
        flb_plg_debug(ctx->ins, "eof cert");
        free(copy);
    }

    BIO_free(out);

    X509_free(cert);

    if (!tenancy_ocid) {
        return NULL;
    }

    flb_plg_debug(ctx->ins, "extracted Tenancy OCID: %s", tenancy_ocid);
    return tenancy_ocid;
}


int get_keys_and_certs(struct flb_oci_logan *ctx, struct flb_config *config)
{
    ctx->u = flb_upstream_create(config, ORACLE_IMDS_HOST, 80, FLB_IO_TCP, NULL);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "failed to create upstream");
        return 0;
    }

    struct flb_connection *u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "failed to get upstream connection");
        return 0;
    }
    flb_sds_t region_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_REGION_PATH);
    flb_sds_t cert_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_CERT_PATH);
    flb_sds_t key_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_LEAF_KEY_PATH);
    flb_sds_t int_cert_resp = make_imds_request(ctx, u_conn, ORACLE_IMDS_BASE_URL ORACLE_IMDS_INTERMEDIATE_CERT_PATH);

    if (!region_resp) {
        flb_plg_error(ctx->ins, "failed to get region from IMDS");
        goto error;
    }
    flb_plg_debug(ctx->ins, "Region: %s", region_resp);
    if (!cert_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf cert from IMDS");
        goto error;
    }
    flb_plg_debug(ctx->ins, "Leaf Cert: %s", cert_resp);
    if (!key_resp) {
        flb_plg_error(ctx->ins, "failed to get leaf key from IMDS");
        goto error;
    }
    flb_plg_debug(ctx->ins, "Private Key: %s", key_resp);

    if (!int_cert_resp) {
        flb_plg_error(ctx->ins, "failed to get intermediate cert from IMDS");
        goto error;    
    }
    flb_plg_debug(ctx->ins, "Intermediate Cert: %s", int_cert_resp);
    ctx->imds.region = region_resp;
    ctx->imds.leaf_cert = cert_resp;
    ctx->imds.leaf_key = key_resp;
    ctx->imds.intermediate_cert = int_cert_resp;
    ctx->imds.tenancy_ocid = extract_tenancy_ocid_from_cert(ctx, ctx->imds.leaf_cert); // still have to checkk return
    flb_plg_debug(ctx->ins, "Tenancy OCID: %s", ctx->imds.tenancy_ocid);
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(ctx->u);
    ctx->u = NULL;
    return 1;

error:
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
    ctx->imds.intermediate_cert = NULL;
    ctx->imds.leaf_cert = NULL;
    ctx->imds.leaf_key = NULL;
    ctx->imds.region = NULL;
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(ctx->u);
    ctx->u = NULL;
    return 0;
}

char *extract_base64_from_pem(const char *pem, const char *begin, const char *end) {
    const char *start = strstr(pem, begin);
    if (!start) return NULL;
    start += strlen(begin);
    const char *stop = strstr(start, end);
    if (!stop) {
        return NULL;
    }

    size_t len = stop - start;
    char *b64 = malloc(len + 1);
    strncpy(b64, start, len);
    b64[len] = '\0';

    char *src = b64, *dst = b64;
    while (*src) {
        if (*src != '\n' && *src != '\r') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
    return b64;
}

char *base64url_encode(const unsigned char *input, int length) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    for (int i = 0; i < bptr->length; ++i) {
        if (buff[i] == '+') {
            buff[i] = '-';
        }
        else if (buff[i] == '/') {
            buff[i] = '_';
        }
    }

    for (int i = strlen(buff) - 1; i >= 0 && buff[i] == '='; --i){
        buff[i] = '\0';
    }

    BIO_free_all(b64);
    return buff;
}

// Load private key from PEM
EVP_PKEY *load_private_key(const char *pem_key) {
    BIO *bio = BIO_new_mem_buf(pem_key, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

char *build_signed_jwt(const char *leaf_cert_pem, const char *inter_cert_pem,
                       const char *private_key_pem, const char *tenancy_ocid) {
    char *leaf_cert_b64 = extract_base64_from_pem(leaf_cert_pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
    char *inter_cert_b64 = extract_base64_from_pem(inter_cert_pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");

    // for header
    char header_json[2048];
    snprintf(header_json, sizeof(header_json),
             "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"x5c\":[\"%s\",\"%s\"]}",
             leaf_cert_b64, inter_cert_b64);

    //payloadd
    time_t now = time(NULL);
    char payload_json[1024];
    snprintf(payload_json, sizeof(payload_json),
             "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"oracle-cloud\","
             "\"exp\":%ld,\"nbf\":%ld,\"iat\":%ld}",
             tenancy_ocid, tenancy_ocid, now + 1800, now, now);

    char *encoded_header = base64url_encode((unsigned char *)header_json, strlen(header_json));
    char *encoded_payload = base64url_encode((unsigned char *)payload_json, strlen(payload_json));

    char signing_input[4096];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", encoded_header, encoded_payload);

    EVP_PKEY *pkey = load_private_key(private_key_pem);
    if (!pkey) {
        return NULL;
    }

    unsigned char sig[512];
    unsigned int sig_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, signing_input, strlen(signing_input));
    EVP_SignFinal(ctx, sig, &sig_len, pkey);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    char *encoded_sig = base64url_encode(sig, sig_len);

    char *jwt = malloc(strlen(signing_input) + strlen(encoded_sig) + 2);
    sprintf(jwt, "%s.%s", signing_input, encoded_sig);


    // to be updated it still have to be more readable
    free(leaf_cert_b64);
    free(inter_cert_b64);
    free(encoded_header);
    free(encoded_payload);
    free(encoded_sig);

    return jwt;
}


struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config) {
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

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

    if(strcmp (ctx->auth_mode, "instance_principal") == 0){
        // get certs and keys
        flb_plg_error(ctx->ins, "instance principal authentication still not available");
        get_keys_and_certs(ctx, config);
        // if (ctx->imds == NULL) {
        //     flb_plg_error(ctx->ins, "failed to create imds context");
        //     flb_oci_logan_conf_destroy(ctx);
        //     return NULL;
        // }
        char *jwt = build_signed_jwt(ctx->imds.leaf_cert, ctx->imds.intermediate_cert, \
            ctx->imds.leaf_key, ctx->imds.tenancy_ocid);
        flb_plg_debug(ctx->ins, "jwt -> %s", jwt);
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
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

    if (!ctx->config_file_location) {
        flb_plg_error(ctx->ins, "config file location is required");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    ret = load_oci_credentials(ctx);
    if(ret != 0) {
        flb_errno();
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region) {
            flb_plg_error(ctx->ins, "Region is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
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



    if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
        flb_plg_error(ctx->ins, "failed to create pk context");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }


    ctx->key_id = flb_sds_create_size(512);
    flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                     "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);


    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        default_port = 443;
    }
    else {
        flb_plg_error(ctx->ins, "TLS must be enabled, for OCI");
        return NULL;
    }
#else
    flb_plg_error(ctx->ins, "TLS support required for for OCI");
    return NULL;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    flb_output_net_default(host, default_port, ins);
    flb_sds_destroy(host);

    if (ctx->proxy) {
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->proxy_host = p_host;
        ctx->proxy_port = atoi(p_port);
        flb_free(protocol);
        flb_free(p_port);
        flb_free(p_uri);
        flb_free(p_host);
    }

    if (ctx->proxy) {
        upstream = flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
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

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx) {
    if(ctx == NULL) {
        return 0;
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
    if(ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if(ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if(ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if(ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    metadata_fields_destroy(ctx);

    flb_free(ctx);
    return 0;
}