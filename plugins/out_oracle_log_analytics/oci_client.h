//
// Created by Aditya Bharadwaj on 22/09/23.
//


#ifndef FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H
#define FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H

#define FLB_OCI_TOKEN "token"
#define RSA_EXP 65537

#define FLB_OCI_HEADER_REQUEST_TARGET           "(request-target)"
#define FLB_OCI_HEADER_USER_AGENT                      "User-Agent"
#define FLB_OCI_HEADER_USER_AGENT_VAL                  "Fluent-Bit"
#define FLB_OCI_HEADER_CONTENT_TYPE                    "content-type"
#define FLB_OCI_HEADER_CONTENT_TYPE_VAL                "application/octet-stream"
#define FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL            "application/json"
#define FLB_OCI_HEADER_X_CONTENT_SHA256                "x-content-sha256"
#define FLB_OCI_HEADER_CONTENT_LENGTH                  "content-length"
#define FLB_OCI_HEADER_HOST                            "host"
#define FLB_OCI_HEADER_DATE                            "date"
#define FLB_OCI_HEADER_AUTH                            "Authorization"
#define FLB_OCI_PAYLOAD_TYPE                           "payloadType"

#define FLB_OCI_SIGN_SIGNATURE_VERSION   "Signature version=\"1\""
#define FLB_OCI_SIGN_KEYID   "keyId"
#define FLB_OCI_SIGN_ALGORITHM   "algorithm=\"rsa-sha256\""

#define FLB_OCI_SIGN_HEADERS     "headers=\"" \
    FLB_OCI_HEADER_REQUEST_TARGET " " \
    FLB_OCI_HEADER_HOST " " \
    FLB_OCI_HEADER_DATE " " \
    FLB_OCI_HEADER_X_CONTENT_SHA256 " " \
    FLB_OCI_HEADER_CONTENT_TYPE " " \
    FLB_OCI_HEADER_CONTENT_LENGTH "\""

#define FLB_OCI_SIGN_SIGNATURE   "signature"
#define FLB_OCI_FED_SIGN_HEADERS "headers=\"" \
    FLB_OCI_HEADER_REQUEST_TARGET " " \
    FLB_OCI_HEADER_DATE " " \
    FLB_OCI_HEADER_X_CONTENT_SHA256 " " \
    FLB_OCI_HEADER_CONTENT_TYPE " " \
    FLB_OCI_HEADER_CONTENT_LENGTH "\""


#endif //FLUENT_BIT_PLUGINS_OUT_OCI_LOGAN_OCI_CLIENT_H_

#include <fluent-bit/flb_sds.h>
#include <openssl/x509.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_output_plugin.h>

flb_sds_t refresh_cert(struct flb_upstream *u, flb_sds_t cert_url,
                       struct flb_output_instance *ins);
flb_sds_t get_tenancy_id_from_certificate(X509 *cert);
char* sanitize_certificate_string(flb_sds_t cert_pem);
void colon_separated_fingerprint(unsigned char* readbuf, void *writebuf, size_t len);
flb_sds_t fingerprint(X509 *cert);
int session_key_supplier(flb_sds_t *priv_key,
                         flb_sds_t *pub_key,
                         struct flb_output_instance *ins);
X509 *get_cert_from_string(flb_sds_t cert_pem);
flb_sds_t get_region(struct flb_upstream *u, flb_sds_t region_url,
                     struct flb_hash_table *ht);
flb_sds_t parse_token(char *response,
                      size_t response_len);
flb_sds_t add_header_and_signing(struct flb_http_client *c,
                                 flb_sds_t signing_str,
                                 const char *header,
                                 int headersize,
                                 const char *val, int val_size);
flb_sds_t get_date(void);
flb_sds_t create_base64_sha256_signature(flb_sds_t private_key,
                                         flb_sds_t signing_string);
flb_sds_t create_authorization_header_content(flb_sds_t signature,
                                              flb_sds_t key_id);
const char* get_token_exp(flb_sds_t token_string,
                          time_t *exp,
                          struct flb_output_instance *ins);
flb_sds_t create_fed_authorization_header_content(flb_sds_t signature,
                                                  flb_sds_t key_id);
