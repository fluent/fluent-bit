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


#ifndef FLUENT_BIT_INCLUDE_FLUENT_BIT_ORACLE_FLB_ORACLE_CLIENT_H_
#define FLUENT_BIT_INCLUDE_FLUENT_BIT_ORACLE_FLB_ORACLE_CLIENT_H_

#define RSA_EXP 65537
#define FLB_OCI_TOKEN "token"

#define OCI_FEDERATION_REQUEST_PAYLOAD            "{\"certificate\":\"%s\",\"publicKey\":\"%s\", \"intermediateCertificates\":[\"%s\"]}"
#define OCI_OKE_PROXYMUX_PAYLOAD                  "{\"podKey\":\"%s\"}"

/* Http Header */
#define FLB_OCI_HEADER_REQUEST_TARGET           "(request-target)"
#define FLB_OCI_HEADER_USER_AGENT                      "User-Agent"
#define FLB_OCI_HEADER_USER_AGENT_VAL                  "Fluent-Bit"
#define FLB_OCI_HEADER_CONTENT_TYPE                    "content-type"
#define FLB_OCI_HEADER_CONTENT_TYPE_JSON               "application/json"
#define FLB_OCI_HEADER_CONTENT_TYPE_OCTET_STREAM       "application/octet-stream"
#define FLB_OCI_HEADER_X_CONTENT_SHA256                "x-content-sha256"
#define FLB_OCI_HEADER_CONTENT_LENGTH                  "content-length"
#define FLB_OCI_HEADER_HOST                            "host"
#define FLB_OCI_HEADER_DATE                            "date"
#define FLB_OCI_HEADER_AUTH                            "Authorization"
#define FLB_OCI_PAYLOAD_TYPE                           "payloadType"

/* For OCI signing */
#define FLB_OCI_PARAM_TENANCY     "tenancy"
#define FLB_OCI_PARAM_USER        "user"
#define FLB_OCI_PARAM_KEY_FINGERPRINT     "fingerprint"
#define FLB_OCI_PARAM_KEY_FILE     "key_file"
#define FLB_OCI_PARAM_REGION  "region"
#define FLB_OCI_PARAM_KEY_FILE_PASSPHRASE "key_file_passphrase"

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

#define METADATA_HOST_BASE "169.254.169.254"
#define GET_REGION_URL  "/opc/v2/instance/region"
#define GET_REGION_INFO_URL "/opc/v2/instance/regionInfo/"
#define LEAF_CERTIFICATE_URL "/opc/v2/identity/cert.pem"
#define LEAF_CERTIFICATE_PRIVATE_KEY_URL "/opc/v2/identity/key.pem"
#define INTERMEDIATE_CERTIFICATE_URL "/opc/v2/identity/intermediate.pem"

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output_plugin.h>
#include <openssl/x509.h>

struct federation_client {
  struct flb_upstream *u;
  flb_sds_t region;
  flb_sds_t tenancy_id;
  struct cert_retriever *leaf_cert_ret;
  struct cert_retriever *intermediate_cert_ret;
  // session key supplier
  flb_sds_t private_key;
  flb_sds_t public_key;
  flb_sds_t key_id;
  flb_sds_t security_token;
  time_t expire;
  pthread_mutex_t lock;
};

struct cert_retriever {
  struct flb_upstream *u;
  flb_sds_t cert_pem;
  X509 *cert;
  flb_sds_t private_key_pem;
};

int create_pk_context(flb_sds_t filepath,
                      const char *key_passphrase,
                      struct flb_output_instance *ins,
                      flb_sds_t *p_key);

int load_oci_credentials(struct flb_output_instance *ins,
                         flb_sds_t config_file_location,
                         flb_sds_t profile_name,
                         flb_sds_t *user, flb_sds_t *tenancy,
                         flb_sds_t *key_file, flb_sds_t *key_fingerprint,
                         flb_sds_t *region);
flb_sds_t create_authorization_header_content(flb_sds_t key_id,
                                              flb_sds_t signature,
                                              char* sign_header);
flb_sds_t create_base64_sha256_signature(flb_sds_t private_key,
                                         flb_sds_t signing_string,
                                         struct flb_output_instance *ins);
flb_sds_t get_date(void);
flb_sds_t add_header_and_signing(struct flb_http_client *c,
                                 flb_sds_t signing_str, const char *header, int headersize,
                                 const char *val, int val_size);
int build_headers(struct flb_http_client *c,
                  flb_sds_t private_key,
                  flb_sds_t key_id, flb_sds_t json,
                  flb_sds_t uri,
                  struct flb_output_instance *ins,
                  char *content_type);
int build_federation_client_headers(struct flb_http_client *c,
                  flb_sds_t private_key,
                  flb_sds_t key_id, flb_sds_t json,
                  flb_sds_t uri,
                  struct flb_output_instance *ins);
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
const char* get_token_exp(flb_sds_t token_string,
                          time_t *exp,
                          struct flb_output_instance *ins);
flb_sds_t create_fed_authorization_header_content(flb_sds_t signature,
                                                  flb_sds_t key_id);
void build_region_table(struct flb_hash_table **region_table);
int refresh_security_token(struct federation_client *fed_client,
                           struct flb_config *config,
                           struct flb_output_instance *ins,
                           struct flb_upstream *fed_u,
                           struct flb_upstream *cert_u,
                           struct flb_hash_table *region_table);
int refresh_oke_workload_security_token(struct federation_client *fed_client,
                                        struct flb_config *config,
                                        struct flb_output_instance *ins,
                                        struct flb_upstream *fed_u,
                                        flb_sds_t oke_sa_ca_file,
                                        flb_sds_t oke_sa_token_file,
                                        flb_sds_t *key_id);
#endif //FLUENT_BIT_INCLUDE_FLUENT_BIT_ORACLE_FLB_ORACLE_CLIENT_H_

