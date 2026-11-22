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


#ifndef FLB_OUT_OCI_LOGAN_H
#define FLB_OUT_OCI_LOGAN_H

#define FLB_OCI_LOG_ENTITY_ID_KEY "oci_la_entity_id"
#define FLB_OCI_LOG_ENTITY_ID_KEY_SIZE sizeof(FLB_OCI_LOG_ENTITY_ID_KEY) - 1

#define FLB_OCI_LOG_ENTITY_TYPE_KEY "oci_la_entity_type"
#define FLB_OCI_LOG_ENTITY_TYPE_KEY_SIZE sizeof(FLB_OCI_LOG_ENTITY_TYPE_KEY) - 1

#define FLB_OCI_LOG_GROUP_ID_KEY "oci_la_log_group_id"
#define FLB_OCI_LOG_GROUP_ID_KEY_SIZE sizeof(FLB_OCI_LOG_GROUP_ID_KEY) - 1

#define FLB_OCI_LOG_SET_ID_KEY "oci_la_log_set_id"
#define FLB_OCI_LOG_SET_ID_KEY_SIZE sizeof(FLB_OCI_LOG_SET_ID_KEY) - 1

#define FLB_OCI_LOG_SOURCE_NAME_KEY "oci_la_log_source_name"
#define FLB_OCI_LOG_SOURCE_NAME_KEY_SIZE sizeof(FLB_OCI_LOG_SOURCE_NAME_KEY) - 1

#define FLB_OCI_LOG_PATH_KEY "oci_la_log_path"
#define FLB_OCI_LOG_PATH_KEY_SIZE sizeof(FLB_OCI_LOG_PATH_KEY) - 1

#define FLB_OCI_METADATA_KEY "oci_la_metadata"
#define FLB_OCI_METADATA_KEY_SIZE sizeof(FLB_OCI_METADATA_KEY) - 1

#define FLB_OCI_GLOBAL_METADATA_KEY "oci_la_global_metadata"
#define FLB_OCI_GLOBAL_METADATA_KEY_SIZE sizeof(FLB_OCI_GLOBAL_METADATA_KEY) - 1

#define FLB_OCI_LOG_EVENTS  "logEvents"
#define FLB_OCI_LOG_EVENTS_SIZE sizeof(FLB_OCI_LOG_EVENTS)-1

#define FLB_OCI_LOG_RECORDS  "logRecords"
#define FLB_OCI_LOG_RECORDS_SIZE sizeof(FLB_OCI_LOG_RECORDS)-1

#define FLB_OCI_LOG_GROUP_ID "logGroupId"
#define FLB_OCI_LOG_GROUP_ID_SIZE sizeof(FLB_OCI_LOG_GROUP_ID)-1

#define FLB_OCI_ENTITY_TYPE "entityType"
#define FLB_OCI_ENTITY_TYPE_SIZE sizeof(FLB_OCI_ENTITY_TYPE) - 1

#define FLB_OCI_LOG_SET "logSet"
#define FLB_OCI_LOG_SET_SIZE sizeof(FLB_OCI_LOG_SET)-1

#define FLB_OCI_LOG_METADATA "metadata"
#define FLB_OCI_LOG_METADATA_SIZE sizeof(FLB_OCI_LOG_METADATA)-1

#define FLB_OCI_ENTITY_ID "entityId"
#define FLB_OCI_ENTITY_ID_SIZE sizeof(FLB_OCI_ENTITY_ID)-1

#define FLB_OCI_LOG_SOURCE_NAME "logSourceName"
#define FLB_OCI_LOG_SOURCE_NAME_SIZE sizeof(FLB_OCI_LOG_SOURCE_NAME)-1

#define FLB_OCI_LOG_PATH "logPath"
#define FLB_OCI_LOG_PATH_SIZE sizeof(FLB_OCI_LOG_PATH)-1

#define FLB_OCI_META_PREFIX "metadata_"
#define FLB_OCI_META_PREFIX_SIZE sizeof(FLB_OCI_META_PREFIX)-1

#define FLB_OCI_MATCH_PREFIX "oci_match_"
#define FLB_OCI_MATCH_PREFIX_SIZE sizeof(FLB_OCI_MATCH_PREFIX)-1

#define FLB_OCI_LOG_TIMEZONE_KEY "oci_la_timezone"
#define FLB_OCI_LOG_TIMEZONE_KEY_SIZE sizeof(FLB_OCI_LOG_TIMEZONE_KEY) - 1

#define FLB_OCI_LOG_TIMEZONE "timezone"
#define FLB_OCI_LOG_TIMEZONE_SIZE sizeof(FLB_OCI_LOG_TIMEZONE) - 1

#ifdef FLB_HAVE_REGEX
#define FLB_OCI_MATCH_REGEX_PREFIX "oci_match_regex_"
#define FLB_OCI_MATCH_REGEX_PREFIX_SIZE sizeof(FLB_OCI_MATCH_REGEX_PREFIX)-1
#endif

/* Params */
#define FLB_OCI_PARAM_SKIP_HTTP_POST "skip_http_post"
#define FLB_OCI_PARAM_URI "uri"
#define FLB_OCI_PARAM_ENABLE_TRACE_OUTPUT "enable_trace"
#define FLB_OCI_PARAM_TRACE_OUTPUT_PATH "trace_file_path"
#define FLB_OCI_PARAM_TRACE_OUTPUT_FILE "trace_file_name"
#define FLB_OCI_PARAM_COLLECT_TIME_FIELD "collect_time_field_name"

#define FLB_OCI_PARAM_USE_RAW_RECORD "use_raw_record"
#define FLB_OCI_PARAM_USE_RAW_RECORD_SIZE sizeof(FLB_OCI_PARAM_USE_RAW_RECORD)-1

#define FLB_OCI_PARAM_INCLUDE_COLLECT_TIME "include_collect_time"
#define FLB_OCI_PARAM_INCLUDE_COLLECT_TIME_SIZE sizeof(FLB_OCI_PARAM_INCLUDE_COLLECT_TIME)-1

#define FLB_OCI_MATCH_ID_MAX 1000       // TO avoid too large memory allocation

#define FLB_OCI_DEFAULT_COLLECT_TIME       "oci_collect_time"
#define FLB_OCI_DEFAULT_COLLECT_TIME_SIZE sizeof(FLB_OCI_DEFAULT_COLLECT_TIME)-1

/* Http Header */
#define FLB_OCI_HEADER_REQUEST_TARGET           "(request-target)"
#define FLB_OCI_HEADER_USER_AGENT                      "User-Agent"
#define FLB_OCI_HEADER_USER_AGENT_VAL                  "Fluent-Bit"
#define FLB_OCI_HEADER_CONTENT_TYPE                    "content-type"
#define FLB_OCI_HEADER_CONTENT_TYPE_VAL                "application/octet-stream"
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

/* For error response */
#define FLB_OCI_ERROR_RESPONSE_CODE     "code"
#define FLB_OCI_ERROR_RESPONSE_MESSAGE  "message"

#define FLB_OCI_ERROR_CODE_RELATED_RESOURCE_NOT_FOUND      "RelatedResourceNotAuthorizedOrNotFound"
#define FLB_OCI_ERROR_CODE_NOT_AUTHENTICATED               "NotAuthenticated"
#define FLB_OCI_ERROR_CODE_NOT_AUTHENTICATEDORNOTFOUND     "NotAuthorizedOrNotFound"
#define FLB_OCI_ERROR_CODE_INCORRECTSTATE                  "IncorrectState"
#define FLB_OCI_ERROR_CODE_NOT_AUTH_OR_RESOURCE_EXIST      "NotAuthorizedOrResourceAlreadyExists"
#define FLB_OCI_ERROR_CODE_TOO_MANY_REQUESTS               "TooManyRequests"
#define FLB_OCI_ERROR_CODE_INTERNAL_SERVER_ERROR           "InternalServerError"

/* for imds request*/
#define ORACLE_IMDS_HOST "169.254.169.254"
#define ORACLE_IMDS_BASE_URL "/opc/v2"
#define ORACLE_IMDS_REGION_PATH "/instance/region"
#define ORACLE_IMDS_LEAF_CERT_PATH "/identity/cert.pem"
#define ORACLE_IMDS_LEAF_KEY_PATH "/identity/key.pem"
#define ORACLE_IMDS_INTERMEDIATE_CERT_PATH "/identity/intermediate.pem"
#define ORACLE_AUTH_HEADER "Authorization: Bearer Oracle"
#define ORACLE_IMDS_TOKEN_PATH "/opc/v2/instancePrincipal/token"


#define COUNT_OF_REGION (sizeof(region_mappings) / sizeof(region_mappings[0]) - 1)

/* for chunking */
#define MAX_PAYLOAD_SIZE_BYTES (3800000)        // 3.8 mb

#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core/mk_list.h>
#include <fluent-bit/flb_jsmn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <msgpack.h>
#include <string.h>

struct metadata_obj
{
    flb_sds_t key;
    flb_sds_t val;
    struct mk_list _head;

};

struct flb_oci_error_response
{
    flb_sds_t code;
    flb_sds_t message;
};

struct flb_oracle_imds
{
    flb_sds_t region;
    flb_sds_t leaf_cert;
    flb_sds_t leaf_key;
    flb_sds_t intermediate_cert;
    flb_sds_t tenancy_ocid;
    flb_sds_t fingerprint;
    flb_sds_t session_pubkey;
    flb_sds_t session_privkey;
    struct flb_upstream *upstream;
    struct flb_output_instance *ins;
};

struct oci_security_token
{
    flb_sds_t token;
    time_t expires_at;
    flb_sds_t session_privkey;
};

typedef struct
{
    const char *region;
    const char *realm;
} region_realm_mapping_t;

typedef struct
{
    const char *short_name;
    const char *long_name;
} region_mapping_t;

typedef struct
{
    const char *realm_code;
    const char *domain_suffix;
} realm_mapping_t;

struct flb_oci_logan
{
    flb_sds_t namespace;
    flb_sds_t config_file_location;
    flb_sds_t profile_name;
    int oci_config_in_record;
    flb_sds_t uri;

    char *domain_suffix;
    struct flb_upstream *u;
    flb_sds_t proxy;
    char *proxy_host;
    int proxy_port;

    // oci_la_* configs

    flb_sds_t oci_la_entity_id;

    flb_sds_t oci_la_entity_type;

    flb_sds_t oci_la_log_source_name;

    flb_sds_t oci_la_log_path;

    flb_sds_t oci_la_log_group_id;

    flb_sds_t oci_la_log_set_id;

    flb_sds_t oci_la_timezone;

    struct mk_list *oci_la_global_metadata;
    struct mk_list global_metadata_fields;
    struct mk_list *oci_la_metadata;
    struct mk_list log_event_metadata_fields;

    // config_file
    flb_sds_t user;
    flb_sds_t region;
    flb_sds_t tenancy;
    flb_sds_t key_fingerprint;
    flb_sds_t key_file;
    /* For OCI signing */
    flb_sds_t key_id;           // tenancy/user/key_fingerprint
    flb_sds_t private_key;
    struct flb_output_instance *ins;

    // instance prinicipal auth
    struct flb_oracle_imds imds;
    EVP_PKEY *session_key_pair;
    struct oci_security_token security_token;
    char *auth_type;

    // dump payload
    char *payload_files_location;
    bool dump_payload_file;
};

int is_valid_timezone(const char *log_timezone);
const char *get_domain_suffix_for_realm(const char *realm);
const char *determine_realm_from_region(const char *region);
const char *long_region_name(char *short_region_name);
#endif
