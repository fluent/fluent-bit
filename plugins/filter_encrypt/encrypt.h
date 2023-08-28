/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#ifndef FLUENT_BIT_V2_0_8_PLUGINS_FILTER_ENCRYPT_ENCRYPT_H_
#define FLUENT_BIT_V2_0_8_PLUGINS_FILTER_ENCRYPT_ENCRYPT_H_

#include "json/mjson.h"
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_sds.h>

#define FLB_FILTER_ENCRYPT_HOST             "host"
#define FLB_FILTER_ENCRYPT_PORT             "port"
#define FLB_FILTER_ENCRYPT_URI_PII_FIELDS   "uri_pii_fields"
#define FLB_FILTER_ENCRYPT_AUTH_TOKEN       "auth_token"
#define FLB_FILTER_ENCRYPT_TENANT_ID        "tenant_id"
#define FLB_FILTER_ENCRYPT_AGENT_ID         "agent_id"
#define FLB_FILTER_ENCRYPT_URI_ENC_KEYS      "uri_enc_keys"
#define FLB_FILTER_ENCRYPT_MASTER_ENC_KEY   "master_enc_key"

#define FLB_FILTER_ENCRYPT_HEADER_AUTHORIZATION "Authorization"
#define FLB_FILTER_ENCRYPT_HEADER_TOKEN         "Token "

#define MAX_KEY_SALT_LENGTH 100
#define MAX_LENGTH 50
#define VALUE_MAX_LENGTH 512

static char aes_det_key[MAX_KEY_SALT_LENGTH];
static char ip_encryption_key[MAX_KEY_SALT_LENGTH];

struct flb_filter_encrypt {
    flb_sds_t host;
    int port;
    flb_sds_t uri_pii_fields;
    flb_sds_t auth_token;
    flb_sds_t tenant_id;
    flb_sds_t agent_id;
    flb_sds_t uri_enc_keys;
    flb_sds_t master_enc_key;
    struct flb_upstream *upstream;
    struct flb_filter_instance *f_ins;
};



struct pii_kv {
    int id;
    char key[50];
    int key_len;
    char val[512];
    int val_len;
    struct mk_list _head;
};


// PII fields
struct pii_record_struct_t {
    int id;
    char eventType[MAX_LENGTH];
    char fieldName[MAX_LENGTH];
    char maskingTechnique[MAX_LENGTH];
};
static struct pii_record_struct_t pii_fields_records_array[5];

static int pii_obj_count;

struct mk_list *head_pii;
struct mk_list items_pii;

static const struct json_attr_t events_attr[] = {
    {"id",  t_integer,  .addr.offset = offsetof(struct pii_record_struct_t, id),.len = MAX_LENGTH},
    {"eventType",  t_string,  .addr.offset = offsetof(struct pii_record_struct_t, eventType),.len = MAX_LENGTH},
    {"fieldName",  t_string,  .addr.offset = offsetof(struct pii_record_struct_t, fieldName),.len = MAX_LENGTH},
    {"maskingTechnique",  t_string,  .addr.offset = offsetof(struct pii_record_struct_t, maskingTechnique),.len = MAX_LENGTH},
    {NULL},
};

static const struct json_attr_t pii_fields_json_attrs_items[] = {
    {"entries", t_array, .addr.array.element_type = t_structobject,
        .addr.array.arr.objects.base = (char*)&pii_fields_records_array,
        .addr.array.arr.objects.stride = sizeof(struct pii_record_struct_t),
        .addr.array.arr.objects.subtype = events_attr,
        .addr.array.count = &pii_obj_count,
        .addr.array.maxlen = sizeof(pii_fields_records_array)/sizeof(pii_fields_records_array[0])},
    {NULL},
};

// Data encryption keys
struct dek_kv {
    int id;
    char created_on[128];
    int created_on_len;
    char encryption_key[1024];
    int encryption_key_len;
    char encryption_key_time_start[128];
    int encryption_key_time_start_len;
    char purpose[128];
    int purpose_len;
    bool is_default;
    int is_default_len;
    struct mk_list _head;
};

struct mk_list *head_dek;
struct mk_list items_dek;

struct dek_record_struct_t {
    int id;
    char created_on[MAX_LENGTH];
    char encryption_key_time_start[MAX_LENGTH];
    char encryption_key[VALUE_MAX_LENGTH];
    char purpose[VALUE_MAX_LENGTH];
    bool is_default;
};
static struct dek_record_struct_t dek_records_array[5];

static int dek_obj_count;

static char value_delimiters[128];

static const struct json_attr_t dek_events_attr[] = {
    {"id",  t_integer,  .addr.offset = offsetof(struct dek_record_struct_t, id),.len = MAX_LENGTH},
    {"created_on",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, created_on),.len = MAX_LENGTH},
    {"encryption_key",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, encryption_key),.len = VALUE_MAX_LENGTH},
    {"encryption_key_time_start",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, encryption_key_time_start),.len = MAX_LENGTH},
    {"purpose",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, purpose),.len = MAX_LENGTH},
    {"is_default",  t_boolean,  .addr.offset = offsetof(struct dek_record_struct_t, is_default),.len = MAX_LENGTH},
    {NULL},
};

static const struct json_attr_t dek_fields_json_attrs_items[] = {
    {"entries", t_array, .addr.array.element_type = t_structobject,
        .addr.array.arr.objects.base = (char*)&dek_records_array,
        .addr.array.arr.objects.stride = sizeof(struct dek_record_struct_t),
        .addr.array.arr.objects.subtype = dek_events_attr,
        .addr.array.count = &dek_obj_count,
        .addr.array.maxlen = sizeof(dek_records_array)/sizeof(dek_records_array[0])},
    {NULL},
};

flb_sds_t flb_json_get_val(char *response, size_t response_len, char *key);

static flb_sds_t make_http_request(struct flb_config *config,
                                   const char* URI,
                                   const int PORT,
                                   const char* URI_PATH,
                                   const char* header_key,
                                   const char* header_value);


// clock for API request to check for any configuration changes.
time_t start, end;
int interval_seconds = 15;
int interval_exit_time = 60;
double elapsed;
double elapsed_exit_time = 0.0;
#endif //FLUENT_BIT_V2_0_8_PLUGINS_FILTER_ENCRYPT_ENCRYPT_H_
