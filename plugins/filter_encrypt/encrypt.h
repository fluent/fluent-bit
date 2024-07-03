/* -*-  Mode:C; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (C) 2004-2024 by the University of Southern California
 * $Id: 08c7e189cae19260957f372fd3199a29447d2827 $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 * CryptopANT is a C library for IP address anonymization using crypto-PAn algorithm, originally defined by Georgia Tech.
 * URL: https://ant.isi.edu/software/cryptopANT/index.html
 *
 */
#ifndef FLUENT_BIT_V2_0_8_PLUGINS_FILTER_ENCRYPT_ENCRYPT_H_
#define FLUENT_BIT_V2_0_8_PLUGINS_FILTER_ENCRYPT_ENCRYPT_H_

#include "mjson.h"
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_sds.h>

#define FLB_FILTER_ENCRYPT_HOST             "host"
#define FLB_FILTER_ENCRYPT_PORT             "port"
#define FLB_FILTER_ENCRYPT_URI_PII_FIELDS   "uri_pii_fields"
#define FLB_FILTER_ENCRYPT_ORGANIZATION_KEY "organization_key"
#define FLB_FILTER_ENCRYPT_API_ACCESS_KEY   "api_access_key"
#define FLB_FILTER_ENCRYPT_API_SECRET_KEY   "api_secret_key"
#define FLB_FILTER_ENCRYPT_TENANT_ID        "tenant_id"
#define FLB_FILTER_ENCRYPT_AGENT_ID         "agent_id"
#define FLB_FILTER_ENCRYPT_URI_ENC_KEYS     "uri_enc_keys"
#define FLB_FILTER_ENCRYPT_MASTER_ENC_KEY   "master_enc_key"

#define FLB_FILTER_ENCRYPT_HEADER_X_ORGANIZATION_KEY "X-ORGANIZATION-KEY"
#define FLB_FILTER_ENCRYPT_HEADER_X_ACCESS_KEY "X-API-ACCESS-KEY"
#define FLB_FILTER_ENCRYPT_HEADER_X_SECRET_KEY "X-API-SECRET-KEY"

#define MAX_KEY_SALT_LENGTH 100
#define MAX_LENGTH 50
#define VALUE_MAX_LENGTH 512

static char aes_det_key[MAX_KEY_SALT_LENGTH];
static char ip_encryption_key[MAX_KEY_SALT_LENGTH];

struct flb_filter_encrypt {
    flb_sds_t host;
    int port;
    flb_sds_t uri_pii_fields;
    flb_sds_t organization_key;
    flb_sds_t api_access_key;
    flb_sds_t api_secret_key;
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
    struct mk_list _head;
};

struct mk_list *head_dek;
struct mk_list items_dek;

struct dek_record_struct_t {
    int id;
    char created_on[MAX_LENGTH];
    char encryption_key_time_start[MAX_LENGTH];
    char encryption_key[VALUE_MAX_LENGTH];
};
static struct dek_record_struct_t dek_records_array[5];

static int dek_obj_count;

static char value_delimiters[128];

static const struct json_attr_t dek_events_attr[] = {
    {"id",  t_integer,  .addr.offset = offsetof(struct dek_record_struct_t, id),.len = MAX_LENGTH},
    {"created_on",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, created_on),.len = MAX_LENGTH},
    {"encryption_key",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, encryption_key),.len = VALUE_MAX_LENGTH},
    {"encryption_key_time_start",  t_string,  .addr.offset = offsetof(struct dek_record_struct_t, encryption_key_time_start),.len = MAX_LENGTH},
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
                                   const char* HOST,
                                   const int PORT,
                                   const char* URI_PATH,
                                   const char** headers,
                                   size_t num_headers);


// clock for API request to check for any configuration changes.
time_t start, end;
int interval_seconds = 15;
int interval_exit_time = 60;
double elapsed;
double elapsed_exit_time = 0.0;
#endif //FLUENT_BIT_V2_0_8_PLUGINS_FILTER_ENCRYPT_ENCRYPT_H_
