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

#ifndef FLB_OUT_STACKDRIVER_H
#define FLB_OUT_STACKDRIVER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>

/* refresh token every 50 minutes */
#define FLB_STD_TOKEN_REFRESH 3000

/* Stackdriver Logging write scope */
#define FLB_STD_SCOPE     "https://www.googleapis.com/auth/logging.write"

/* Stackdriver authorization URL */
#define FLB_STD_AUTH_URL  "https://www.googleapis.com/oauth2/v4/token"

/* Stackdriver Logging 'write' end-point */
#define FLB_STD_WRITE_URI "/v2/entries:write"
#define FLB_STD_WRITE_URL \
    "https://logging.googleapis.com" FLB_STD_WRITE_URI

/* Timestamp format */
#define FLB_STD_TIME_FMT  "%Y-%m-%dT%H:%M:%S"

/* Default Resource type */
#define FLB_SDS_RESOURCE_TYPE "global"

#define OPERATION_FIELD_IN_JSON "logging.googleapis.com/operation"
#define LOCAL_RESOURCE_ID_KEY "logging.googleapis.com/local_resource_id"
#define DEFAULT_LABELS_KEY "logging.googleapis.com/labels"
#define DEFAULT_INSERT_ID_KEY "logging.googleapis.com/insertId"
#define SOURCELOCATION_FIELD_IN_JSON "logging.googleapis.com/sourceLocation"
#define HTTPREQUEST_FIELD_IN_JSON "logging.googleapis.com/http_request"
#define INSERT_ID_SIZE 31
#define LEN_LOCAL_RESOURCE_ID_KEY 40
#define OPERATION_KEY_SIZE 32
#define SOURCE_LOCATION_SIZE 37
#define HTTP_REQUEST_KEY_SIZE 35

#define K8S_CONTAINER "k8s_container"
#define K8S_NODE      "k8s_node"
#define K8S_POD       "k8s_pod"

#define STREAM_STDOUT 1
#define STREAM_STDERR 2
#define STREAM_UNKNOWN 3

#define STDOUT "stdout"
#define STDERR "stderr"

struct flb_stackdriver {
    /* credentials */
    flb_sds_t credentials_file;

    /* parsed credentials file */
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
    bool metadata_server_auth;

    /* metadata server (GCP specific, WIP) */
    flb_sds_t zone;
    flb_sds_t instance_id;
    flb_sds_t instance_name;

    /* kubernetes specific */
    flb_sds_t cluster_name;
    flb_sds_t cluster_location;
    flb_sds_t namespace_name;
    flb_sds_t pod_name;
    flb_sds_t container_name;
    flb_sds_t node_name;
    bool k8s_resource_type;
    
    flb_sds_t labels_key;

    /* other */
    flb_sds_t resource;
    flb_sds_t severity_key;

    /* oauth2 context */
    struct flb_oauth2 *o;

    /* upstream context for stackdriver write end-point */
    struct flb_upstream *u;

    /* upstream context for metadata end-point */
    struct flb_upstream *metadata_u;

    /* plugin instance */
    struct flb_output_instance *ins;

    /* Fluent Bit context */
    struct flb_config *config;
};

typedef enum {
    FLB_STD_EMERGENCY = 800,
    FLB_STD_ALERT     = 700,
    FLB_STD_CRITICAL  = 600,
    FLB_STD_ERROR     = 500,
    FLB_STD_WARNING   = 400,
    FLB_STD_NOTICE    = 300,
    FLB_STD_INFO      = 200,
    FLB_STD_DEBUG     = 100,
    FLB_STD_DEFAULT   = 0
} severity_t;

struct local_resource_id_list {
    flb_sds_t val;
    struct mk_list _head;
};

typedef enum {
    INSERTID_VALID = 0,
    INSERTID_INVALID = 1,
    INSERTID_NOT_PRESENT = 2
} insert_id_status;

#endif
