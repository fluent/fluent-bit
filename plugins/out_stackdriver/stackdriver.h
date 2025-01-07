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

#ifndef FLB_OUT_STACKDRIVER_H
#define FLB_OUT_STACKDRIVER_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_metrics.h>

#include <cmetrics/cmt_histogram.h>

/* refresh token every 50 minutes */
#define FLB_STD_TOKEN_REFRESH 3000

/* Stackdriver Logging write scope */
#define FLB_STD_SCOPE     "https://www.googleapis.com/auth/logging.write"

/* Stackdriver authorization URL */
#define FLB_STD_AUTH_URL  "https://oauth2.googleapis.com/token"

/* Stackdriver Logging 'write' end-point */
#define FLB_STD_WRITE_URI "/v2/entries:write"
#define FLB_STD_WRITE_URI_SIZE 17
#define FLB_STD_WRITE_URL "https://logging.googleapis.com" FLB_STD_WRITE_URI

/* Timestamp format */
#define FLB_STD_TIME_FMT  "%Y-%m-%dT%H:%M:%S"

/* Default Resource type */
#define FLB_SDS_RESOURCE_TYPE "global"
#define OPERATION_FIELD_IN_JSON "logging.googleapis.com/operation"
#define MONITORED_RESOURCE_KEY "logging.googleapis.com/monitored_resource"
#define LOCAL_RESOURCE_ID_KEY "logging.googleapis.com/local_resource_id"
#define DEFAULT_LABELS_KEY "logging.googleapis.com/labels"
#define DEFAULT_PROJECT_ID_KEY "logging.googleapis.com/projectId"
#define DEFAULT_SEVERITY_KEY "logging.googleapis.com/severity"
#define DEFAULT_TRACE_KEY "logging.googleapis.com/trace"
#define DEFAULT_SPAN_ID_KEY "logging.googleapis.com/spanId"
#define DEFAULT_TRACE_SAMPLED_KEY "logging.googleapis.com/traceSampled"
#define DEFAULT_LOG_NAME_KEY "logging.googleapis.com/logName"
#define DEFAULT_INSERT_ID_KEY "logging.googleapis.com/insertId"
#define SOURCELOCATION_FIELD_IN_JSON "logging.googleapis.com/sourceLocation"
#define HTTPREQUEST_FIELD_IN_JSON "logging.googleapis.com/http_request"
#define INSERT_ID_SIZE 31
#define LEN_LOCAL_RESOURCE_ID_KEY 40
#define OPERATION_KEY_SIZE 32
#define SOURCE_LOCATION_SIZE 37
#define HTTP_REQUEST_KEY_SIZE 35

/*
 * Stackdriver implements a specific HTTP status code that is used internally in clients to keep
 * track of networking errors that could happen before a successful HTTP request/response. For
 * metrics counting purposes, every failed networking connection will use a 502 HTTP status code
 * that can be used later to query the metrics by using labels with that value.
 */
#define STACKDRIVER_NET_ERROR  502

#define K8S_CLUSTER   "k8s_cluster"
#define K8S_CONTAINER "k8s_container"
#define K8S_NODE      "k8s_node"
#define K8S_POD       "k8s_pod"

#define STDOUT "stdout"
#define STDERR "stderr"

#define DEFAULT_TAG_REGEX "(?<pod_name>[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)_(?<namespace_name>[^_]+)_(?<container_name>.+)-(?<docker_id>[a-z0-9]{64})\\.log$"

/* Metrics */
#ifdef FLB_HAVE_METRICS
#define FLB_STACKDRIVER_SUCCESSFUL_REQUESTS  1000   /* successful requests */
#define FLB_STACKDRIVER_FAILED_REQUESTS      1001   /* failed requests */
#endif

// https://grpc.github.io/grpc/core/md_doc_statuscodes.html
#define GRPC_STATUS_CODES_SIZE 17
#define PARTIAL_SUCCESS_GRPC_TYPE "type.googleapis.com/google.logging.v2.WriteLogEntriesPartialErrors"
#define PARTIAL_SUCCESS_GRPC_TYPE_SIZE 66

struct flb_stackdriver_oauth_credentials {
    /* parsed credentials file */
    flb_sds_t type;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
};

struct flb_stackdriver_env {
    flb_sds_t creds_file;
    flb_sds_t metadata_server;
};

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
    flb_sds_t metadata_server;
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

    flb_sds_t local_resource_id;
    flb_sds_t tag_prefix;
    /* shadow tag_prefix for safe deallocation */
    flb_sds_t tag_prefix_k8s;

    /* labels */
    flb_sds_t labels_key;
    struct mk_list *labels;
    struct mk_list config_labels;

    /* resource type flag */
    int resource_type;

    /* resource labels api */
    struct mk_list *resource_labels;
    struct mk_list resource_labels_kvs;
    int should_skip_resource_labels_api;

    /* generic resources */
    flb_sds_t location;
    flb_sds_t namespace_id;

    /* generic_node specific */
    flb_sds_t node_id;

    /* generic_task specific */
    flb_sds_t job;
    flb_sds_t task_id;

    /* Internal variable to reduce string comparisons */
    int compress_gzip;

    /* other */
    flb_sds_t export_to_project_id;
    flb_sds_t project_id_key;
    flb_sds_t resource;
    flb_sds_t severity_key;
    flb_sds_t trace_key;
    flb_sds_t span_id_key;
    flb_sds_t trace_sampled_key;
    flb_sds_t log_name_key;
    flb_sds_t http_request_key;
    int http_request_key_size;
    int autoformat_stackdriver_trace;
    int test_log_entry_format;

    flb_sds_t stackdriver_agent;

    /* Regex context to parse tags */
    flb_sds_t custom_k8s_regex;
    struct flb_regex *regex;

    /* oauth2 context */
    struct flb_oauth2 *o;

    /* parsed oauth2 credentials */
    struct flb_stackdriver_oauth_credentials *creds;

    /* environment variable settings */
    struct flb_stackdriver_env *env;

    /* mutex for acquiring oauth tokens */
    pthread_mutex_t token_mutex;

    /* upstream context for stackdriver write end-point */
    struct flb_upstream *u;

    /* upstream context for metadata end-point */
    struct flb_upstream *metadata_u;

    /* the key to extract unstructured text payload from */
    flb_sds_t text_payload_key;

    /* config key to allow an alternate Cloud Logging URL */
    flb_sds_t cloud_logging_base_url;
    flb_sds_t cloud_logging_write_url;

#ifdef FLB_HAVE_METRICS
    /* metrics */
    struct cmt_counter *cmt_successful_requests;
    struct cmt_counter *cmt_failed_requests;
    struct cmt_counter *cmt_requests_total;
    struct cmt_counter *cmt_proc_records_total;
    struct cmt_counter *cmt_retried_records_total;
    struct cmt_histogram *cmt_write_entries_latency;
#endif

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
