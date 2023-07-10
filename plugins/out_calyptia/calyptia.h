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

#ifndef FLB_OUT_CALYPTIA_H
#define FLB_OUT_CALYPTIA_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_fstore.h>

/* End point */
#define CALYPTIA_HOST            "cloud-api.calyptia.com"
#define CALYPTIA_PORT            "443"

/* HTTP action types */
#define CALYPTIA_ACTION_REGISTER  0
#define CALYPTIA_ACTION_PATCH     1
#define CALYPTIA_ACTION_METRICS   2
#define CALYPTIA_ACTION_TRACE     3

/* Endpoints */
#define CALYPTIA_ENDPOINT_CREATE  "/v1/agents"
#define CALYPTIA_ENDPOINT_PATCH   "/v1/agents/%s"
#define CALYPTIA_ENDPOINT_METRICS "/v1/agents/%s/metrics"
#define CALYPTIA_ENDPOINT_TRACE   "/v1/traces/%s"

/* Storage */
#define CALYPTIA_SESSION_FILE     "session.CALYPTIA"

/* Headers */
#define CALYPTIA_H_PROJECT       "X-Project-Token"
#define CALYPTIA_H_AGENT_TOKEN   "X-Agent-Token"
#define CALYPTIA_H_CTYPE         "Content-Type"
#define CALYPTIA_H_CTYPE_JSON    "application/json"
#define CALYPTIA_H_CTYPE_MSGPACK "application/x-msgpack"

struct flb_calyptia {
    /* config map */
    int cloud_port;
    flb_sds_t api_key;
    flb_sds_t cloud_host;
    flb_sds_t store_path;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /* internal */
    flb_sds_t agent_id;
    flb_sds_t agent_token;
    flb_sds_t machine_id;                 /* machine-id  */
    flb_sds_t fleet_id;                   /* fleet-id  */
    flb_sds_t metrics_endpoint;           /* metrics endpoint */
    struct flb_fstore *fs;                /* fstore ctx */
    struct flb_fstore_stream *fs_stream;  /* fstore stream */
    struct flb_fstore_file *fs_file;      /* fstore session file */
    struct flb_env *env;                  /* environment */
    struct flb_upstream *u;               /* upstream connection */
    struct mk_list kv_labels;             /* parsed add_labels */
    struct flb_output_instance *ins;      /* plugin instance */
    struct flb_config *config;            /* Fluent Bit context */
/* used for reporting chunk trace records to calyptia cloud. */
#ifdef FLB_HAVE_CHUNK_TRACE
    flb_sds_t trace_endpoint;
    flb_sds_t pipeline_id;
#endif /* FLB_HAVE_CHUNK_TRACE */
};

#endif
