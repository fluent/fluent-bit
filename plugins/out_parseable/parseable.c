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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_input_event.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>
#include <msgpack.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <ctraces/ctr_encode_opentelemetry.h>
#include <ctraces/ctr_encode_text.h>

#include <fluent-otel-proto/fluent-otel.h>

extern cfl_sds_t cmt_encode_opentelemetry_create(struct cmt *cmt);
extern void cmt_encode_opentelemetry_destroy(cfl_sds_t text);

#include "parseable.h"

/* Forward declarations */
static int parseable_format_json(struct flb_out_parseable *ctx,
                                  const void *data, size_t bytes,
                                  void **out_buf, size_t *out_size,
                                  struct flb_config *config);

/*
 * Helper: Find a string value in a msgpack map by key name.
 * Returns the value object or NULL if not found.
 */
static msgpack_object *find_map_str_value(msgpack_object *map, 
                                           const char *key_name, 
                                           size_t key_len)
{
    int i;
    msgpack_object key;
    
    if (map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    
    for (i = 0; i < map->via.map.size; i++) {
        key = map->via.map.ptr[i].key;
        if (key.type == MSGPACK_OBJECT_STR &&
            key.via.str.size == key_len &&
            strncmp(key.via.str.ptr, key_name, key_len) == 0) {
            return &map->via.map.ptr[i].val;
        }
    }
    return NULL;
}

/*
 * Helper: Get string value from msgpack object.
 * Returns newly allocated flb_sds_t or NULL.
 */
static flb_sds_t get_str_value(msgpack_object *obj)
{
    if (obj && obj->type == MSGPACK_OBJECT_STR && obj->via.str.size > 0) {
        return flb_sds_create_len(obj->via.str.ptr, obj->via.str.size);
    }
    return NULL;
}

/*
 * Extract dynamic dataset name from Kubernetes metadata.
 * Priority:
 *   1. kubernetes.annotations["parseable/dataset"]
 *   2. kubernetes.labels["app"] + "-logs"
 *   3. kubernetes.labels["app.kubernetes.io/name"] + "-logs"
 *   4. kubernetes.namespace_name + "-logs"
 *   5. "_parseable_dataset" field (legacy/Lua-set)
 *   6. NULL (use configured dataset)
 *
 * Also checks kubernetes.annotations["parseable/exclude"] to drop records.
 * Returns a newly allocated flb_sds_t or NULL if not found.
 * Sets *exclude to 1 if record should be excluded.
 */
static flb_sds_t extract_dynamic_stream(struct flb_out_parseable *ctx,
                                         const void *data, size_t bytes,
                                         int *exclude)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *kubernetes;
    msgpack_object *annotations;
    msgpack_object *labels;
    msgpack_object *val;
    flb_sds_t stream = NULL;
    
    *exclude = 0;
    msgpack_unpacked_init(&result);
    
    /* Iterate through records */
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        
        /* Each record is an array: [timestamp, map] */
        if (root.type != MSGPACK_OBJECT_ARRAY || root.via.array.size < 2) {
            continue;
        }
        
        map = root.via.array.ptr[1];
        if (map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }
        
        /* 1. Check for legacy _parseable_dataset field first */
        val = find_map_str_value(&map, "_parseable_dataset", 18);
        if (val) {
            stream = get_str_value(val);
            if (stream) {
                flb_plg_info(ctx->ins, "Using _parseable_dataset: %s", stream);
                msgpack_unpacked_destroy(&result);
                return stream;
            }
        }
        
        /* 2. Look for kubernetes metadata */
        kubernetes = find_map_str_value(&map, "kubernetes", 10);
        if (!kubernetes || kubernetes->type != MSGPACK_OBJECT_MAP) {
            /* No kubernetes metadata, check next record */
            break;
        }
        
        /* 3. Check annotations for parseable/exclude */
        annotations = find_map_str_value(kubernetes, "annotations", 11);
        if (annotations && annotations->type == MSGPACK_OBJECT_MAP) {
            val = find_map_str_value(annotations, "parseable/exclude", 17);
            if (val && val->type == MSGPACK_OBJECT_STR) {
                if (val->via.str.size == 4 && 
                    strncmp(val->via.str.ptr, "true", 4) == 0) {
                    flb_plg_debug(ctx->ins, "Record excluded via parseable/exclude annotation");
                    *exclude = 1;
                    msgpack_unpacked_destroy(&result);
                    return NULL;
                }
            }
            
            /* 4. Check annotations for parseable/dataset */
            val = find_map_str_value(annotations, "parseable/dataset", 17);
            if (val) {
                stream = get_str_value(val);
                if (stream) {
                    flb_plg_info(ctx->ins, "Using annotation parseable/dataset: %s", stream);
                    msgpack_unpacked_destroy(&result);
                    return stream;
                }
            }
        }
        
        /* 5. Try to derive stream from labels */
        labels = find_map_str_value(kubernetes, "labels", 6);
        if (labels && labels->type == MSGPACK_OBJECT_MAP) {
            /* Try "app" label first */
            val = find_map_str_value(labels, "app", 3);
            if (val) {
                flb_sds_t app = get_str_value(val);
                if (app) {
                    stream = flb_sds_create_size(flb_sds_len(app) + 6);
                    flb_sds_cat_safe(&stream, app, flb_sds_len(app));
                    flb_sds_cat_safe(&stream, "-logs", 5);
                    flb_plg_info(ctx->ins, "Derived stream from app label: %s", stream);
                    flb_sds_destroy(app);
                    msgpack_unpacked_destroy(&result);
                    return stream;
                }
            }
            
            /* Try "app.kubernetes.io/name" label */
            val = find_map_str_value(labels, "app.kubernetes.io/name", 22);
            if (val) {
                flb_sds_t app = get_str_value(val);
                if (app) {
                    stream = flb_sds_create_size(flb_sds_len(app) + 6);
                    flb_sds_cat_safe(&stream, app, flb_sds_len(app));
                    flb_sds_cat_safe(&stream, "-logs", 5);
                    flb_plg_info(ctx->ins, "Derived stream from app.kubernetes.io/name label: %s", stream);
                    flb_sds_destroy(app);
                    msgpack_unpacked_destroy(&result);
                    return stream;
                }
            }
        }
        
        /* 6. Fall back to namespace_name */
        val = find_map_str_value(kubernetes, "namespace_name", 14);
        if (val) {
            flb_sds_t ns = get_str_value(val);
            if (ns) {
                stream = flb_sds_create_size(flb_sds_len(ns) + 6);
                flb_sds_cat_safe(&stream, ns, flb_sds_len(ns));
                flb_sds_cat_safe(&stream, "-logs", 5);
                flb_plg_info(ctx->ins, "Derived stream from namespace: %s", stream);
                flb_sds_destroy(ns);
                msgpack_unpacked_destroy(&result);
                return stream;
            }
        }
        
        /* Only check first record */
        break;
    }
    
    msgpack_unpacked_destroy(&result);
    return NULL;
}

/*
 * Extract dynamic stream from tag (for rewrite_tag filter).
 * Tag format: parseable.<stream_name>
 * Returns a newly allocated flb_sds_t or NULL if not matching.
 */
static flb_sds_t extract_stream_from_tag(struct flb_out_parseable *ctx,
                                          const char *tag, int tag_len)
{
    const char *prefix = "parseable.";
    size_t prefix_len = 10;
    
    if (tag_len > prefix_len && strncmp(tag, prefix, prefix_len) == 0) {
        flb_sds_t stream = flb_sds_create_len(tag + prefix_len, tag_len - prefix_len);
        flb_plg_debug(ctx->ins, "Extracted stream from tag: %s", stream);
        return stream;
    }
    
    return NULL;
}

/*
 * Structure to hold extracted Kubernetes metadata for enrichment.
 */
struct k8s_metadata {
    flb_sds_t namespace_name;
    flb_sds_t pod_name;
    flb_sds_t container_name;
    flb_sds_t host;
    flb_sds_t env;
    flb_sds_t service;
    flb_sds_t version;
};

/*
 * Initialize k8s_metadata structure.
 */
static void k8s_metadata_init(struct k8s_metadata *meta)
{
    meta->namespace_name = NULL;
    meta->pod_name = NULL;
    meta->container_name = NULL;
    meta->host = NULL;
    meta->env = NULL;
    meta->service = NULL;
    meta->version = NULL;
}

/*
 * Destroy k8s_metadata structure and free all strings.
 */
static void k8s_metadata_destroy(struct k8s_metadata *meta)
{
    if (meta->namespace_name) flb_sds_destroy(meta->namespace_name);
    if (meta->pod_name) flb_sds_destroy(meta->pod_name);
    if (meta->container_name) flb_sds_destroy(meta->container_name);
    if (meta->host) flb_sds_destroy(meta->host);
    if (meta->env) flb_sds_destroy(meta->env);
    if (meta->service) flb_sds_destroy(meta->service);
    if (meta->version) flb_sds_destroy(meta->version);
}

/*
 * Extract Kubernetes metadata from a record for enrichment.
 * Extracts: namespace_name, pod_name, container_name, host
 * Also extracts unified service tags from annotations/labels:
 *   - parseable/env or labels[environment/env]
 *   - parseable/service or labels[app/app.kubernetes.io/name]
 *   - parseable/version or labels[version/app.kubernetes.io/version]
 */
static int extract_k8s_metadata(msgpack_object *map, struct k8s_metadata *meta)
{
    msgpack_object *kubernetes;
    msgpack_object *annotations;
    msgpack_object *labels;
    msgpack_object *val;
    
    k8s_metadata_init(meta);
    
    /* Find kubernetes object */
    kubernetes = find_map_str_value(map, "kubernetes", 10);
    if (!kubernetes || kubernetes->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }
    
    /* Extract basic K8s fields */
    val = find_map_str_value(kubernetes, "namespace_name", 14);
    if (val) meta->namespace_name = get_str_value(val);
    
    val = find_map_str_value(kubernetes, "pod_name", 8);
    if (val) meta->pod_name = get_str_value(val);
    
    val = find_map_str_value(kubernetes, "container_name", 14);
    if (val) meta->container_name = get_str_value(val);
    
    val = find_map_str_value(kubernetes, "host", 4);
    if (val) meta->host = get_str_value(val);
    
    /* Get annotations and labels */
    annotations = find_map_str_value(kubernetes, "annotations", 11);
    labels = find_map_str_value(kubernetes, "labels", 6);
    
    /* Extract env: parseable/env annotation or environment/env label */
    if (annotations && annotations->type == MSGPACK_OBJECT_MAP) {
        val = find_map_str_value(annotations, "parseable/env", 13);
        if (val) meta->env = get_str_value(val);
    }
    if (!meta->env && labels && labels->type == MSGPACK_OBJECT_MAP) {
        val = find_map_str_value(labels, "environment", 11);
        if (val) meta->env = get_str_value(val);
        if (!meta->env) {
            val = find_map_str_value(labels, "env", 3);
            if (val) meta->env = get_str_value(val);
        }
    }
    
    /* Extract service: parseable/service annotation or app label */
    if (annotations && annotations->type == MSGPACK_OBJECT_MAP) {
        val = find_map_str_value(annotations, "parseable/service", 17);
        if (val) meta->service = get_str_value(val);
    }
    if (!meta->service && labels && labels->type == MSGPACK_OBJECT_MAP) {
        val = find_map_str_value(labels, "app", 3);
        if (val) meta->service = get_str_value(val);
        if (!meta->service) {
            val = find_map_str_value(labels, "app.kubernetes.io/name", 22);
            if (val) meta->service = get_str_value(val);
        }
    }
    
    /* Extract version: parseable/version annotation or version label */
    if (annotations && annotations->type == MSGPACK_OBJECT_MAP) {
        val = find_map_str_value(annotations, "parseable/version", 17);
        if (val) meta->version = get_str_value(val);
    }
    if (!meta->version && labels && labels->type == MSGPACK_OBJECT_MAP) {
        val = find_map_str_value(labels, "version", 7);
        if (val) meta->version = get_str_value(val);
        if (!meta->version) {
            val = find_map_str_value(labels, "app.kubernetes.io/version", 25);
            if (val) meta->version = get_str_value(val);
        }
    }
    
    return 0;
}

/*
 * Pack a msgpack map with additional K8s enrichment fields.
 * This creates a new msgpack buffer with the original fields plus:
 *   - k8s_namespace, k8s_pod, k8s_container, k8s_node
 *   - environment, service, version (if available)
 */
static int enrich_record_with_k8s(struct flb_out_parseable *ctx,
                                   msgpack_object *timestamp,
                                   msgpack_object *map,
                                   struct k8s_metadata *meta,
                                   msgpack_sbuffer *sbuf,
                                   msgpack_packer *pk)
{
    int i;
    int extra_fields = 0;
    
    /* Count extra fields to add */
    if (meta->namespace_name) extra_fields++;
    if (meta->pod_name) extra_fields++;
    if (meta->container_name) extra_fields++;
    if (meta->host) extra_fields++;
    if (meta->env) extra_fields++;
    if (meta->service) extra_fields++;
    if (meta->version) extra_fields++;
    
    /* Pack array: [timestamp, map] */
    msgpack_pack_array(pk, 2);
    
    /* Pack timestamp */
    if (timestamp->type == MSGPACK_OBJECT_EXT) {
        msgpack_pack_ext(pk, timestamp->via.ext.size, timestamp->via.ext.type);
        msgpack_pack_ext_body(pk, timestamp->via.ext.ptr, timestamp->via.ext.size);
    } else {
        msgpack_pack_object(pk, *timestamp);
    }
    
    /* Pack map with extra fields */
    msgpack_pack_map(pk, map->via.map.size + extra_fields);
    
    /* Copy original fields */
    for (i = 0; i < map->via.map.size; i++) {
        msgpack_pack_object(pk, map->via.map.ptr[i].key);
        msgpack_pack_object(pk, map->via.map.ptr[i].val);
    }
    
    /* Add K8s context fields */
    if (meta->namespace_name) {
        msgpack_pack_str(pk, 13);
        msgpack_pack_str_body(pk, "k8s_namespace", 13);
        msgpack_pack_str(pk, flb_sds_len(meta->namespace_name));
        msgpack_pack_str_body(pk, meta->namespace_name, flb_sds_len(meta->namespace_name));
    }
    if (meta->pod_name) {
        msgpack_pack_str(pk, 7);
        msgpack_pack_str_body(pk, "k8s_pod", 7);
        msgpack_pack_str(pk, flb_sds_len(meta->pod_name));
        msgpack_pack_str_body(pk, meta->pod_name, flb_sds_len(meta->pod_name));
    }
    if (meta->container_name) {
        msgpack_pack_str(pk, 13);
        msgpack_pack_str_body(pk, "k8s_container", 13);
        msgpack_pack_str(pk, flb_sds_len(meta->container_name));
        msgpack_pack_str_body(pk, meta->container_name, flb_sds_len(meta->container_name));
    }
    if (meta->host) {
        msgpack_pack_str(pk, 8);
        msgpack_pack_str_body(pk, "k8s_node", 8);
        msgpack_pack_str(pk, flb_sds_len(meta->host));
        msgpack_pack_str_body(pk, meta->host, flb_sds_len(meta->host));
    }
    
    /* Add unified service tags */
    if (meta->env) {
        msgpack_pack_str(pk, 11);
        msgpack_pack_str_body(pk, "environment", 11);
        msgpack_pack_str(pk, flb_sds_len(meta->env));
        msgpack_pack_str_body(pk, meta->env, flb_sds_len(meta->env));
    }
    if (meta->service) {
        msgpack_pack_str(pk, 7);
        msgpack_pack_str_body(pk, "service", 7);
        msgpack_pack_str(pk, flb_sds_len(meta->service));
        msgpack_pack_str_body(pk, meta->service, flb_sds_len(meta->service));
    }
    if (meta->version) {
        msgpack_pack_str(pk, 7);
        msgpack_pack_str_body(pk, "version", 7);
        msgpack_pack_str(pk, flb_sds_len(meta->version));
        msgpack_pack_str_body(pk, meta->version, flb_sds_len(meta->version));
    }
    
    return 0;
}

/*
 * Enrich all records in a msgpack buffer with Kubernetes metadata.
 * Returns a new msgpack buffer with enriched records.
 */
static int enrich_records_k8s(struct flb_out_parseable *ctx,
                               const void *data, size_t bytes,
                               void **out_data, size_t *out_bytes)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    struct k8s_metadata meta;
    int enriched = 0;
    
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);
    
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        
        /* Each record is an array: [timestamp, map] */
        if (root.type != MSGPACK_OBJECT_ARRAY || root.via.array.size < 2) {
            /* Pass through as-is */
            msgpack_pack_object(&pk, root);
            continue;
        }
        
        msgpack_object *timestamp = &root.via.array.ptr[0];
        msgpack_object *map = &root.via.array.ptr[1];
        
        if (map->type != MSGPACK_OBJECT_MAP) {
            msgpack_pack_object(&pk, root);
            continue;
        }
        
        /* Try to extract K8s metadata */
        if (extract_k8s_metadata(map, &meta) == 0) {
            /* Enrich the record */
            enrich_record_with_k8s(ctx, timestamp, map, &meta, &sbuf, &pk);
            k8s_metadata_destroy(&meta);
            enriched++;
        } else {
            /* No K8s metadata, pass through as-is */
            msgpack_pack_object(&pk, root);
        }
    }
    
    msgpack_unpacked_destroy(&result);
    
    if (enriched > 0) {
        flb_plg_debug(ctx->ins, "Enriched %d records with K8s metadata", enriched);
    }
    
    /* Return the new buffer */
    *out_data = sbuf.data;
    *out_bytes = sbuf.size;
    
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "stream", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, stream),
     "Parseable stream name (required, sent as X-P-Stream header)"
    },
    {
     FLB_CONFIG_MAP_STR, "log_source", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, log_source),
     "Parseable log source (optional, sent as X-P-Log-Source header)"
    },
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, uri),
     "URI path for Parseable ingestion endpoint (auto-set based on data_type if not specified)"
    },
    {
     FLB_CONFIG_MAP_STR, "data_type", "logs",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, data_type),
     "Data type: logs, metrics, or traces (determines endpoint: /v1/logs, /v1/metrics, /v1/traces)"
    },
    {
     FLB_CONFIG_MAP_STR, "auth_header", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, auth_header),
     "Authorization header value (e.g., 'Basic base64(user:pass)')"
    },
    {
     FLB_CONFIG_MAP_INT, "json_date_format", "0",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, json_date_format),
     "JSON date format: 0=epoch, 1=iso8601, 2=java_sql_timestamp"
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", FLB_PARSEABLE_DEFAULT_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, date_key),
     "Key name for timestamp in JSON output"
    },
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Enable payload compression. Option: gzip"
    },
    {
     FLB_CONFIG_MAP_SIZE, "batch_size", "5242880",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, batch_size),
     "Maximum batch size in bytes (default: 5MB)"
    },
    {
     FLB_CONFIG_MAP_INT, "retry_limit", "-1",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, retry_limit),
     "Maximum number of retries (-1 = unlimited, 0 = no retries)"
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_parseable, headers),
     "Add custom HTTP header. Multiple headers can be set"
    },
    {
     FLB_CONFIG_MAP_BOOL, "dynamic_stream", "false",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, dynamic_stream),
     "Enable dynamic stream routing from record metadata (_parseable_dataset field)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "enrich_kubernetes", "false",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, enrich_kubernetes),
     "Enable Kubernetes metadata enrichment (adds k8s_namespace, k8s_pod, k8s_container, k8s_node, environment, service, version)"
    },
    
    /* EOF */
    {0}
};

static int cb_parseable_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    int ret;
    int io_flags = 0;
    const char *tmp;
    struct flb_out_parseable *ctx;
    (void) data;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_parseable));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* Set default network configuration */
    flb_output_net_default(FLB_PARSEABLE_DEFAULT_HOST, 
                          FLB_PARSEABLE_DEFAULT_PORT, ins);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    /* Validate required configuration */
    if (!ctx->stream) {
        flb_plg_error(ins, "'stream' configuration is required");
        flb_free(ctx);
        return -1;
    }

    /* Auto-set URI based on data_type if not explicitly provided */
    if (!ctx->uri) {
        if (ctx->data_type) {
            if (strcasecmp(ctx->data_type, "metrics") == 0 ||
                strcasecmp(ctx->data_type, "otel-metric") == 0 ||
                strcasecmp(ctx->data_type, "otel-metrics") == 0) {
                /* Metrics use /v1/metrics for OTEL format */
                ctx->uri = flb_sds_create("/v1/metrics");
                flb_plg_info(ins, "auto-set URI to /v1/metrics for metrics data");
            }
            else if (strcasecmp(ctx->data_type, "traces") == 0 || 
                     strcasecmp(ctx->data_type, "otel-trace") == 0 ||
                     strcasecmp(ctx->data_type, "otel-traces") == 0) {
                ctx->uri = flb_sds_create("/v1/traces");
                flb_plg_info(ins, "auto-set URI to /v1/traces for traces data");
            }
            else {
                /* Logs use /v1/logs for OTEL format */
                ctx->uri = flb_sds_create("/v1/logs");
                flb_plg_info(ins, "auto-set URI to /v1/logs for logs data");
            }
        }
        else {
            /* Default to logs endpoint */
            ctx->uri = flb_sds_create("/v1/logs");
            flb_plg_info(ins, "using default URI /v1/logs");
        }
    }
    else {
        flb_plg_info(ins, "using configured URI: %s", ctx->uri);
    }

    /* Compression configuration */
    ctx->compress_gzip = FLB_FALSE;
    tmp = flb_output_get_property("compress", ins);
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
            flb_plg_info(ins, "gzip compression enabled");
        }
    }

    /* Set up TLS if enabled */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create upstream connection */
    ctx->u = flb_upstream_create(config,
                                 ins->host.name,
                                 ins->host.port,
                                 io_flags,
                                 ins->tls);
    if (!ctx->u) {
        flb_plg_error(ins, "cannot create upstream connection to %s:%d",
                      ins->host.name, ins->host.port);
        flb_free(ctx);
        return -1;
    }

    /* Set upstream properties */
    flb_output_upstream_set(ctx->u, ins);

    /* Initialize metrics */
    ctx->cmt_requests_total = cmt_counter_create(ins->cmt, "parseable", "requests",
                                                  "total", "Total number of HTTP requests",
                                                  1, (char *[]) {"status"});
    
    ctx->cmt_errors_total = cmt_counter_create(ins->cmt, "parseable", "errors",
                                                "total", "Total number of errors",
                                                1, (char *[]) {"type"});
    
    ctx->cmt_records_total = cmt_counter_create(ins->cmt, "parseable", "records",
                                                 "total", "Total number of records sent",
                                                 0, NULL);
    
    ctx->cmt_bytes_total = cmt_counter_create(ins->cmt, "parseable", "bytes",
                                               "total", "Total bytes sent (after compression)",
                                               0, NULL);
    
    ctx->cmt_batch_size_bytes = cmt_gauge_create(ins->cmt, "parseable", "batch_size",
                                                  "bytes", "Current batch size in bytes",
                                                  0, NULL);

    /* Set plugin context */
    flb_output_set_context(ins, ctx);

    /* Register HTTP debug callbacks */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins, "initialized: host=%s port=%d stream=%s uri=%s batch_size=%zu compress=%s",
                 ins->host.name, ins->host.port, ctx->stream, ctx->uri,
                 ctx->batch_size, ctx->compress_gzip ? "gzip" : "none");

    return 0;
}

static flb_sds_t escape_json_string(flb_sds_t dest, const char *str, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        char c = str[i];
        if (c == '"') {
            dest = flb_sds_cat(dest, "\\\"", 2);
        } else if (c == '\\') {
            dest = flb_sds_cat(dest, "\\\\", 2);
        } else if (c == '\n') {
            dest = flb_sds_cat(dest, "\\n", 2);
        } else if (c == '\r') {
            dest = flb_sds_cat(dest, "\\r", 2);
        } else if (c == '\t') {
            dest = flb_sds_cat(dest, "\\t", 2);
        } else if (c < 32) {
            /* Skip other control characters */
            continue;
        } else {
            dest = flb_sds_cat(dest, &c, 1);
        }
    }
    return dest;
}

/* Helper to add flattened attributes from nested msgpack objects */
static flb_sds_t add_flattened_attributes(flb_sds_t dest, const char *prefix, 
                                          msgpack_object *obj, int *attr_count)
{
    size_t i;
    msgpack_object_kv *kv;
    flb_sds_t tmp;
    flb_sds_t key_name;
    
    if (obj->type == MSGPACK_OBJECT_MAP) {
        for (i = 0; i < obj->via.map.size; i++) {
            kv = &obj->via.map.ptr[i];
            
            if (kv->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            
            /* Build the flattened key name with dot notation */
            if (prefix && strlen(prefix) > 0) {
                key_name = flb_sds_create_size(strlen(prefix) + kv->key.via.str.size + 2);
                key_name = flb_sds_cat(key_name, prefix, strlen(prefix));
                key_name = flb_sds_cat(key_name, ".", 1);
                key_name = flb_sds_cat(key_name, kv->key.via.str.ptr, kv->key.via.str.size);
            } else {
                key_name = flb_sds_create_len(kv->key.via.str.ptr, kv->key.via.str.size);
            }
            
            /* If value is a nested map, recurse */
            if (kv->val.type == MSGPACK_OBJECT_MAP) {
                dest = add_flattened_attributes(dest, key_name, &kv->val, attr_count);
                flb_sds_destroy(key_name);
            }
            /* If value is an array, convert to JSON string */
            else if (kv->val.type == MSGPACK_OBJECT_ARRAY) {
                if (*attr_count > 0) {
                    dest = flb_sds_cat(dest, ",", 1);
                }
                
                dest = flb_sds_cat(dest, "{\"key\":\"", 8);
                dest = escape_json_string(dest, key_name, flb_sds_len(key_name));
                dest = flb_sds_cat(dest, "\",\"value\":{\"stringValue\":\"[", 28);
                
                /* Simple array representation */
                for (size_t j = 0; j < kv->val.via.array.size; j++) {
                    if (j > 0) dest = flb_sds_cat(dest, ",", 1);
                    msgpack_object *item = &kv->val.via.array.ptr[j];
                    if (item->type == MSGPACK_OBJECT_STR) {
                        dest = escape_json_string(dest, item->via.str.ptr, item->via.str.size);
                    } else if (item->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                        tmp = flb_sds_printf(&dest, "%llu", (unsigned long long)item->via.u64);
                    } else if (item->type == MSGPACK_OBJECT_FLOAT || item->type == MSGPACK_OBJECT_FLOAT32) {
                        tmp = flb_sds_printf(&dest, "%f", item->via.f64);
                    }
                }
                
                dest = flb_sds_cat(dest, "]\"}}", 4);
                (*attr_count)++;
                flb_sds_destroy(key_name);
            }
            /* Simple value types */
            else {
                if (*attr_count > 0) {
                    dest = flb_sds_cat(dest, ",", 1);
                }
                
                dest = flb_sds_cat(dest, "{\"key\":\"", 8);
                dest = escape_json_string(dest, key_name, flb_sds_len(key_name));
                dest = flb_sds_cat(dest, "\",\"value\":{", 11);
                
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    dest = flb_sds_cat(dest, "\"stringValue\":\"", 15);
                    dest = escape_json_string(dest, kv->val.via.str.ptr, kv->val.via.str.size);
                    dest = flb_sds_cat(dest, "\"", 1);
                }
                else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    tmp = flb_sds_printf(&dest, "\"intValue\":%llu", 
                                        (unsigned long long)kv->val.via.u64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    tmp = flb_sds_printf(&dest, "\"intValue\":%lld", 
                                        (long long)kv->val.via.i64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_FLOAT || kv->val.type == MSGPACK_OBJECT_FLOAT32) {
                    tmp = flb_sds_printf(&dest, "\"doubleValue\":%f", kv->val.via.f64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_BOOLEAN) {
                    dest = flb_sds_cat(dest, "\"stringValue\":\"", 15);
                    if (kv->val.via.boolean) {
                        dest = flb_sds_cat(dest, "true", 4);
                    } else {
                        dest = flb_sds_cat(dest, "false", 5);
                    }
                    dest = flb_sds_cat(dest, "\"", 1);
                }
                else {
                    dest = flb_sds_cat(dest, "\"stringValue\":\"\"", 17);
                }
                
                dest = flb_sds_cat(dest, "}}", 2);
                (*attr_count)++;
                flb_sds_destroy(key_name);
            }
        }
    }
    
    return dest;
}

static int parseable_format_json_to_otel(struct flb_out_parseable *ctx,
                                          const void *data, size_t bytes,
                                          void **out_buf, size_t *out_size,
                                          struct flb_config *config)
{
    int ret;
    flb_sds_t otel_json;
    flb_sds_t tmp;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    msgpack_object *map;
    msgpack_object_kv *kv;
    int i;
    int is_metrics = 0;
    int is_traces = 0;
    char time_str[64];
    struct tm tm;
    time_t t;

    /* Check data type */
    if (ctx->data_type && (strcasecmp(ctx->data_type, "metrics") == 0 ||
                           strcasecmp(ctx->data_type, "otel-metric") == 0 ||
                           strcasecmp(ctx->data_type, "otel-metrics") == 0)) {
        is_metrics = 1;
    }
    else if (ctx->data_type && (strcasecmp(ctx->data_type, "traces") == 0 ||
                                 strcasecmp(ctx->data_type, "otel-trace") == 0 ||
                                 strcasecmp(ctx->data_type, "otel-traces") == 0)) {
        is_traces = 1;
    }

    /* Check if data is already in OTLP format (contains resourceSpans, resourceMetrics, etc.) */
    /* This happens when data comes from HTTP input with OTLP JSON */
    /* For OTEL-trace/OTEL-metric types, skip the OTEL formatting if data already has the structure */
    if (is_traces || is_metrics) {
        ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
        if (ret == FLB_EVENT_DECODER_SUCCESS) {
            /* Try to decode first event to check if it has OTLP structure */
            if (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
                map = log_event.body;
                if (map && map->type == MSGPACK_OBJECT_MAP) {
                    /* Check for OTLP structure markers */
                    for (i = 0; i < map->via.map.size; i++) {
                        kv = &map->via.map.ptr[i];
                        if (kv->key.type == MSGPACK_OBJECT_STR && kv->key.via.str.size >= 12) {
                            if (strncmp(kv->key.via.str.ptr, "resourceSpans", 13) == 0 ||
                                strncmp(kv->key.via.str.ptr, "resourceMetrics", 15) == 0 ||
                                strncmp(kv->key.via.str.ptr, "resourceLogs", 12) == 0) {
                                /* Data is already in OTLP format, pass it through as-is */
                                flb_plg_info(ctx->ins, "Data already in OTLP format, passing through");
                                flb_log_event_decoder_destroy(&log_decoder);
                                
                                /* Convert msgpack to JSON directly without OTEL formatting */
                                return parseable_format_json(ctx, data, bytes, out_buf, out_size, config);
                            }
                        }
                    }
                }
            }
            flb_log_event_decoder_destroy(&log_decoder);
        }
    }

    /* Initialize log decoder for normal processing */
    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "failed to initialize log event decoder");
        return -1;
    }

    /* Extract resource attributes from first record */
    flb_sds_t resource_attrs = flb_sds_create("{\"attributes\":[");
    int resource_attr_count = 0;
    msgpack_object *resource_map = NULL;
    
    if (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        map = log_event.body;
        if (map->type == MSGPACK_OBJECT_MAP) {
            /* First check if there's a 'resource' field with 'attributes' */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    strncmp(kv->key.via.str.ptr, "resource", 8) == 0 &&
                    kv->key.via.str.size == 8 &&
                    kv->val.type == MSGPACK_OBJECT_MAP) {
                    
                    /* Look for 'attributes' inside resource */
                    for (size_t j = 0; j < kv->val.via.map.size; j++) {
                        msgpack_object_kv *res_kv = &kv->val.via.map.ptr[j];
                        if (res_kv->key.type == MSGPACK_OBJECT_STR &&
                            strncmp(res_kv->key.via.str.ptr, "attributes", 10) == 0 &&
                            res_kv->key.via.str.size == 10 &&
                            res_kv->val.type == MSGPACK_OBJECT_MAP) {
                            resource_map = &res_kv->val;
                            break;
                        }
                    }
                    break;
                }
            }
            
            /* If resource.attributes found, use it; otherwise extract common fields */
            if (resource_map) {
                /* Use the resource.attributes map directly */
                for (i = 0; i < resource_map->via.map.size; i++) {
                    kv = &resource_map->via.map.ptr[i];
                    if (kv->key.type != MSGPACK_OBJECT_STR) continue;
                    
                    if (resource_attr_count > 0) {
                        resource_attrs = flb_sds_cat(resource_attrs, ",", 1);
                    }
                    
                    resource_attrs = flb_sds_cat(resource_attrs, "{\"key\":\"", 8);
                    resource_attrs = escape_json_string(resource_attrs, kv->key.via.str.ptr, kv->key.via.str.size);
                    resource_attrs = flb_sds_cat(resource_attrs, "\",\"value\":{", 11);
                    
                    if (kv->val.type == MSGPACK_OBJECT_STR) {
                        resource_attrs = flb_sds_cat(resource_attrs, "\"stringValue\":\"", 15);
                        resource_attrs = escape_json_string(resource_attrs, kv->val.via.str.ptr, kv->val.via.str.size);
                        resource_attrs = flb_sds_cat(resource_attrs, "\"", 1);
                    }
                    else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                        flb_sds_t tmp = flb_sds_printf(&resource_attrs, "\"intValue\":%llu", 
                                                      (unsigned long long)kv->val.via.u64);
                    }
                    else {
                        resource_attrs = flb_sds_cat(resource_attrs, "\"stringValue\":\"\"", 17);
                    }
                    
                    resource_attrs = flb_sds_cat(resource_attrs, "}}", 2);
                    resource_attr_count++;
                }
            }
            else {
                /* Fallback: extract common service-level fields */
                const char *resource_keys[] = {"service", "environment", "cluster", "hostname"};
                for (size_t rk = 0; rk < sizeof(resource_keys)/sizeof(resource_keys[0]); rk++) {
                    for (i = 0; i < map->via.map.size; i++) {
                        kv = &map->via.map.ptr[i];
                        if (kv->key.type == MSGPACK_OBJECT_STR &&
                            strncmp(kv->key.via.str.ptr, resource_keys[rk], strlen(resource_keys[rk])) == 0 &&
                            kv->key.via.str.size == strlen(resource_keys[rk])) {
                            
                            if (resource_attr_count > 0) {
                                resource_attrs = flb_sds_cat(resource_attrs, ",", 1);
                            }
                            
                            resource_attrs = flb_sds_cat(resource_attrs, "{\"key\":\"", 8);
                            if (strcmp(resource_keys[rk], "service") == 0) {
                                resource_attrs = flb_sds_cat(resource_attrs, "service.name", 12);
                            } else {
                                resource_attrs = flb_sds_cat(resource_attrs, resource_keys[rk], strlen(resource_keys[rk]));
                            }
                            resource_attrs = flb_sds_cat(resource_attrs, "\",\"value\":{\"stringValue\":\"", 28);
                            
                            if (kv->val.type == MSGPACK_OBJECT_STR) {
                                resource_attrs = escape_json_string(resource_attrs, kv->val.via.str.ptr, kv->val.via.str.size);
                            }
                            resource_attrs = flb_sds_cat(resource_attrs, "\"}}", 3);
                            resource_attr_count++;
                            break;
                        }
                    }
                }
            }
        }
    }
    resource_attrs = flb_sds_cat(resource_attrs, "]}", 2);
    
    /* Reset decoder to process all records */
    flb_log_event_decoder_destroy(&log_decoder);
    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "failed to re-initialize log event decoder");
        flb_sds_destroy(resource_attrs);
        return -1;
    }

    /* Start OTEL format with resource attributes */
    if (is_metrics) {
        otel_json = flb_sds_create_size(256);
        otel_json = flb_sds_cat(otel_json, "{\"resourceMetrics\":[{\"resource\":", 35);
        otel_json = flb_sds_cat(otel_json, resource_attrs, flb_sds_len(resource_attrs));
        otel_json = flb_sds_cat(otel_json, ",\"scopeMetrics\":[{\"scope\":{\"name\":\"fluent-bit\"},\"metrics\":[", 62);
    }
    else if (is_traces) {
        otel_json = flb_sds_create_size(256);
        otel_json = flb_sds_cat(otel_json, "{\"resourceSpans\":[{\"resource\":", 32);
        otel_json = flb_sds_cat(otel_json, resource_attrs, flb_sds_len(resource_attrs));
        otel_json = flb_sds_cat(otel_json, ",\"scopeSpans\":[{\"scope\":{\"name\":\"fluent-bit\"},\"spans\":[", 59);
    }
    else {
        otel_json = flb_sds_create_size(256);
        otel_json = flb_sds_cat(otel_json, "{\"resourceLogs\":[{\"resource\":", 30);
        otel_json = flb_sds_cat(otel_json, resource_attrs, flb_sds_len(resource_attrs));
        otel_json = flb_sds_cat(otel_json, ",\"scopeLogs\":[{\"scope\":{\"name\":\"fluent-bit\"},\"logRecords\":[", 62);
    }
    
    flb_sds_destroy(resource_attrs);

    if (!otel_json) {
        flb_log_event_decoder_destroy(&log_decoder);
        return -1;
    }

    int record_count = 0;
    /* Process each record */
    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        if (record_count > 0) {
            otel_json = flb_sds_cat(otel_json, ",", 1);
        }

        map = log_event.body;
        if (map->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* Convert timestamp to nanoseconds */
        uint64_t time_nano = (uint64_t)(log_event.timestamp.tm.tv_sec) * 1000000000ULL + 
                             (uint64_t)(log_event.timestamp.tm.tv_nsec);

        if (is_metrics) {
            /* OTEL Metrics format */
            tmp = flb_sds_printf(&otel_json, "{\"name\":\"");
            
            /* Extract metric_name if present */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    strncmp(kv->key.via.str.ptr, "metric_name", 11) == 0 &&
                    kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    break;
                }
            }
            if (i >= map->via.map.size) {
                otel_json = flb_sds_cat(otel_json, "unknown", 7);
            }

            tmp = flb_sds_printf(&otel_json, "\",\"gauge\":{\"dataPoints\":[{\"timeUnixNano\":\"%llu\",\"attributes\":[", 
                                (unsigned long long)time_nano);

            /* Add all fields as attributes */
            int attr_count = 0;
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type != MSGPACK_OBJECT_STR) continue;

                /* Skip internal metric fields and resource-level attributes */
                if (strncmp(kv->key.via.str.ptr, "metric_", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "date", 4) == 0 ||
                    strncmp(kv->key.via.str.ptr, "service", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "environment", 11) == 0 ||
                    strncmp(kv->key.via.str.ptr, "cluster", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "hostname", 8) == 0) {
                    continue;
                }

                /* Handle nested maps separately - flatten them */
                if (kv->val.type == MSGPACK_OBJECT_MAP) {
                    char prefix[256];
                    snprintf(prefix, sizeof(prefix), "%.*s", (int)kv->key.via.str.size, kv->key.via.str.ptr);
                    otel_json = add_flattened_attributes(otel_json, prefix, &kv->val, &attr_count);
                    continue;
                }

                if (attr_count > 0) {
                    otel_json = flb_sds_cat(otel_json, ",", 1);
                }

                otel_json = flb_sds_cat(otel_json, "{\"key\":\"", 8);
                otel_json = escape_json_string(otel_json, kv->key.via.str.ptr, kv->key.via.str.size);
                otel_json = flb_sds_cat(otel_json, "\",\"value\":{", 11);

                /* Add value based on type */
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"", 15);
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    otel_json = flb_sds_cat(otel_json, "\"", 1);
                }
                else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    tmp = flb_sds_printf(&otel_json, "\"intValue\":%llu", 
                                        (unsigned long long)kv->val.via.u64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_FLOAT || kv->val.type == MSGPACK_OBJECT_FLOAT32) {
                    tmp = flb_sds_printf(&otel_json, "\"doubleValue\":%f", kv->val.via.f64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_BOOLEAN) {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"", 15);
                    if (kv->val.via.boolean) {
                        otel_json = flb_sds_cat(otel_json, "true", 4);
                    } else {
                        otel_json = flb_sds_cat(otel_json, "false", 5);
                    }
                    otel_json = flb_sds_cat(otel_json, "\"", 1);
                }
                else if (kv->val.type == MSGPACK_OBJECT_ARRAY) {
                    /* Convert array to simple string representation */
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"[", 16);
                    for (size_t j = 0; j < kv->val.via.array.size; j++) {
                        if (j > 0) otel_json = flb_sds_cat(otel_json, ",", 1);
                        msgpack_object *item = &kv->val.via.array.ptr[j];
                        if (item->type == MSGPACK_OBJECT_STR) {
                            otel_json = escape_json_string(otel_json, item->via.str.ptr, item->via.str.size);
                        } else if (item->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            tmp = flb_sds_printf(&otel_json, "%llu", (unsigned long long)item->via.u64);
                        } else if (item->type == MSGPACK_OBJECT_FLOAT || item->type == MSGPACK_OBJECT_FLOAT32) {
                            tmp = flb_sds_printf(&otel_json, "%f", item->via.f64);
                        }
                    }
                    otel_json = flb_sds_cat(otel_json, "]\"", 2);
                }
                else {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"\"", 17);
                }

                otel_json = flb_sds_cat(otel_json, "}}", 2);
                attr_count++;
            }

            /* Close attributes array, add gauge value, close dataPoint, dataPoints, gauge, and metric */
            otel_json = flb_sds_cat(otel_json, "],\"data_point_value\":0.0}]}}", 28);
        }
        else if (is_traces) {
            /* OTEL Traces format with Parseable field names */
            flb_plg_debug(ctx->ins, "Starting trace span object");
            otel_json = flb_sds_cat(otel_json, "{\"span_trace_id\":\"", 18);
            if (!otel_json) {
                flb_plg_error(ctx->ins, "Failed to add span_trace_id field");
                flb_log_event_decoder_destroy(&log_decoder);
                return -1;
            }
            flb_plg_debug(ctx->ins, "Added span_trace_id field, buffer len=%zu", flb_sds_len(otel_json));
            
            /* Extract trace_id if present */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    strncmp(kv->key.via.str.ptr, "trace_id", 8) == 0 &&
                    kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    break;
                }
            }
            if (i >= map->via.map.size) {
                otel_json = flb_sds_cat(otel_json, "00000000000000000000000000000000", 32);
            }
            
            otel_json = flb_sds_cat(otel_json, "\",\"span_id\":\"", strlen("\",\"span_id\":\""));
            
            /* Extract span_id if present */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    strncmp(kv->key.via.str.ptr, "span_id", 7) == 0 &&
                    kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    break;
                }
            }
            if (i >= map->via.map.size) {
                otel_json = flb_sds_cat(otel_json, "0000000000000000", 16);
            }
            
            otel_json = flb_sds_printf(&otel_json, "\",\"span_start_time\":\"%llu\",\"span_end_time\":\"%llu\",\"span_name\":\"", 
                                (unsigned long long)time_nano, (unsigned long long)time_nano);
            
            /* Extract operation name */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    strncmp(kv->key.via.str.ptr, "operation", 9) == 0 &&
                    kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    break;
                }
            }
            if (i >= map->via.map.size) {
                otel_json = flb_sds_cat(otel_json, "unknown", 7);
            }
            
            otel_json = flb_sds_cat(otel_json, "\",\"span_kind\":1,\"attributes\":[", strlen("\",\"span_kind\":1,\"attributes\":["));
            
            /* Add all fields as attributes */
            int attr_count = 0;
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type != MSGPACK_OBJECT_STR) continue;
                
                /* Skip trace-specific fields and resource-level attributes */
                if (strncmp(kv->key.via.str.ptr, "trace_id", 8) == 0 ||
                    strncmp(kv->key.via.str.ptr, "span_id", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "operation", 9) == 0 ||
                    strncmp(kv->key.via.str.ptr, "date", 4) == 0 ||
                    strncmp(kv->key.via.str.ptr, "service", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "environment", 11) == 0 ||
                    strncmp(kv->key.via.str.ptr, "cluster", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "hostname", 8) == 0) {
                    continue;
                }
                
                /* Handle nested maps */
                if (kv->val.type == MSGPACK_OBJECT_MAP) {
                    char prefix[256];
                    snprintf(prefix, sizeof(prefix), "%.*s", (int)kv->key.via.str.size, kv->key.via.str.ptr);
                    otel_json = add_flattened_attributes(otel_json, prefix, &kv->val, &attr_count);
                    continue;
                }
                
                if (attr_count > 0) {
                    otel_json = flb_sds_cat(otel_json, ",", 1);
                }
                
                otel_json = flb_sds_cat(otel_json, "{\"key\":\"", 8);
                otel_json = escape_json_string(otel_json, kv->key.via.str.ptr, kv->key.via.str.size);
                otel_json = flb_sds_cat(otel_json, "\",\"value\":{", 11);
                
                /* Add value based on type */
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"", 15);
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    otel_json = flb_sds_cat(otel_json, "\"", 1);
                }
                else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    tmp = flb_sds_printf(&otel_json, "\"intValue\":%llu", 
                                        (unsigned long long)kv->val.via.u64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_FLOAT || kv->val.type == MSGPACK_OBJECT_FLOAT32) {
                    tmp = flb_sds_printf(&otel_json, "\"doubleValue\":%f", kv->val.via.f64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_BOOLEAN) {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"", 15);
                    if (kv->val.via.boolean) {
                        otel_json = flb_sds_cat(otel_json, "true", 4);
                    } else {
                        otel_json = flb_sds_cat(otel_json, "false", 5);
                    }
                    otel_json = flb_sds_cat(otel_json, "\"", 1);
                }
                else {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"\"", 17);
                }
                
                otel_json = flb_sds_cat(otel_json, "}}", 2);
                attr_count++;
            }
            
            /* Close span */
            otel_json = flb_sds_cat(otel_json, "],\"span_status\":\"OK\"}", strlen("],\"span_status\":\"OK\"}"));
        }
        else {
            /* OTEL Logs format */
            tmp = flb_sds_printf(&otel_json, "{\"timeUnixNano\":\"%llu\",\"observedTimeUnixNano\":\"%llu\",\"severityNumber\":9,\"severityText\":\"INFO\",\"body\":{\"stringValue\":\"", 
                                (unsigned long long)time_nano, (unsigned long long)time_nano);

            /* Extract body/message */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    (strncmp(kv->key.via.str.ptr, "log", 3) == 0 ||
                     strncmp(kv->key.via.str.ptr, "message", 7) == 0) &&
                    kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    break;
                }
            }

            otel_json = flb_sds_cat(otel_json, "\"},\"attributes\":[", 17);

            /* Add all fields as attributes */
            int attr_count = 0;
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type != MSGPACK_OBJECT_STR) continue;

                /* Skip resource-level attributes */
                if (strncmp(kv->key.via.str.ptr, "service", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "environment", 11) == 0 ||
                    strncmp(kv->key.via.str.ptr, "cluster", 7) == 0 ||
                    strncmp(kv->key.via.str.ptr, "hostname", 8) == 0) {
                    continue;
                }

                /* Handle nested maps separately - flatten them */
                if (kv->val.type == MSGPACK_OBJECT_MAP) {
                    char prefix[256];
                    snprintf(prefix, sizeof(prefix), "%.*s", (int)kv->key.via.str.size, kv->key.via.str.ptr);
                    otel_json = add_flattened_attributes(otel_json, prefix, &kv->val, &attr_count);
                    continue;
                }

                if (attr_count > 0) {
                    otel_json = flb_sds_cat(otel_json, ",", 1);
                }

                otel_json = flb_sds_cat(otel_json, "{\"key\":\"", 8);
                otel_json = escape_json_string(otel_json, kv->key.via.str.ptr, kv->key.via.str.size);
                otel_json = flb_sds_cat(otel_json, "\",\"value\":{", 11);

                /* Add value based on type */
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"", 15);
                    otel_json = escape_json_string(otel_json, kv->val.via.str.ptr, kv->val.via.str.size);
                    otel_json = flb_sds_cat(otel_json, "\"", 1);
                }
                else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    tmp = flb_sds_printf(&otel_json, "\"intValue\":%llu", 
                                        (unsigned long long)kv->val.via.u64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_FLOAT || kv->val.type == MSGPACK_OBJECT_FLOAT32) {
                    tmp = flb_sds_printf(&otel_json, "\"doubleValue\":%f", kv->val.via.f64);
                }
                else if (kv->val.type == MSGPACK_OBJECT_BOOLEAN) {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"", 15);
                    if (kv->val.via.boolean) {
                        otel_json = flb_sds_cat(otel_json, "true", 4);
                    } else {
                        otel_json = flb_sds_cat(otel_json, "false", 5);
                    }
                    otel_json = flb_sds_cat(otel_json, "\"", 1);
                }
                else if (kv->val.type == MSGPACK_OBJECT_ARRAY) {
                    /* Convert array to simple string representation */
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"[", 16);
                    for (size_t j = 0; j < kv->val.via.array.size; j++) {
                        if (j > 0) otel_json = flb_sds_cat(otel_json, ",", 1);
                        msgpack_object *item = &kv->val.via.array.ptr[j];
                        if (item->type == MSGPACK_OBJECT_STR) {
                            otel_json = escape_json_string(otel_json, item->via.str.ptr, item->via.str.size);
                        } else if (item->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            tmp = flb_sds_printf(&otel_json, "%llu", (unsigned long long)item->via.u64);
                        } else if (item->type == MSGPACK_OBJECT_FLOAT || item->type == MSGPACK_OBJECT_FLOAT32) {
                            tmp = flb_sds_printf(&otel_json, "%f", item->via.f64);
                        }
                    }
                    otel_json = flb_sds_cat(otel_json, "]\"", 2);
                }
                else {
                    otel_json = flb_sds_cat(otel_json, "\"stringValue\":\"\"", 17);
                }

                otel_json = flb_sds_cat(otel_json, "}}", 2);
                attr_count++;
            }

            otel_json = flb_sds_cat(otel_json, "],\"traceId\":\"\",\"spanId\":\"\"}", 31);
        }

        record_count++;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Close OTEL format */
    otel_json = flb_sds_cat(otel_json, "]}]}]}", 6);
    if (!otel_json) {
        flb_plg_error(ctx->ins, "Failed to close OTEL JSON structure");
        return -1;
    }
    
    /* Remove any null bytes that may have been inserted */
    size_t len = flb_sds_len(otel_json);
    size_t write_pos = 0;
    for (size_t read_pos = 0; read_pos < len; read_pos++) {
        if (otel_json[read_pos] != '\0') {
            if (write_pos != read_pos) {
                otel_json[write_pos] = otel_json[read_pos];
            }
            write_pos++;
        }
    }
    if (write_pos < len) {
        flb_plg_warn(ctx->ins, "Removed %zu null bytes from OTEL JSON", len - write_pos);
        flb_sds_len_set(otel_json, write_pos);
    }
    
    flb_plg_info(ctx->ins, "OTEL JSON complete: %zu bytes, %d records", 
                 flb_sds_len(otel_json), record_count);

    /* Debug: Log the generated JSON to file for inspection */
    static int file_counter = 0;
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/otel_debug_%d.json", file_counter++);
    FILE *debug_file = fopen(filename, "wb");
    if (debug_file) {
        fwrite(otel_json, 1, flb_sds_len(otel_json), debug_file);
        fwrite("\n", 1, 1, debug_file);
        fclose(debug_file);
        flb_plg_info(ctx->ins, "Generated OTEL JSON (%zu bytes) - saved to %s", 
                      flb_sds_len(otel_json), filename);
    }

    *out_buf = otel_json;
    *out_size = flb_sds_len(otel_json);

    return 0;
}


/* Convert CMetrics msgpack to OTEL protobuf format (for metrics only) */
static int parseable_format_metrics_protobuf(struct flb_out_parseable *ctx,
                                              const void *data, size_t bytes,
                                              void **out_buf, size_t *out_size,
                                              struct flb_config *config)
{
    int ret;
    int ok;
    size_t off = 0;
    struct cmt *cmt;
    cfl_sds_t encoded_chunk;
    flb_sds_t buf = NULL;
    
    ok = CMT_DECODE_MSGPACK_SUCCESS;
    
    /* Buffer to concatenate multiple metrics contexts */
    buf = flb_sds_create_size(bytes);
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer");
        return -1;
    }
    
    flb_plg_debug(ctx->ins, "cmetrics msgpack size: %lu", bytes);
    
    /* Decode and encode every CMetric context */
    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) data,
                                            bytes, &off)) == ok) {
        /* Create OpenTelemetry payload */
        encoded_chunk = cmt_encode_opentelemetry_create(cmt);
        if (encoded_chunk == NULL) {
            flb_plg_error(ctx->ins,
                          "Error encoding context as opentelemetry");
            cmt_destroy(cmt);
            flb_sds_destroy(buf);
            return -1;
        }
        
        flb_plg_debug(ctx->ins, "encoded payload_size=%lu",
                      cfl_sds_len(encoded_chunk));
        
        /* concat buffer */
        flb_sds_cat_safe(&buf, encoded_chunk, cfl_sds_len(encoded_chunk));
        
        /* release */
        cmt_encode_opentelemetry_destroy(encoded_chunk);
        cmt_destroy(cmt);
    }
    
    if (ret == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA && flb_sds_len(buf) > 0) {
        flb_plg_info(ctx->ins, "Packed protobuf: %zu bytes", flb_sds_len(buf));
        
        *out_buf = buf;
        *out_size = flb_sds_len(buf);
        return 0;
    }
    else {
        flb_plg_error(ctx->ins, "Error decoding msgpack encoded context");
        flb_sds_destroy(buf);
        return -1;
    }
}

/* Convert CTraces msgpack to JSON format (for traces) */
static int parseable_format_traces_json(struct flb_out_parseable *ctx,
                                         const void *data, size_t bytes,
                                         void **out_buf, size_t *out_size,
                                         struct flb_config *config)
{
    cfl_sds_t text_output;
    flb_sds_t buf = NULL;
    size_t off = 0;
    struct ctrace *ctr;
    
    buf = flb_sds_create_size(bytes * 2);  /* Estimate JSON is larger than msgpack */
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer for traces");
        return -1;
    }
    
    flb_plg_debug(ctx->ins, "ctraces msgpack size: %lu", bytes);
    
    /* Decode and encode every CTrace context */
    while (ctr_decode_msgpack_create(&ctr,
                                     (char *) data,
                                     bytes, &off) == 0) {
        /* Create text representation of trace */
        text_output = ctr_encode_text_create(ctr);
        if (text_output == NULL) {
            flb_plg_error(ctx->ins,
                          "Error encoding trace context as text");
            ctr_destroy(ctr);
            flb_sds_destroy(buf);
            return -1;
        }
        
        flb_plg_debug(ctx->ins, "encoded trace text_size=%lu",
                      cfl_sds_len(text_output));
        
        /* Wrap in JSON format for Parseable */
        flb_sds_cat_safe(&buf, "{\"trace_data\":\"", 15);
        /* Escape the text output for JSON */
        for (size_t i = 0; i < cfl_sds_len(text_output); i++) {
            char c = text_output[i];
            if (c == '"') {
                flb_sds_cat_safe(&buf, "\\\"", 2);
            } else if (c == '\\') {
                flb_sds_cat_safe(&buf, "\\\\", 2);
            } else if (c == '\n') {
                flb_sds_cat_safe(&buf, "\\n", 2);
            } else if (c == '\r') {
                flb_sds_cat_safe(&buf, "\\r", 2);
            } else if (c == '\t') {
                flb_sds_cat_safe(&buf, "\\t", 2);
            } else {
                flb_sds_cat_safe(&buf, &c, 1);
            }
        }
        flb_sds_cat_safe(&buf, "\"}\n", 3);
        
        /* release */
        ctr_encode_text_destroy(text_output);
        ctr_destroy(ctr);
    }
    
    if (flb_sds_len(buf) > 0) {
        flb_plg_info(ctx->ins, "Formatted trace JSON: %zu bytes", flb_sds_len(buf));
        
        *out_buf = buf;
        *out_size = flb_sds_len(buf);
        return 0;
    }
    else {
        flb_plg_error(ctx->ins, "Error decoding trace msgpack");
        flb_sds_destroy(buf);
        return -1;
    }
}

/* Convert CTraces msgpack to OTEL protobuf format (for traces) */
static int parseable_format_traces_protobuf(struct flb_out_parseable *ctx,
                                             const void *data, size_t bytes,
                                             void **out_buf, size_t *out_size,
                                             struct flb_config *config)
{
    int ret;
    cfl_sds_t encoded_chunk;
    flb_sds_t buf = NULL;
    size_t off = 0;
    struct ctrace *ctr;
    
    buf = flb_sds_create_size(bytes);
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer");
        return -1;
    }
    
    flb_plg_debug(ctx->ins, "ctraces msgpack size: %lu", bytes);
    
    /* Decode and encode every CTrace context */
    while (ctr_decode_msgpack_create(&ctr,
                                     (char *) data,
                                     bytes, &off) == 0) {
        /* Create OpenTelemetry payload */
        encoded_chunk = ctr_encode_opentelemetry_create(ctr);
        if (encoded_chunk == NULL) {
            flb_plg_error(ctx->ins,
                          "Error encoding trace context as opentelemetry");
            ctr_destroy(ctr);
            flb_sds_destroy(buf);
            return -1;
        }
        
        flb_plg_debug(ctx->ins, "encoded trace payload_size=%lu",
                      cfl_sds_len(encoded_chunk));
        
        /* concat buffer */
        ret = flb_sds_cat_safe(&buf, encoded_chunk, cfl_sds_len(encoded_chunk));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Error appending encoded trace to buffer");
            ctr_encode_opentelemetry_destroy(encoded_chunk);
            ctr_destroy(ctr);
            flb_sds_destroy(buf);
            return -1;
        }
        
        /* release */
        ctr_encode_opentelemetry_destroy(encoded_chunk);
        ctr_destroy(ctr);
    }
    
    if (flb_sds_len(buf) > 0) {
        flb_plg_info(ctx->ins, "Packed trace protobuf: %zu bytes", flb_sds_len(buf));
        
        *out_buf = buf;
        *out_size = flb_sds_len(buf);
        return 0;
    }
    else {
        flb_plg_error(ctx->ins, "Error decoding trace msgpack encoded context");
        flb_sds_destroy(buf);
        return -1;
    }
}

static int parseable_format_json(struct flb_out_parseable *ctx,
                                  const void *data, size_t bytes,
                                  void **out_buf, size_t *out_size,
                                  struct flb_config *config)
{
    void *enriched_data = NULL;
    size_t enriched_bytes = 0;
    const void *data_to_use = data;
    size_t bytes_to_use = bytes;
    int need_free_enriched = 0;
    
    /* Check if we should use OTEL JSON format */
    if (ctx->log_source && 
        (strstr(ctx->log_source, "otel") != NULL || strstr(ctx->log_source, "OTEL") != NULL)) {
        /* Use OTEL JSON format */
        flb_plg_debug(ctx->ins, "Using OTEL JSON format");
        return parseable_format_json_to_otel(ctx, data, bytes, out_buf, out_size, config);
    }
    
    /* Enrich records with K8s metadata if enabled */
    if (ctx->enrich_kubernetes) {
        if (enrich_records_k8s(ctx, data, bytes, &enriched_data, &enriched_bytes) == 0 
            && enriched_data != NULL) {
            data_to_use = enriched_data;
            bytes_to_use = enriched_bytes;
            need_free_enriched = 1;
            flb_plg_debug(ctx->ins, "K8s enrichment applied: %zu -> %zu bytes", 
                          bytes, enriched_bytes);
        }
    }
    
    /* Use standard JSON format */
    flb_sds_t json_buf = flb_pack_msgpack_to_json_format(data_to_use, (uint64_t)bytes_to_use,
                                                          FLB_PACK_JSON_FORMAT_JSON,
                                                          FLB_PACK_JSON_DATE_DOUBLE,
                                                          NULL, FLB_FALSE);
    
    /* Free enriched buffer if allocated */
    if (need_free_enriched && enriched_data) {
        flb_free(enriched_data);
    }
    
    if (!json_buf) {
        return -1;
    }
    
    *out_buf = json_buf;
    *out_size = flb_sds_len(json_buf);
    return 0;
}

static int parseable_http_post(struct flb_out_parseable *ctx,
                                const void *body, size_t body_len,
                                const char *tag, int tag_len,
                                int record_count,
                                int is_protobuf,
                                const char *dynamic_stream)
{
    int ret;
    int out_ret = FLB_OK;
    int compressed = FLB_FALSE;
    size_t b_sent;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;
    uint64_t ts;
    char status_str[16];
    const char *stream_to_use;

    /* Get upstream connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        cmt_counter_inc(ctx->cmt_errors_total, ts = cfl_time_now(),
                        1, (char *[]) {"connection"});
        return FLB_RETRY;
    }

    /* Map payload */
    payload_buf = (void *) body;
    payload_size = body_len;

    /* Compress payload if enabled */
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) body, body_len,
                                &payload_buf, &payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
            flb_plg_debug(ctx->ins, "compressed payload: %zu -> %zu bytes",
                          body_len, payload_size);
        }
        else {
            flb_plg_warn(ctx->ins, "compression failed, sending uncompressed");
            compressed = FLB_FALSE;
            payload_buf = (void *) body;
            payload_size = body_len;
        }
    }

    /* Update batch size metric */
    cmt_gauge_set(ctx->cmt_batch_size_bytes, ts = cfl_time_now(),
                  payload_size, 0, NULL);

    /* Log request details */
    flb_plg_info(ctx->ins, "Sending to %s:%d%s, size=%zu bytes", 
                 u->tcp_host, u->tcp_port, ctx->uri, payload_size);
    
    /* Create HTTP client */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        payload_buf, payload_size,
                        u->tcp_host, u->tcp_port,
                        NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client");
        if (compressed && payload_buf != body) {
            flb_free(payload_buf);
        }
        flb_upstream_conn_release(u_conn);
        cmt_counter_inc(ctx->cmt_errors_total, ts = cfl_time_now(),
                        1, (char *[]) {"http_client"});
        return FLB_RETRY;
    }

    /* Add required headers */
    if (is_protobuf) {
        /* Use protobuf content type for metrics and traces */
        flb_http_add_header(c,
                            FLB_PARSEABLE_CONTENT_TYPE, 
                            sizeof(FLB_PARSEABLE_CONTENT_TYPE) - 1,
                            "application/x-protobuf", 22);
    } else {
        /* Use JSON content type for logs */
        flb_http_add_header(c,
                            FLB_PARSEABLE_CONTENT_TYPE, 
                            sizeof(FLB_PARSEABLE_CONTENT_TYPE) - 1,
                            FLB_PARSEABLE_MIME_JSON, 
                            sizeof(FLB_PARSEABLE_MIME_JSON) - 1);
    }

    flb_http_add_header(c,
                        "User-Agent", 10,
                        "Fluent-Bit", 10);

    /* Add Content-Encoding if compressed */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Add X-P-Stream header (required) - use dynamic stream if provided */
    stream_to_use = dynamic_stream ? dynamic_stream : ctx->stream;
    if (stream_to_use) {
        flb_http_add_header(c,
                            FLB_PARSEABLE_HEADER_STREAM,
                            sizeof(FLB_PARSEABLE_HEADER_STREAM) - 1,
                            stream_to_use, strlen(stream_to_use));
        if (dynamic_stream) {
            flb_plg_info(ctx->ins, "Header: X-P-Stream: %s (dynamic)", stream_to_use);
        } else {
            flb_plg_debug(ctx->ins, "Header: X-P-Stream: %s", stream_to_use);
        }
    }

    /* Add X-P-Log-Source header (optional) */
    if (ctx->log_source) {
        flb_http_add_header(c,
                            FLB_PARSEABLE_HEADER_LOG_SOURCE,
                            sizeof(FLB_PARSEABLE_HEADER_LOG_SOURCE) - 1,
                            ctx->log_source, flb_sds_len(ctx->log_source));
        flb_plg_debug(ctx->ins, "Header: X-P-Log-Source: %s", ctx->log_source);
    }

    /* Add Authorization header if configured */
    if (ctx->auth_header) {
        flb_http_add_header(c,
                            "Authorization", 13,
                            ctx->auth_header, flb_sds_len(ctx->auth_header));
        flb_plg_info(ctx->ins, "Header: Authorization: %s", ctx->auth_header);
    }

    /* Add custom headers */
    if (ctx->headers) {
        flb_config_map_foreach(head, mv, ctx->headers) {
            key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
            val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

            flb_http_add_header(c,
                                key->str, flb_sds_len(key->str),
                                val->str, flb_sds_len(val->str));
        }
    }

    /* Perform HTTP request */
    ret = flb_http_do(c, &b_sent);
    ts = cfl_time_now();
    
    if (ret == 0) {
        /* Check HTTP status code */
        snprintf(status_str, sizeof(status_str), "%d", c->resp.status);
        cmt_counter_inc(ctx->cmt_requests_total, ts,
                        1, (char *[]) {status_str});
        
        if (c->resp.status < 200 || c->resp.status > 299) {
            if (c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              u->tcp_host, u->tcp_port,
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              u->tcp_host, u->tcp_port, c->resp.status);
            }

            cmt_counter_inc(ctx->cmt_errors_total, ts,
                            1, (char *[]) {"http_error"});

            /* Decide whether to retry based on status code */
            if (c->resp.status >= 400 && c->resp.status < 500 &&
                c->resp.status != 429 && c->resp.status != 408) {
                /* Client errors (except 429 Too Many Requests and 408 Timeout) should not be retried */
                out_ret = FLB_ERROR;
            }
            else {
                /* Server errors and retryable client errors */
                out_ret = FLB_RETRY;
            }
        }
        else {
            /* Success */
            flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i, sent %zu bytes (%d records)",
                          u->tcp_host, u->tcp_port, c->resp.status,
                          payload_size, record_count);
            
            /* Update success metrics */
            cmt_counter_add(ctx->cmt_records_total, ts, record_count, 0, NULL);
            cmt_counter_add(ctx->cmt_bytes_total, ts, payload_size, 0, NULL);
        }
    }
    else {
        flb_plg_error(ctx->ins, "HTTP request failed to %s:%i (http_do=%i)",
                      u->tcp_host, u->tcp_port, ret);
        cmt_counter_inc(ctx->cmt_errors_total, ts,
                        1, (char *[]) {"network"});
        out_ret = FLB_RETRY;
    }

    /* Cleanup */
    if (compressed && payload_buf != body) {
        flb_free(payload_buf);
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

static void cb_parseable_flush(struct flb_event_chunk *event_chunk,
                                struct flb_output_flush *out_flush,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    int ret;
    int record_count = 0;
    struct flb_out_parseable *ctx = out_context;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    flb_sds_t dynamic_stream = NULL;
    (void) i_ins;
    (void) out_flush;

    /* Note: Retry limit checking is handled by Fluent Bit's core retry mechanism */
    
    /* Debug: Log event type and tag */
    flb_plg_info(ctx->ins, "cb_parseable_flush called: type=%d tag=%s size=%zu", 
                 event_chunk->type, event_chunk->tag, event_chunk->size);
    flb_plg_debug(ctx->ins, "Event chunk type: %d (LOGS=%d, METRICS=%d, TRACES=%d)", 
                  event_chunk->type, FLB_INPUT_LOGS, FLB_INPUT_METRICS, FLB_INPUT_TRACES);

    int is_protobuf = 0;
    
    /* Extract dynamic stream if enabled */
    int exclude_record = 0;
    if (ctx->dynamic_stream) {
        /* First try to extract from tag (parseable.<stream>) */
        dynamic_stream = extract_stream_from_tag(ctx, event_chunk->tag, 
                                                  flb_sds_len(event_chunk->tag));
        
        /* If not found in tag, try to extract from record metadata (Kubernetes) */
        if (!dynamic_stream && event_chunk->type == FLB_INPUT_LOGS) {
            dynamic_stream = extract_dynamic_stream(ctx, event_chunk->data, 
                                                     event_chunk->size, &exclude_record);
            
            /* Check if record should be excluded (parseable/exclude annotation) */
            if (exclude_record) {
                flb_plg_debug(ctx->ins, "Dropping record due to parseable/exclude annotation");
                FLB_OUTPUT_RETURN(FLB_OK);
            }
        }
        
        if (dynamic_stream) {
            flb_plg_info(ctx->ins, "Using dynamic stream: %s", dynamic_stream);
        }
    }
    
    /* Handle based on event type */
    if (event_chunk->type == FLB_INPUT_TRACES) {
        /* Traces data from OpenTelemetry input - use protobuf encoding */
        flb_plg_info(ctx->ins, "Processing FLB_INPUT_TRACES with protobuf");
        
        /* Use protobuf format for traces */
        ret = parseable_format_traces_protobuf(ctx,
                                               event_chunk->data, event_chunk->size,
                                               &out_buf, &out_size,
                                               config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to format traces as protobuf");
            if (dynamic_stream) flb_sds_destroy(dynamic_stream);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        record_count = 1; /* Count traces */
        is_protobuf = 1;
    }
    else if (event_chunk->type == FLB_INPUT_METRICS) {
        /* Real metrics data - use CMetrics protobuf encoding */
        flb_plg_info(ctx->ins, "Processing FLB_INPUT_METRICS with protobuf");
        ret = parseable_format_metrics_protobuf(ctx,
                                                 event_chunk->data, event_chunk->size,
                                                 &out_buf, &out_size,
                                                 config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to format metrics as protobuf");
            if (dynamic_stream) flb_sds_destroy(dynamic_stream);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        record_count = 1; /* Metrics are batched differently */
        is_protobuf = 1;
    }
    else {
        /* Log events (including metrics from input plugins) - use JSON */
        flb_plg_debug(ctx->ins, "Processing FLB_INPUT_LOGS with JSON");
        
        /* Count records in the chunk */
        ret = flb_log_event_decoder_init(&log_decoder,
                                         (char *) event_chunk->data,
                                         event_chunk->size);
        if (ret == FLB_EVENT_DECODER_SUCCESS) {
            while (flb_log_event_decoder_next(&log_decoder, &log_event) ==
                   FLB_EVENT_DECODER_SUCCESS) {
                record_count++;
            }
            flb_log_event_decoder_destroy(&log_decoder);
        }

        /* Check batch size limit */
        if (ctx->batch_size > 0 && event_chunk->size > ctx->batch_size) {
            flb_plg_warn(ctx->ins, "chunk size (%zu bytes) exceeds batch_size limit (%zu bytes), "
                         "sending anyway", event_chunk->size, ctx->batch_size);
        }

        /* Check if we need OTEL formatting based on data_type */
        if (ctx->data_type && (strcasecmp(ctx->data_type, "traces") == 0 ||
                               strcasecmp(ctx->data_type, "otel-trace") == 0 ||
                               strcasecmp(ctx->data_type, "otel-traces") == 0 ||
                               strcasecmp(ctx->data_type, "metrics") == 0 ||
                               strcasecmp(ctx->data_type, "otel-metric") == 0 ||
                               strcasecmp(ctx->data_type, "otel-metrics") == 0)) {
            /* Format as OTEL */
            ret = parseable_format_json_to_otel(ctx,
                                                event_chunk->data, event_chunk->size,
                                                &out_buf, &out_size,
                                                config);
        } else {
            /* Convert msgpack to JSON */
            ret = parseable_format_json(ctx,
                                        event_chunk->data, event_chunk->size,
                                        &out_buf, &out_size,
                                        config);
        }
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to format data");
            if (dynamic_stream) flb_sds_destroy(dynamic_stream);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Send HTTP POST to Parseable */
    ret = parseable_http_post(ctx, out_buf, out_size,
                              event_chunk->tag, flb_sds_len(event_chunk->tag),
                              record_count, is_protobuf, dynamic_stream);

    /* Free formatted buffer */
    if (out_buf) {
        flb_sds_destroy(out_buf);
    }
    
    /* Free dynamic stream if allocated */
    if (dynamic_stream) {
        flb_sds_destroy(dynamic_stream);
    }

    FLB_OUTPUT_RETURN(ret);
}

static int cb_parseable_exit(void *data, struct flb_config *config)
{
    struct flb_out_parseable *ctx = data;
    (void) config;

    if (!ctx) {
        return 0;
    }

    /* Destroy upstream connection */
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    /* Free context */
    flb_free(ctx);

    return 0;
}

/* Plugin descriptor */
struct flb_output_plugin out_parseable_plugin = {
    .name        = "parseable",
    .description = "Send logs, metrics, and traces to Parseable",
    .cb_init     = cb_parseable_init,
    .cb_pre_run  = NULL,
    .cb_flush    = cb_parseable_flush,
    .cb_exit     = cb_parseable_exit,
    .config_map  = config_map,
    .event_type  = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .workers     = 2
};
