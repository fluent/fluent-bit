/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
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

/* Forward declarations for cmetrics opentelemetry encoding */
extern cfl_sds_t cmt_encode_opentelemetry_create(struct cmt *cmt);
extern void cmt_encode_opentelemetry_destroy(cfl_sds_t text);

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <ctraces/ctr_encode_opentelemetry.h>
#include <ctraces/ctr_encode_text.h>

#include <fluent-otel-proto/fluent-otel.h>

#include "parseable.h"

/* Forward declarations */
static int parseable_format_json(struct flb_out_parseable *ctx,
                                  const void *data, size_t bytes,
                                  void **out_buf, size_t *out_size,
                                  struct flb_config *config);

/*
 * Helper macro for safe SDS concatenation with cleanup on failure.
 * Usage: SDS_CAT_OR_GOTO(sds_var, str, len, cleanup_label)
 */
#define SDS_CAT_OR_GOTO(sds, str, len, label) \
    do { \
        sds = flb_sds_cat(sds, str, len); \
        if (!sds) { goto label; } \
    } while (0)

/*
 * Helper: Find a string value in a msgpack map by key name.
 * Returns the value object or NULL if not found.
 */
static msgpack_object *find_map_str_value(msgpack_object *map, 
                                           const char *key_name, 
                                           size_t key_len)
{
    uint32_t i;
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
                flb_plg_debug(ctx->ins, "Using _parseable_dataset: %s", stream);
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
                    flb_plg_debug(ctx->ins,
                        "Record excluded via "
                        "parseable/exclude");
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
                    flb_plg_debug(ctx->ins,
                        "annotation dataset: %s",
                        stream);
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
                    if (!stream) {
                        flb_sds_destroy(app);
                        msgpack_unpacked_destroy(&result);
                        return NULL;
                    }
                    flb_sds_cat_safe(&stream, app, flb_sds_len(app));
                    flb_sds_cat_safe(&stream, "-logs", 5);
                    flb_plg_debug(ctx->ins, "Derived stream from app label: %s", stream);
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
                    if (!stream) {
                        flb_sds_destroy(app);
                        msgpack_unpacked_destroy(&result);
                        return NULL;
                    }
                    flb_sds_cat_safe(&stream, app, flb_sds_len(app));
                    flb_sds_cat_safe(&stream, "-logs", 5);
                    flb_plg_debug(ctx->ins,
                        "stream from "
                        "app.k8s.io/name: %s",
                        stream);
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
                if (!stream) {
                    flb_sds_destroy(ns);
                    msgpack_unpacked_destroy(&result);
                    return NULL;
                }
                flb_sds_cat_safe(&stream, ns, flb_sds_len(ns));
                flb_sds_cat_safe(&stream, "-logs", 5);
                flb_plg_debug(ctx->ins, "Derived stream from namespace: %s", stream);
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
    uint32_t i;
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
        msgpack_pack_str_body(pk,
            meta->namespace_name,
            flb_sds_len(meta->namespace_name));
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
        msgpack_pack_str_body(pk,
            meta->container_name,
            flb_sds_len(meta->container_name));
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
     "URI path for Parseable ingestion endpoint"
    },
    {
     FLB_CONFIG_MAP_STR, "data_type", "logs",
     0, FLB_TRUE, offsetof(struct flb_out_parseable, data_type),
     "Data type: logs, metrics, or traces"
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
     "Enable Kubernetes metadata enrichment"
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
                if (!ctx->uri) {
                    flb_plg_error(ins, "failed to allocate URI /v1/metrics");
                    flb_free(ctx);
                    return -1;
                }
                flb_plg_debug(ins, "auto-set URI to /v1/metrics for metrics data");
            }
            else if (strcasecmp(ctx->data_type, "traces") == 0 || 
                     strcasecmp(ctx->data_type, "otel-trace") == 0 ||
                     strcasecmp(ctx->data_type, "otel-traces") == 0) {
                ctx->uri = flb_sds_create("/v1/traces");
                if (!ctx->uri) {
                    flb_plg_error(ins, "failed to allocate URI /v1/traces");
                    flb_free(ctx);
                    return -1;
                }
                flb_plg_debug(ins, "auto-set URI to /v1/traces for traces data");
            }
            else {
                /* Logs use /v1/logs for OTEL format */
                ctx->uri = flb_sds_create("/v1/logs");
                if (!ctx->uri) {
                    flb_plg_error(ins, "failed to allocate URI /v1/logs");
                    flb_free(ctx);
                    return -1;
                }
                flb_plg_debug(ins, "auto-set URI to /v1/logs for logs data");
            }
        }
        else {
            /* Default to logs endpoint */
            ctx->uri = flb_sds_create("/v1/logs");
            if (!ctx->uri) {
                flb_plg_error(ins, "failed to allocate URI /v1/logs");
                flb_free(ctx);
                return -1;
            }
            flb_plg_debug(ins, "using default URI /v1/logs");
        }
    }
    else {
        flb_plg_debug(ins, "using configured URI: %s", ctx->uri);
    }

    /* Compression configuration */
    ctx->compress_gzip = FLB_FALSE;
    tmp = flb_output_get_property("compress", ins);
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
            flb_plg_debug(ins, "gzip compression enabled");
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

    /* Initialize metrics - failures are non-fatal, metrics will be skipped if NULL */
    ctx->cmt_requests_total = cmt_counter_create(
        ins->cmt, "parseable", "requests",
        "total", "Total HTTP requests",
        1, (char *[]) {"status"});
    if (!ctx->cmt_requests_total) {
        flb_plg_warn(ins, "could not create requests_total metric");
    }
    
    ctx->cmt_errors_total = cmt_counter_create(ins->cmt, "parseable", "errors",
                                                "total", "Total number of errors",
                                                1, (char *[]) {"type"});
    if (!ctx->cmt_errors_total) {
        flb_plg_warn(ins, "could not create errors_total metric");
    }
    
    ctx->cmt_records_total = cmt_counter_create(ins->cmt, "parseable", "records",
                                                 "total", "Total number of records sent",
                                                 0, NULL);
    if (!ctx->cmt_records_total) {
        flb_plg_warn(ins, "could not create records_total metric");
    }
    
    ctx->cmt_bytes_total = cmt_counter_create(
        ins->cmt, "parseable", "bytes",
        "total", "Total bytes sent",
        0, NULL);
    if (!ctx->cmt_bytes_total) {
        flb_plg_warn(ins, "could not create bytes_total metric");
    }
    
    ctx->cmt_batch_size_bytes = cmt_gauge_create(ins->cmt, "parseable", "batch_size",
                                                  "bytes", "Current batch size in bytes",
                                                  0, NULL);
    if (!ctx->cmt_batch_size_bytes) {
        flb_plg_warn(ins, "could not create batch_size_bytes metric");
    }

    /* Set plugin context */
    flb_output_set_context(ins, ctx);

    /* Register HTTP debug callbacks */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins,
        "initialized: host=%s port=%d "
        "stream=%s uri=%s "
        "batch_size=%zu compress=%s",
        ins->host.name, ins->host.port,
        ctx->stream, ctx->uri,
        ctx->batch_size,
        ctx->compress_gzip ? "gzip" : "none");

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
        if (!dest) {
            return NULL;
        }
    }
    return dest;
}

/* Helper to add flattened attributes from nested msgpack objects.
 * Returns NULL on allocation failure, caller must handle cleanup.
 */
static flb_sds_t add_flattened_attributes(flb_sds_t dest, const char *prefix, 
                                          msgpack_object *obj, int *attr_count)
{
    size_t i;
    msgpack_object_kv *kv;
    flb_sds_t key_name = NULL;
    
    if (!dest) {
        return NULL;
    }
    
    if (obj->type == MSGPACK_OBJECT_MAP) {
        for (i = 0; i < obj->via.map.size; i++) {
            kv = &obj->via.map.ptr[i];
            
            if (kv->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            
            /* Build the flattened key name with dot notation */
            if (prefix && strlen(prefix) > 0) {
                key_name = flb_sds_create_size(strlen(prefix) + kv->key.via.str.size + 2);
                if (!key_name) {
                    return NULL;
                }
                SDS_CAT_OR_GOTO(key_name, prefix, strlen(prefix), flatten_key_error);
                SDS_CAT_OR_GOTO(key_name, ".", 1, flatten_key_error);
                SDS_CAT_OR_GOTO(key_name,
                    kv->key.via.str.ptr,
                    kv->key.via.str.size,
                    flatten_key_error);
            } else {
                key_name = flb_sds_create_len(kv->key.via.str.ptr, kv->key.via.str.size);
                if (!key_name) {
                    return NULL;
                }
            }
            
            /* If value is a nested map, recurse */
            if (kv->val.type == MSGPACK_OBJECT_MAP) {
                dest = add_flattened_attributes(dest, key_name, &kv->val, attr_count);
                flb_sds_destroy(key_name);
                key_name = NULL;
                if (!dest) {
                    return NULL;
                }
            }
            /* If value is an array, convert to JSON string */
            else if (kv->val.type == MSGPACK_OBJECT_ARRAY) {
                if (*attr_count > 0) {
                    SDS_CAT_OR_GOTO(dest, ",", 1, flatten_error);
                }
                
                SDS_CAT_OR_GOTO(dest, "{\"key\":\"", 8, flatten_error);
                dest = escape_json_string(dest, key_name, flb_sds_len(key_name));
                if (!dest) { goto flatten_error; }
                SDS_CAT_OR_GOTO(dest,
                    "\",\"value\":"
                    "{\"stringValue\":\"[",
                    27, flatten_error);
                
                /* Simple array representation */
                for (size_t j = 0; j < kv->val.via.array.size; j++) {
                    if (j > 0) {
                        SDS_CAT_OR_GOTO(dest, ",", 1, flatten_error);
                    }
                    msgpack_object *item = &kv->val.via.array.ptr[j];
                    if (item->type == MSGPACK_OBJECT_STR) {
                        dest = escape_json_string(
                            dest,
                            item->via.str.ptr,
                            item->via.str.size);
                        if (!dest) {
                            goto flatten_error;
                        }
                    }
                    else if (item->type ==
                        MSGPACK_OBJECT_POSITIVE_INTEGER) {
                        flb_sds_printf(&dest, "%llu", (unsigned long long)item->via.u64);
                        if (!dest) { goto flatten_error; }
                    }
                    else if (
                        item->type ==
                        MSGPACK_OBJECT_FLOAT ||
                        item->type ==
                        MSGPACK_OBJECT_FLOAT32) {
                        flb_sds_printf(&dest, "%f", item->via.f64);
                        if (!dest) { goto flatten_error; }
                    }
                }
                
                SDS_CAT_OR_GOTO(dest, "]\"}}", 4, flatten_error);
                (*attr_count)++;
                flb_sds_destroy(key_name);
                key_name = NULL;
            }
            /* Simple value types */
            else {
                if (*attr_count > 0) {
                    SDS_CAT_OR_GOTO(dest, ",", 1, flatten_error);
                }
                
                SDS_CAT_OR_GOTO(dest, "{\"key\":\"", 8, flatten_error);
                dest = escape_json_string(dest, key_name, flb_sds_len(key_name));
                if (!dest) { goto flatten_error; }
                SDS_CAT_OR_GOTO(dest, "\",\"value\":{", 11, flatten_error);
                
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    SDS_CAT_OR_GOTO(dest, "\"stringValue\":\"", 15, flatten_error);
                    dest = escape_json_string(
                        dest,
                        kv->val.via.str.ptr,
                        kv->val.via.str.size);
                    if (!dest) { goto flatten_error; }
                    SDS_CAT_OR_GOTO(dest, "\"", 1, flatten_error);
                }
                else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    flb_sds_printf(&dest, "\"intValue\":%llu", 
                                        (unsigned long long)kv->val.via.u64);
                    if (!dest) { goto flatten_error; }
                }
                else if (kv->val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    flb_sds_printf(&dest, "\"intValue\":%lld", 
                                        (long long)kv->val.via.i64);
                    if (!dest) { goto flatten_error; }
                }
                else if (
                    kv->val.type ==
                    MSGPACK_OBJECT_FLOAT ||
                    kv->val.type ==
                    MSGPACK_OBJECT_FLOAT32) {
                    flb_sds_printf(&dest, "\"doubleValue\":%f", kv->val.via.f64);
                    if (!dest) { goto flatten_error; }
                }
                else if (kv->val.type == MSGPACK_OBJECT_BOOLEAN) {
                    SDS_CAT_OR_GOTO(dest, "\"stringValue\":\"", 15, flatten_error);
                    if (kv->val.via.boolean) {
                        SDS_CAT_OR_GOTO(dest, "true", 4, flatten_error);
                    } else {
                        SDS_CAT_OR_GOTO(dest, "false", 5, flatten_error);
                    }
                    SDS_CAT_OR_GOTO(dest, "\"", 1, flatten_error);
                }
                else {
                    SDS_CAT_OR_GOTO(dest, "\"stringValue\":\"\"", 16, flatten_error);
                }
                
                SDS_CAT_OR_GOTO(dest, "}}", 2, flatten_error);
                (*attr_count)++;
                flb_sds_destroy(key_name);
                key_name = NULL;
            }
        }
    }
    
    return dest;

flatten_key_error:
    if (key_name) {
        flb_sds_destroy(key_name);
    }
    return NULL;

flatten_error:
    if (key_name) {
        flb_sds_destroy(key_name);
    }
    /* Note: dest is already NULL or invalid, caller handles cleanup */
    return NULL;
}

static int parseable_format_json_to_otel(struct flb_out_parseable *ctx,
                                          const void *data, size_t bytes,
                                          void **out_buf, size_t *out_size,
                                          struct flb_config *config)
{
    int ret;
    flb_sds_t otel_json = NULL;
    flb_sds_t resource_attrs = NULL;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    msgpack_object *map;
    msgpack_object *resource_map = NULL;
    msgpack_object_kv *kv;
    uint32_t i;
    size_t j;
    size_t rk;
    int is_metrics = 0;
    int is_traces = 0;
    int record_count = 0;
    int attr_count = 0;
    int resource_attr_count = 0;
    uint64_t time_nano;
    char prefix[256];

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

    /*
     * Check if data is already in OTLP format.
     * Skip OTEL formatting if already structured.
     */
    if (is_traces || is_metrics) {
        ret = flb_log_event_decoder_init(
            &log_decoder,
            (char *) data, bytes);
        if (ret == FLB_EVENT_DECODER_SUCCESS) {
            ret = flb_log_event_decoder_next(
                &log_decoder, &log_event);
            if (ret ==
                FLB_EVENT_DECODER_SUCCESS) {
                map = log_event.body;
                if (map && map->type ==
                    MSGPACK_OBJECT_MAP) {
                    for (i = 0;
                         i < map->via.map.size;
                         i++) {
                        kv =
                            &map->via.map.ptr[i];
                        if (kv->key.type !=
                            MSGPACK_OBJECT_STR) {
                            continue;
                        }
                        /* Check OTLP markers */
                        if ((kv->key.via.str.size
                             == 13 &&
                             strncmp(
                                kv->key.via
                                .str.ptr,
                                "resourceSpans",
                                13) == 0) ||
                            (kv->key.via.str.size
                             == 15 &&
                             strncmp(
                                kv->key.via
                                .str.ptr,
                                "resourceMetrics",
                                15) == 0) ||
                            (kv->key.via.str.size
                             == 12 &&
                             strncmp(
                                kv->key.via
                                .str.ptr,
                                "resourceLogs",
                                12) == 0)) {
                            flb_sds_t json_buf;
                            flb_plg_debug(
                                ctx->ins,
                                "Already OTLP "
                                "format");
                            flb_log_event_decoder_destroy(
                                &log_decoder);
                            json_buf =
                                flb_pack_msgpack_to_json_format(
                                    data,
                                    (uint64_t)
                                    bytes,
                                    FLB_PACK_JSON_FORMAT_JSON,
                                    FLB_PACK_JSON_DATE_DOUBLE,
                                    NULL,
                                    FLB_FALSE);
                            if (!json_buf) {
                                return -1;
                            }
                            *out_buf = json_buf;
                            *out_size =
                                flb_sds_len(
                                    json_buf);
                            return 0;
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
    resource_attrs = flb_sds_create(
        "{\"attributes\":[");
    if (!resource_attrs) {
        flb_plg_error(ctx->ins,
                      "failed to allocate "
                      "resource_attrs buffer");
        flb_log_event_decoder_destroy(&log_decoder);
        return -1;
    }
    
    ret = flb_log_event_decoder_next(
        &log_decoder, &log_event);
    if (ret == FLB_EVENT_DECODER_SUCCESS) {
        map = log_event.body;
        if (map->type == MSGPACK_OBJECT_MAP) {
            /* Check for 'resource' field */
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type == MSGPACK_OBJECT_STR &&
                    strncmp(kv->key.via.str.ptr, "resource", 8) == 0 &&
                    kv->key.via.str.size == 8 &&
                    kv->val.type == MSGPACK_OBJECT_MAP) {
                    
                    /* Find 'attributes' in resource */
                    for (j = 0;
                         j < kv->val.via.map.size;
                         j++) {
                        msgpack_object_kv *res_kv;
                        res_kv =
                            &kv->val.via.map.ptr[j];
                        if (res_kv->key.type ==
                            MSGPACK_OBJECT_STR &&
                            strncmp(
                                res_kv->key.via
                                .str.ptr,
                                "attributes",
                                10) == 0 &&
                            res_kv->key.via
                            .str.size == 10 &&
                            res_kv->val.type ==
                            MSGPACK_OBJECT_MAP) {
                            resource_map =
                                &res_kv->val;
                            break;
                        }
                    }
                    break;
                }
            }

            /* Use resource.attributes or fallback */
            if (resource_map) {
                for (i = 0;
                     i < resource_map->via.map.size;
                     i++) {
                    kv = &resource_map
                        ->via.map.ptr[i];
                    if (kv->key.type !=
                        MSGPACK_OBJECT_STR) {
                        continue;
                    }

                    if (resource_attr_count > 0) {
                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            ",", 1,
                            otel_alloc_error);
                    }

                    SDS_CAT_OR_GOTO(
                        resource_attrs,
                        "{\"key\":\"", 8,
                        otel_alloc_error);
                    resource_attrs =
                        escape_json_string(
                            resource_attrs,
                            kv->key.via.str.ptr,
                            kv->key.via.str.size);
                    if (!resource_attrs) {
                        goto otel_alloc_error;
                    }
                    SDS_CAT_OR_GOTO(
                        resource_attrs,
                        "\",\"value\":{", 11,
                        otel_alloc_error);

                    if (kv->val.type ==
                        MSGPACK_OBJECT_STR) {
                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            "\"stringValue\":\""
                            , 15,
                            otel_alloc_error);
                        resource_attrs =
                            escape_json_string(
                                resource_attrs,
                                kv->val.via
                                .str.ptr,
                                kv->val.via
                                .str.size);
                        if (!resource_attrs) {
                            goto otel_alloc_error;
                        }
                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            "\"", 1,
                            otel_alloc_error);
                    }
                    else if (kv->val.type ==
                        MSGPACK_OBJECT_POSITIVE_INTEGER) {
                        flb_sds_printf(
                            &resource_attrs,
                            "\"intValue\":%llu",
                            (unsigned long long)
                            kv->val.via.u64);
                        if (!resource_attrs) {
                            goto otel_alloc_error;
                        }
                    }
                    else {
                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            "\"stringValue\":"
                            "\"\"", 16,
                            otel_alloc_error);
                    }

                    SDS_CAT_OR_GOTO(
                        resource_attrs,
                        "}}", 2,
                        otel_alloc_error);
                    resource_attr_count++;
                }
            }
            else {
                /* Fallback: extract common fields */
                const char *resource_keys[] = {
                    "service",
                    "environment",
                    "cluster",
                    "hostname"
                };
                for (rk = 0;
                     rk < sizeof(resource_keys)
                     / sizeof(resource_keys[0]);
                     rk++) {
                    for (i = 0;
                         i < map->via.map.size;
                         i++) {
                        kv = &map->via.map.ptr[i];
                        if (kv->key.type !=
                            MSGPACK_OBJECT_STR) {
                            continue;
                        }
                        if (strncmp(
                            kv->key.via.str.ptr,
                            resource_keys[rk],
                            strlen(
                                resource_keys[rk])
                            ) != 0) {
                            continue;
                        }
                        if (kv->key.via.str.size !=
                            strlen(
                                resource_keys[rk])
                            ) {
                            continue;
                        }

                        if (resource_attr_count
                            > 0) {
                            SDS_CAT_OR_GOTO(
                                resource_attrs,
                                ",", 1,
                                otel_alloc_error);
                        }

                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            "{\"key\":\"", 8,
                            otel_alloc_error);
                        if (strcmp(
                            resource_keys[rk],
                            "service") == 0) {
                            SDS_CAT_OR_GOTO(
                                resource_attrs,
                                "service.name",
                                12,
                                otel_alloc_error);
                        }
                        else {
                            SDS_CAT_OR_GOTO(
                                resource_attrs,
                                resource_keys[rk],
                                strlen(
                                    resource_keys
                                    [rk]),
                                otel_alloc_error);
                        }
                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            "\",\"value\":"
                            "{\"stringValue\":"
                            "\"",
                            26,
                            otel_alloc_error);

                        if (kv->val.type ==
                            MSGPACK_OBJECT_STR) {
                            resource_attrs =
                                escape_json_string(
                                    resource_attrs,
                                    kv->val.via
                                    .str.ptr,
                                    kv->val.via
                                    .str.size);
                            if (!resource_attrs) {
                                goto
                                otel_alloc_error;
                            }
                        }
                        SDS_CAT_OR_GOTO(
                            resource_attrs,
                            "\"}}", 3,
                            otel_alloc_error);
                        resource_attr_count++;
                        break;
                    }
                }
            }
        }
    }
    SDS_CAT_OR_GOTO(resource_attrs,
                     "]}", 2,
                     otel_alloc_error);
    
    /* Reset decoder to process all records */
    flb_log_event_decoder_destroy(&log_decoder);
    ret = flb_log_event_decoder_init(
        &log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
            "failed to re-init log decoder");
        flb_sds_destroy(resource_attrs);
        return -1;
    }

    /* Start OTEL format with resource attrs */
    otel_json = flb_sds_create_size(256);
    if (!otel_json) {
        goto otel_alloc_error;
    }

    if (is_metrics) {
        SDS_CAT_OR_GOTO(otel_json,
            "{\"resourceMetrics\":"
            "[{\"resource\":",
            32, otel_alloc_error);
        SDS_CAT_OR_GOTO(otel_json,
            resource_attrs,
            flb_sds_len(resource_attrs),
            otel_alloc_error);
        SDS_CAT_OR_GOTO(otel_json,
            ",\"scopeMetrics\":"
            "[{\"scope\":{\"name\":"
            "\"fluent-bit\"},"
            "\"metrics\":[",
            59, otel_alloc_error);
    }
    else if (is_traces) {
        SDS_CAT_OR_GOTO(otel_json,
            "{\"resourceSpans\":"
            "[{\"resource\":",
            30, otel_alloc_error);
        SDS_CAT_OR_GOTO(otel_json,
            resource_attrs,
            flb_sds_len(resource_attrs),
            otel_alloc_error);
        SDS_CAT_OR_GOTO(otel_json,
            ",\"scopeSpans\":"
            "[{\"scope\":{\"name\":"
            "\"fluent-bit\"},"
            "\"spans\":[",
            55, otel_alloc_error);
    }
    else {
        SDS_CAT_OR_GOTO(otel_json,
            "{\"resourceLogs\":"
            "[{\"resource\":",
            29, otel_alloc_error);
        SDS_CAT_OR_GOTO(otel_json,
            resource_attrs,
            flb_sds_len(resource_attrs),
            otel_alloc_error);
        SDS_CAT_OR_GOTO(otel_json,
            ",\"scopeLogs\":"
            "[{\"scope\":{\"name\":"
            "\"fluent-bit\"},"
            "\"logRecords\":[",
            59, otel_alloc_error);
    }
    
    flb_sds_destroy(resource_attrs);
    resource_attrs = NULL;

    /* Process each record */
    while (flb_log_event_decoder_next(
        &log_decoder,
        &log_event) ==
        FLB_EVENT_DECODER_SUCCESS) {
        if (record_count > 0) {
            SDS_CAT_OR_GOTO(otel_json,
                            ",", 1,
                            otel_alloc_error);
        }

        map = log_event.body;
        if (map->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* Convert timestamp to nanoseconds */
        time_nano =
            (uint64_t) log_event.timestamp.tm.tv_sec
            * 1000000000ULL
            + (uint64_t)
            log_event.timestamp.tm.tv_nsec;

        if (is_metrics) {
            /* OTEL Metrics format */
            SDS_CAT_OR_GOTO(otel_json,
                "{\"name\":\"", 9,
                otel_alloc_error);

            /* Extract metric_name */
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type ==
                    MSGPACK_OBJECT_STR &&
                    strncmp(
                        kv->key.via.str.ptr,
                        "metric_name",
                        11) == 0 &&
                    kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    break;
                }
            }
            if (i >= map->via.map.size) {
                SDS_CAT_OR_GOTO(otel_json,
                    "unknown", 7,
                    otel_alloc_error);
            }

            flb_sds_printf(&otel_json,
                "\",\"gauge\":"
                "{\"dataPoints\":"
                "[{\"timeUnixNano\":\"%llu\","
                "\"attributes\":[",
                (unsigned long long)
                time_nano);
            if (!otel_json) {
                goto otel_alloc_error;
            }

            /* Add all fields as attributes */
            attr_count = 0;
            for (i = 0; i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* Skip internal metric fields */
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
                    snprintf(prefix,
                             sizeof(prefix),
                             "%.*s",
                             (int) kv->key.via.str.size,
                             kv->key.via.str.ptr);
                    otel_json =
                        add_flattened_attributes(
                            otel_json, prefix,
                            &kv->val, &attr_count);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    continue;
                }

                if (attr_count > 0) {
                    SDS_CAT_OR_GOTO(otel_json,
                                    ",", 1,
                                    otel_alloc_error);
                }

                SDS_CAT_OR_GOTO(otel_json,
                                "{\"key\":\"", 8,
                                otel_alloc_error);
                otel_json = escape_json_string(
                    otel_json,
                    kv->key.via.str.ptr,
                    kv->key.via.str.size);
                if (!otel_json) {
                    goto otel_alloc_error;
                }
                SDS_CAT_OR_GOTO(otel_json,
                                "\",\"value\":{", 11,
                                otel_alloc_error);

                /* Add value based on type */
                if (kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"", 15,
                        otel_alloc_error);
                    otel_json = escape_json_string(
                        otel_json,
                        kv->val.via.str.ptr,
                        kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    SDS_CAT_OR_GOTO(otel_json,
                                    "\"", 1,
                                    otel_alloc_error);
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    flb_sds_printf(
                        &otel_json,
                        "\"intValue\":%llu",
                        (unsigned long long)
                        kv->val.via.u64);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_FLOAT ||
                    kv->val.type ==
                    MSGPACK_OBJECT_FLOAT32) {
                    flb_sds_printf(
                        &otel_json,
                        "\"doubleValue\":%f",
                        kv->val.via.f64);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_BOOLEAN) {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"", 15,
                        otel_alloc_error);
                    if (kv->val.via.boolean) {
                        SDS_CAT_OR_GOTO(
                            otel_json,
                            "true", 4,
                            otel_alloc_error);
                    }
                    else {
                        SDS_CAT_OR_GOTO(
                            otel_json,
                            "false", 5,
                            otel_alloc_error);
                    }
                    SDS_CAT_OR_GOTO(otel_json,
                                    "\"", 1,
                                    otel_alloc_error);
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_ARRAY) {
                    msgpack_object *item;
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"[", 16,
                        otel_alloc_error);
                    for (j = 0;
                         j < kv->val.via.array.size;
                         j++) {
                        item =
                            &kv->val.via.array.ptr[j];
                        if (j > 0) {
                            SDS_CAT_OR_GOTO(
                                otel_json,
                                ",", 1,
                                otel_alloc_error);
                        }
                        if (item->type ==
                            MSGPACK_OBJECT_STR) {
                            otel_json =
                                escape_json_string(
                                    otel_json,
                                    item->via.str.ptr,
                                    item->via.str.size);
                            if (!otel_json) {
                                goto otel_alloc_error;
                            }
                        }
                        else if (item->type ==
                            MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            flb_sds_printf(
                                &otel_json,
                                "%llu",
                                (unsigned long long)
                                item->via.u64);
                            if (!otel_json) {
                                goto otel_alloc_error;
                            }
                        }
                        else if (item->type ==
                            MSGPACK_OBJECT_FLOAT ||
                            item->type ==
                            MSGPACK_OBJECT_FLOAT32) {
                            flb_sds_printf(
                                &otel_json, "%f",
                                item->via.f64);
                            if (!otel_json) {
                                goto otel_alloc_error;
                            }
                        }
                    }
                    SDS_CAT_OR_GOTO(otel_json,
                                    "]\"", 2,
                                    otel_alloc_error);
                }
                else {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"\"", 16,
                        otel_alloc_error);
                }

                SDS_CAT_OR_GOTO(otel_json,
                                "}}", 2,
                                otel_alloc_error);
                attr_count++;
            }

            /* Close metric record */
            SDS_CAT_OR_GOTO(
                otel_json,
                "],\"data_point_value\":"
                "0.0}]}}",
                28, otel_alloc_error);
        }
        else if (is_traces) {
            /* OTEL Traces format */
            SDS_CAT_OR_GOTO(otel_json,
                "{\"span_trace_id\":\"",
                18, otel_alloc_error);

            /* Extract trace_id */
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type ==
                    MSGPACK_OBJECT_STR &&
                    strncmp(
                        kv->key.via.str.ptr,
                        "trace_id", 8) == 0 &&
                    kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    break;
                }
            }
            if (i >= map->via.map.size) {
                SDS_CAT_OR_GOTO(otel_json,
                    "00000000000000000000"
                    "000000000000",
                    32, otel_alloc_error);
            }

            SDS_CAT_OR_GOTO(otel_json,
                "\",\"span_id\":\"",
                13, otel_alloc_error);

            /* Extract span_id */
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type ==
                    MSGPACK_OBJECT_STR &&
                    strncmp(
                        kv->key.via.str.ptr,
                        "span_id", 7) == 0 &&
                    kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    break;
                }
            }
            if (i >= map->via.map.size) {
                SDS_CAT_OR_GOTO(otel_json,
                    "0000000000000000",
                    16, otel_alloc_error);
            }

            flb_sds_printf(&otel_json,
                "\",\"span_start_time\":"
                "\"%llu\","
                "\"span_end_time\":\"%llu\","
                "\"span_name\":\"",
                (unsigned long long) time_nano,
                (unsigned long long) time_nano);
            if (!otel_json) {
                goto otel_alloc_error;
            }

            /* Extract operation name */
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type ==
                    MSGPACK_OBJECT_STR &&
                    strncmp(
                        kv->key.via.str.ptr,
                        "operation", 9) == 0 &&
                    kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    break;
                }
            }
            if (i >= map->via.map.size) {
                SDS_CAT_OR_GOTO(otel_json,
                    "unknown", 7,
                    otel_alloc_error);
            }

            SDS_CAT_OR_GOTO(otel_json,
                "\",\"span_kind\":1,"
                "\"attributes\":[",
                30, otel_alloc_error);

            /* Add all fields as attributes */
            attr_count = 0;
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type !=
                    MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* Skip trace/resource fields */
                if (strncmp(
                        kv->key.via.str.ptr,
                        "trace_id", 8) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "span_id", 7) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "operation", 9) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "date", 4) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "service", 7) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "environment",
                        11) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "cluster", 7) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "hostname", 8) == 0) {
                    continue;
                }

                /* Handle nested maps */
                if (kv->val.type ==
                    MSGPACK_OBJECT_MAP) {
                    snprintf(prefix,
                             sizeof(prefix),
                             "%.*s",
                             (int)
                             kv->key.via.str.size,
                             kv->key.via.str.ptr);
                    otel_json =
                        add_flattened_attributes(
                            otel_json, prefix,
                            &kv->val,
                            &attr_count);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    continue;
                }

                if (attr_count > 0) {
                    SDS_CAT_OR_GOTO(
                        otel_json, ",", 1,
                        otel_alloc_error);
                }

                SDS_CAT_OR_GOTO(otel_json,
                    "{\"key\":\"", 8,
                    otel_alloc_error);
                otel_json = escape_json_string(
                    otel_json,
                    kv->key.via.str.ptr,
                    kv->key.via.str.size);
                if (!otel_json) {
                    goto otel_alloc_error;
                }
                SDS_CAT_OR_GOTO(otel_json,
                    "\",\"value\":{", 11,
                    otel_alloc_error);

                if (kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"",
                        15, otel_alloc_error);
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    SDS_CAT_OR_GOTO(
                        otel_json, "\"", 1,
                        otel_alloc_error);
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    flb_sds_printf(
                        &otel_json,
                        "\"intValue\":%llu",
                        (unsigned long long)
                        kv->val.via.u64);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_FLOAT ||
                    kv->val.type ==
                    MSGPACK_OBJECT_FLOAT32) {
                    flb_sds_printf(
                        &otel_json,
                        "\"doubleValue\":%f",
                        kv->val.via.f64);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_BOOLEAN) {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"",
                        15, otel_alloc_error);
                    if (kv->val.via.boolean) {
                        SDS_CAT_OR_GOTO(
                            otel_json,
                            "true", 4,
                            otel_alloc_error);
                    }
                    else {
                        SDS_CAT_OR_GOTO(
                            otel_json,
                            "false", 5,
                            otel_alloc_error);
                    }
                    SDS_CAT_OR_GOTO(
                        otel_json, "\"", 1,
                        otel_alloc_error);
                }
                else {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"\"",
                        16, otel_alloc_error);
                }

                SDS_CAT_OR_GOTO(otel_json,
                    "}}", 2,
                    otel_alloc_error);
                attr_count++;
            }

            /* Close span */
            SDS_CAT_OR_GOTO(otel_json,
                "],\"span_status\":"
                "\"OK\"}",
                21, otel_alloc_error);
        }
        else {
            /* OTEL Logs format */
            flb_sds_printf(&otel_json,
                "{\"timeUnixNano\":\"%llu\","
                "\"observedTimeUnixNano\":"
                "\"%llu\","
                "\"severityNumber\":9,"
                "\"severityText\":\"INFO\","
                "\"body\":{\"stringValue\":\"",
                (unsigned long long) time_nano,
                (unsigned long long) time_nano);
            if (!otel_json) {
                goto otel_alloc_error;
            }

            /* Extract body/message */
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type ==
                    MSGPACK_OBJECT_STR &&
                    (strncmp(
                        kv->key.via.str.ptr,
                        "log", 3) == 0 ||
                     strncmp(
                        kv->key.via.str.ptr,
                        "message", 7) == 0) &&
                    kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    break;
                }
            }

            SDS_CAT_OR_GOTO(otel_json,
                "\"},\"attributes\":[",
                17, otel_alloc_error);

            /* Add all fields as attributes */
            attr_count = 0;
            for (i = 0;
                 i < map->via.map.size; i++) {
                kv = &map->via.map.ptr[i];
                if (kv->key.type !=
                    MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* Skip resource-level attrs */
                if (strncmp(
                        kv->key.via.str.ptr,
                        "service", 7) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "environment",
                        11) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "cluster", 7) == 0 ||
                    strncmp(
                        kv->key.via.str.ptr,
                        "hostname", 8) == 0) {
                    continue;
                }

                /* Flatten nested maps */
                if (kv->val.type ==
                    MSGPACK_OBJECT_MAP) {
                    snprintf(prefix,
                             sizeof(prefix),
                             "%.*s",
                             (int)
                             kv->key.via.str.size,
                             kv->key.via.str.ptr);
                    otel_json =
                        add_flattened_attributes(
                            otel_json, prefix,
                            &kv->val,
                            &attr_count);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    continue;
                }

                if (attr_count > 0) {
                    SDS_CAT_OR_GOTO(
                        otel_json, ",", 1,
                        otel_alloc_error);
                }

                SDS_CAT_OR_GOTO(otel_json,
                    "{\"key\":\"", 8,
                    otel_alloc_error);
                otel_json = escape_json_string(
                    otel_json,
                    kv->key.via.str.ptr,
                    kv->key.via.str.size);
                if (!otel_json) {
                    goto otel_alloc_error;
                }
                SDS_CAT_OR_GOTO(otel_json,
                    "\",\"value\":{", 11,
                    otel_alloc_error);

                if (kv->val.type ==
                    MSGPACK_OBJECT_STR) {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"",
                        15, otel_alloc_error);
                    otel_json =
                        escape_json_string(
                            otel_json,
                            kv->val.via.str.ptr,
                            kv->val.via.str.size);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                    SDS_CAT_OR_GOTO(
                        otel_json, "\"", 1,
                        otel_alloc_error);
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    flb_sds_printf(
                        &otel_json,
                        "\"intValue\":%llu",
                        (unsigned long long)
                        kv->val.via.u64);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_FLOAT ||
                    kv->val.type ==
                    MSGPACK_OBJECT_FLOAT32) {
                    flb_sds_printf(
                        &otel_json,
                        "\"doubleValue\":%f",
                        kv->val.via.f64);
                    if (!otel_json) {
                        goto otel_alloc_error;
                    }
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_BOOLEAN) {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"",
                        15, otel_alloc_error);
                    if (kv->val.via.boolean) {
                        SDS_CAT_OR_GOTO(
                            otel_json,
                            "true", 4,
                            otel_alloc_error);
                    }
                    else {
                        SDS_CAT_OR_GOTO(
                            otel_json,
                            "false", 5,
                            otel_alloc_error);
                    }
                    SDS_CAT_OR_GOTO(
                        otel_json, "\"", 1,
                        otel_alloc_error);
                }
                else if (kv->val.type ==
                    MSGPACK_OBJECT_ARRAY) {
                    msgpack_object *item;
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"[",
                        16, otel_alloc_error);
                    for (j = 0;
                         j <
                         kv->val.via.array.size;
                         j++) {
                        item =
                            &kv->val.via.array
                            .ptr[j];
                        if (j > 0) {
                            SDS_CAT_OR_GOTO(
                                otel_json,
                                ",", 1,
                                otel_alloc_error);
                        }
                        if (item->type ==
                            MSGPACK_OBJECT_STR) {
                            otel_json =
                                escape_json_string(
                                    otel_json,
                                    item->via
                                    .str.ptr,
                                    item->via
                                    .str.size);
                            if (!otel_json) {
                                goto
                                otel_alloc_error;
                            }
                        }
                        else if (item->type ==
                            MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            flb_sds_printf(
                                &otel_json,
                                "%llu",
                                (unsigned
                                 long long)
                                item->via.u64);
                            if (!otel_json) {
                                goto
                                otel_alloc_error;
                            }
                        }
                        else if (item->type ==
                            MSGPACK_OBJECT_FLOAT
                            || item->type ==
                            MSGPACK_OBJECT_FLOAT32) {
                            flb_sds_printf(
                                &otel_json,
                                "%f",
                                item->via.f64);
                            if (!otel_json) {
                                goto
                                otel_alloc_error;
                            }
                        }
                    }
                    SDS_CAT_OR_GOTO(
                        otel_json, "]\"", 2,
                        otel_alloc_error);
                }
                else {
                    SDS_CAT_OR_GOTO(
                        otel_json,
                        "\"stringValue\":\"\"",
                        16, otel_alloc_error);
                }

                SDS_CAT_OR_GOTO(otel_json,
                    "}}", 2,
                    otel_alloc_error);
                attr_count++;
            }

            SDS_CAT_OR_GOTO(otel_json,
                "],\"traceId\":\"\","
                "\"spanId\":\"\"}",
                27, otel_alloc_error);
        }

        record_count++;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Close OTEL format */
    SDS_CAT_OR_GOTO(otel_json,
                     "]}]}]}", 6,
                     otel_alloc_error);

    /* Remove null bytes that may have been added */
    {
        size_t len = flb_sds_len(otel_json);
        size_t write_pos = 0;
        size_t read_pos;
        for (read_pos = 0;
             read_pos < len; read_pos++) {
            if (otel_json[read_pos] != '\0') {
                if (write_pos != read_pos) {
                    otel_json[write_pos] =
                        otel_json[read_pos];
                }
                write_pos++;
            }
        }
        if (write_pos < len) {
            flb_plg_warn(ctx->ins,
                "Removed %zu null bytes "
                "from OTEL JSON",
                len - write_pos);
            flb_sds_len_set(otel_json,
                            write_pos);
        }
    }

    flb_plg_debug(ctx->ins,
        "OTEL JSON: %zu bytes, %d records",
        flb_sds_len(otel_json),
        record_count);

    *out_buf = otel_json;
    *out_size = flb_sds_len(otel_json);

    return 0;

otel_alloc_error:
    flb_plg_error(ctx->ins, "memory allocation failed in OTEL JSON formatting");
    if (resource_attrs) {
        flb_sds_destroy(resource_attrs);
    }
    if (otel_json) {
        flb_sds_destroy(otel_json);
    }
    flb_log_event_decoder_destroy(&log_decoder);
    return -1;
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
        flb_plg_debug(ctx->ins, "Packed protobuf: %zu bytes", flb_sds_len(buf));
        
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
        flb_plg_debug(ctx->ins, "Packed trace protobuf: %zu bytes", flb_sds_len(buf));
        
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
        (strstr(ctx->log_source, "otel") ||
         strstr(ctx->log_source, "OTEL"))) {
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
    flb_sds_t json_buf;
    json_buf = flb_pack_msgpack_to_json_format(
        data_to_use, (uint64_t) bytes_to_use,
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
    if (ctx->cmt_batch_size_bytes) {
        cmt_gauge_set(ctx->cmt_batch_size_bytes, ts = cfl_time_now(),
                      payload_size, 0, NULL);
    }

    /* Log request details */
    flb_plg_debug(ctx->ins, "Sending to %s:%d%s, size=%zu bytes", 
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
        flb_plg_debug(ctx->ins, "Header: X-P-Stream: %s%s", stream_to_use,
                      dynamic_stream ? " (dynamic)" : "");
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
        flb_plg_debug(ctx->ins, "Header: Authorization: [REDACTED]");
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
        if (ctx->cmt_requests_total) {
            cmt_counter_inc(ctx->cmt_requests_total, ts,
                            1, (char *[]) {status_str});
        }
        
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

            if (ctx->cmt_errors_total) {
                cmt_counter_inc(ctx->cmt_errors_total, ts,
                                1, (char *[]) {"http_error"});
            }

            /* Decide whether to retry based on status code */
            if (c->resp.status >= 400 && c->resp.status < 500 &&
                c->resp.status != 429 && c->resp.status != 408) {
                /* Client errors (not 429/408) */
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
            if (ctx->cmt_records_total) {
                cmt_counter_add(ctx->cmt_records_total, ts, record_count, 0, NULL);
            }
            if (ctx->cmt_bytes_total) {
                cmt_counter_add(ctx->cmt_bytes_total, ts, payload_size, 0, NULL);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "HTTP request failed to %s:%i (http_do=%i)",
                      u->tcp_host, u->tcp_port, ret);
        if (ctx->cmt_errors_total) {
            cmt_counter_inc(ctx->cmt_errors_total, ts,
                            1, (char *[]) {"network"});
        }
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

    flb_plg_debug(ctx->ins, "flush: type=%d tag=%s size=%zu", 
                   event_chunk->type, event_chunk->tag, event_chunk->size);

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
                flb_plg_debug(ctx->ins,
                    "Dropping record: "
                    "parseable/exclude");
                FLB_OUTPUT_RETURN(FLB_OK);
            }
        }
        
        if (dynamic_stream) {
            flb_plg_debug(ctx->ins, "Using dynamic stream: %s", dynamic_stream);
        }
    }
    
    /* Handle based on event type */
    if (event_chunk->type == FLB_INPUT_TRACES) {
        /* Traces data from OpenTelemetry input - use protobuf encoding */
        flb_plg_debug(ctx->ins, "Processing traces with protobuf");
        
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
        flb_plg_debug(ctx->ins, "Processing metrics with protobuf");
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
            flb_plg_warn(ctx->ins,
                "chunk (%zu bytes) exceeds "
                "batch_size (%zu), sending",
                event_chunk->size,
                ctx->batch_size);
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

static void parseable_config_destroy(struct flb_out_parseable *ctx)
{
    if (!ctx) {
        return;
    }

    /* Destroy upstream connection */
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    /*
     * Free only manually-allocated SDS fields.
     * Fields managed by config_map (stream,
     * log_source, auth_header, date_key,
     * data_type, headers) are freed by the
     * framework automatically.
     *
     * uri is auto-set by init when not provided
     * by the user, so we must free it here.
     */
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }

    /* Free context */
    flb_free(ctx);
}

static int cb_parseable_exit(void *data, struct flb_config *config)
{
    struct flb_out_parseable *ctx = data;
    (void) config;

    parseable_config_destroy(ctx);

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
