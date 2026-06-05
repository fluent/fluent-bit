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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_metrics_exporter.h>
#include <fluent-bit/flb_jsmn.h>

#include <monkey/mk_core/mk_list.h>

#include "podman_metrics.h"
#include "podman_metrics_config.h"
#include "podman_metrics_data.h"

/*
 * Collect information about podman containers (ID and Name) from podman configuration
 * file (default is /var/lib/containers/storage/overlay-containers/containers.json).
 * Since flb_jsmn library show JSON as a tree, search for objects with parent 0 (objects
 * that are children to root array, and in them, search for ID and name (which is also
 * an array.
 */
static int collect_container_data(struct flb_in_metrics *ctx, int gather_only)
{
    /* Buffers for reading data from JSON */
    char *buffer;
    char name[CONTAINER_NAME_SIZE];
    char id[CONTAINER_ID_SIZE];
    char image_name[IMAGE_NAME_SIZE];
    char metadata[CONTAINER_METADATA_SIZE];
    char *metadata_token_start;
    char *metadata_token_stop;
    int metadata_token_size;

    int array_id;
    int r, i, j;
    size_t read_bytes = 0;
    int collected_containers = 0;
    int token_len;

    jsmn_parser p;
    jsmntok_t t[JSON_TOKENS];

    struct container_id *cid;

    flb_utils_read_file(ctx->config, &buffer, &read_bytes);
    if (!read_bytes) {
        flb_plg_warn(ctx->ins, "Failed to open %s", ctx->config);
        return -1;
    }
    buffer[read_bytes] = 0;
    flb_plg_debug(ctx->ins, "Read %zu bytes", read_bytes);

    jsmn_init(&p);
    r = jsmn_parse(&p, buffer, strlen(buffer), t, sizeof(t) / sizeof(t[0]));
    if (r < 0) {
        flb_plg_warn(ctx->ins, "Failed to parse JSON %d: %s", r, buffer);
        free(buffer);
        return -1;
    }

    flb_plg_debug(ctx->ins, "Got %d nested tokens", t[0].size);

    if (r < 1 || t[0].type != JSMN_ARRAY) {
        flb_plg_warn(ctx->ins, "Expected array at the json root");
        free(buffer);
        return -1;
    }

    for (i=0; i<r; i++) {
        if (t[i].type == JSMN_STRING) {
            if (sizeof(JSON_FIELD_ID)-1 == t[i].end - t[i].start &&
                strncmp(buffer + t[i].start, JSON_FIELD_ID, t[i].end - t[i].start) == 0) {
                token_len = t[i + 1].end - t[i + 1].start;
                strncpy(id, buffer + t[i+1].start, t[i + 1].end - t[i + 1].start);
                id[token_len] = '\0';
                flb_plg_trace(ctx->ins, "Found id %s", id);
            }
            else if (sizeof(JSON_FIELD_NAMES)-1 == t[i].end - t[i].start &&
                     strncmp(buffer + t[i].start, JSON_FIELD_NAMES, t[i].end - t[i].start) == 0) {
                array_id = i + 1;
                if (t[array_id].type == JSMN_ARRAY) {
                    j = array_id + 1;
                    while (t[j].parent == array_id)
                    {
                        strncpy(name, buffer + t[j].start, t[j].end - t[j].start);
                        name[t[j].end - t[j].start] = '\0';
                        flb_plg_trace(ctx->ins, "Found name %s", name);
                        j++;
                    }
                }
            }
            else if (sizeof(JSON_FIELD_METADATA)-1 == t[i].end - t[i].start &&
                strncmp(buffer + t[i].start, JSON_FIELD_METADATA, t[i].end - t[i].start) == 0) {
                token_len = t[i + 1].end - t[i + 1].start;
                strncpy(metadata, buffer + t[i+1].start, t[i + 1].end - t[i + 1].start);
                metadata[token_len] = '\0';

                metadata_token_start = strstr(metadata, JSON_SUBFIELD_IMAGE_NAME);
                if (metadata_token_start) {
                    metadata_token_stop = strstr(metadata_token_start + JSON_SUBFIELD_SIZE_IMAGE_NAME+1, "\\\"");
                    metadata_token_size = metadata_token_stop - metadata_token_start - JSON_SUBFIELD_SIZE_IMAGE_NAME;

                    strncpy(image_name, metadata_token_start+JSON_SUBFIELD_SIZE_IMAGE_NAME, metadata_token_size);
                    image_name[metadata_token_size] = '\0';

                    flb_plg_trace(ctx->ins, "Found image name %s", image_name);
                    if (!gather_only) {
                        add_container_to_list(ctx, id, name, image_name);
                    }
                }
                else {
                    flb_plg_warn(ctx->ins, "Image name was not found for %s", id);
                    if (!gather_only) {
                        add_container_to_list(ctx, id, name, "unknown");
                    }
                }

                if (gather_only) {
                    cid = flb_malloc(sizeof(struct container_id));
                    if (!cid) {
                        flb_errno();
                        return -1;
                    }
                    cid->id = flb_sds_create(id);
                    mk_list_add(&cid->_head, &ctx->ids);
                    flb_plg_trace(ctx->ins, "Found id for gather only %s", cid->id);
                }
                collected_containers++;
            }
        }
    }

    flb_plg_debug(ctx->ins, "Collected %d containers from podman config file", collected_containers);
    free(buffer);
    return collected_containers;
}

/*
 * Create structure instance based on previously found id, name and image name. Set all its values (like
 * memory or cpu to UINT64_MAX, in case it won't be found later. This function also adds this structure
 * to internal list, so it can be found by iteration later on.
 */
static int add_container_to_list(struct flb_in_metrics *ctx, flb_sds_t id, flb_sds_t name, flb_sds_t image_name)
{
    struct container *cnt;
    cnt = flb_malloc(sizeof(struct container));
    if (!cnt) {
        flb_errno();
        return -1;
    }
    cnt->id = flb_sds_create(id);
    cnt->name = flb_sds_create(name);
    cnt->image_name = flb_sds_create(image_name);

    cnt->memory_usage = UINT64_MAX;
    cnt->memory_max_usage = UINT64_MAX;
    cnt->memory_limit = UINT64_MAX;
    cnt->rss = UINT64_MAX;
    cnt->cpu_user = UINT64_MAX;
    cnt->cpu = UINT64_MAX;

    mk_list_init(&cnt->net_data);

    mk_list_add(&cnt->_head, &ctx->items);
    return 0;
}

/*
 * Iterate over container list and remove collected data
 */
static int destroy_container_list(struct flb_in_metrics *ctx)
{
    struct container *cnt;
    struct net_iface *iface;
    struct sysfs_path *pth;
    struct container_id *id;
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_list *inner_head;
    struct mk_list *inner_tmp;
    int can_remove_stale_counters = FLB_FALSE;
    int id_found;
    int collected;

    if (ctx->remove_stale_counters) {
        collected = collect_container_data(ctx, FLB_TRUE);
        if (collected == -1) {
            flb_plg_error(ctx->ins, "Could not collect container ids");
        }
        else {
            can_remove_stale_counters = FLB_TRUE;
            flb_plg_debug(ctx->ins, "Collected %d for deletion", collected);
        }
    }

    mk_list_foreach_safe(head, tmp, &ctx->items) {
        id_found = FLB_FALSE;
        cnt = mk_list_entry(head, struct container, _head);
        flb_plg_debug(ctx->ins, "Destroying container data (id: %s, name: %s", cnt->id, cnt->name);

        /* If recreation was already triggered, there is no point in determining it again */
        if (can_remove_stale_counters && !ctx->recreate_cmt) {
            mk_list_foreach_safe(inner_head, inner_tmp, &ctx->ids) {
                id = mk_list_entry(inner_head, struct container_id, _head);
                if (strcmp(cnt->id, id->id) == 0) {
                   id_found = FLB_TRUE;
                   break;
                }
            }

            if (!id_found) {
                flb_plg_info(ctx->ins, "Counter will be removed because %s is gone", cnt->name);
                ctx->recreate_cmt = FLB_TRUE;
            }
            else {
                flb_plg_debug(ctx->ins, "No need to remove stale counters");
            }
        }


        flb_sds_destroy(cnt->id);
        flb_sds_destroy(cnt->name);
        flb_sds_destroy(cnt->image_name);

        mk_list_foreach_safe(inner_head, inner_tmp, &cnt->net_data) {
            iface = mk_list_entry(inner_head, struct net_iface, _head);
            flb_sds_destroy(iface->name);
            mk_list_del(&iface->_head);
            flb_free(iface);
        }
        mk_list_del(&cnt->_head);
        flb_free(cnt);
    }
    

    mk_list_foreach_safe(head, tmp, &ctx->sysfs_items) {
        pth = mk_list_entry(head, struct sysfs_path, _head);
        flb_plg_trace(ctx->ins, "Destroying sysfs data (name: %s", pth->path);
        flb_sds_destroy(pth->path);
        mk_list_del(&pth->_head);
        flb_free(pth);
    }

    if (ctx->remove_stale_counters) {
        mk_list_foreach_safe(head, tmp, &ctx->ids) {
            id = mk_list_entry(head, struct container_id, _head);
            flb_plg_trace(ctx->ins, "Destroying container id: %s", id->id);
            flb_sds_destroy(id->id);
            mk_list_del(&id->_head);
            flb_free(id);
        }
    }
    return 0;
}

/*
 * Create counter for given metric name, using name, image name and value as counter labels. Counters
 * are created per counter name, so they are "shared" between multiple containers - counter
 * name remains the same, only labels like ID are changed.
 * This function creates counter only once per counter name - every next call only sets counter
 * value for specific labels.
 */
static int create_counter(struct flb_in_metrics *ctx, struct cmt_counter **counter, flb_sds_t id, flb_sds_t name, flb_sds_t image_name, flb_sds_t metric_prefix,
                          flb_sds_t *fields, flb_sds_t metric_name, flb_sds_t description, flb_sds_t interface, uint64_t value)
{
    flb_sds_t *labels;
    uint64_t fvalue = value;
    int label_count;

    if (value == UINT64_MAX) {
        flb_plg_debug(ctx->ins, "Ignoring invalid counter for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        return -1;
    }

    if (strcmp(metric_name, COUNTER_CPU) == 0 || strcmp(metric_name, COUNTER_CPU_USER) == 0) {
        fvalue = fvalue / 1000000000;
        flb_plg_trace(ctx->ins, "Converting %s from nanoseconds to seconds (%lu -> %lu)", metric_name, value, fvalue);

    }

    labels = (char *[]){id, name, image_name, interface};
    if (interface == NULL) {
        label_count = 3;
    }
    else {
        label_count = 4;
    }

    /* if counter was not yet created, it means that this function is called for the first time per counter type */
    if (*counter == NULL) {
        flb_plg_debug(ctx->ins, "Creating counter for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        *counter = cmt_counter_create(ctx->ins->cmt, COUNTER_PREFIX, metric_prefix, metric_name, description, label_count, fields);
    }

    if (ctx->recreate_cmt) {
        flb_plg_debug(ctx->ins, "Recreating counter for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        cmt_counter_destroy(*counter);
        *counter = cmt_counter_create(ctx->ins->cmt, COUNTER_PREFIX, metric_prefix, metric_name, description, label_count, fields);
    }

    /* Allow setting value that is not grater that current one (if, for example, memory usage stays exactly the same) */
    cmt_counter_allow_reset(*counter);
    flb_plg_debug(ctx->ins, "Set counter for %s, %s_%s_%s: %lu", name, COUNTER_PREFIX, metric_prefix, metric_name, fvalue);
    if (cmt_counter_set(*counter, cfl_time_now(), fvalue, label_count, labels) == -1) {
        flb_plg_warn(ctx->ins, "Failed to set counter for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        return -1;
    }
    return 0;
}

/*
 * Create gauge for given metric name, using name, image name and value as counter labels. Gauges
 * are created per counter name, so they are "shared" between multiple containers - counter
 * name remains the same, only labels like ID are changed.
 * This function creates gauge only once per counter name - every next call only sets gauge
 * value for specific labels.
 */
static int create_gauge(struct flb_in_metrics *ctx, struct cmt_gauge **gauge, flb_sds_t id, flb_sds_t name, flb_sds_t image_name, flb_sds_t metric_prefix,
                          flb_sds_t *fields, flb_sds_t metric_name, flb_sds_t description, flb_sds_t interface, uint64_t value)
{
    flb_sds_t *labels;
    int label_count;
    labels = (char *[]){id, name, image_name};
    label_count = 3;

    if (value == UINT64_MAX) {
        flb_plg_debug(ctx->ins, "Ignoring invalid gauge for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        return -1;
    }

    /* if gauge was not yet created, it means that this function is called for the first time per counter type */
    if (*gauge == NULL) {
        flb_plg_debug(ctx->ins, "Creating gauge for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        *gauge = cmt_gauge_create(ctx->ins->cmt, COUNTER_PREFIX, metric_prefix, metric_name, description, label_count, fields);
    }

    if (ctx->recreate_cmt) {
        flb_plg_debug(ctx->ins, "Recreating gauge for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        cmt_gauge_destroy(*gauge);
        *gauge = cmt_gauge_create(ctx->ins->cmt, COUNTER_PREFIX, metric_prefix, metric_name, description, label_count, fields);
    }

    flb_plg_debug(ctx->ins, "Set gauge for %s, %s_%s_%s: %lu", name, COUNTER_PREFIX, metric_prefix, metric_name, value);
    if (cmt_gauge_set(*gauge, cfl_time_now(), value, label_count, labels) == -1) {
        flb_plg_warn(ctx->ins, "Failed to set gauge for %s, %s_%s_%s", name, COUNTER_PREFIX, metric_prefix, metric_name);
        return -1;
    }
    return 0;
}

/*
 * Call create_counter for every counter type defined in this plugin.
 *
 * Currently supported counters are:
 * - container_memory_usage_bytes
 * - container_memory_max_usage_bytes
 * - container_memory_rss
 * - container_spec_memory_limit_bytes
 * - container_cpu_user_seconds_total
 * - container_cpu_usage_seconds_total
 * - container_network_receive_bytes_total
 * - container_network_receive_errors_total
 * - container_network_transmit_bytes_total
 * - container_network_transmit_errors_total
 */
static int create_counters(struct flb_in_metrics *ctx)
{
    struct container *cnt;
    struct net_iface *iface;
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_list *inner_head;
    struct mk_list *inner_tmp;

    mk_list_foreach_safe(head, tmp, &ctx->items)
    {
        cnt = mk_list_entry(head, struct container, _head);
        create_counter(ctx, &ctx->c_memory_usage, cnt->id, cnt->name, cnt->image_name, COUNTER_MEMORY_PREFIX, FIELDS_METRIC, COUNTER_MEMORY_USAGE,
                       DESCRIPTION_MEMORY_USAGE, NULL, cnt->memory_usage);
        create_counter(ctx, &ctx->c_memory_max_usage, cnt->id, cnt->name, cnt->image_name, COUNTER_MEMORY_PREFIX, FIELDS_METRIC, COUNTER_MEMORY_MAX_USAGE,
                       DESCRIPTION_MEMORY_MAX_USAGE, NULL, cnt->memory_max_usage);
        create_counter(ctx, &ctx->c_memory_limit, cnt->id, cnt->name, cnt->image_name, COUNTER_SPEC_MEMORY_PREFIX, FIELDS_METRIC, COUNTER_MEMORY_LIMIT,
                       DESCRIPTION_MEMORY_LIMIT, NULL, cnt->memory_limit);
        create_gauge(ctx, &ctx->g_rss, cnt->id, cnt->name, cnt->image_name, COUNTER_MEMORY_PREFIX, FIELDS_METRIC, GAUGE_MEMORY_RSS,
                     DESCRIPTION_MEMORY_RSS, NULL, cnt->rss);
        create_counter(ctx, &ctx->c_cpu_user, cnt->id, cnt->name, cnt->image_name, COUNTER_CPU_PREFIX, FIELDS_METRIC, COUNTER_CPU_USER,
                       DESCRIPTION_CPU_USER, NULL, cnt->cpu_user);
        create_counter(ctx, &ctx->c_cpu, cnt->id, cnt->name, cnt->image_name, COUNTER_CPU_PREFIX, FIELDS_METRIC, COUNTER_CPU,
                       DESCRIPTION_CPU, NULL, cnt->cpu);
        mk_list_foreach_safe(inner_head, inner_tmp, &cnt->net_data)
        {
            iface = mk_list_entry(inner_head, struct net_iface, _head);
            create_counter(ctx, &ctx->rx_bytes, cnt->id, cnt->name, cnt->image_name, COUNTER_NETWORK_PREFIX, FIELDS_METRIC_WITH_IFACE, COUNTER_RX_BYTES,
                           DESCRIPTION_RX_BYTES, iface->name, iface->rx_bytes);
            create_counter(ctx, &ctx->rx_errors, cnt->id, cnt->name, cnt->image_name, COUNTER_NETWORK_PREFIX, FIELDS_METRIC_WITH_IFACE, COUNTER_RX_ERRORS,
                           DESCRIPTION_RX_ERRORS, iface->name, iface->rx_errors);
            create_counter(ctx, &ctx->tx_bytes, cnt->id, cnt->name, cnt->image_name, COUNTER_NETWORK_PREFIX, FIELDS_METRIC_WITH_IFACE, COUNTER_TX_BYTES,
                           DESCRIPTION_TX_BYTES, iface->name, iface->tx_bytes);
            create_counter(ctx, &ctx->tx_errors, cnt->id, cnt->name, cnt->image_name, COUNTER_NETWORK_PREFIX, FIELDS_METRIC_WITH_IFACE, COUNTER_TX_ERRORS,
                           DESCRIPTION_TX_ERRORS, iface->name, iface->tx_errors);
            /* Stop recreating after first iteration, at this point we cleared all counters/gauges */
            ctx->recreate_cmt = FLB_FALSE;
        }

        // Do it again in case of previous loop not looping at all
        ctx->recreate_cmt = FLB_FALSE;
    }
    return 0;
}

/* Main function. Destroy (optionally) previous data, gather container data and
 * create counters.
 */
static int scrape_metrics(struct flb_config *config, struct flb_in_metrics *ctx)
{
    uint64_t start_ts = cfl_time_now();
    flb_plg_debug(ctx->ins, "Starting to scrape podman metrics");
    if (destroy_container_list(ctx) == -1) {
        flb_plg_error(ctx->ins, "Could not destroy previous container data");
        return -1;
    }

    if (collect_container_data(ctx, FLB_FALSE) == -1) {
        flb_plg_error(ctx->ins, "Could not collect container ids");
        return -1;
    }

    if (collect_sysfs_directories(ctx, ctx->sysfs_path) == -1)
    {
        flb_plg_error(ctx->ins, "Could not collect sysfs data");
        return -1;
    }

    if (ctx->cgroup_version == CGROUP_V1) {
        if (fill_counters_with_sysfs_data_v1(ctx) == -1) {
            flb_plg_error(ctx->ins, "Could not collect V1 sysfs data");
            return -1;
        }
    }
    else if (ctx->cgroup_version == CGROUP_V2) {
        if (fill_counters_with_sysfs_data_v2(ctx) == -1) {
            flb_plg_error(ctx->ins, "Could not collect V2 sysfs data");
            return -1;
        }
    }

    if (create_counters(ctx) == -1) {
        flb_plg_error(ctx->ins, "Could not create container counters");
        return -1;
    }

    if (flb_input_metrics_append(ctx->ins, NULL, 0, ctx->ins->cmt) == -1) {
        flb_plg_error(ctx->ins, "Could not append metrics");
        return -1;
    }

    flb_plg_info(ctx->ins, "Scraping metrics took %luns", cfl_time_now() - start_ts);
    return 0;
}

/*
 * Call scrape_metrics function every `scrape interval`.
 */
static int cb_metrics_collect_runtime(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    return scrape_metrics(config, in_context);
}

/*
 * Initialize plugin, setup config file path and (optionally) scrape container
 * data (if `scrape_at_start` is set).
 */
static int in_metrics_init(struct flb_input_instance *in, struct flb_config *config, void *data)
{
    struct flb_in_metrics *ctx;
    int coll_fd_runtime;

    ctx = flb_calloc(1, sizeof(struct flb_in_metrics));
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;

    ctx->c_memory_usage = NULL;
    ctx->c_memory_max_usage = NULL;
    ctx->g_rss = NULL;
    ctx->c_memory_limit = NULL;
    ctx->c_cpu_user = NULL;
    ctx->c_cpu = NULL;
    ctx->rx_bytes = NULL;
    ctx->rx_errors = NULL;
    ctx->tx_bytes = NULL;
    ctx->tx_errors = NULL;

    ctx->recreate_cmt = FLB_FALSE;

    if (flb_input_config_map_set(in, (void *) ctx) == -1) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);
    coll_fd_runtime = flb_input_set_collector_time(in, cb_metrics_collect_runtime, ctx->scrape_interval, 0, config);
    if (coll_fd_runtime == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for podman metrics plugin");
        return -1;
    }
    ctx->coll_fd_runtime = coll_fd_runtime;

    if (ctx->podman_config_path) {
        flb_plg_info(ctx->ins, "Using config file %s", ctx->podman_config_path);
        ctx->config = flb_sds_create(ctx->podman_config_path);
    }
    else {
        flb_plg_info(ctx->ins, "Using default config file %s", PODMAN_CONFIG_DEFAULT_PATH);
        ctx->config = flb_sds_create(PODMAN_CONFIG_DEFAULT_PATH);
    }

    if (get_cgroup_version(ctx) == CGROUP_V2) {
        flb_plg_info(ctx->ins, "Detected cgroups v2");
        ctx->cgroup_version = CGROUP_V2;
    }
    else {
        flb_plg_info(ctx->ins, "Detected cgroups v1");
        ctx->cgroup_version = CGROUP_V1;
    }

    mk_list_init(&ctx->items);
    mk_list_init(&ctx->sysfs_items);
    mk_list_init(&ctx->ids);

    if (ctx->scrape_interval >= 2 && ctx->scrape_on_start) {
        flb_plg_info(ctx->ins, "Generating podman metrics (initial scrape)");
        if (scrape_metrics(config, ctx) == -1) {
            flb_plg_error(ctx->ins, "Could not start collector for podman metrics plugin");
            flb_sds_destroy(ctx->config);
            destroy_container_list(ctx);
            flb_free(ctx);
            return -1;
        }
    }

    flb_plg_info(ctx->ins, "Generating podman metrics");

    return 0;
}

/*
 * Function called at plugin exit - destroy collected container data list.
 */
static int in_metrics_exit(void *data, struct flb_config *config)
{
    struct flb_in_metrics *ctx = data;

    if (!ctx) {
        return 0;
    }

    destroy_container_list(ctx);
    flb_sds_destroy(ctx->config);
    flb_free(ctx);
    return 0;
}

/*
 * Function called at plugin pause.
 */
static void in_metrics_pause(void *data, struct flb_config *config)
{
    struct flb_in_metrics *ctx = data;
    flb_input_collector_pause(ctx->coll_fd_runtime, ctx->ins);
}

/*
 * Function called at plugin resume.
 */
static void in_metrics_resume(void *data, struct flb_config *config)
{
    struct flb_in_metrics *ctx = data;
    flb_input_collector_resume(ctx->coll_fd_runtime, ctx->ins);
}
