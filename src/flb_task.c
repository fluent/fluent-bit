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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_time.h>
#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif
#include <string.h>

/*
 * Every task created must have an unique ID, this function lookup the
 * lowest number available in the task_map.
 *
 * This 'id' is used by the task interface to communicate with the engine event
 * loop about some action.
 */

static inline int map_get_task_id(struct flb_config *config)
{
    int result;
    int i;

    for (i = 0; i < config->task_map_size ; i++) {
        if (config->task_map[i].task == NULL) {
            return i;
        }
    }

    result = flb_config_task_map_grow(config);

    if (result == 0) {
        return i;
    }

    return -1;
}

static inline void map_set_task_id(int id, struct flb_task *task,
                                   struct flb_config *config)
{
    config->task_map[id].task = task;

}

static inline void map_free_task_id(int id, struct flb_config *config)
{
    config->task_map[id].task = NULL;
}

#ifdef FLB_HAVE_METRICS
static void record_unmatched_route_drop_metrics(struct flb_input_instance *ins,
                                                struct flb_input_chunk *ic,
                                                size_t chunk_size)
{
    struct flb_router *router;
    uint64_t now;
    double dropped_bytes;
    char *labels[2];

    if (!ins || !ic || !ins->config) {
        return;
    }

    if (ic->event_type != FLB_INPUT_LOGS || ic->total_records <= 0) {
        return;
    }

    router = ins->config->router;
    if (!router) {
        return;
    }

    now = cfl_time_now();
    labels[0] = (char *) flb_input_name(ins);
    labels[1] = "unmatched";

    dropped_bytes = (double) chunk_size;
    if (dropped_bytes <= 0) {
        ssize_t real_size;

        real_size = flb_input_chunk_get_real_size(ic);
        if (real_size > 0) {
            dropped_bytes = (double) real_size;
        }
        else {
            dropped_bytes = 0;
        }
    }

    cmt_counter_add(router->logs_drop_records_total,
                    now,
                    (double) ic->total_records,
                    2,
                    labels);

    cmt_counter_add(router->logs_drop_bytes_total,
                    now,
                    dropped_bytes,
                    2,
                    labels);
}
#endif

static int task_collect_output_references(struct flb_config *config,
                                          const struct flb_chunk_direct_route *route,
                                          struct flb_output_instance ***out_matches,
                                          size_t *out_count)
{
    size_t index;
    size_t count;
    int alias_length;
    int label_length;
    int name_length;
    const char *label;
    uint32_t stored_id;
    struct mk_list *head;
    struct flb_output_instance *o_ins;
    struct flb_output_instance **matches;

    if (!config || !route || !out_matches || !out_count) {
        return -1;
    }

    *out_matches = NULL;
    *out_count = 0;

    label = route->label;
    label_length = 0;
    stored_id = route->id;
    if (label != NULL) {
        label_length = route->label_length;
        if (label_length == 0) {
            label_length = (int) strlen(label);
        }
    }

    count = 0;
    if (label != NULL && label_length > 0) {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if (o_ins->alias != NULL) {
                alias_length = (int) strlen(o_ins->alias);
                if (alias_length == label_length &&
                    strncmp(o_ins->alias, label, (size_t) label_length) == 0 &&
                    flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                    count++;
                }
            }
        }

        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            name_length = (int) strlen(o_ins->name);
            if (name_length == label_length &&
                strncmp(o_ins->name, label, (size_t) label_length) == 0 &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                if (o_ins->alias != NULL) {
                    alias_length = (int) strlen(o_ins->alias);
                    if (alias_length == label_length &&
                        strncmp(o_ins->alias, label, (size_t) label_length) == 0) {
                        continue;
                    }
                }
                count++;
            }
        }

        if (count == 0) {
            return 0;
        }
    }
    else {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if ((uint32_t) o_ins->id == stored_id &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                count++;
            }
        }

        if (count == 0) {
            return 0;
        }
    }

    matches = flb_calloc(count, sizeof(struct flb_output_instance *));
    if (!matches) {
        flb_errno();
        return -1;
    }

    index = 0;
    if (label != NULL && label_length > 0) {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if (o_ins->alias != NULL) {
                alias_length = (int) strlen(o_ins->alias);
                if (alias_length == label_length &&
                    strncmp(o_ins->alias, label, (size_t) label_length) == 0 &&
                    flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                    matches[index++] = o_ins;
                }
            }
        }

        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            name_length = (int) strlen(o_ins->name);
            if (name_length == label_length &&
                strncmp(o_ins->name, label, (size_t) label_length) == 0 &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                if (o_ins->alias != NULL) {
                    alias_length = (int) strlen(o_ins->alias);
                    if (alias_length == label_length &&
                        strncmp(o_ins->alias, label, (size_t) label_length) == 0) {
                        continue;
                    }
                }
                matches[index++] = o_ins;
            }
        }
    }
    else {
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if ((uint32_t) o_ins->id == stored_id &&
                flb_chunk_route_plugin_matches(o_ins, route) == FLB_TRUE) {
                matches[index++] = o_ins;
            }
        }
    }

    *out_matches = matches;
    *out_count = index;

    return 0;
}

void flb_task_retry_destroy(struct flb_task_retry *retry)
{
    int ret;

    /* Make sure to invalidate any request from the scheduler */
    ret = flb_sched_request_invalidate(retry->parent->config, retry);
    if (ret == 0) {
        flb_debug("[retry] task retry=%p, invalidated from the scheduler",
                  retry);
    }

    mk_list_del(&retry->_head);
    flb_free(retry);
}

/*
 * For an existing task 'retry', re-schedule it. One of the use case of this function
 * is when the engine dispatcher fails to bring the chunk up due to Chunk I/O
 * configuration restrictions, the task needs to be re-scheduled.
 */
int flb_task_retry_reschedule(struct flb_task_retry *retry, struct flb_config *config)
{
    int seconds;
    struct flb_task *task;

    task = retry->parent;
    seconds = flb_sched_request_create(config, retry, retry->attempts);
    if (seconds == -1) {
        /*
         * This is the worse case scenario: 'cannot re-schedule a retry'. If the Chunk
         * resides only in memory, it will be lost.  */
        flb_warn("[task] retry for task %i could not be re-scheduled", task->id);
        flb_task_retry_destroy(retry);
        if (task->users == 0 && mk_list_size(&task->retries) == 0) {
            flb_task_destroy(task, FLB_TRUE);
        }
        return -1;
    }
    else {
        flb_info("[task] re-schedule retry=%p %i in the next %i seconds",
                  retry, task->id, seconds);
    }

    return 0;
}

struct flb_task_retry *flb_task_retry_create(struct flb_task *task,
                                             struct flb_output_instance *ins)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_task_retry *retry = NULL;

    /* First discover if is there any previous retry context in the task */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        if (retry->o_ins == ins) {
            if (retry->attempts >= ins->retry_limit && ins->retry_limit >= 0) {
                flb_debug("[task] task_id=%i reached retry-attempts limit %i/%i",
                          task->id, retry->attempts, ins->retry_limit);
                flb_task_retry_destroy(retry);
                return NULL;
            }
            break;
        }
        retry = NULL;
    }

    if (!retry) {
        /* Create a new re-try instance */
        retry = flb_malloc(sizeof(struct flb_task_retry));
        if (!retry) {
            flb_errno();
            return NULL;
        }

        retry->attempts = 1;
        retry->o_ins   = ins;
        retry->parent  = task;
        mk_list_add(&retry->_head, &task->retries);

        flb_debug("[retry] new retry created for task_id=%i attempts=%i",
                  task->id, retry->attempts);
    }
    else {
        retry->attempts++;
        flb_debug("[retry] re-using retry for task_id=%i attempts=%i",
                  task->id, retry->attempts);
    }

    /*
     * This 'retry' was issued by an output plugin, from an Engine perspective
     * we need to determinate if the source input plugin have some memory
     * restrictions and if the Storage type is 'filesystem' we need to put
     * the file content down.
     *
     * Note that we can only put the chunk down if there are no more active users
     * otherwise it can lead to a corruption (https://github.com/fluent/fluent-bit/issues/8691)
     */

    if (task->users <= 1) {
        flb_input_chunk_set_up_down(task->ic);
    }

    /*
     * Besides limits adjusted above, a retry that's going to only one place
     * must be down.
     */
    if (mk_list_size(&task->routes) == 1) {
        flb_input_chunk_down(task->ic);
    }

    return retry;
}

/*
 * Return FLB_TRUE or FLB_FALSE if the chunk pointed by the task was
 * created on this running instance or it comes from a chunk in the
 * filesystem from a previous run.
 */
int flb_task_from_fs_storage(struct flb_task *task)
{
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) task->ic;
    return ic->fs_backlog;
}

int flb_task_retry_count(struct flb_task *task, void *data)
{
    struct mk_list *head;
    struct flb_task_retry *retry;
    struct flb_output_instance *o_ins;

    o_ins = (struct flb_output_instance *) data;

    mk_list_foreach(head, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);

        if (retry->o_ins == o_ins) {
            return retry->attempts;
        }
    }

    return -1;
}

/* Check if a 'retry' context exists for a specific task, if so, cleanup */
int flb_task_retry_clean(struct flb_task *task, struct flb_output_instance *ins)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task_retry *retry;

    /* Delete 'retries' only associated with the output instance */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        if (retry->o_ins == ins) {
            flb_task_retry_destroy(retry);
            return 0;
        }
    }

    return -1;
}

/* Allocate an initialize a basic Task structure */
struct flb_task *task_alloc(struct flb_config *config)
{
    int task_id;
    struct flb_task *task;

    /* Allocate the new task */
    task = (struct flb_task *) flb_calloc(1, sizeof(struct flb_task));
    if (!task) {
        flb_errno();
        return NULL;
    }

    /* Get ID and set back 'task' reference */
    task_id = map_get_task_id(config);
    if (task_id == -1) {
        flb_free(task);
        return NULL;
    }

    map_set_task_id(task_id, task, config);

    flb_trace("[task %p] created (id=%i)", task, task_id);

    /* Initialize minimum variables */
    task->id        = task_id;
    task->config    = config;
    task->status    = FLB_TASK_NEW;
    task->users     = 0;
    mk_list_init(&task->routes);
    mk_list_init(&task->retries);

    pthread_mutex_init(&task->lock, NULL);

    return task;
}

/* Return the number of tasks with 'running status' or tasks with retries */
int flb_task_running_count(struct flb_config *config)
{
    int count = 0;
    struct mk_list *head;
    struct mk_list *t_head;
    struct flb_task *task;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        mk_list_foreach(t_head, &ins->tasks) {
            task = mk_list_entry(t_head, struct flb_task, _head);
            if (task->users > 0 || mk_list_size(&task->retries) > 0) {
                count++;
            }
        }
    }

    return count;
}

int flb_task_running_print(struct flb_config *config)
{
    int count = 0;
    flb_sds_t tmp;
    flb_sds_t routes;
    struct mk_list *head;
    struct mk_list *t_head;
    struct mk_list *r_head;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_input_instance *ins;

    routes = flb_sds_create_size(256);
    if (!routes) {
        flb_error("[task] cannot allocate space to report pending tasks");
        return -1;
    }

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        count = mk_list_size(&ins->tasks);
        flb_info("[task] %s/%s has %i pending task(s):",
                 ins->p->name, flb_input_name(ins), count);
        mk_list_foreach(t_head, &ins->tasks) {
            task = mk_list_entry(t_head, struct flb_task, _head);

            mk_list_foreach(r_head, &task->routes) {
                route = mk_list_entry(r_head, struct flb_task_route, _head);
                tmp = flb_sds_printf(&routes, "%s/%s ",
                                     route->out->p->name,
                                     flb_output_name(route->out));
                if (!tmp) {
                    flb_sds_destroy(routes);
                    flb_error("[task] cannot print report for pending tasks");
                    return -1;
                }
                routes = tmp;
            }

            flb_info("[task]   task_id=%i still running on route(s): %s",
                     task->id, routes);
            flb_sds_len_set(routes, 0);
        }
    }
    flb_sds_destroy(routes);
    return 0;
}

int flb_task_map_get_task_id(struct flb_config *config) {
    return map_get_task_id(config);
}

/* Create an engine task to handle the output plugin flushing work */
struct flb_task *flb_task_create(uint64_t ref_id,
                                 const char *buf,
                                 size_t size,
                                 struct flb_input_instance *i_ins,
                                 struct flb_input_chunk *ic,
                                 const char *tag_buf, int tag_len,
                                 struct flb_config *config,
                                 int *err)
{
    int count = 0;
    int total_events = 0;
    int direct_count = 0;
    int stored_routes_result = 0;
    int ret = 0;
    int stored_routes_used = FLB_FALSE;
    int stored_routes_valid = FLB_TRUE;
    int stored_routes_alloc_failed = FLB_FALSE;
    int direct_output_count = 0;
    int direct_output_index = 0;
    uint32_t missing_output_id = 0;
    uint16_t missing_output_label_length = 0;
    const char *missing_output_label;
    struct flb_output_instance **stored_matches;
    size_t stored_match_count;
    size_t stored_match_index;
    struct flb_task *task;
    struct flb_event_chunk *evc;
    struct flb_task_route *route;
    struct flb_router_path *route_path;
    struct flb_output_instance *o_ins;
    struct flb_input_chunk *task_ic;
    struct cfl_list *i_head;
    struct mk_list *o_head;
    struct flb_router_chunk_context router_context;
    int router_context_initialized = FLB_FALSE;
    struct flb_chunk_direct_route *direct_routes;

    /* No error status */
    *err = FLB_FALSE;

    /* allocate task */
    task = task_alloc(config);
    if (!task) {
        *err = FLB_TRUE;
        return NULL;
    }

    total_events = ((struct flb_input_chunk *) ic)->total_records;

    /* event chunk */
    evc = flb_event_chunk_create(ic->event_type,
                                 total_events,
                                 (char *) tag_buf, tag_len,
                                 (char *) buf, size);
    if (!evc) {
        flb_free(task);
        *err = FLB_TRUE;
        return NULL;
    }

    if (flb_router_chunk_context_init(&router_context) != 0) {
        flb_error("[task] failed to initialize router chunk context");
        flb_event_chunk_destroy(evc);
        flb_free(task);
        *err = FLB_TRUE;
        return NULL;
    }
    router_context_initialized = FLB_TRUE;

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ic->trace) {
        flb_debug("add trace to task");
        evc->trace = ic->trace;
    }
#endif

    task->event_chunk = evc;
    task_ic = (struct flb_input_chunk *) ic;
    task_ic->task = task;

    /* Keep track of origins */
    task->ref_id = ref_id;
    task->i_ins  = i_ins;
    task->ic     = ic;
    mk_list_add(&task->_head, &i_ins->tasks);

#ifdef FLB_HAVE_METRICS
    task->records = ((struct flb_input_chunk *) ic)->total_records;
#endif

    /* Direct connects betweek input <> outputs (API based) */
    direct_routes = NULL;
    missing_output_label = NULL;
    missing_output_label_length = 0;
    if (flb_input_chunk_has_direct_routes(task_ic) == FLB_TRUE) {
        stored_routes_result = flb_input_chunk_get_direct_routes(task_ic,
                                                                 &direct_routes,
                                                                 &direct_output_count);
        if (stored_routes_result == 0 && direct_output_count > 0) {
            stored_routes_valid = FLB_TRUE;
            missing_output_id = 0;
            for (direct_output_index = 0;
                 direct_output_index < direct_output_count;
                 direct_output_index++) {
                stored_matches = NULL;
                stored_match_count = 0;
                ret = task_collect_output_references(config,
                                                     &direct_routes[direct_output_index],
                                                     &stored_matches,
                                                     &stored_match_count);
                if (ret == -1) {
                    flb_error("[task] failed collecting restored routes for chunk %s",
                              flb_input_chunk_get_name(task_ic));
                }

                if (ret != 0 || stored_match_count == 0) {
                    stored_routes_valid = FLB_FALSE;
                    missing_output_id = direct_routes[direct_output_index].id;
                    missing_output_label = direct_routes[direct_output_index].label;
                    missing_output_label_length = direct_routes[direct_output_index].label_length;
                    if (missing_output_label_length == 0 && missing_output_label != NULL) {
                        missing_output_label_length = (uint16_t) strlen(missing_output_label);
                    }
                    if (stored_matches != NULL) {
                        flb_free(stored_matches);
                    }
                    break;
                }

                if (stored_matches != NULL) {
                    flb_free(stored_matches);
                }
            }

            if (stored_routes_valid == FLB_TRUE) {
                direct_count = 0;
                stored_routes_alloc_failed = FLB_FALSE;
                for (direct_output_index = 0;
                     direct_output_index < direct_output_count;
                     direct_output_index++) {
                    stored_matches = NULL;
                    stored_match_count = 0;
                    ret = task_collect_output_references(config,
                                                         &direct_routes[direct_output_index],
                                                         &stored_matches,
                                                         &stored_match_count);
                    if (ret != 0 || stored_match_count == 0 || stored_matches == NULL) {
                        if (stored_matches != NULL) {
                            flb_free(stored_matches);
                        }
                        continue;
                    }

                    for (stored_match_index = 0;
                         stored_match_index < stored_match_count;
                         stored_match_index++) {
                        route = flb_calloc(1, sizeof(struct flb_task_route));
                        if (!route) {
                            flb_errno();
                            stored_routes_alloc_failed = FLB_TRUE;
                            break;
                        }

                        route->status = FLB_TASK_ROUTE_INACTIVE;
                        route->out = stored_matches[stored_match_index];
                        mk_list_add(&route->_head, &task->routes);
                        direct_count++;
                    }

                    flb_free(stored_matches);

                    if (stored_routes_alloc_failed == FLB_TRUE) {
                        break;
                    }
                }

                if (stored_routes_alloc_failed == FLB_TRUE) {
                    if (router_context_initialized) {
                        flb_router_chunk_context_destroy(&router_context);
                        router_context_initialized = FLB_FALSE;
                    }
                    if (direct_routes) {
                        flb_input_chunk_destroy_direct_routes(direct_routes,
                                                              direct_output_count);
                    }
                    task->event_chunk->data = NULL;
                    flb_task_destroy(task, FLB_TRUE);
                    return NULL;
                }

                if (direct_count > 0) {
                    stored_routes_used = FLB_TRUE;
                }
            }
            else {
                flb_warn("[task] input=%s/%s stored direct route id=%u label=%.*s not found for chunk %s, falling back to configured routes",
                         i_ins->p->name,
                         flb_input_name(i_ins),
                         (unsigned int) missing_output_id,
                         (int) missing_output_label_length,
                         missing_output_label ? missing_output_label : "",
                         flb_input_chunk_get_name(task_ic));
            }
        }
        else if (stored_routes_result == -2) {
            flb_warn("[task] input=%s/%s invalid stored direct routing metadata for chunk %s, falling back to configured routes",
                     i_ins->p->name,
                     flb_input_name(i_ins),
                     flb_input_chunk_get_name(task_ic));
        }
    }

    if (stored_routes_used == FLB_TRUE) {
        if (direct_routes) {
            flb_input_chunk_destroy_direct_routes(direct_routes, direct_output_count);
        }
        flb_debug("[task] restored direct task=%p id=%i with %i route(s)",
                  task, task->id, direct_count);
        if (router_context_initialized) {
            flb_router_chunk_context_destroy(&router_context);
            router_context_initialized = FLB_FALSE;
        }
        return task;
    }

    if (direct_routes) {
        flb_input_chunk_destroy_direct_routes(direct_routes, direct_output_count);
        direct_routes = NULL;
    }

    if (cfl_list_size(&i_ins->routes_direct) > 0) {
        direct_count = 0;

        cfl_list_foreach(i_head, &i_ins->routes_direct) {
            route_path = cfl_list_entry(i_head, struct flb_router_path, _head);

            if (flb_router_path_should_route(task->event_chunk,
                                             &router_context,
                                             route_path) == FLB_FALSE) {
                continue;
            }

            o_ins = route_path->ins;

            /* For conditional routing, also check the route mask */
            if (task_ic->routes_mask) {
                if (flb_routes_mask_get_bit(task_ic->routes_mask,
                                            o_ins->id,
                                            o_ins->config->router) == 0) {
                    continue;
                }
            }

            route = flb_calloc(1, sizeof(struct flb_task_route));
            if (!route) {
                flb_errno();
                if (router_context_initialized) {
                    flb_router_chunk_context_destroy(&router_context);
                    router_context_initialized = FLB_FALSE;
                }
                task->event_chunk->data = NULL;
                flb_task_destroy(task, FLB_TRUE);
                return NULL;
            }

            route->status = FLB_TASK_ROUTE_INACTIVE;
            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
            direct_count++;
        }

        if (direct_count == 0) {
            flb_debug("[task] dropping direct task=%p id=%i without matching routes",
                      task, task->id);
            if (router_context_initialized) {
                flb_router_chunk_context_destroy(&router_context);
                router_context_initialized = FLB_FALSE;
            }
            task->event_chunk->data = NULL;
            flb_task_destroy(task, FLB_TRUE);
            return NULL;
        }

        flb_debug("[task] created direct task=%p id=%i with %i route(s)",
                  task, task->id, direct_count);
        if (router_context_initialized) {
            flb_router_chunk_context_destroy(&router_context);
            router_context_initialized = FLB_FALSE;
        }
        return task;
    }

    /* Find matching routes for the incoming task */
    mk_list_foreach(o_head, &config->outputs) {
        o_ins = mk_list_entry(o_head,
                              struct flb_output_instance, _head);

        /* skip output plugins that don't handle proper event types */
        if (!flb_router_match_type(ic->event_type, o_ins)) {
            continue;
        }

        if (flb_routes_mask_get_bit(task_ic->routes_mask,
                                    o_ins->id,
                                    o_ins->config->router) != 0) {
            route = flb_calloc(1, sizeof(struct flb_task_route));
            if (!route) {
                flb_errno();
                continue;
            }

            route->status = FLB_TASK_ROUTE_INACTIVE;
            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
            count++;
        }
    }

    /* no destinations ?, useless task. */
    if (count == 0) {
#ifdef FLB_HAVE_METRICS
        record_unmatched_route_drop_metrics(i_ins, task_ic, size);
#endif
        flb_debug("[task] created task=%p id=%i without routes, dropping.",
                  task, task->id);
        if (router_context_initialized) {
            flb_router_chunk_context_destroy(&router_context);
            router_context_initialized = FLB_FALSE;
        }
        task->event_chunk->data = NULL;
        flb_task_destroy(task, FLB_TRUE);
        return NULL;
    }

    if (router_context_initialized) {
        flb_router_chunk_context_destroy(&router_context);
        router_context_initialized = FLB_FALSE;
    }
    flb_debug("[task] created task=%p id=%i OK", task, task->id);
    return task;
}

void flb_task_destroy(struct flb_task *task, int del)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task_route *route;
    struct flb_task_retry *retry;

    flb_debug("[task] destroy task=%p (task_id=%i)", task, task->id);

    /* Release task_id */
    map_free_task_id(task->id, task->config);

    /* Remove routes */
    mk_list_foreach_safe(head, tmp, &task->routes) {
        route = mk_list_entry(head, struct flb_task_route, _head);
        mk_list_del(&route->_head);
        flb_free(route);
    }

    /* Unlink and release task */
    if (!mk_list_entry_is_orphan(&task->_head)) {
        mk_list_del(&task->_head);
    }

    /* destroy chunk */
    if (task->ic != NULL) {
        flb_input_chunk_destroy(task->ic, del);
    }

    /* Remove 'retries' */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);

        flb_task_retry_destroy(retry);
    }

    if (task->i_ins != NULL) {
        flb_input_chunk_set_limits(task->i_ins);
    }

    if (task->event_chunk != NULL) {
        flb_event_chunk_destroy(task->event_chunk);
    }

    flb_free(task);
}

struct flb_task_queue* flb_task_queue_create() {
    struct flb_task_queue *tq;
    tq = flb_malloc(sizeof(struct flb_task_queue));
    if (!tq) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&tq->pending);
    mk_list_init(&tq->in_progress);
    return tq;
}

void flb_task_queue_destroy(struct flb_task_queue *queue) {
    struct flb_task_enqueued *queued_task;
    struct mk_list *tmp;
    struct mk_list *head;

    mk_list_foreach_safe(head, tmp, &queue->pending) {
        queued_task = mk_list_entry(head, struct flb_task_enqueued, _head);
        mk_list_del(&queued_task->_head);
        flb_free(queued_task);
    }

    mk_list_foreach_safe(head, tmp, &queue->in_progress) {
        queued_task = mk_list_entry(head, struct flb_task_enqueued, _head);
        mk_list_del(&queued_task->_head);
        flb_free(queued_task);
    }

    flb_free(queue);
}
