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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_key.h>
#include <fluent-bit/stream_processor/flb_sp_stream.h>
#include <fluent-bit/stream_processor/flb_sp_snapshot.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_func_time.h>
#include <fluent-bit/stream_processor/flb_sp_func_record.h>
#include <fluent-bit/stream_processor/flb_sp_aggregate_func.h>
#include <fluent-bit/stream_processor/flb_sp_window.h>
#include <fluent-bit/stream_processor/flb_sp_groupby.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/* don't do this at home */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

/* String type to numerical conversion */
#define FLB_STR_INT   1
#define FLB_STR_FLOAT 2

/* Read and process file system configuration file */
static int sp_config_file(struct flb_config *config, struct flb_sp *sp,
                          const char *file)
{
    int ret;
    flb_sds_t name;
    flb_sds_t exec;
    char *cfg = NULL;
    char tmp[PATH_MAX + 1];
    struct stat st;
    struct mk_list *head;
    struct flb_sp_task *task;
    struct flb_cf *cf;
    struct flb_cf_section *section;

#ifndef FLB_HAVE_STATIC_CONF
    ret = stat(file, &st);
    if (ret == -1 && errno == ENOENT) {
        /* Try to resolve the real path (if exists) */
        if (file[0] == '/') {
            flb_error("[sp] cannot open configuration file: %s", file);
            return -1;
        }

        if (config->conf_path) {
            snprintf(tmp, PATH_MAX, "%s%s", config->conf_path, file);
            cfg = tmp;
        }
    }
    else {
        cfg = (char *) file;
    }

    cf = flb_cf_create_from_file(NULL, cfg);
#else
    cf = flb_config_static_open(file);
#endif

    if (!cf) {
        return -1;
    }

    /*
     * Note on reading the sections
     * ----------------------------
     * Classic mode configuration looks for [STREAM_TASK], while the
     * new Yaml parser expects the section names to be stream_processor.
     *
     * On Yaml mode, each pair of "name/exec" is set as an independent section,
     * so the adjusted code below works for both type of files.
     */
    mk_list_foreach(head, &cf->sections) {
        section = mk_list_entry(head, struct flb_cf_section, _head);
        if (strcasecmp(section->name, "stream_task") != 0 &&
            strcasecmp(section->name, "stream_processor") != 0) {
            continue;
        }

        name = NULL;
        exec = NULL;

        /* name */
        name = flb_cf_section_property_get_string(cf, section, "name");
        if (!name) {
            flb_error("[sp] task 'name' not found in file '%s'", cfg);
            goto fconf_error;
        }

        /* exec */
        exec = flb_cf_section_property_get_string(cf, section, "exec");
        if (!exec) {
            flb_error("[sp] task '%s' don't have an 'exec' command", name);
            goto fconf_error;
        }

        /* Register the task */
        task = flb_sp_task_create(sp, name, exec);
        if (!task) {
            goto fconf_error;
        }
        flb_sds_destroy(name);
        flb_sds_destroy(exec);
        name = NULL;
        exec = NULL;
    }

    flb_cf_destroy(cf);
    return 0;

fconf_error:
    if (name) {
        flb_sds_destroy(name);
    }
    if (exec) {
        flb_sds_destroy(exec);
    }
    flb_cf_destroy(cf);
    return -1;
}

static int sp_task_to_instance(struct flb_sp_task *task, struct flb_sp *sp)
{
    struct mk_list *head;
    struct flb_input_instance *in;

    if (task->cmd->source_type != FLB_SP_STREAM) {
        return -1;
    }

    mk_list_foreach(head, &sp->config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if (in->alias) {
            if (strcasecmp(in->alias, task->cmd->source_name) == 0) {
                task->source_instance = in;
                return 0;
            }
        }

        if (strcasecmp(in->name, task->cmd->source_name) == 0) {
            task->source_instance = in;
            return 0;
        }
    }

    return -1;
}

static void sp_info(struct flb_sp *sp)
{
    struct mk_list *head;
    struct flb_sp_task *task;

    flb_info("[sp] stream processor started");

    mk_list_foreach(head, &sp->tasks) {
        task = mk_list_entry(head, struct flb_sp_task, _head);
        flb_info("[sp] registered task: %s", task->name);
    }
}

int subkeys_compare(struct mk_list *subkeys1, struct mk_list *subkeys2)
{
    int i;
    struct flb_slist_entry *entry1;
    struct flb_slist_entry *entry2;

    if (!subkeys1 && !subkeys2) {
        return 0;
    }

    if (!subkeys1 || !subkeys2) {
        return -1;
    }

    if (mk_list_size(subkeys1) != mk_list_size(subkeys2)) {
        return -1;
    }

    entry1 = mk_list_entry_first(subkeys1, struct flb_slist_entry, _head);
    entry2 = mk_list_entry_first(subkeys2, struct flb_slist_entry, _head);

    for (i = 0; i < mk_list_size(subkeys1); i++) {
        if (flb_sds_cmp(entry1->str, entry2->str, flb_sds_len(entry2->str)) != 0) {
            return -1;
        }

        entry1 = mk_list_entry_next(&entry1->_head, struct flb_slist_entry,
                                    _head, subkeys1);
        entry2 = mk_list_entry_next(&entry2->_head, struct flb_slist_entry,
                                    _head, subkeys2);
    }

    return 0;
}

static int sp_cmd_aggregated_keys(struct flb_sp_cmd *cmd)
{
    int aggr = 0;
    int not_aggr = 0;
    struct mk_list *head;
    struct mk_list *head_gb;
    struct flb_sp_cmd_key *key;
    struct flb_sp_cmd_gb_key *gb_key;

    mk_list_foreach(head, &cmd->keys) {
        key = mk_list_entry(head, struct flb_sp_cmd_key, _head);
        if (key->time_func > 0 || key->record_func > 0) {
            continue;
        }

        if (key->aggr_func > 0) {
            /* AVG, SUM, COUNT or timeseries functions */
            aggr++;
        }
        else {
            mk_list_foreach(head_gb, &cmd->gb_keys) {
                gb_key = mk_list_entry(head_gb, struct flb_sp_cmd_gb_key, _head);

                if (!key->name) { /* Key name is a wildcard '*' */
                    break;
                }

                if (flb_sds_cmp(key->name, gb_key->name,
                                flb_sds_len(gb_key->name)) == 0) {
                    if (subkeys_compare(key->subkeys, gb_key->subkeys) != 0) {
                        continue;
                    }

                    not_aggr--;

                    /* Map key selector with group-by */
                    key->gb_key = gb_key;
                    break;
                }
            }

            not_aggr++;
        }
    }

    /*
     * If aggregated functions are included in the query, non-aggregated keys are
     * not allowed (except for the ones inside GROUP BY statement).
     */
    if (aggr > 0 && not_aggr == 0) {
        return aggr;
    }
    else if (aggr > 0 && not_aggr > 0) {
        return -1;
    }

    return 0;
}

/*
 * Convert a string to a numerical representation:
 *
 * - if output number is an integer, 'i' is set and returns FLB_STR_INT
 * - if output number is a float, 'd' is set and returns FLB_STR_FLOAT
 * - if no conversion is possible (not a number), returns -1
 */
static int string_to_number(const char *str, int len, int64_t *i, double *d)
{
    int c;
    int dots = 0;
    char *end;
    int64_t i_out;
    double d_out;

    /* Detect if this is a floating point number */
    for (c = 0; c < len; c++) {
        if (str[c] == '.') {
            dots++;
        }
    }

    if (dots > 1) {
        return -1;
    }
    else if (dots == 1) {
        /* Floating point number */
        errno = 0;
        d_out = strtold(str, &end);

        /* Check for various possible errors */
        if ((errno == ERANGE || (errno != 0 && d_out == 0))) {
            return -1;
        }

        if (end == str) {
            return -1;
        }

        *d = d_out;
        return FLB_STR_FLOAT;
    }
    else {
        /* Integer */
        errno = 0;
        i_out = strtoll(str, &end, 10);

        /* Check for various possible errors */
        if ((errno == ERANGE || (errno != 0 && i_out == 0))) {
            return -1;
        }

        if (end == str) {
            return -1;
        }

        *i = i_out;
        return FLB_STR_INT;
    }

    return -1;
}

/*
 * Convert a msgpack object value to a number 'if possible'. The conversion
 * result is either stored on 'i' for 64 bits integers or in 'd' for
 * float/doubles.
 *
 * This function aims to take care of strings representing a value too.
 */
static int object_to_number(msgpack_object obj, int64_t *i, double *d,
                            int convert_str_to_num)
{
    int ret;
    int64_t i_out;
    double d_out;
    char str_num[20];

    if (obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
        obj.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *i = obj.via.i64;
        return FLB_STR_INT;
    }
    else if (obj.type == MSGPACK_OBJECT_FLOAT32 ||
             obj.type == MSGPACK_OBJECT_FLOAT) {
        *d = obj.via.f64;
        return FLB_STR_FLOAT;
    }
    else if (obj.type == MSGPACK_OBJECT_STR && convert_str_to_num == FLB_TRUE) {
        /* A numeric representation of a string should not exceed 19 chars */
        if (obj.via.str.size > 19) {
            return -1;
        }

        memcpy(str_num, obj.via.str.ptr, obj.via.str.size);
        str_num[obj.via.str.size] = '\0';

        ret = string_to_number(str_num, obj.via.str.size,
                               &i_out, &d_out);
        if (ret == FLB_STR_FLOAT) {
            *d = d_out;
            return FLB_STR_FLOAT;
        }
        else if (ret == FLB_STR_INT) {
            *i = i_out;
            return FLB_STR_INT;
        }
    }

    return -1;
}

int flb_sp_snapshot_create(struct flb_sp_task *task)
{
    struct flb_sp_cmd *cmd;
    struct flb_sp_snapshot *snapshot;

    cmd = task->cmd;

    snapshot = (struct flb_sp_snapshot *) flb_calloc(1, sizeof(struct flb_sp_snapshot));
    if (!snapshot) {
        flb_error("[sp] could not create snapshot '%s'", cmd->stream_name);
        return -1;
    }

    mk_list_init(&snapshot->pages);
    snapshot->record_limit = cmd->limit;

    if (flb_sp_cmd_stream_prop_get(cmd, "seconds") != NULL) {
        snapshot->time_limit = atoi(flb_sp_cmd_stream_prop_get(cmd, "seconds"));
    }

    if (snapshot->time_limit == 0 && snapshot->record_limit == 0) {
        flb_error("[sp] could not create snapshot '%s': size is not defined",
                  cmd->stream_name);
        flb_sp_snapshot_destroy(snapshot);
        return -1;
    }

    task->snapshot = snapshot;
    return 0;
}

struct flb_sp_task *flb_sp_task_create(struct flb_sp *sp, const char *name,
                                       const char *query)
{
    int fd;
    int ret;
    struct mk_event *event;
    struct flb_sp_cmd *cmd;
    struct flb_sp_task *task;

    /*
     * Parse and validate the incoming exec query and create the 'command'
     * context (this will be associated to the task in a later step
     */
    cmd = flb_sp_cmd_create(query);

    if (!cmd) {
        flb_error("[sp] invalid query on task '%s': '%s'", name, query);
        return NULL;
    }

    /* Check if we got an invalid type due an error/restriction */
    if (cmd->status == FLB_SP_ERROR) {
        flb_error("[sp] invalid query on task '%s': '%s'", name, query);
        flb_sp_cmd_destroy(cmd);
        return NULL;
    }

    /* Create the task context */
    task = flb_calloc(1, sizeof(struct flb_sp_task));
    if (!task) {
        flb_errno();
        flb_sp_cmd_destroy(cmd);
        return NULL;
    }
    task->name = flb_sds_create(name);
    if (!task->name) {
        flb_free(task);
        flb_sp_cmd_destroy(cmd);
        return NULL;
    }

    task->query = flb_sds_create(query);
    if (!task->query) {
        flb_sds_destroy(task->name);
        flb_free(task);
        flb_sp_cmd_destroy(cmd);
        return NULL;
    }

    task->sp = sp;
    task->cmd = cmd;
    mk_list_add(&task->_head, &sp->tasks);

    /*
     * Assume no aggregated keys exists, if so, a different strategy is
     * required to process the records.
     */
    task->aggregate_keys = FLB_FALSE;

    mk_list_init(&task->window.data);
    mk_list_init(&task->window.aggregate_list);
    rb_tree_new(&task->window.aggregate_tree, flb_sp_groupby_compare);

    mk_list_init(&task->window.hopping_slot);

    /* Check and validate aggregated keys */
    ret = sp_cmd_aggregated_keys(task->cmd);
    if (ret == -1) {
        flb_error("[sp] aggregated query cannot include the aggregated keys: %s",
                  query);
        flb_sp_task_destroy(task);
        return NULL;
    }
    else if (ret > 0) {
        task->aggregate_keys = FLB_TRUE;

        task->window.type = cmd->window.type;

        /* Register a timer event when task contains aggregation rules */
        if (task->window.type != FLB_SP_WINDOW_DEFAULT) {
            /* Initialize event loop context */
            event = &task->window.event;
            MK_EVENT_ZERO(event);

            /* Run every 'window size' seconds */
            fd = mk_event_timeout_create(sp->config->evl,
                                         cmd->window.size, (long) 0,
                                         event);
            if (fd == -1) {
                flb_error("[sp] registration for task %s failed", task->name);
                flb_free(task);
                return NULL;
            }
            task->window.fd = fd;

            if (task->window.type == FLB_SP_WINDOW_HOPPING) {
                /* Initialize event loop context */
                event = &task->window.event_hop;
                MK_EVENT_ZERO(event);

                /* Run every 'size' seconds */
                fd = mk_event_timeout_create(sp->config->evl,
                                             cmd->window.advance_by, (long) 0,
                                             event);
                if (fd == -1) {
                    flb_error("[sp] registration for task %s failed", task->name);
                    flb_free(task);
                    return NULL;
                }
                task->window.advance_by = cmd->window.advance_by;
                task->window.fd_hop = fd;
                task->window.first_hop = true;
            }
        }
    }

    /* Init snapshot page list */
    if (cmd->type == FLB_SP_CREATE_SNAPSHOT) {
        if (flb_sp_snapshot_create(task) == -1) {
            flb_sp_task_destroy(task);
            return NULL;
        }
    }

    /*
     * If the task involves a stream creation (CREATE STREAM abc..), create
     * the stream.
     */
    if (cmd->type == FLB_SP_CREATE_STREAM ||
        cmd->type == FLB_SP_CREATE_SNAPSHOT ||
        cmd->type == FLB_SP_FLUSH_SNAPSHOT) {

        ret = flb_sp_stream_create(cmd->stream_name, task, sp);
        if (ret == -1) {
            flb_error("[sp] could not create stream '%s'", cmd->stream_name);
            flb_sp_task_destroy(task);
            return NULL;
        }
    }

    /*
     * Based in the command type, check if the source of data is a known
     * stream so make a reference on this task for a quick comparisson and
     * access it when processing data.
     */
    sp_task_to_instance(task, sp);
    return task;
}

void groupby_nums_destroy(struct aggregate_num *groupby_nums, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        if (groupby_nums[i].type == FLB_SP_STRING) {
            flb_sds_destroy(groupby_nums[i].string);
          }
    }

    flb_free(groupby_nums);
}

/*
 * Destroy aggregation node context: before to use this function make sure
 * to unlink from the linked list.
 */
void flb_sp_aggregate_node_destroy(struct flb_sp_cmd *cmd,
                              struct aggregate_node *aggr_node)
{
    int i;
    int key_id;
    struct mk_list *head;
    struct aggregate_num *num;
    struct flb_sp_cmd_key *ckey;

    for (i = 0; i < aggr_node->nums_size; i++) {
        num = &aggr_node->nums[i];
        if (num->type == FLB_SP_STRING) {
            flb_sds_destroy(num->string);
        }
    }

    groupby_nums_destroy(aggr_node->groupby_nums, aggr_node->groupby_keys);

    key_id = 0;
    mk_list_foreach(head, &cmd->keys) {
        ckey = mk_list_entry(head, struct flb_sp_cmd_key, _head);

        if (!ckey->aggr_func) {
            key_id++;
            continue;
        }

        aggregate_func_destroy[ckey->aggr_func - 1](aggr_node, key_id);
        key_id++;
    }

    flb_free(aggr_node->nums);
    flb_free(aggr_node->aggregate_data);
    flb_free(aggr_node);
}

void flb_sp_window_destroy(struct flb_sp_task *task)
{
    struct flb_sp_window_data *data;
    struct aggregate_node *aggr_node;
    struct flb_sp_hopping_slot *hs;
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_list *head_hs;
    struct mk_list *tmp_hs;

    mk_list_foreach_safe(head, tmp, &task->window.data) {
        data = mk_list_entry(head, struct flb_sp_window_data, _head);
        flb_free(data->buf_data);
        mk_list_del(&data->_head);
        flb_free(data);
    }

    mk_list_foreach_safe(head, tmp, &task->window.aggregate_list) {
        aggr_node = mk_list_entry(head, struct aggregate_node, _head);
        mk_list_del(&aggr_node->_head);
        flb_sp_aggregate_node_destroy(task->cmd, aggr_node);
    }

    mk_list_foreach_safe(head, tmp, &task->window.hopping_slot) {
        hs = mk_list_entry(head, struct flb_sp_hopping_slot, _head);
        mk_list_foreach_safe(head_hs, tmp_hs, &hs->aggregate_list) {
            aggr_node = mk_list_entry(head_hs, struct aggregate_node, _head);
            mk_list_del(&aggr_node->_head);
            flb_sp_aggregate_node_destroy(task->cmd, aggr_node);
        }
        rb_tree_destroy(&hs->aggregate_tree);
        flb_free(hs);
    }

    if (task->window.fd > 0) {
        mk_event_timeout_destroy(task->sp->config->evl, &task->window.event);
        mk_event_closesocket(task->window.fd);
    }

    rb_tree_destroy(&task->window.aggregate_tree);
}

void flb_sp_task_destroy(struct flb_sp_task *task)
{
    flb_sds_destroy(task->name);
    flb_sds_destroy(task->query);
    flb_sp_window_destroy(task);
    flb_sp_snapshot_destroy(task->snapshot);

    mk_list_del(&task->_head);

    if (task->stream) {
        flb_sp_stream_destroy(task->stream, task->sp);
    }

    flb_sp_cmd_destroy(task->cmd);
    flb_free(task);
}

/* Create the stream processor context */
struct flb_sp *flb_sp_create(struct flb_config *config)
{
    int i = 0;
    int ret;
    char buf[32];
    char *task_name;
    char *task_exec;
    struct mk_list *head;
    struct flb_sp *sp;
    struct flb_slist_entry *e;
    struct flb_sp_task *task;
    struct cfl_variant *var;
    struct flb_cf_section *section;

    /* Allocate context */
    sp = flb_malloc(sizeof(struct flb_sp));
    if (!sp) {
        flb_errno();
        return NULL;
    }
    sp->config = config;
    mk_list_init(&sp->tasks);

    /* Check for pre-configured Tasks (command line) */
    mk_list_foreach(head, &config->stream_processor_tasks) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        snprintf(buf, sizeof(buf) - 1, "flb-console:%i", i);
        i++;
        task = flb_sp_task_create(sp, buf, e->str);
        if (!task) {
            continue;
        }
    }

    /* register stream processor tasks registered through Yaml config */
    if (config->cf_main) {
        mk_list_foreach(head, &config->cf_main->stream_processors) {
            section = mk_list_entry(head, struct flb_cf_section, _head_section);

            /* task name */
            var = cfl_kvlist_fetch(section->properties, "name");
            if (!var || var->type != CFL_VARIANT_STRING) {
                flb_error("[sp] missing 'name' property in stream_processor section");
                continue;
            }
            task_name = var->data.as_string;

            /* task exec/query */
            var = cfl_kvlist_fetch(section->properties, "exec");
            if (!var || var->type != CFL_VARIANT_STRING) {
                flb_error("[sp] missing 'exec' property in stream_processor section");
                continue;
            }
            task_exec = var->data.as_string;

            /* create task */
            task = flb_sp_task_create(sp, task_name, task_exec);
            if (!task) {
                continue;
            }
        }
    }

    /* Lookup configuration file if any */
    if (config->stream_processor_file) {
        ret = sp_config_file(config, sp, config->stream_processor_file);
        if (ret == -1) {
            flb_error("[sp] could not initialize stream processor");
            flb_sp_destroy(sp);
            return NULL;
        }
    }

    /* Write sp info to stdout */
    sp_info(sp);

    return sp;
}

void free_value(struct flb_exp_val *v)
{
    if (!v) {
        return;
    }

    if (v->type == FLB_EXP_STRING) {
        flb_sds_destroy(v->val.string);
    }

    flb_free(v);
}

static void itof_convert(struct flb_exp_val *val)
{
    if (val->type != FLB_EXP_INT) {
        return;
    }

    val->type = FLB_EXP_FLOAT;
    val->val.f64 = (double) val->val.i64;
}

/* Convert (string) expression to number */
static void exp_string_to_number(struct flb_exp_val *val)
{
    int ret;
    int len;
    int64_t i = 0;
    char *str;
    double d = 0.0;

    len = flb_sds_len(val->val.string);
    str = val->val.string;

    ret = string_to_number(str, len, &i, &d);
    if (ret == -1) {
        return;
    }

    /* Assign to proper type */
    if (ret == FLB_STR_FLOAT) {
        flb_sds_destroy(val->val.string);
        val->type = FLB_EXP_FLOAT;
        val->val.f64 = d;
    }
    else if (ret == FLB_STR_INT) {
        flb_sds_destroy(val->val.string);
        val->type = FLB_EXP_INT;
        val->val.i64 = i;
    }
}

static void numerical_comp(struct flb_exp_val *left,
                           struct flb_exp_val *right,
                           struct flb_exp_val *result, int op)
{
    result->type = FLB_EXP_BOOL;

    if (left == NULL || right == NULL) {
        result->val.boolean = false;
        return;
    }

    /* Check if left expression value is a number, if so, convert it */
    if (left->type == FLB_EXP_STRING && right->type != FLB_EXP_STRING) {
        exp_string_to_number(left);
    }

    if (left->type == FLB_EXP_INT && right->type == FLB_EXP_FLOAT) {
        itof_convert(left);
    }
    else if (left->type == FLB_EXP_FLOAT && right->type == FLB_EXP_INT) {
        itof_convert(right);
    }

    switch (op) {
    case FLB_EXP_EQ:
        if (left->type == right->type) {
            switch(left->type) {
            case FLB_EXP_NULL:
                result->val.boolean = true;
                break;
            case FLB_EXP_BOOL:
                result->val.boolean = (left->val.boolean == right->val.boolean);
                break;
            case FLB_EXP_INT:
                result->val.boolean = (left->val.i64 == right->val.i64);
                break;
            case FLB_EXP_FLOAT:
                result->val.boolean = (left->val.f64 == right->val.f64);
                break;
            case FLB_EXP_STRING:
                if (flb_sds_len(left->val.string) !=
                    flb_sds_len(right->val.string)) {
                    result->val.boolean = false;
                }
                else if (strncmp(left->val.string, right->val.string,
                                 flb_sds_len(left->val.string)) != 0) {
                    result->val.boolean = false;
                }
                else {
                    result->val.boolean = true;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case FLB_EXP_LT:
        if (left->type == right->type) {
            switch(left->type) {
            case FLB_EXP_INT:
                result->val.boolean = (left->val.i64 < right->val.i64);
                break;
            case FLB_EXP_FLOAT:
                result->val.boolean = (left->val.f64 < right->val.f64);
                break;
            case FLB_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) < 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case FLB_EXP_LTE:
        if (left->type == right->type) {
            switch(left->type) {
            case FLB_EXP_INT:
                result->val.boolean = (left->val.i64 <= right->val.i64);
                break;
            case FLB_EXP_FLOAT:
                result->val.boolean = (left->val.f64 <= right->val.f64);
                break;
            case FLB_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) <= 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case FLB_EXP_GT:
        if (left->type == right->type) {
            switch(left->type) {
            case FLB_EXP_INT:
                result->val.boolean = (left->val.i64 > right->val.i64);
                break;
            case FLB_EXP_FLOAT:
                result->val.boolean = (left->val.f64 > right->val.f64);
                break;
            case FLB_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) > 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case FLB_EXP_GTE:
        if (left->type == right->type) {
            switch(left->type) {
            case FLB_EXP_INT:
                result->val.boolean = (left->val.i64 >= right->val.i64);
                break;
            case FLB_EXP_FLOAT:
                result->val.boolean = (left->val.f64 >= right->val.f64);
                break;
            case FLB_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) >= 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    }
}

static bool value_to_bool(struct flb_exp_val *val) {
    bool result = FLB_FALSE;

    switch (val->type) {
    case FLB_EXP_BOOL:
        result = val->val.boolean;
        break;
    case FLB_EXP_INT:
        result = val->val.i64 > 0;
        break;
    case FLB_EXP_FLOAT:
        result = val->val.f64 > 0;
        break;
    case FLB_EXP_STRING:
        result = true;
        break;
    }

    return result;
}


static void logical_operation(struct flb_exp_val *left,
                              struct flb_exp_val *right,
                              struct flb_exp_val *result, int op)
{
    bool lval;
    bool rval;

    result->type = FLB_EXP_BOOL;

    /* Null is always interpreted as false in a logical operation */
    lval = left ? value_to_bool(left) : false;
    rval = right ? value_to_bool(right) : false;

    switch (op) {
    case FLB_EXP_NOT:
        result->val.boolean = !lval;
        break;
    case FLB_EXP_AND:
        result->val.boolean = lval & rval;
        break;
    case FLB_EXP_OR:
        result->val.boolean = lval | rval;
        break;
    }
}

static struct flb_exp_val *reduce_expression(struct flb_exp *expression,
                                             const char *tag, int tag_len,
                                             struct flb_time *tms,
                                             msgpack_object *map)
{
    int operation;
    flb_sds_t s;
    flb_sds_t tmp_sds = NULL;
    struct flb_exp_key *key;
    struct flb_sp_value *sval;
    struct flb_exp_val *ret, *left, *right;
    struct flb_exp_val *result;

    if (!expression) {
        return NULL;
    }

    result = flb_calloc(1, sizeof(struct flb_exp_val));
    if (!result) {
        flb_errno();
        return NULL;
    }

    switch (expression->type) {
    case FLB_EXP_NULL:
        result->type = expression->type;
        break;
    case FLB_EXP_BOOL:
        result->type = expression->type;
        result->val.boolean = ((struct flb_exp_val *) expression)->val.boolean;
        break;
    case FLB_EXP_INT:
        result->type = expression->type;
        result->val.i64 = ((struct flb_exp_val *) expression)->val.i64;
        break;
    case FLB_EXP_FLOAT:
        result->type = expression->type;
        result->val.f64 = ((struct flb_exp_val *) expression)->val.f64;
        break;
    case FLB_EXP_STRING:
        s = ((struct flb_exp_val *) expression)->val.string;
        result->type = expression->type;
        result->val.string = flb_sds_create_size(flb_sds_len(s));
        tmp_sds = flb_sds_copy(result->val.string, s, flb_sds_len(s));
        if (tmp_sds != result->val.string) {
            result->val.string = tmp_sds;
        }
        break;
    case FLB_EXP_KEY:
        key = (struct flb_exp_key *) expression;
        sval = flb_sp_key_to_value(key->name, *map, key->subkeys);
        if (sval) {
            result->type = sval->type;
            result->val = sval->val;
            flb_free(sval);
            return result;
        }
        else {
            flb_free(result);
            return NULL;
        }
        break;
    case FLB_EXP_FUNC:
        /* we don't need result */
        flb_free(result);
        ret = reduce_expression(((struct flb_exp_func *) expression)->param,
                                tag, tag_len, tms, map);
        result = ((struct flb_exp_func *) expression)->cb_func(tag, tag_len,
                                                               tms, ret);
        free_value(ret);
        break;
    case FLB_LOGICAL_OP:
        left = reduce_expression(expression->left,
                                 tag, tag_len, tms, map);
        right = reduce_expression(expression->right,
                                  tag, tag_len, tms, map);

        operation = ((struct flb_exp_op *) expression)->operation;

        switch (operation) {
        case FLB_EXP_PAR:
            if (left == NULL) { /* Null is always interpreted as false in a
                                   logical operation */
                result->type = FLB_EXP_BOOL;
                result->val.boolean = false;
            }
            else { /* Left and right sides of a logical operation reduce to
                      boolean values */
                result->type = FLB_EXP_BOOL;
                result->val.boolean = left->val.boolean;
            }
            break;
        case FLB_EXP_EQ:
        case FLB_EXP_LT:
        case FLB_EXP_LTE:
        case FLB_EXP_GT:
        case FLB_EXP_GTE:
            numerical_comp(left, right, result, operation);
            break;
        case FLB_EXP_NOT:
        case FLB_EXP_AND:
        case FLB_EXP_OR:
            logical_operation(left, right, result, operation);
            break;
        }
        free_value(left);
        free_value(right);
    }
    return result;
}


void package_results(const char *tag, int tag_len,
                     char **out_buf, size_t *out_size,
                     struct flb_sp_task *task)
{
    char *c_name;
    int i;
    int len;
    int map_entries;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct aggregate_num *num;
    struct flb_time tm;
    struct flb_sp_cmd_key *ckey;
    struct flb_sp_cmd *cmd = task->cmd;
    struct mk_list *head;
    struct aggregate_node *aggr_node;
    struct flb_sp_cmd_gb_key *gb_key = NULL;

    map_entries = mk_list_size(&cmd->keys);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    mk_list_foreach(head, &task->window.aggregate_list) {
        aggr_node = mk_list_entry(head, struct aggregate_node, _head);

        /* set outgoing array + map and it fixed size */
        msgpack_pack_array(&mp_pck, 2);

        flb_time_get(&tm);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);
        msgpack_pack_map(&mp_pck, map_entries);

        /* Packaging results */
        ckey = mk_list_entry_first(&cmd->keys, struct flb_sp_cmd_key, _head);
        for (i = 0; i < map_entries; i++) {
            num = &aggr_node->nums[i];

            /* Check if there is a defined function */
            if (ckey->time_func > 0) {
                flb_sp_func_time(&mp_pck, ckey);
                goto next;
            }
            else if (ckey->record_func > 0) {
                flb_sp_func_record(tag, tag_len, &tm, &mp_pck, ckey);
                goto next;
            }

            /* Pack key */
            if (ckey->alias) {
                msgpack_pack_str(&mp_pck, flb_sds_len(ckey->alias));
                msgpack_pack_str_body(&mp_pck,
                                      ckey->alias,
                                      flb_sds_len(ckey->alias));
            }
            else {
                if (!ckey->name) {
                    c_name = "*";
                }
                else {
                    c_name = ckey->name;
                }
                len = strlen(c_name);

                msgpack_pack_str(&mp_pck, len);
                msgpack_pack_str_body(&mp_pck, c_name, len);
            }

            /*
             * If a group_by key is mapped as a source of this key,
             * change the 'num' reference to obtain the proper information
             * for the grouped key value.
             */
            if (ckey->gb_key != NULL) {
                gb_key = ckey->gb_key;
                if (aggr_node->groupby_keys > 0) {
                    num = &aggr_node->groupby_nums[gb_key->id];
                }
            }

            /* Pack value */
            switch (ckey->aggr_func) {
            case FLB_SP_NOP:
                if (num->type == FLB_SP_NUM_I64) {
                    msgpack_pack_int64(&mp_pck, num->i64);
                }
                else if (num->type == FLB_SP_NUM_F64) {
                    msgpack_pack_float(&mp_pck, num->f64);
                }
                else if (num->type == FLB_SP_STRING) {
                    msgpack_pack_str(&mp_pck,
                                     flb_sds_len(num->string));
                    msgpack_pack_str_body(&mp_pck,
                                          num->string,
                                          flb_sds_len(num->string));
                }
                else if (num->type == FLB_SP_BOOLEAN) {
                    if (num->boolean) {
                        msgpack_pack_true(&mp_pck);
                    }
                    else {
                        msgpack_pack_false(&mp_pck);
                    }
                }
                break;
            default:
                aggregate_func_calc[ckey->aggr_func - 1](aggr_node, ckey, &mp_pck, i);
                break;
            }

next:
            ckey = mk_list_entry_next(&ckey->_head, struct flb_sp_cmd_key,
                                      _head, &cmd->keys);
        }
    }

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;
}

static struct aggregate_node * sp_process_aggregate_data(struct flb_sp_task *task,
                                                         msgpack_object map,
                                                         int convert_str_to_num)
{
    int i;
    int ret;
    int map_size;
    int key_id;
    int map_entries;
    int gb_entries;
    int values_found;
    int64_t ival;
    double dval;
    struct flb_sp_value *sval;
    struct aggregate_num *gb_nums;
    struct aggregate_node *aggr_node;
    struct flb_sp_cmd *cmd;
    struct flb_sp_cmd_gb_key *gb_key;
    struct mk_list *head;
    struct rb_tree_node *rb_result;
    msgpack_object key;

    aggr_node = NULL;
    cmd = task->cmd;
    map_size = map.via.map.size;
    values_found = 0;

    /* Number of expected output entries in the map */
    map_entries = mk_list_size(&cmd->keys);
    gb_entries = mk_list_size(&cmd->gb_keys);

    if (gb_entries > 0) {
        gb_nums = flb_calloc(1, sizeof(struct aggregate_num) * gb_entries);
        if (!gb_nums) {
            return NULL;
        }

        /* extract GROUP BY values */
        for (i = 0; i < map_size; i++) { /* extract group-by values */
            key = map.via.map.ptr[i].key;

            key_id = 0;
            mk_list_foreach(head, &cmd->gb_keys) {
                gb_key = mk_list_entry(head, struct flb_sp_cmd_gb_key,
                                       _head);
                if (flb_sds_cmp(gb_key->name, key.via.str.ptr,
                                key.via.str.size) != 0) {
                    key_id++;
                    continue;
                }

                sval = flb_sp_key_to_value(gb_key->name, map, gb_key->subkeys);
                if (!sval) {
                    /* If evaluation fails/sub-key doesn't exist */
                    key_id++;
                    continue;
                }

                values_found++;

                /* Convert string to number if that is possible */
                ret = object_to_number(sval->o, &ival, &dval, convert_str_to_num);
                if (ret == -1) {
                    if (sval->o.type == MSGPACK_OBJECT_STR) {
                        gb_nums[key_id].type = FLB_SP_STRING;
                        gb_nums[key_id].string =
                            flb_sds_create_len(sval->o.via.str.ptr,
                                               sval->o.via.str.size);
                    }
                    else if (sval->o.type == MSGPACK_OBJECT_BOOLEAN) {
                        gb_nums[key_id].type = FLB_SP_NUM_I64;
                        gb_nums[key_id].i64 = sval->o.via.boolean;
                    }
                }
                else if (ret == FLB_STR_INT) {
                    gb_nums[key_id].type = FLB_SP_NUM_I64;
                    gb_nums[key_id].i64 = ival;
                }
                else if (ret == FLB_STR_FLOAT) {
                    gb_nums[key_id].type = FLB_SP_NUM_F64;
                    gb_nums[key_id].f64 = dval;
                }

                key_id++;
                flb_sp_key_value_destroy(sval);
            }
        }

        /* if some GROUP BY keys are not found in the record */
        if (values_found < gb_entries) {
            groupby_nums_destroy(gb_nums, gb_entries);
            return NULL;
        }

        aggr_node = (struct aggregate_node *) flb_calloc(1, sizeof(struct aggregate_node));
        if (!aggr_node) {
            flb_errno();
            groupby_nums_destroy(gb_nums, gb_entries);
            return NULL;
        }

        aggr_node->groupby_keys = gb_entries;
        aggr_node->groupby_nums = gb_nums;

        rb_tree_find_or_insert(&task->window.aggregate_tree, aggr_node, &aggr_node->_rb_head, &rb_result);
        if (&aggr_node->_rb_head != rb_result) {
            /* We don't need aggr_node anymore */
            flb_sp_aggregate_node_destroy(cmd, aggr_node);

            aggr_node = container_of(rb_result, struct aggregate_node, _rb_head);
            container_of(rb_result, struct aggregate_node, _rb_head)->records++;
        }
        else {
            aggr_node->nums = flb_calloc(1, sizeof(struct aggregate_num) * map_entries);
            if (!aggr_node->nums) {
                flb_sp_aggregate_node_destroy(cmd, aggr_node);
                return NULL;
            }
            aggr_node->records = 1;
            aggr_node->nums_size = map_entries;
            aggr_node->aggregate_data = (struct aggregate_data **) flb_calloc(1, sizeof(struct aggregate_data *) * map_entries);
            mk_list_add(&aggr_node->_head, &task->window.aggregate_list);
        }
    }
    else { /* If query doesn't have GROUP BY */
        if (!mk_list_size(&task->window.aggregate_list)) {
            aggr_node = flb_calloc(1, sizeof(struct aggregate_node));
            if (!aggr_node) {
                flb_errno();
                return NULL;
            }
            aggr_node->nums = flb_calloc(1, sizeof(struct aggregate_num) * map_entries);
            if (!aggr_node->nums) {
                flb_sp_aggregate_node_destroy(cmd, aggr_node);
                return NULL;
            }

            aggr_node->nums_size = map_entries;
            aggr_node->records = 1;
            aggr_node->aggregate_data = (struct aggregate_data **) flb_calloc(1, sizeof(struct aggregate_data *) * map_entries);
            mk_list_add(&aggr_node->_head, &task->window.aggregate_list);
        }
        else {
            aggr_node = mk_list_entry_first(&task->window.aggregate_list, struct aggregate_node, _head);
            aggr_node->records++;
        }
    }

    return aggr_node;
}

/*
 * Process data, task and it defined command involves the call of aggregation
 * functions (AVG, SUM, COUNT, MIN, MAX).
 */
int sp_process_data_aggr(const char *buf_data, size_t buf_size,
                         const char *tag, int tag_len,
                         struct flb_sp_task *task,
                         struct flb_sp *sp,
                         int convert_str_to_num)
{
    int i;
    int ok;
    int ret;
    int map_size;
    int key_id;
    size_t off;
    int64_t ival;
    double dval;
    msgpack_object root;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_object key;
    msgpack_object *obj;
    struct aggregate_num *nums = NULL;
    struct mk_list *head;
    struct flb_time tms;
    struct flb_sp_cmd *cmd = task->cmd;
    struct flb_sp_cmd_key *ckey;
    struct flb_sp_value *sval;
    struct flb_exp_val *condition;
    struct aggregate_node *aggr_node;

    /* Number of expected output entries in the map */
    off = 0;

    /* vars initialization */
    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);

    /* Iterate incoming records */
    while (msgpack_unpack_next(&result, buf_data, buf_size, &off) == ok) {
        root = result.data;

        /* extract timestamp */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* get the map data and it size (number of items) */
        map   = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* Evaluate condition */
        if (cmd->condition) {
            condition = reduce_expression(cmd->condition,
                                          tag, tag_len, &tms, &map);
            if (!condition) {
                continue;
            }
            else if (!condition->val.boolean) {
                flb_free(condition);
                continue;
            }
            else {
                flb_free(condition);
            }
        }

        aggr_node = sp_process_aggregate_data(task, map, convert_str_to_num);
        if (!aggr_node)
        {
            continue;
        }

        task->window.records++;

        nums = aggr_node->nums;

        /* Iterate each map key and see if it matches any command key */
        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;

            if (key.type != MSGPACK_OBJECT_STR) {
                continue;
            }


            /*
             * Iterate each command key. Note that since the command key
             * can have different aggregation functions to the same key
             * we should compare all of them.
             */
            key_id = 0;
            mk_list_foreach(head, &cmd->keys) {
                ckey = mk_list_entry(head, struct flb_sp_cmd_key, _head);

                if (!ckey->name) {
                    key_id++;
                    continue;
                }

                if (flb_sds_cmp(ckey->name, key.via.str.ptr,
                                key.via.str.size) != 0) {
                    key_id++;
                    continue;
                }

                /* convert the value if it string */
                sval = flb_sp_key_to_value(ckey->name, map, ckey->subkeys);
                if (!sval) {
                    key_id++;
                    continue;
                }

                /*
                 * Convert value to a numeric representation only if key has an
                 * assigned aggregation function
                 */
                ival = 0;
                dval = 0.0;
                if (ckey->aggr_func != FLB_SP_NOP) {
                    ret = object_to_number(sval->o, &ival, &dval, convert_str_to_num);
                    if (ret == -1) {
                        /* Value cannot be represented as a number */
                        key_id++;
                        flb_sp_key_value_destroy(sval);
                        continue;
                    }

                    /*
                     * If a floating pointer number exists, we use the same data
                     * type for the output.
                     */
                    if (dval != 0.0 && nums[key_id].type == FLB_SP_NUM_I64) {
                        nums[key_id].type = FLB_SP_NUM_F64;
                        nums[key_id].f64 = (double) nums[key_id].i64;
                    }

                    aggregate_func_add[ckey->aggr_func - 1](aggr_node, ckey, key_id, &tms, ival, dval);
                }
                else {
                    if (sval->o.type == MSGPACK_OBJECT_BOOLEAN) {
                        nums[key_id].type = FLB_SP_BOOLEAN;
                        nums[key_id].boolean = sval->o.via.boolean;
                    }
                    if (sval->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                        sval->o.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                        nums[key_id].type = FLB_SP_NUM_I64;
                        nums[key_id].i64 = sval->o.via.i64;
                    }
                    else if (sval->o.type == MSGPACK_OBJECT_FLOAT32 ||
                             sval->o.type == MSGPACK_OBJECT_FLOAT) {
                        nums[key_id].type = FLB_SP_NUM_F64;
                        nums[key_id].f64 = sval->o.via.f64;
                    }
                    else if (sval->o.type == MSGPACK_OBJECT_STR) {
                        nums[key_id].type = FLB_SP_STRING;
                        if (nums[key_id].string == NULL) {
                            nums[key_id].string =
                                flb_sds_create_len(sval->o.via.str.ptr,
                                                   sval->o.via.str.size);
                        }
                    }
                }

                key_id++;
                flb_sp_key_value_destroy(sval);
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    return task->window.records;
}

/*
 * Data processing (no aggregation functions)
 */
int sp_process_data(const char *tag, int tag_len,
                    const char *buf_data, size_t buf_size,
                    char **out_buf, size_t *out_size,
                    struct flb_sp_task *task,
                    struct flb_sp *sp)
{
    int i;
    int ok;
    int ret;
    int map_size;
    int map_entries;
    int records;
    uint8_t h;
    off_t map_off;
    off_t no_data;
    size_t off;
    size_t off_copy;
    size_t snapshot_out_size;
    char *tmp;
    char *snapshot_out_buffer;
    msgpack_object root;
    msgpack_object *obj;
    msgpack_object key;
    msgpack_object val;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object map;
    struct flb_time tms;
    struct mk_list *head;
    struct flb_sp_cmd *cmd;
    struct flb_sp_cmd_key *cmd_key;
    struct flb_exp_val *condition;
    struct flb_sp_value *sval;

    /* Vars initialization */
    off = 0;
    off_copy = off;
    records = 0;
    cmd = task->cmd;
    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    snapshot_out_size = 0;
    snapshot_out_buffer = NULL;

    /* Iterate incoming records */
    while (msgpack_unpack_next(&result, buf_data, buf_size, &off) == ok) {
        root = result.data;

        /* extract timestamp */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /* Store the buffer if the stream is a snapshot */
        if (cmd->type == FLB_SP_CREATE_SNAPSHOT) {
            flb_sp_snapshot_update(task, buf_data + off_copy, off - off_copy, &tms);
            off_copy = off;
            continue;
        }

        /* get the map data and it size (number of items) */
        map   = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* Evaluate condition */
        if (cmd->condition) {
            condition = reduce_expression(cmd->condition,
                                          tag, tag_len, &tms, &map);
            if (!condition) {
                continue;
            }
            else if (!condition->val.boolean) {
                flb_free(condition);
                continue;
            }
            else {
                flb_free(condition);
            }
        }

        records++;

        /* Flush the snapshot if condition holds */
        if (cmd->type == FLB_SP_FLUSH_SNAPSHOT) {
            if (flb_sp_snapshot_flush(sp, task, &snapshot_out_buffer,
                                      &snapshot_out_size) == -1) {
                msgpack_unpacked_destroy(&result);
                msgpack_sbuffer_destroy(&mp_sbuf);
                return -1;
            }
            continue;
        }


        /*
         * If for some reason the Task keys did not insert any data, we will
         * need to discard any changes and reset the buffer position, let's
         * keep the memory size for that purpose.
         */
        no_data = mp_sbuf.size;

        /* Pack main array */
        msgpack_pack_array(&mp_pck, 2);
        msgpack_pack_object(&mp_pck, root.via.array.ptr[0]);

        /*
         * Save the current size/position of the buffer since this is
         * where the Map header will be stored.
         */
        map_off = mp_sbuf.size;

        /*
         * In the new record register the same number of items, if due to
         * fields selection the number is lower, we perform an adjustment
         */
        msgpack_pack_map(&mp_pck, map_size);

        /* Counter for new entries added to the outgoing map */
        map_entries = 0;

        /* Iterate key selection */
        mk_list_foreach(head, &cmd->keys) {
            cmd_key = mk_list_entry(head, struct flb_sp_cmd_key, _head);
            if (cmd_key->time_func > 0) {
                /* Process time function */
                ret = flb_sp_func_time(&mp_pck, cmd_key);
                if (ret > 0) {
                    map_entries += ret;
                }
                continue;
            }
            else if (cmd_key->record_func > 0) {
                ret = flb_sp_func_record(tag, tag_len, &tms, &mp_pck, cmd_key);
                if (ret > 0) {
                    map_entries += ret;
                }
                continue;
            }

            /* Lookup selection key in the incoming map */
            for (i = 0; i < map_size; i++) {
                key = map.via.map.ptr[i].key;
                val = map.via.map.ptr[i].val;

                if (key.type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* Wildcard selection: * */
                if (cmd_key->name == NULL) {
                    msgpack_pack_object(&mp_pck, key);
                    msgpack_pack_object(&mp_pck, val);
                    map_entries++;
                    continue;
                }

                /* Compare lengths */
                if (flb_sds_cmp(cmd_key->name,
                                key.via.str.ptr, key.via.str.size) != 0) {
                    continue;
                }

                /*
                 * Package key name:
                 *
                 * Check if the command ask for an alias 'key AS abc'
                 */
                if (cmd_key->alias) {
                    msgpack_pack_str(&mp_pck,
                                     flb_sds_len(cmd_key->alias));
                    msgpack_pack_str_body(&mp_pck,
                                          cmd_key->alias,
                                          flb_sds_len(cmd_key->alias));
                }
                else {
                    msgpack_pack_object(&mp_pck, key);
                }

                /* Package value */
                sval = flb_sp_key_to_value(cmd_key->name, map,
                                           cmd_key->subkeys);
                if (sval) {
                    msgpack_pack_object(&mp_pck, sval->o);
                    flb_sp_key_value_destroy(sval);
                }

                map_entries++;
            }
        }

        /* Final Map size adjustment */
        if (map_entries == 0) {
            mp_sbuf.size = no_data;
        }
        else {
            /*
             * The fields were packed, now we need to adjust the map size
             * to set the proper number of fields appended to the record.
             */
            tmp = mp_sbuf.data + map_off;
            h = tmp[0];
            if (h >> 4 == 0x8) {
                *tmp = (uint8_t) 0x8 << 4 | ((uint8_t) map_entries);
            }
            else if (h == 0xde) {
                tmp++;
                pack_uint16(tmp, map_entries);
            }
            else if (h == 0xdf) {
                tmp++;
                pack_uint32(tmp, map_entries);
            }
        }
    }

    msgpack_unpacked_destroy(&result);

    if (records == 0) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return 0;
    }

    /* Use snapshot out buffer if it is flush stream */
    if (cmd->type == FLB_SP_FLUSH_SNAPSHOT) {
        if (snapshot_out_size == 0) {
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_free(snapshot_out_buffer);
            return 0;
        }
        else {
            *out_buf = snapshot_out_buffer;
            *out_size = snapshot_out_size;
            return records;
        }
    }

    /* set outgoing results */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return records;
}

int sp_process_hopping_slot(const char *tag, int tag_len,
                            struct flb_sp_task *task)
{
    int i;
    int key_id;
    int map_entries;
    int gb_entries;
    struct flb_sp_cmd *cmd = task->cmd;
    struct mk_list *head;
    struct mk_list *head_hs;
    struct aggregate_node *aggr_node;
    struct aggregate_node *aggr_node_hs;
    struct aggregate_node *aggr_node_prev;
    struct flb_sp_hopping_slot *hs;
    struct flb_sp_hopping_slot *hs_;
    struct rb_tree_node *rb_result;
    struct flb_sp_cmd_key *ckey;
    rb_result_t result;

    map_entries = mk_list_size(&cmd->keys);
    gb_entries = mk_list_size(&cmd->gb_keys);

    /* Initialize a hoping slot */
    hs = flb_calloc(1, sizeof(struct flb_sp_hopping_slot));
    if (!hs) {
        flb_errno();
        return -1;
    }

    mk_list_init(&hs->aggregate_list);
    rb_tree_new(&hs->aggregate_tree, flb_sp_groupby_compare);

    /* Loop over aggregation nodes on window */
    mk_list_foreach(head, &task->window.aggregate_list) {
        /* Window aggregation node */
        aggr_node = mk_list_entry(head, struct aggregate_node, _head);

        /* Create a hopping slot aggregation node */
        aggr_node_hs = flb_calloc(1, sizeof(struct aggregate_node));
        if (!aggr_node_hs) {
            flb_errno();
            flb_free(hs);
            return -1;
        }

        aggr_node_hs->nums = malloc(sizeof(struct aggregate_node) * map_entries);
        if (!aggr_node_hs->nums) {
            flb_errno();
            flb_free(hs);
            flb_free(aggr_node_hs);
            return -1;
        }

        memcpy(aggr_node_hs->nums, aggr_node->nums, sizeof(struct aggregate_num) * map_entries);
        aggr_node_hs->records = aggr_node->records;

        /* Clone aggregate data */
        key_id = 0;
        mk_list_foreach(head_hs, &cmd->keys) {
            ckey = mk_list_entry(head_hs, struct flb_sp_cmd_key, _head);

            if (ckey->aggr_func) {
                if (!aggr_node_hs->aggregate_data) {
                    aggr_node_hs->aggregate_data = (struct aggregate_data **)
                                       flb_calloc(1, sizeof(struct aggregate_data *) * map_entries);
                    if (!aggr_node_hs->aggregate_data) {
                        flb_errno();
                        flb_free(hs);
                        flb_free(aggr_node_hs->nums);
                        flb_free(aggr_node_hs);
                        return -1;
                    }
                }

                if (aggregate_func_clone[ckey->aggr_func - 1](aggr_node_hs, aggr_node, ckey, key_id) == -1) {
                    flb_errno();
                    flb_free(aggr_node_hs->nums);
                    flb_free(aggr_node_hs->aggregate_data);
                    flb_free(aggr_node_hs);
                    flb_free(hs);
                    return -1;
                }
            }

            key_id++;
        }

        /* Traverse over previous slots to calculate values/record numbers */
        mk_list_foreach(head_hs, &task->window.hopping_slot) {
            hs_ = mk_list_entry(head_hs, struct flb_sp_hopping_slot, _head);
            result = rb_tree_find(&hs_->aggregate_tree, aggr_node, &rb_result);
            /* If corresponding aggregation node exists in previous hopping slot,
             * calculate aggregation values
             */
            if (result == RB_OK) {
                aggr_node_prev = mk_list_entry(rb_result, struct aggregate_node,
                                               _rb_head);
                aggr_node_hs->records -= aggr_node_prev->records;

                key_id = 0;
                ckey = mk_list_entry_first(&cmd->keys, struct flb_sp_cmd_key,
                                           _head);
                for (i = 0; i < map_entries; i++) {
                    if (ckey->aggr_func) {
                        aggregate_func_remove[ckey->aggr_func - 1](aggr_node_hs, aggr_node_prev, i);
                    }

                    ckey = mk_list_entry_next(&ckey->_head, struct flb_sp_cmd_key,
                                              _head, &cmd->keys);
                }
            }
        }

        if (aggr_node_hs->records > 0) {
            aggr_node_hs->groupby_nums =
                flb_calloc(1, sizeof(struct aggregate_node) * gb_entries);
            if (gb_entries > 0 && !aggr_node_hs->groupby_nums) {
                flb_errno();
                flb_free(hs);
                flb_free(aggr_node_hs->nums);
                flb_free(aggr_node_hs->aggregate_data);
                flb_free(aggr_node_hs);
                return -1;
            }

            if (aggr_node_hs->groupby_nums != NULL) {
                memcpy(aggr_node_hs->groupby_nums, aggr_node->groupby_nums,
                       sizeof(struct aggregate_num) * gb_entries);
            }

            aggr_node_hs->nums_size = aggr_node->nums_size;
            aggr_node_hs->groupby_keys = aggr_node->groupby_keys;

            rb_tree_insert(&hs->aggregate_tree, aggr_node_hs, &aggr_node_hs->_rb_head);
            mk_list_add(&aggr_node_hs->_head, &hs->aggregate_list);
        }
        else {
            flb_free(aggr_node_hs->nums);
            flb_free(aggr_node_hs->aggregate_data);
            flb_free(aggr_node_hs);
        }
    }

    hs->records = task->window.records;
    mk_list_foreach(head_hs, &task->window.hopping_slot) {
        hs_ = mk_list_entry(head_hs, struct flb_sp_hopping_slot, _head);
        hs->records -= hs_->records;
    }

    mk_list_add(&hs->_head, &task->window.hopping_slot);

    return 0;
}

/* Iterate and find input chunks to process */
int flb_sp_do(struct flb_sp *sp, struct flb_input_instance *in,
              const char *tag, int tag_len,
              const char *buf_data, size_t buf_size)

{
    int ret;
    size_t out_size;
    char *out_buf;
    struct mk_list *head;
    struct flb_sp_task *task;
    struct flb_sp_cmd *cmd;

    /* Lookup tasks that match the incoming instance data */
    mk_list_foreach(head, &sp->tasks) {
        task = mk_list_entry(head, struct flb_sp_task, _head);
        cmd = task->cmd;

        if (cmd->source_type == FLB_SP_STREAM) {
            if (task->source_instance != in) {
                continue;
            }
        }
        else if (cmd->source_type == FLB_SP_TAG) {
            ret = flb_router_match(tag, tag_len, cmd->source_name, NULL);
            if (ret == FLB_FALSE) {
                continue;
            }
        }

        /* We found a task that matches the stream rule */
        if (task->aggregate_keys == FLB_TRUE) {
            ret = sp_process_data_aggr(buf_data, buf_size,
                                       tag, tag_len,
                                       task, sp, in->config->stream_processor_str_conv);

            if (ret == -1) {
                flb_error("[sp] error processing records for '%s'",
                          task->name);
                continue;
            }

            if (flb_sp_window_populate(task, buf_data, buf_size) == -1) {
                flb_error("[sp] error populating window for '%s'",
                          task->name);
                continue;
            }

            if (task->window.type == FLB_SP_WINDOW_DEFAULT) {
                package_results(tag, tag_len, &out_buf, &out_size, task);
                flb_sp_window_prune(task);
            }
        }
        else {
            ret = sp_process_data(tag, tag_len,
                                  buf_data, buf_size,
                                  &out_buf, &out_size,
                                  task, sp);

            if (ret == -1) {
                flb_error("[sp] error processing records for '%s'",
                          task->name);
                continue;
            }
        }

        if (ret == 0) {
            /* no records */
            continue;
        }

        /*
         * This task involves append data to a stream, which
         * means: register the output of the query as data
         * generated by an input instance plugin.
         */
        if (task->aggregate_keys != FLB_TRUE ||
            task->window.type == FLB_SP_WINDOW_DEFAULT) {
            /*
             * Add to stream processing stream if there is no
             * aggregation function. Otherwise, write it at timer event
             */
            if (task->stream) {
                flb_sp_stream_append_data(out_buf, out_size, task->stream);
            }
            else {
                flb_pack_print(out_buf, out_size);
                flb_free(out_buf);
            }
        }
    }

    return -1;
}

int flb_sp_fd_event(int fd, struct flb_sp *sp)
{
    bool update_timer_event;
    char *out_buf;
    char *tag = NULL;
    int tag_len = 0;
    int fd_timeout = 0;
    size_t out_size;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sp_task *task;
    struct flb_input_instance *in = NULL;

    /* Lookup Tasks that matches the incoming event */
    mk_list_foreach_safe(head, tmp, &sp->tasks) {
        task = mk_list_entry(head, struct flb_sp_task, _head);

        if (fd == task->window.fd) {
            update_timer_event = task->window.type == FLB_SP_WINDOW_HOPPING &&
                                 task->window.first_hop;

            in = task->source_instance;
            if (in) {
                if (in->tag && in->tag_len > 0) {
                    tag = in->tag;
                    tag_len = in->tag_len;
                }
                else {
                    tag = in->name;
                    tag_len = strlen(in->name);
                }
            }
            else {
                in = NULL;
            }

            if (task->window.records > 0) {
                /* find input tag from task source */
                package_results(tag, tag_len, &out_buf, &out_size, task);
                if (task->stream) {
                    flb_sp_stream_append_data(out_buf, out_size, task->stream);
                }
                else {
                    flb_pack_print(out_buf, out_size);
                    flb_free(out_buf);
                }

            }

            flb_sp_window_prune(task);

            flb_utils_timer_consume(fd);

            if (update_timer_event && in) {
                task->window.first_hop = false;
                mk_event_timeout_destroy(in->config->evl, &task->window.event);
                mk_event_closesocket(fd);

                fd_timeout = mk_event_timeout_create(in->config->evl,
                                                     task->window.advance_by, (long) 0,
                                                     &task->window.event);
                if (fd_timeout == -1) {
                    flb_error("[sp] registration for task (updating timer event) %s failed", task->name);
                    return -1;
                }
                task->window.fd = fd_timeout;
            }

            break;
        }
        else if (fd == task->window.fd_hop) {
            in = task->source_instance;
            if (in) {
                if (in->tag && in->tag_len > 0) {
                    tag = in->tag;
                    tag_len = in->tag_len;
                }
                else {
                    tag = in->name;
                    tag_len = strlen(in->name);
                }
            }
            sp_process_hopping_slot(tag, tag_len, task);
            flb_utils_timer_consume(fd);
        }
    }
    return 0;
}

/* Destroy stream processor context */
void flb_sp_destroy(struct flb_sp *sp)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sp_task *task;

    /* destroy tasks */
    mk_list_foreach_safe(head, tmp, &sp->tasks) {
        task = mk_list_entry(head, struct flb_sp_task, _head);
        flb_sp_task_destroy(task);
    }

    flb_free(sp);
}
