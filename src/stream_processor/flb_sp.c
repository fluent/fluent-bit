/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_key.h>
#include <fluent-bit/stream_processor/flb_sp_stream.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_func_time.h>
#include <fluent-bit/stream_processor/flb_sp_func_record.h>
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
    char *name;
    char *exec;
    const char *cfg = NULL;
    char tmp[PATH_MAX + 1];
    struct stat st;
    struct mk_rconf *fconf;
    struct mk_rconf_section *section;
    struct mk_list *head;
    struct flb_sp_task *task;

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
        cfg = file;
    }

    fconf = mk_rconf_open(cfg);
#else
    fconf = flb_config_static_open(file);
#endif

    if (!fconf) {
        return -1;
    }

    /* Read all [STREAM_TASK] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "STREAM_TASK") != 0) {
            continue;
        }

        name = NULL;
        exec = NULL;

        /* Name */
        name = mk_rconf_section_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_error("[sp] task 'name' not found in file '%s'", cfg);
            goto fconf_error;
        }

        /* Exec */
        exec = mk_rconf_section_get_key(section, "Exec", MK_RCONF_STR);
        if (!exec) {
            flb_error("[sp] task '%s' don't have an 'exec' command", name);
            goto fconf_error;
        }

        /* Register the task */
        task = flb_sp_task_create(sp, name, exec);
        if (!task) {
            goto fconf_error;
        }

        flb_free(name);
        flb_free(exec);
    }

    mk_rconf_free(fconf);
    return 0;

fconf_error:
    flb_free(name);
    flb_free(exec);

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

        if (key->aggr_func > 0) { /* AVG, SUM or COUNT */
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
                    not_aggr--;
                    break;
                }
            }

            not_aggr++;
        }
    }

    /*
     * if some aggregated function is required, not aggregated keys are
     * not allowed so we return an error (-1).
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
static int object_to_number(msgpack_object obj, int64_t *i, double *d)
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
    else if (obj.type == MSGPACK_OBJECT_STR) {
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

/* Summarize a value into the temporal array considering data type */
static void aggr_sum(struct aggr_num *nums, int key_id, int64_t i, double d)
{
    if (nums[key_id].type == FLB_SP_NUM_I64) {
        nums[key_id].i64 += i;
        nums[key_id].ops++;
    }
    else if (nums[key_id].type == FLB_SP_NUM_F64) {
        if (d != 0.0) {
            nums[key_id].f64 += d;
        }
        else {
            nums[key_id].f64 += (double) i;
        }
        nums[key_id].ops++;
    }
}

/* Calculate the minimum value considering data type */
static void aggr_min(struct aggr_num *nums, int key_id, int64_t i, double d)
{
    if (nums[key_id].type == FLB_SP_NUM_I64) {
        if (nums[key_id].ops == 0) {
            nums[key_id].i64 = i;
            nums[key_id].ops++;
        }
        else {
            if (nums[key_id].i64 > i) {
                nums[key_id].i64 = i;
                nums[key_id].ops++;
            }
        }
    }
    else if (nums[key_id].type == FLB_SP_NUM_F64) {
        if (d != 0.0) {
            if (nums[key_id].ops == 0) {
                nums[key_id].f64 = d;
                nums[key_id].ops++;
            }
            else {
                if (nums[key_id].f64 > d) {
                    nums[key_id].f64 = d;
                    nums[key_id].ops++;
                }
            }
        }
        else {
            if (nums[key_id].ops == 0) {
                nums[key_id].f64 = (double) i;
                nums[key_id].ops++;
            }
            else {
                if (nums[key_id].f64 > (double) i) {
                    nums[key_id].f64 = i;
                    nums[key_id].ops++;
                }
            }
        }
    }
}

/* Calculate the maximum value considering data type */
static void aggr_max(struct aggr_num *nums, int key_id, int64_t i, double d)
{
    if (nums[key_id].type == FLB_SP_NUM_I64) {
        if (nums[key_id].ops == 0) {
            nums[key_id].i64 = i;
            nums[key_id].ops++;
        }
        else {
            if (nums[key_id].i64 < i) {
                nums[key_id].i64 = i;
                nums[key_id].ops++;
            }
        }
    }
    else if (nums[key_id].type == FLB_SP_NUM_F64) {
        if (d != 0.0) {
            if (nums[key_id].ops == 0) {
                nums[key_id].f64 = d;
                nums[key_id].ops++;
            }
            else {
                if (nums[key_id].f64 < d) {
                    nums[key_id].f64 = d;
                    nums[key_id].ops++;
                }
            }
        }
        else {
            if (nums[key_id].ops == 0) {
                nums[key_id].f64 = (double) i;
                nums[key_id].ops++;
            }
            else {
                if (nums[key_id].f64 < (double) i) {
                    nums[key_id].f64 = (double) i;
                    nums[key_id].ops++;
                }
            }
        }
    }
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
    task->aggr_keys = FLB_FALSE;

    mk_list_init(&task->window.data);
    mk_list_init(&task->window.aggr_list);
    rb_tree_new(&task->window.aggr_tree, flb_sp_groupby_compare);

    mk_list_init(&task->window.hopping_slot);

    /* Check and validate aggregated keys */
    ret = sp_cmd_aggregated_keys(task->cmd);
    if (ret == -1) {
        flb_error("[sp] aggregated query cannot mix not aggregated keys: %s",
                  query);
        flb_sp_task_destroy(task);
        return NULL;
    }
    else if (ret > 0) {
        task->aggr_keys = FLB_TRUE;

        task->window.type = cmd->window.type;

        /* Register a timer event when task contains aggregation rules */
        if (task->window.type != FLB_SP_WINDOW_DEFAULT) {
            /* Initialize event loop context */
            event = &task->window.event;
            MK_EVENT_ZERO(event);

            /* Run every 'size' seconds */
            fd = mk_event_timeout_create(sp->config->evl,
                                         cmd->window.size, (long) 0,
                                         &task->window.event);
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
                                             &task->window.event_hop);
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

    /*
     * If the task involves a stream creation (CREATE STREAM abc..), create
     * the stream.
     */
    if (cmd->type == FLB_SP_CREATE_STREAM) {
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

/*
 * Destroy aggregation node context: before to use this function make sure
 * to unlink from the linked list.
 */
void flb_sp_aggr_node_destroy(struct aggr_node *aggr_node)
{
    int i;
    struct aggr_num *num;

    for (i = 0; i < aggr_node->nums_size; i++) {
        num = &aggr_node->nums[i];
        if (num->type == FLB_SP_STRING) {
            flb_sds_destroy(num->string);
        }
    }

    for (i = 0; i < aggr_node->groupby_keys; i++) {
        num = &aggr_node->groupby_nums[i];
        if (num->type == FLB_SP_STRING) {
            flb_sds_destroy(num->string);
        }
    }

    flb_free(aggr_node->nums);
    flb_free(aggr_node->groupby_nums);
    flb_free(aggr_node);
}

void flb_sp_window_destroy(struct flb_sp_task_window *window)
{
    struct flb_sp_window_data *data;
    struct aggr_node *aggr_node;
    struct flb_sp_hopping_slot *hs;
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_list *head_hs;
    struct mk_list *tmp_hs;

    mk_list_foreach_safe(head, tmp, &window->data) {
        data = mk_list_entry(head, struct flb_sp_window_data, _head);
        flb_free(data->buf_data);
        mk_list_del(&data->_head);
        flb_free(data);
    }

    mk_list_foreach_safe(head, tmp, &window->aggr_list) {
        aggr_node = mk_list_entry(head, struct aggr_node, _head);
        mk_list_del(&aggr_node->_head);
        flb_sp_aggr_node_destroy(aggr_node);
    }

    mk_list_foreach_safe(head, tmp, &window->hopping_slot) {
        hs = mk_list_entry(head, struct flb_sp_hopping_slot, _head);
        mk_list_foreach_safe(head_hs, tmp_hs, &hs->aggr_list) {
            aggr_node = mk_list_entry(head_hs, struct aggr_node, _head);
            mk_list_del(&aggr_node->_head);
            flb_sp_aggr_node_destroy(aggr_node);
        }
        rb_tree_destroy(&hs->aggr_tree);
        flb_free(hs);
    }

    rb_tree_destroy(&window->aggr_tree);
}

void flb_sp_task_destroy(struct flb_sp_task *task)
{
    flb_sds_destroy(task->name);
    flb_sds_destroy(task->query);
    flb_sp_window_destroy(&task->window);
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
    struct mk_list *head;
    struct flb_sp *sp;
    struct flb_slist_entry *e;
    struct flb_sp_task *task;

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
    val->val.f64 = val->val.i64;
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


static void package_results(const char *tag, int tag_len,
                            char **out_buf, size_t *out_size,
                            struct flb_sp_task *task)
{
    int i;
    int len;
    int map_entries;
    double d_val;
    int records;
    char key_name[256];
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct aggr_num *nums;
    struct flb_time tm;
    struct flb_sp_cmd_key *ckey;
    struct flb_sp_cmd *cmd = task->cmd;
    struct mk_list *head;
    struct aggr_node *aggr_node;

    map_entries = mk_list_size(&cmd->keys);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    mk_list_foreach(head, &task->window.aggr_list) {
        aggr_node = mk_list_entry(head, struct aggr_node, _head);
        nums = aggr_node->nums;
        records = aggr_node->records;

        /* set outgoing array + map and it fixed size */
        msgpack_pack_array(&mp_pck, 2);

        flb_time_get(&tm);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);
        msgpack_pack_map(&mp_pck, map_entries);

        /* Packaging results */
        ckey = mk_list_entry_first(&cmd->keys, struct flb_sp_cmd_key, _head);
        for (i = 0; i < map_entries; i++) {
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
                len = 0;
                char *c_name;
                if (!ckey->name) {
                    c_name = "*";
                }
                else if (ckey->name_keys) {
                    c_name = ckey->name_keys;
                }
                else {
                    c_name = ckey->name;
                }

                switch (ckey->aggr_func) {
                case FLB_SP_NOP:
                    len = snprintf(key_name, sizeof(key_name) - 1,
                                   "%s", c_name);
                    break;
                case FLB_SP_AVG:
                    len = snprintf(key_name, sizeof(key_name) - 1,
                                   "AVG(%s)", c_name);
                    break;
                case FLB_SP_SUM:
                    len = snprintf(key_name, sizeof(key_name) - 1,
                                   "SUM(%s)", c_name);
                    break;
                case FLB_SP_COUNT:
                    len = snprintf(key_name, sizeof(key_name) - 1,
                                   "COUNT(%s)", c_name);
                    break;
                case FLB_SP_MIN:
                    len = snprintf(key_name, sizeof(key_name) - 1,
                                   "MIN(%s)", c_name);
                    break;
                case FLB_SP_MAX:
                    len = snprintf(key_name, sizeof(key_name) - 1,
                                   "MAX(%s)", c_name);
                    break;
                }

                msgpack_pack_str(&mp_pck, len);
                msgpack_pack_str_body(&mp_pck, key_name, len);
            }

            /* Pack value */
            switch (ckey->aggr_func) {
            case FLB_SP_NOP:
                if (nums[i].type == FLB_SP_NUM_I64) {
                    msgpack_pack_int64(&mp_pck, nums[i].i64);
                }
                else if (nums[i].type == FLB_SP_NUM_F64) {
                    msgpack_pack_float(&mp_pck, nums[i].f64);
                }
                else if (nums[i].type == FLB_SP_STRING) {
                    msgpack_pack_str(&mp_pck,
                                     flb_sds_len(nums[i].string));
                    msgpack_pack_str_body(&mp_pck,
                                          nums[i].string,
                                          flb_sds_len(nums[i].string));
                }
                else if (nums[i].type == FLB_SP_BOOLEAN) {
                    if (nums[i].boolean) {
                        msgpack_pack_true(&mp_pck);
                    }
                    else {
                        msgpack_pack_false(&mp_pck);
                    }
                }
                break;
            case FLB_SP_AVG:
                /* average = sum(values) / records */
                d_val = 0;
                if (nums[i].type == FLB_SP_NUM_I64) {
                    d_val = (double) nums[i].i64 / records;
                }
                else if (nums[i].type == FLB_SP_NUM_F64) {
                    d_val = (double) nums[i].f64 / records;
                }
                msgpack_pack_float(&mp_pck, d_val);
                break;
            case FLB_SP_SUM:
            case FLB_SP_MIN:
            case FLB_SP_MAX:
                /* pack result stored in nums[key_id] */
                if (nums[i].type == FLB_SP_NUM_I64) {
                    msgpack_pack_int64(&mp_pck, nums[i].i64);
                }
                else if (nums[i].type == FLB_SP_NUM_F64) {
                    msgpack_pack_float(&mp_pck, nums[i].f64);
                }
                break;
            case FLB_SP_COUNT:
                /* number of records in total */
                msgpack_pack_int64(&mp_pck, records);
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

/*
 * Process data, task and it defined command involves the call of aggregation
 * functions (AVG, SUM, COUNT, MIN, MAX).
 */
static int sp_process_data_aggr(const char *buf_data, size_t buf_size,
                                const char *tag, int tag_len,
                                struct flb_sp_task *task,
                                struct flb_sp *sp)
{
    int i;
    int ok;
    int ret;
    int map_entries;
    int gb_entries;
    int map_size;
    int key_id;
    size_t off;
    int64_t ival;
    double dval;
    msgpack_object root;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_object key;
    msgpack_object val;
    msgpack_object *obj;
    struct aggr_num *nums = NULL;
    struct aggr_num *gb_nums; // group-by keys
    struct mk_list *head;
    struct flb_time tms;
    struct flb_sp_cmd *cmd = task->cmd;
    struct flb_sp_cmd_key *ckey;
    struct flb_sp_cmd_gb_key *gb_key;
    struct flb_sp_value *sval;
    struct flb_exp_val *condition;
    struct aggr_node *aggr_node;
    struct rb_tree_node *rb_result;

    /* Number of expected output entries in the map */
    map_entries = mk_list_size(&cmd->keys);
    gb_entries = mk_list_size(&cmd->gb_keys);
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

        task->window.records++;

        if (gb_entries > 0) {
            gb_nums = flb_calloc(1, sizeof(struct aggr_num) * gb_entries);
            if (!gb_nums) {
                flb_errno();
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            /* extract GROUP BY values */
            for (i = 0; i < map_size; i++) { /* extract group-by values */
                key = map.via.map.ptr[i].key;
                val = map.via.map.ptr[i].val;

                key_id = 0;
                mk_list_foreach(head, &cmd->gb_keys) {
                    gb_key = mk_list_entry(head, struct flb_sp_cmd_gb_key,
                                           _head);
                    if (flb_sds_cmp(gb_key->name, key.via.str.ptr,
                                    key.via.str.size) != 0) {
                        key_id++;
                        continue;
                    }

                    /* Convert string to number if that is possible */
                    ret = object_to_number(val, &ival, &dval);
                    if (ret == -1 && val.type == MSGPACK_OBJECT_STR) {
                        gb_nums[key_id].type = FLB_SP_STRING;
                        gb_nums[key_id].string =
                            flb_sds_create_len(val.via.str.ptr,
                                               val.via.str.size);
                        continue;
                    }

                    if (ret == -1 && val.type == MSGPACK_OBJECT_BOOLEAN) {
                        gb_nums[key_id].type = FLB_SP_NUM_I64;
                        gb_nums[key_id].i64 = val.via.boolean;

                        continue;
                    }

                    if (ret == FLB_STR_INT) {
                        gb_nums[key_id].type = FLB_SP_NUM_I64;
                        gb_nums[key_id].i64 = ival;
                    }
                    else if (ret == FLB_STR_FLOAT) {
                        gb_nums[key_id].type = FLB_SP_NUM_F64;
                        gb_nums[key_id].f64 = dval;
                    }
                }
            }

            aggr_node = (struct aggr_node *) flb_calloc(1, sizeof(struct aggr_node));
            aggr_node->groupby_keys = gb_entries;
            aggr_node->groupby_nums = gb_nums;

            rb_tree_find_or_insert(&task->window.aggr_tree, aggr_node, &aggr_node->_rb_head, &rb_result);
            if (&aggr_node->_rb_head != rb_result) {
                nums = container_of(rb_result, struct aggr_node, _rb_head)->nums;
                container_of(rb_result, struct aggr_node, _rb_head)->records++;

                /* We don't need aggr_node anymore */
                flb_sp_aggr_node_destroy(aggr_node);
            }
            else {
                aggr_node->nums = flb_calloc(1, sizeof(struct aggr_num) * map_entries);
                if (!aggr_node->nums) {
                    flb_errno();
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }
                nums = aggr_node->nums;
                aggr_node->records = 1;
                aggr_node->nums_size = map_entries;
                mk_list_add(&aggr_node->_head, &task->window.aggr_list);
            }
        }
        else { /* If query doesn't have GROUP BY */
            if (!mk_list_size(&task->window.aggr_list)) {
                aggr_node = flb_calloc(1, sizeof(struct aggr_node));
                if (!aggr_node) {
                    flb_errno();
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }
                aggr_node->nums = flb_calloc(1, sizeof(struct aggr_num) * map_entries);
                if (!aggr_node->nums) {
                    flb_errno();
                    flb_free(aggr_node);
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }

                aggr_node->nums_size = map_entries;
                aggr_node->records = 1;
                mk_list_add(&aggr_node->_head, &task->window.aggr_list);
            }
            else {
                aggr_node = mk_list_entry_first(&task->window.aggr_list, struct aggr_node, _head);
                aggr_node->records++;
            }

            nums = aggr_node->nums;
        }

        /* Iterate each map key and see if it matches any command key */
        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;
            val = map.via.map.ptr[i].val;

            if (key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            ival = 0;
            dval = 0.0;

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

                sval = flb_sp_key_to_value(ckey->name, map, ckey->subkeys);
                if (!sval) {
                    key_id++;
                    continue;
                }

                /*
                 * Convert value to a numeric representation only if key has an
                 * assigned aggregation function
                 */
                if (ckey->aggr_func != FLB_SP_NOP) {
                    if (ival == 0 && dval == 0.0) {
                        ret = object_to_number(sval->o, &ival, &dval);
                        if (ret == -1) {
                            /* Value cannot be represented as a number */
                            key_id++;
                            flb_sp_key_value_destroy(sval);
                            continue;
                        }
                    }

                    /*
                     * If a floating pointer number exists, we use the same data
                     * type for the output.
                     */
                    if (dval != 0.0 && nums[key_id].type == FLB_SP_NUM_I64) {
                        nums[key_id].type = FLB_SP_NUM_F64;
                        nums[key_id].f64 = (double) nums[key_id].i64;
                    }
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
                    else if (val.type == MSGPACK_OBJECT_FLOAT32 ||
                             val.type == MSGPACK_OBJECT_FLOAT) {
                        nums[key_id].type = FLB_SP_NUM_F64;
                        nums[key_id].f64 = sval->o.via.f64;
                    }
                    else if (val.type == MSGPACK_OBJECT_STR) {
                        nums[key_id].type = FLB_SP_STRING;
                        if (nums[key_id].string == NULL) {
                            nums[key_id].string =
                                flb_sds_create_len(sval->o.via.str.ptr,
                                                   sval->o.via.str.size);
                        }
                    }
                }

                switch (ckey->aggr_func) {
                case FLB_SP_AVG:
                case FLB_SP_SUM:
                    aggr_sum(nums, key_id, ival, dval);
                    break;
                case FLB_SP_COUNT:
                    break;
                case FLB_SP_MIN:
                    aggr_min(nums, key_id, ival, dval);
                    break;
                case FLB_SP_MAX:
                    aggr_max(nums, key_id, ival, dval);
                    break;
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
static int sp_process_data(const char *tag, int tag_len,
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
    int records = 0;
    uint8_t h;
    off_t map_off;
    off_t no_data;
    size_t off = 0;
    char *tmp;
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
    struct flb_sp_cmd *cmd = task->cmd;
    struct flb_sp_cmd_key *cmd_key;
    struct flb_exp_val *condition;
    struct flb_sp_value *sval;

    /* Vars initialization */
    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Iterate incoming records */
    while (msgpack_unpack_next(&result, buf_data, buf_size, &off) == ok) {
        root = result.data;
        records++;

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
                else if (cmd_key->subkeys &&
                         mk_list_size(cmd_key->subkeys) > 0) {
                    msgpack_pack_str(&mp_pck,
                                     flb_sds_len(cmd_key->name_keys));
                    msgpack_pack_str_body(&mp_pck,
                                          cmd_key->name_keys,
                                          flb_sds_len(cmd_key->name_keys));
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

    /* set outgoing results */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return records;
}

static int sp_process_hopping_slot(const char *tag, int tag_len,
                                   struct flb_sp_task *task)
{
    int i;
    int map_entries;
    int gb_entries;
    struct aggr_num *nums = NULL;
    struct flb_sp_cmd *cmd = task->cmd;
    struct mk_list *head;
    struct mk_list *head_hs;
    struct aggr_node *aggr_node;
    struct aggr_node *aggr_node_hs;
    struct aggr_node *aggr_node_prev;
    struct flb_sp_hopping_slot *hs;
    struct flb_sp_hopping_slot *hs_;
    struct rb_tree_node *rb_result;
    struct flb_sp_cmd_key *ckey;
    rb_result_t result;

    map_entries = mk_list_size(&cmd->keys);
    gb_entries = mk_list_size(&cmd->gb_keys);

    // Initialize a hoping slot
    hs = flb_calloc(1, sizeof(struct flb_sp_hopping_slot));
    if (!hs) {
        flb_errno();
        return -1;
    }

    mk_list_init(&hs->aggr_list);
    rb_tree_new(&hs->aggr_tree, flb_sp_groupby_compare);

    // Loop over aggregation nodes on window
    mk_list_foreach(head, &task->window.aggr_list) {
        // Window aggregation node
        aggr_node = mk_list_entry(head, struct aggr_node, _head);

        // Create a hopping slot aggregation node
        aggr_node_hs = flb_calloc(1, sizeof(struct aggr_node));
        nums = flb_calloc(1, sizeof(struct aggr_node) * map_entries);

        memcpy(nums, aggr_node->nums, sizeof(struct aggr_num) * map_entries);
        aggr_node_hs->records = aggr_node->records;

        // Traverse over previous slots to calculate values/record numbers
        mk_list_foreach(head_hs, &task->window.hopping_slot) {
            hs_ = mk_list_entry(head_hs, struct flb_sp_hopping_slot, _head);
            result = rb_tree_find(&hs_->aggr_tree, aggr_node, &rb_result);
            /* If corresponding aggregation node exists in previous hopping slot,
             * calculate aggregation values
             */
            if (result == RB_OK) {
                aggr_node_prev = mk_list_entry(rb_result, struct aggr_node,
                                               _rb_head);
                aggr_node_hs->records -= aggr_node_prev->records;

                ckey = mk_list_entry_first(&cmd->keys, struct flb_sp_cmd_key,
                                           _head);
                for (i = 0; i < map_entries; i++) {
                    switch (ckey->aggr_func) {
                    case FLB_SP_AVG:
                    case FLB_SP_SUM:
                        if (nums[i].type == FLB_SP_NUM_I64) {
                            nums[i].i64 -= aggr_node_prev->nums[i].i64;
                        }
                        else if (nums[i].type == FLB_SP_NUM_F64) {
                            nums[i].f64 -= aggr_node_prev->nums[i].f64;
                        }
                        break;
                    }

                    ckey = mk_list_entry_next(&ckey->_head, struct flb_sp_cmd_key,
                                              _head, &cmd->keys);
                }
            }
        }

        if (aggr_node_hs->records > 0) {
            aggr_node_hs->groupby_nums =
                flb_calloc(1, sizeof(struct aggr_node) * gb_entries);
            memcpy(aggr_node_hs->groupby_nums, aggr_node->groupby_nums,
                   sizeof(struct aggr_num) * gb_entries);

            aggr_node_hs->nums = nums;
            aggr_node_hs->nums_size = aggr_node->nums_size;
            aggr_node_hs->groupby_keys = aggr_node->groupby_keys;

            rb_tree_insert(&hs->aggr_tree, aggr_node_hs, &aggr_node_hs->_rb_head);
            mk_list_add(&aggr_node_hs->_head, &hs->aggr_list);
        }
        else {
            flb_free(nums);
            flb_free(aggr_node_hs->groupby_nums);
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

/*
 * Do data processing for internal unit tests, no engine required, set
 * results on out_data/out_size variables.
 */
int flb_sp_test_do(struct flb_sp *sp, struct flb_sp_task *task,
                   const char *tag, int tag_len,
                   const char *buf_data, size_t buf_size,
                   char **out_data, size_t *out_size)
{
    int ret;
    int records;
    struct flb_sp_cmd *cmd;

    cmd = task->cmd;
    if (cmd->source_type == FLB_SP_TAG) {
        ret = flb_router_match(tag, tag_len, cmd->source_name, NULL);
        if (ret == FLB_FALSE) {
            *out_data = NULL;
            *out_size = 0;
            return 0;
        }
    }

    if (task->aggr_keys == FLB_TRUE) {
        ret = sp_process_data_aggr(buf_data, buf_size,
                                   tag, tag_len,
                                   task, sp);
        if (ret == -1) {
            flb_error("[sp] error error processing records for '%s'",
                      task->name);
            return -1;
        }

        if (flb_sp_window_populate(task, buf_data, buf_size) == -1) {
            flb_error("[sp] error populating window for '%s'",
                      task->name);
            return -1;
        }

        if (task->window.type == FLB_SP_WINDOW_DEFAULT) {
            package_results(tag, tag_len, out_data, out_size, task);
        }

        records = task->window.records;
    }
    else {
        ret = sp_process_data(tag, tag_len,
                              buf_data, buf_size,
                              out_data, out_size,
                              task, sp);
        if (ret == -1) {
            flb_error("[sp] error processing records for '%s'",
                      task->name);
            return -1;
        }
        records = ret;
    }

    if (records == 0) {
        *out_data = NULL;
        *out_size = 0;
        return 0;
    }

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

    /* Lookup Tasks that matches the incoming instance data */
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
        if (task->aggr_keys == FLB_TRUE) {
            ret = sp_process_data_aggr(buf_data, buf_size,
                                       tag, tag_len,
                                       task, sp);

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
        if (task->aggr_keys != FLB_TRUE ||
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
    struct flb_input_instance *in;


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

            if (update_timer_event) {
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

int flb_sp_test_fd_event(int fd, struct flb_sp_task *task, char **out_data,
                         size_t *out_size)
{
    char *tag = NULL;
    int tag_len = 0;

    if (task->window.type != FLB_SP_WINDOW_DEFAULT) {
        if (fd == task->window.fd) {
            if (task->window.records > 0) {
                /* find input tag from task source */
                package_results(tag, tag_len, out_data, out_size, task);
                if (task->stream) {
                    flb_sp_stream_append_data(*out_data, *out_size, task->stream);
                }
                else {
                    flb_pack_print(*out_data, *out_size);
                }
            }

            flb_sp_window_prune(task);
        }
        else if (fd == task->window.fd_hop) {
            sp_process_hopping_slot(tag, tag_len, task);
        }

    }
    return 0;
}
