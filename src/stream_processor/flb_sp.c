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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_stream.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* Aggr num type */
#define FLB_SP_NUM_I64       0
#define FLB_SP_NUM_F64       1

/* don't do this at home */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

struct aggr_num {
    int type;
    int ops;
    int64_t i64;
    double f64;
};

/* Read and process file system configuration file */
static int sp_config_file(struct flb_config *config, struct flb_sp *sp,
                          char *file)
{
    int ret;
    char *name;
    char *exec;
    char *cfg = NULL;
    char tmp[PATH_MAX + 1];
    struct stat st;
    struct mk_rconf *fconf;
    struct mk_rconf_section *section;
    struct mk_list *head;

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
        ret = flb_sp_task_create(sp, name, exec);
        if (ret == -1) {
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
    struct flb_sp_cmd_key *key;

    mk_list_foreach(head, &cmd->keys) {
        key = mk_list_entry(head, struct flb_sp_cmd_key, _head);
        if (key->aggr_func > 0) { /* AVG, SUM or COUNT */
            aggr++;
        }
        else {
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
 * Convert a msgpack object value to a number 'if possible'. The conversion
 * result is either stored on 'i' for 64 bits integers or in 'd' for
 * float/doubles.
 *
 * This function aims to take care of strings representing a value too.
 */
static int object_to_num(msgpack_object obj, int64_t *i, double *d)
{
    int c;
    int dots = 0;
    int64_t i_out;
    double d_out;
    char *end;
    char str_num[20];

    if (obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
        obj.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *i = obj.via.i64;
        return 0;
    }
    else if (obj.type == MSGPACK_OBJECT_FLOAT32 ||
             obj.type == MSGPACK_OBJECT_FLOAT) {
        *d = obj.via.f64;
        return 0;
    }
    else if (obj.type == MSGPACK_OBJECT_STR) {
        /* A numeric representation of a string should not exceed 19 chars */
        if (obj.via.str.size > 19) {
            return -1;
        }

        /* Detect if this is a floating point number */
        for (c = 0; c < obj.via.str.size; c++) {
            if (obj.via.str.ptr[c] == '.') {
                dots++;
            }
        }

        if (dots > 1) {
            return -1;
        }
        else if (dots == 1) {
            /* Floating point number */
            errno = 0;
            memcpy(str_num, obj.via.str.ptr, obj.via.str.size);
            str_num[obj.via.str.size] = '\0';

            d_out = strtold(str_num, &end);

            /* Check for various possible errors */
            if ((errno == ERANGE || (errno != 0 && d_out == 0))) {
                return -1;
            }

            if (end == obj.via.str.ptr) {
                return -1;
            }

            *d = d_out;
            return 0;
        }
        else {
            /* Integer */
            errno = 0;
            memcpy(str_num, obj.via.str.ptr, obj.via.str.size);
            str_num[obj.via.str.size] = '\0';

            i_out = strtoll(str_num, &end, 10);

            /* Check for various possible errors */
            if ((errno == ERANGE || (errno != 0 && i_out == 0))) {
                return -1;
            }

            if (end == obj.via.str.ptr) {
                return -1;
            }

            *i = i_out;
            return 0;
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

int flb_sp_task_create(struct flb_sp *sp, char *name, char *query)
{
    int ret;
    struct flb_sp_cmd *cmd;
    struct flb_sp_task *task;

    /*
     * Parse and validate the incoming exec query and create the 'command'
     * context (this will be associated to the task in a later step
     */
    cmd = flb_sp_cmd_create(query);
    if (!cmd) {
        flb_error("[sp] invalid query on task '%s': '%s'", name, query);
        return -1;
    }

    /* Create the task context */
    task = flb_calloc(1, sizeof(struct flb_sp_task));
    if (!task) {
        flb_errno();
        flb_sp_cmd_destroy(cmd);
        return -1;
    }
    task->name = flb_sds_create(name);
    if (!task->name) {
        flb_free(task);
        flb_sp_cmd_destroy(cmd);
        return -1;
    }

    task->query = flb_sds_create(query);
    if (!task->query) {
        flb_sds_destroy(task->name);
        flb_free(task);
        flb_sp_cmd_destroy(cmd);
        return -1;
    }

    task->sp = sp;
    task->cmd = cmd;
    mk_list_add(&task->_head, &sp->tasks);

    /*
     * Assume no aggregated keys exists, if so, a different strategy is
     * required to process the records.
     */
    task->aggr_keys = FLB_FALSE;

    /* Check and validate aggregated keys */
    ret = sp_cmd_aggregated_keys(task->cmd);
    if (ret == -1) {
        flb_error("[sp] aggregated query cannot mix not aggregated keys: %s",
                  query);
        flb_sp_task_destroy(task);
        return -1;
    }
    else if (ret > 0) {
        task->aggr_keys = FLB_TRUE;
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
            return -1;
        }
    }

    /*
     * Based in the command type, check if the source of data is a known
     * stream so make a reference on this task for a quick comparisson and
     * access it when processing data.
     */
    sp_task_to_instance(task, sp);
    return 0;
}

void flb_sp_task_destroy(struct flb_sp_task *task)
{
    flb_sds_destroy(task->name);
    flb_sds_destroy(task->query);
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
    int ret;
    struct flb_sp *sp;

    /* Allocate context */
    sp = flb_malloc(sizeof(struct flb_sp));
    if (!sp) {
        flb_errno();
        return NULL;
    }
    sp->config = config;
    mk_list_init(&sp->tasks);

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

static struct flb_exp_val *key_to_value(flb_sds_t ckey, msgpack_object *map)
{
     /* We might need to find a more efficient way to evaluate the keys
        appeain a condition */
    int i;
    int map_size;
    msgpack_object key;
    msgpack_object val;
    struct flb_exp_val *result;

    map_size = map->via.map.size;

    for (i = 0; i < map_size; i++) {
        key = map->via.map.ptr[i].key;
        val = map->via.map.ptr[i].val;

        /* Compare by length and by key name */
        if (flb_sds_cmp(ckey, (char *) key.via.str.ptr,
            key.via.str.size) != 0) {
            continue;
        }

        result = flb_malloc(sizeof(struct flb_exp_val));
        if (!result) {
            flb_errno();
            return NULL;
        }

        if (val.type == MSGPACK_OBJECT_BOOLEAN) {
            result->type = FLB_EXP_BOOL;
            result->val.boolean = val.via.boolean;
            return result;
        }
        else if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
            val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            result->type = FLB_EXP_INT;
            result->val.i64 = val.via.i64;
            return result;
        }
        else if (val.type == MSGPACK_OBJECT_FLOAT32 ||
                   val.type == MSGPACK_OBJECT_FLOAT) {
            result->type = FLB_EXP_FLOAT;
            result->val.f64 = val.via.f64;
            return result;
        }
        else if (val.type == MSGPACK_OBJECT_STR) {
            result->type = FLB_EXP_STRING;
            result->val.string = flb_sds_create_len((char *) val.via.str.ptr,
                                                    val.via.str.size);
            return result;
        }
        else {
            flb_free(result);
            return NULL;
        }
    }

    return NULL;
}

static void itof_convert(struct flb_exp_val *val) {
    if (val->type != FLB_EXP_INT) {
        return;
    }

    val->type = FLB_EXP_FLOAT;
    val->val.f64 = val->val.i64;
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

    if(left->type == FLB_EXP_INT && right->type == FLB_EXP_FLOAT) {
        itof_convert(left);
    }
    else if (left->type == FLB_EXP_FLOAT && right->type == FLB_EXP_INT) {
        itof_convert(right);
    }

    switch (op) {
    case FLB_EXP_EQ:
        if (left->type == right->type) {
            switch(left->type){
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
            switch(left->type){
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
    bool result;

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

    /* Null is always interpreted as false in a logical operation */
    lval = left? value_to_bool(left) : false;
    rval = right? value_to_bool(right) : false;

    result->type = FLB_EXP_BOOL;

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
                                             msgpack_object *map)
{
    int operation;
    struct flb_exp_val *ret, *left, *right;
    struct flb_exp_val *result;

    if (!expression) {
        return NULL;
    }

    result = flb_malloc(sizeof(struct flb_exp_val));
    if (!result) {
       flb_errno();
       return NULL;
    }

    switch (expression->type) {
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
        result->type = expression->type;
        result->val.string = ((struct flb_exp_val *) expression)->val.string;
        break;
    case FLB_EXP_KEY:
        ret = key_to_value(((struct flb_exp_key *) expression)->name, map);
        if (!ret) {
           flb_free(result);
           result = NULL;
           break;
        }

        switch (ret->type) {
        case FLB_EXP_BOOL:
            result->val.boolean = ret->val.boolean;
            break;
        case FLB_EXP_INT:
            result->val.i64 = ret->val.i64;
            break;
        case FLB_EXP_FLOAT:
                result->val.f64 = ret->val.f64;
                break;
            case FLB_EXP_STRING:
                result->val.string = ret->val.string;
        }
        result->type = ret->type;
        flb_free(ret);
        break;
    case FLB_LOGICAL_OP:
        left = reduce_expression(expression->left, map);
        right = reduce_expression(expression->right, map);

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
        flb_free(left);
        flb_free(right);
    }
    return result;
}

/*
 * Process data, task and it defined command involves the call of aggregation
 * functions (AVG, SUM, COUNT, MIN, MAX).
 */
static int sp_process_data_aggr(char *buf_data, size_t buf_size,
                                char **out_buf, size_t *out_size,
                                struct flb_sp_task *task,
                                struct flb_sp *sp)
{
    int i;
    int ok;
    int len;
    int ret;
    int map_entries;
    int map_size;
    int key_id;
    int records = 0;
    struct aggr_num *nums;
    size_t off = 0;
    char key_name[256];
    msgpack_object root;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    msgpack_object key;
    msgpack_object val;
    struct mk_list *head;
    struct flb_time tm;
    struct flb_sp_cmd *cmd = task->cmd;
    struct flb_sp_cmd_key *ckey;

    /* Number of expected output entries in the map */
    map_entries = mk_list_size(&cmd->keys);

    /* Allocate an array to keep results per key */
    nums = flb_calloc(1, sizeof(struct aggr_num) * map_entries);
    if (!nums) {
        flb_errno();
        return -1;
    }

    /* vars initialization */
    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* set outgoing array + map and it fixed size */
    msgpack_pack_array(&mp_pck, 2);

    flb_time_get(&tm);
    flb_time_append_to_msgpack(&tm, &mp_pck, 0);
    msgpack_pack_map(&mp_pck, map_entries);

    /* Iterate incoming records */
    while (msgpack_unpack_next(&result, buf_data, buf_size, &off) == ok) {
        root = result.data;
        records++;

        /* get the map data and it size (number of items) */
        map   = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* Iterate each map key and see if it matches any command key */
        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;
            val = map.via.map.ptr[i].val;

            if (key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            int64_t i = 0;
            double d = 0.0;

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

                /* Compare by length and by key name */
                if (flb_sds_len(ckey->name) != key.via.str.size) {
                    key_id++;
                    continue;
                }

                /* Matched key ? */
                if (strncmp(ckey->name, key.via.str.ptr,
                            key.via.str.size) != 0) {
                    key_id++;
                    continue;
                }

                /* Convert value to a numeric representation */
                if (i == 0 && d == 0.0) {
                    ret = object_to_num(val, &i, &d);
                    if (ret == -1) {
                        /* Value cannot be represented as a number */
                        key_id++;
                        continue;
                    }
                }

                /*
                 * If a floating pointer number exists, we use the same data
                 * type for the output.
                 */
                if (d != 0.0 && nums[key_id].type == FLB_SP_NUM_I64) {
                    nums[key_id].type = FLB_SP_NUM_F64;
                    nums[key_id].f64 = (double) nums[key_id].i64;
                }

                switch (ckey->aggr_func) {
                case FLB_SP_AVG:
                case FLB_SP_SUM:
                    aggr_sum(nums, key_id, i, d);
                    break;
                case FLB_SP_COUNT:
                    break;
                case FLB_SP_MIN:
                    aggr_min(nums, key_id, i, d);
                    break;
                case FLB_SP_MAX:
                    aggr_max(nums, key_id, i, d);
                    break;
                }
                key_id++;
            }
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Packaging results */
    ckey = mk_list_entry_first(&cmd->keys, struct flb_sp_cmd_key, _head);
    for (i = 0; i < map_entries; i++) {
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
            else {
                c_name = ckey->name;
            }

            switch (ckey->aggr_func) {
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
        case FLB_SP_AVG:
            /* average = sum(values) / records */
            if (nums[i].type == FLB_SP_NUM_I64) {
                msgpack_pack_float(&mp_pck, nums[i].i64 / records);
            }
            else if (nums[i].type == FLB_SP_NUM_F64) {
                msgpack_pack_float(&mp_pck, nums[i].f64 / records);
            }
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

        ckey = mk_list_entry_next(&ckey->_head, struct flb_sp_cmd_key,
                                  _head, &cmd->keys);
    }

    flb_free(nums);
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return records;
}

/*
 * Data processing (no aggregation functions)
 */
static int sp_process_data(char *buf_data, size_t buf_size,
                           char **out_buf, size_t *out_size,
                           struct flb_sp_task *task,
                           struct flb_sp *sp)
{
    int i;
    int ok;
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
    msgpack_packer  mp_pck;
    msgpack_object map;
    struct flb_time tms;
    struct mk_list *head;
    struct flb_sp_cmd *cmd = task->cmd;
    struct flb_sp_cmd_key *cmd_key;
    struct flb_exp_val *condition;

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
            condition = reduce_expression(cmd->condition, &map);
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

        /* Iterate every key/value pair and compare with task field selection */
        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;
            val = map.via.map.ptr[i].val;

            if (key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            /* Iterate task keys */
            mk_list_foreach(head, &cmd->keys) {
                cmd_key = mk_list_entry(head, struct flb_sp_cmd_key, _head);

                /* Wildcard selection: * */
                if (cmd_key->name == NULL) {
                    msgpack_pack_object(&mp_pck, key);
                    msgpack_pack_object(&mp_pck, val);
                    map_entries++;
                    continue;
                }

                /* Compare lengths */
                if (flb_sds_len(cmd_key->name) != key.via.str.size) {
                    continue;
                }

                /* Compare key name */
                if (strncmp(cmd_key->name, key.via.str.ptr,
                            key.via.str.size) == 0) {

                    /* Check if the command ask for an alias 'key AS abc' */
                    if (cmd_key->alias) {
                        msgpack_pack_str(&mp_pck, flb_sds_len(cmd_key->alias));
                        msgpack_pack_str_body(&mp_pck,
                                              cmd_key->alias,
                                              flb_sds_len(cmd_key->alias));
                    }
                    else {
                        msgpack_pack_object(&mp_pck, key);
                    }
                    msgpack_pack_object(&mp_pck, val);
                    map_entries++;
                }
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

/* Iterate and find input chunks to process */
int flb_sp_do(struct flb_sp *sp, struct flb_input_instance *in,
              char *buf_data, size_t buf_size)

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
            if (task->source_instance == in) {
                /*
                 * We found a task associated to one instance, do data
                 * processing.
                 */
                if (task->aggr_keys == FLB_TRUE) {
                    ret = sp_process_data_aggr(buf_data, buf_size,
                                               &out_buf, &out_size,
                                               task, sp);
                }
                else {
                    ret = sp_process_data(buf_data, buf_size,
                                          &out_buf, &out_size,
                                          task, sp);
                }

                if (ret == -1) {
                    flb_error("[sp] error processing records for '%'",
                              task->name);
                    continue;
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
                if (task->stream) {
                    flb_sp_stream_append_data(out_buf, out_size, task->stream);
                }
                else {
                    flb_pack_print(out_buf, out_size);
                    flb_free(out_buf);
                }
            }
        }
    }

    return -1;
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
