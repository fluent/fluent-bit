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

#ifndef FLB_SP_TIMESERIES_H
#define FLB_SP_TIMESERIES_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

#include <math.h>
#include <float.h>

#define TIMESERIES_FUNCTIONS_SIZE 2

typedef struct timeseries *(*timeseries_function_alloc_typ)(int);
typedef struct timeseries *(*timeseries_function_clone_typ)(struct timeseries *);

typedef void (*timeseries_function_add_typ)(struct timeseries *,
                                            struct flb_time *);

typedef void (*timeseries_function_rem_typ) (struct timeseries *,
                                             struct timeseries *,
                                             struct flb_time *);

typedef void (*timeseries_function_calc_typ) (struct timeseries *,
                                              struct flb_sp_cmd_key *,
                                              msgpack_packer *,
                                              int, struct flb_time *);

typedef void (*timeseries_function_destroy_typ)(struct timeseries *);

/* forecast functions */
struct timeseries *cb_forecast_alloc()
{
    struct timeseries *ts;

    ts = (struct timeseries *) flb_calloc(1, sizeof(struct timeseries_forecast));

    return ts;
}

struct timeseries *cb_forecast_clone(struct timeseries *ts)
{
    /*
       This function doean't actually clone all parameters. It only copies the
       values required for hopping window calculations
     */
    struct timeseries_forecast *forecast;
    struct timeseries_forecast *forecast_c;

    forecast = (struct timeseries_forecast *) ts;

    forecast_c = (struct timeseries_forecast *)
                 flb_calloc(1, sizeof(struct timeseries_forecast));
    if (!forecast_c) {
        flb_errno();
        return NULL;
    }

    forecast_c->sigma_x = forecast->sigma_x;
    forecast_c->sigma_y = forecast->sigma_y;
    forecast_c->sigma_xy = forecast->sigma_xy;
    forecast_c->sigma_x2 = forecast->sigma_x2;

    return (struct timeseries *) forecast_c;
}

void cb_forecast_add(struct timeseries *ts, struct flb_time *tm)
{
    double x;
    double y;
    struct timeseries_forecast *forecast;
    struct aggr_num *val;

    forecast = (struct timeseries_forecast *) ts;

    val = ts->nums;

    switch (val->type) {
    /* Forecast values are always floating points */
    case FLB_SP_NUM_I64:
        if (!forecast->offset) {
            forecast->offset = flb_calloc(1, sizeof(double));
            if (!forecast->offset) {
                flb_errno();
                return;
            }
            *forecast->offset = (double) val->i64;
        }

        x = ((double) val->i64 - *forecast->offset);
        break;
    case FLB_SP_NUM_F64:
        if (!forecast->offset) {
            forecast->offset = flb_calloc(1, sizeof(double));
            if (!forecast->offset) {
                flb_errno();
                return;
            }
            *forecast->offset = val->f64;
        }
        x = val->f64 - *forecast->offset;
        break;
    default:
        return;
        break;
    }

    if (!forecast->latest_x) {
        forecast->latest_x = flb_malloc(sizeof(double));
        if (!forecast->latest_x) {
            flb_errno();
            return;
        }
    }

    *forecast->latest_x = x;

    val++;
    switch (val->type) {
    /* Forecast values are always floating points */
    case FLB_SP_NUM_I64:
        y = (double) val->i64;
        break;
    case FLB_SP_NUM_F64:
        y = val->f64;
        break;
    default:
        return;
        break;
    }

    forecast->sigma_x += x;
    forecast->sigma_y += y;

    forecast->sigma_xy += x * y;
    forecast->sigma_x2 += x * x;
}

void cb_forecast_rem(struct timeseries *ts_w,
                     struct timeseries *ts_h, struct flb_time *tm)
{
    struct timeseries_forecast *forecast_w;
    struct timeseries_forecast *forecast_h;

    forecast_w = (struct timeseries_forecast *) ts_w;
    forecast_h = (struct timeseries_forecast *) ts_h;

    forecast_w->sigma_x -= forecast_h->sigma_x;
    forecast_w->sigma_y -= forecast_h->sigma_y;
    forecast_w->sigma_xy -= forecast_h->sigma_xy;
    forecast_w->sigma_x2 -= forecast_h->sigma_x2;
}

void cb_forecast_calc(struct timeseries *ts, struct flb_sp_cmd_key *cmd_key,
                      msgpack_packer *mp_pck, int records, struct flb_time *tm)
{
    double mean_x;
    double mean_y;
    double var_x;
    double cov_xy;
    double result;
    /* y = b0 + b1 * x */
    double b0;
    double b1;
    struct aggr_num *val;
    struct timeseries_forecast *forecast;

    forecast = (struct timeseries_forecast *) ts;

    mean_x = forecast->sigma_x / records;
    mean_y = forecast->sigma_y / records;
    cov_xy = (forecast->sigma_xy / (double) records) - mean_x * mean_y;
    var_x = (forecast->sigma_x2 / records) - mean_x * mean_x;

    b1 = cov_xy / var_x;
    b0 = mean_y - b1 * mean_x;

    /*
     * calculate forecast for value (3rd argument) + latest 'x' seen in window.
     */
    val = ts->nums + 2;

    switch (val->type) {
    case FLB_SP_NUM_I64:
        result = b0 + b1 * ((double) val->i64 + *forecast->latest_x);
        break;
    case FLB_SP_NUM_F64:
        result = b0 + b1 * (val->f64 + *forecast->latest_x);
        break;
    default:
        result = nan("");
        break;
    }

    /* pack the result */
    if (cmd_key->alias) {
        msgpack_pack_str(mp_pck, flb_sds_len(cmd_key->alias));
        msgpack_pack_str_body(mp_pck,
                              cmd_key->alias,
                              flb_sds_len(cmd_key->alias));
    }
    else {
        msgpack_pack_str(mp_pck, 8);
        msgpack_pack_str_body(mp_pck, "FORECAST", 8);
    }
    msgpack_pack_float(mp_pck, result);
}

void cb_forecast_r_calc(struct timeseries *ts, struct flb_sp_cmd_key *cmd_key,
                        msgpack_packer *mp_pck, int records, struct flb_time *tm)
{
    double mean_x;
    double mean_y;
    double var_x;
    double cov_xy;
    double result;
    /* y = b0 + b1 * x */
    double b0;
    double b1;

    double maximum_x;
    struct aggr_num *val;
    struct timeseries_forecast *forecast;

    forecast = (struct timeseries_forecast *) ts;

    mean_x = forecast->sigma_x / records;
    mean_y = forecast->sigma_y / records;
    cov_xy = (forecast->sigma_xy / (double) records) - mean_x * mean_y;
    var_x = (forecast->sigma_x2 / records) - mean_x * mean_x;

    b1 = cov_xy / var_x;
    b0 = mean_y - b1 * mean_x;


    /* Get the cap (4th arguement) */
    val = ts->nums + 3;
    switch (val->type) {
    case FLB_SP_NUM_I64:
        maximum_x = (double) val->i64;
        break;
    case FLB_SP_NUM_F64:
        maximum_x = val->f64;
        break;
    default:
        return;
        break;
    }

    /*
     * calculate forecast for value (3rd argument).
     */
    val = ts->nums + 2;

    if (b1 == 0) {
        result = maximum_x;
    }
    else {
        switch (val->type) {
        case FLB_SP_NUM_I64:
            result = (((double) val->i64 - b0) / b1) - *forecast->latest_x;
            break;
        case FLB_SP_NUM_F64:
            result = ((val->i64 - b0) / b1) - *forecast->latest_x;
            break;
        default:
            result = nan("");
            break;
        }

        if (result < 0) {
            result = maximum_x;
        }
    }

    /* pack the result */
    if (cmd_key->alias) {
        msgpack_pack_str(mp_pck, flb_sds_len(cmd_key->alias));
        msgpack_pack_str_body(mp_pck,
                              cmd_key->alias,
                              flb_sds_len(cmd_key->alias));
    }
    else {
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "FORECAST_R", 10);
    }
    msgpack_pack_float(mp_pck, result);
}

void cb_forecast_destroy(struct timeseries *ts)
{
    struct timeseries_forecast *forecast;

    forecast = (struct timeseries_forecast *) ts;

    flb_free(forecast->offset);
    forecast->offset = NULL;

    flb_free(forecast->latest_x);
    forecast->latest_x = NULL;
}


char *timeseries_functions[TIMESERIES_FUNCTIONS_SIZE] = {
    "forecast",
    "forecast_r",
};

/* Timeseries function memory allocation */
timeseries_function_alloc_typ timeseries_functions_alloc_ptr[TIMESERIES_FUNCTIONS_SIZE] = {
    cb_forecast_alloc,
    cb_forecast_alloc,
};

/* Timeseries function clone */
timeseries_function_clone_typ timeseries_functions_clone_ptr[TIMESERIES_FUNCTIONS_SIZE] = {
    cb_forecast_clone,
    cb_forecast_clone,
};

/* Timeseries function record addition */
timeseries_function_add_typ timeseries_functions_add_ptr[TIMESERIES_FUNCTIONS_SIZE] = {
    cb_forecast_add,
    cb_forecast_add,
};

/* Timeseries function record removal */
timeseries_function_rem_typ timeseries_functions_rem_ptr[TIMESERIES_FUNCTIONS_SIZE] = {
    cb_forecast_rem,
    cb_forecast_rem,
};

/* Timeseries function calculation */
timeseries_function_calc_typ timeseries_functions_calc_ptr[TIMESERIES_FUNCTIONS_SIZE] = {
    cb_forecast_calc,
    cb_forecast_r_calc,
};

/* Timeseries function calculation */
timeseries_function_destroy_typ timeseries_functions_destroy_ptr[TIMESERIES_FUNCTIONS_SIZE] = {
    cb_forecast_destroy,
    cb_forecast_destroy,
};

#endif
