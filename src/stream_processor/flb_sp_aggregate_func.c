#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_aggregate_func.h>

char aggregate_func_string[AGGREGATE_FUNCTIONS][sizeof("TIMESERIES_FORECAST") + 1] = {
    "AVG",
    "SUM",
    "COUNT",
    "MIN",
    "MAX",
    "TIMESERIES_FORECAST"
};

int aggregate_func_clone_nop(struct aggregate_node *aggr_node,
                              struct aggregate_node *aggr_node_prev,
                              struct flb_sp_cmd_key *ckey,
                              int key_id) {
    return 0;
}

int aggregate_func_clone_timeseries_forecast(struct aggregate_node *aggr_node_clone,
                                              struct aggregate_node *aggr_node,
                                              struct flb_sp_cmd_key *ckey,
                                              int key_id) {
    struct timeseries_forecast *forecast_clone;
    struct timeseries_forecast *forecast;

    forecast_clone = (struct timeseries_forecast *) aggr_node_clone->aggregate_data[key_id];
    if (!forecast_clone) {
        forecast_clone = (struct timeseries_forecast *) flb_calloc(1, sizeof(struct timeseries_forecast));
        if (!forecast_clone) {
          return -1;
        }

        forecast_clone->future_time = ckey->constant;
        aggr_node_clone->aggregate_data[key_id] = (struct aggregate_data *) forecast_clone;
    }

    forecast = (struct timeseries_forecast *) aggr_node->aggregate_data[key_id];

    forecast_clone->sigma_x = forecast->sigma_x;
    forecast_clone->sigma_y = forecast->sigma_y;
    forecast_clone->sigma_xy = forecast->sigma_xy;
    forecast_clone->sigma_x2 = forecast->sigma_x2;

    return 0;
}

/* Summarize a value into the temporary array considering data type */
void aggregate_func_add_sum(struct aggregate_node *aggr_node,
                            struct flb_sp_cmd_key *ckey,
                            int key_id,
                            struct flb_time *tms,
                            int64_t ival, double dval) {
    if (aggr_node->nums[key_id].type == FLB_SP_NUM_I64) {
        aggr_node->nums[key_id].i64 += ival;
        aggr_node->nums[key_id].ops++;
    }
    else if (aggr_node->nums[key_id].type == FLB_SP_NUM_F64) {
        if (dval != 0.0) {
            aggr_node->nums[key_id].f64 += dval;
        }
        else {
            aggr_node->nums[key_id].f64 += (double) ival;
        }
        aggr_node->nums[key_id].ops++;
    }
}

void aggregate_func_add_count(struct aggregate_node *aggr_node,
                              struct flb_sp_cmd_key *ckey,
                              int key_id,
                              struct flb_time *tms,
                              int64_t ival, double dval) {
}

/* Calculate the minimum value considering data type */
void aggregate_func_add_min(struct aggregate_node *aggr_node,
                            struct flb_sp_cmd_key *ckey,
                            int key_id,
                            struct flb_time *tms,
                            int64_t ival, double dval) {

    if (aggr_node->nums[key_id].type == FLB_SP_NUM_I64) {
        if (aggr_node->nums[key_id].ops == 0) {
            aggr_node->nums[key_id].i64 = ival;
            aggr_node->nums[key_id].ops++;
        }
        else {
            if (aggr_node->nums[key_id].i64 > ival) {
                aggr_node->nums[key_id].i64 = ival;
                aggr_node->nums[key_id].ops++;
            }
        }
    }
    else if (aggr_node->nums[key_id].type == FLB_SP_NUM_F64) {
        if (dval != 0.0) {
            if (aggr_node->nums[key_id].ops == 0) {
                aggr_node->nums[key_id].f64 = dval;
                aggr_node->nums[key_id].ops++;
            }
            else {
                if (aggr_node->nums[key_id].f64 > dval) {
                    aggr_node->nums[key_id].f64 = dval;
                    aggr_node->nums[key_id].ops++;
                }
            }
        }
        else {
            if (aggr_node->nums[key_id].ops == 0) {
                aggr_node->nums[key_id].f64 = (double) ival;
                aggr_node->nums[key_id].ops++;
            }
            else {
                if (aggr_node->nums[key_id].f64 > (double) ival) {
                    aggr_node->nums[key_id].f64 = ival;
                    aggr_node->nums[key_id].ops++;
                }
            }
        }
    }
}

/* Calculate the maximum value considering data type */
void aggregate_func_add_max(struct aggregate_node *aggr_node,
                            struct flb_sp_cmd_key *ckey,
                            int key_id,
                            struct flb_time *tms,
                            int64_t ival, double dval) {
    if (aggr_node->nums[key_id].type == FLB_SP_NUM_I64) {
        if (aggr_node->nums[key_id].ops == 0) {
            aggr_node->nums[key_id].i64 = ival;
            aggr_node->nums[key_id].ops++;
        }
        else {
            if (aggr_node->nums[key_id].i64 < ival) {
                aggr_node->nums[key_id].i64 = ival;
                aggr_node->nums[key_id].ops++;
            }
        }
    }
    else if (aggr_node->nums[key_id].type == FLB_SP_NUM_F64) {
        if (dval != 0.0) {
            if (aggr_node->nums[key_id].ops == 0) {
                aggr_node->nums[key_id].f64 = dval;
                aggr_node->nums[key_id].ops++;
            }
            else {
                if (aggr_node->nums[key_id].f64 < dval) {
                    aggr_node->nums[key_id].f64 = dval;
                    aggr_node->nums[key_id].ops++;
                }
            }
        }
        else {
            if (aggr_node->nums[key_id].ops == 0) {
                aggr_node->nums[key_id].f64 = (double) ival;
                aggr_node->nums[key_id].ops++;
            }
            else {
                if (aggr_node->nums[key_id].f64 < (double) ival) {
                    aggr_node->nums[key_id].f64 = (double) ival;
                    aggr_node->nums[key_id].ops++;
                }
            }
        }
    }
}

void aggregate_func_calc_avg(struct aggregate_node *aggr_node,
                             struct flb_sp_cmd_key *ckey,
                             msgpack_packer *mp_pck,
                             int key_id) {
    double dval = 0.0;
    /* average = sum(values) / records */
    if (aggr_node->nums[key_id].type == FLB_SP_NUM_I64) {
        dval = (double) aggr_node->nums[key_id].i64 / aggr_node->records;
    }
    else if (aggr_node->nums[key_id].type == FLB_SP_NUM_F64) {
        dval = (double) aggr_node->nums[key_id].f64 / aggr_node->records;
    }

    msgpack_pack_float(mp_pck, dval);
}

void aggregate_func_calc_sum(struct aggregate_node *aggr_node,
                             struct flb_sp_cmd_key *ckey,
                             msgpack_packer *mp_pck,
                             int key_id) {
    /* pack result stored in nums[key_id] */
    if (aggr_node->nums[key_id].type == FLB_SP_NUM_I64) {
        msgpack_pack_int64(mp_pck, aggr_node->nums[key_id].i64);
    }
    else if (aggr_node->nums[key_id].type == FLB_SP_NUM_F64) {
        msgpack_pack_float(mp_pck, aggr_node->nums[key_id].f64);
    }
}

void aggregate_func_calc_count(struct aggregate_node *aggr_node,
                               struct flb_sp_cmd_key *ckey,
                               msgpack_packer *mp_pck,
                               int key_id) {
    /* number of records in total */
    msgpack_pack_int64(mp_pck, aggr_node->records);
}

void aggregate_func_remove_sum(struct aggregate_node *aggr_node,
                               struct aggregate_node *aggr_node_prev,
                               int key_id) {
    if (aggr_node->nums[key_id].type == FLB_SP_NUM_I64) {
        aggr_node->nums[key_id].i64 -= aggr_node_prev->nums[key_id].i64;
    }
    else if (aggr_node->nums[key_id].type == FLB_SP_NUM_F64) {
        aggr_node->nums[key_id].f64 -= aggr_node_prev->nums[key_id].f64;
    }
}

void aggregate_func_remove_nop(struct aggregate_node *aggr_node,
                               struct aggregate_node *aggr_node_prev,
                               int key_id) {
}

void aggregate_func_add_timeseries_forecast(struct aggregate_node *aggr_node,
                                            struct flb_sp_cmd_key *ckey,
                                            int key_id,
                                            struct flb_time *tms,
                                            int64_t ival, double dval)
{
    double x;
    double y;
    struct timeseries_forecast *forecast;

    forecast = (struct timeseries_forecast *) aggr_node->aggregate_data[key_id];
    if (!forecast) {
        forecast = (struct timeseries_forecast *) flb_calloc(1, sizeof(struct timeseries_forecast));
        /* fixme: return if error */

        forecast->future_time = ckey->constant;
        aggr_node->aggregate_data[key_id] = (struct aggregate_data *) forecast;
    }

    if (!forecast->offset) {
        forecast->offset = flb_time_to_double(tms);
    }

    x = flb_time_to_double(tms) - forecast->offset;

    forecast->latest_x = x;

    if (ival) {
      y = (double) ival;
    }
    else {
        y = dval;
      }

    forecast->sigma_x += x;
    forecast->sigma_y += y;

    forecast->sigma_xy += x * y;
    forecast->sigma_x2 += x * x;
}

void aggregate_func_calc_timeseries_forecast(struct aggregate_node *aggr_node,
                                             struct flb_sp_cmd_key *ckey,
                                             msgpack_packer *mp_pck,
                                             int key_id)
{
    double mean_x;
    double mean_y;
    double var_x;
    double cov_xy;
    double result;
    /* y = b0 + b1 * x */
    double b0;
    double b1;
    struct timeseries_forecast *forecast;

    forecast = (struct timeseries_forecast *) aggr_node->aggregate_data[key_id];

    mean_x = forecast->sigma_x / aggr_node->records;
    mean_y = forecast->sigma_y / aggr_node->records;
    cov_xy = (forecast->sigma_xy / (double) aggr_node->records) - mean_x * mean_y;
    var_x = (forecast->sigma_x2 / aggr_node->records) - mean_x * mean_x;

    b1 = cov_xy / var_x;
    b0 = mean_y - b1 * mean_x;

    result = b0 + b1 * (forecast->future_time + forecast->latest_x);

    msgpack_pack_float(mp_pck, result);
}

void aggregate_func_remove_timeseries_forecast(struct aggregate_node *aggr_node,
                                               struct aggregate_node *aggr_node_prev,
                                               int key_id)
{
    struct timeseries_forecast *forecast_w;
    struct timeseries_forecast *forecast_h;

    forecast_w = (struct timeseries_forecast *) aggr_node->aggregate_data[key_id];
    forecast_h = (struct timeseries_forecast *) aggr_node_prev->aggregate_data[key_id];

    forecast_w->sigma_x -= forecast_h->sigma_x;
    forecast_w->sigma_y -= forecast_h->sigma_y;
    forecast_w->sigma_xy -= forecast_h->sigma_xy;
    forecast_w->sigma_x2 -= forecast_h->sigma_x2;
}

void aggregate_func_destroy_sum(struct aggregate_node *aggr_node,
                                int key_id)
{
}

void aggregate_func_destroy_timeseries_forecast(struct aggregate_node *aggr_node,
                                                int key_id)
{
    flb_free(aggr_node->aggregate_data[key_id]);
}

aggregate_function_clone aggregate_func_clone[AGGREGATE_FUNCTIONS] = {
    aggregate_func_clone_nop,
    aggregate_func_clone_nop,
    aggregate_func_clone_nop,
    aggregate_func_clone_nop,
    aggregate_func_clone_nop,
    aggregate_func_clone_timeseries_forecast,
};

aggregate_function_add aggregate_func_add[AGGREGATE_FUNCTIONS] = {
    aggregate_func_add_sum,
    aggregate_func_add_sum,
    aggregate_func_add_count,
    aggregate_func_add_min,
    aggregate_func_add_max,
    aggregate_func_add_timeseries_forecast,
};

aggregate_function_calc aggregate_func_calc[AGGREGATE_FUNCTIONS] = {
    aggregate_func_calc_avg,
    aggregate_func_calc_sum,
    aggregate_func_calc_count,
    aggregate_func_calc_sum,
    aggregate_func_calc_sum,
    aggregate_func_calc_timeseries_forecast,
};

aggregate_function_remove aggregate_func_remove[AGGREGATE_FUNCTIONS] = {
    aggregate_func_remove_sum,
    aggregate_func_remove_sum,
    aggregate_func_remove_nop,
    aggregate_func_remove_nop,
    aggregate_func_remove_nop,
    aggregate_func_remove_timeseries_forecast,
};

aggregate_function_destroy aggregate_func_destroy[AGGREGATE_FUNCTIONS] = {
    aggregate_func_destroy_sum,
    aggregate_func_destroy_sum,
    aggregate_func_destroy_sum,
    aggregate_func_destroy_sum,
    aggregate_func_destroy_sum,
    aggregate_func_destroy_timeseries_forecast,
};
