#include <math.h>

#include <lua.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_untyped.h>

#include "calyptia_metrics_to_lua.h"
#include "cfl_to_lua.h"

#define DOUBLE_MAX_SAFE_INTEGER 9007199254740991
#define DOUBLE_MIN_SAFE_INTEGER -9007199254740991

static void push_uint64(lua_State *L, uint64_t val)
{
    char buf[64];
    if (val > DOUBLE_MAX_SAFE_INTEGER || val < DOUBLE_MIN_SAFE_INTEGER) {
        snprintf(buf, sizeof(buf), "%" PRIu64, val);
        lua_pushstring(L, buf);
    }
    else {
        lua_pushnumber(L, val);
    }
}

static void push_timestamp(lua_State *L, struct cmt_map *map,
                           struct cmt_metric *metric)
{
    uint64_t timestamp;

    timestamp = cmt_metric_get_timestamp(metric);
    if (timestamp) {
        push_timestamp_as_string(L, cmt_metric_get_timestamp(metric));
        lua_setfield(L, -2, "timestamp");
    }
}

static void push_counter_gauge_untyped(lua_State *L, struct cmt_map *map,
                                       struct cmt_metric *metric)
{
    lua_pushnumber(L, cmt_metric_get_value(metric));
    lua_setfield(L, -2, "value");
}

static void push_histogram(lua_State *L, struct cmt_map *map,
                           struct cmt_metric *metric)
{
    int i;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *bucket;
    struct cmt_opts *opts;

    histogram = (struct cmt_histogram *) map->parent;
    bucket = histogram->buckets;
    opts = map->opts;

    lua_createtable(L, bucket->count, 0);
    for (i = 0; i <= bucket->count; i++) {
        if (i < bucket->count) {
            lua_pushnumber(L, bucket->upper_bounds[i]);
        }
        else {
            lua_pushnumber(L, INFINITY);
        }
        push_uint64(L, cmt_metric_hist_get_value(metric, i));
        lua_settable(L, -3);
    }
    lua_setfield(L, -2, "buckets");

    lua_pushnumber(L, cmt_metric_hist_get_sum_value(metric));
    lua_setfield(L, -2, "sum");

    lua_pushnumber(L, cmt_metric_hist_get_count_value(metric));
    lua_setfield(L, -2, "count");
}

static void push_summary(lua_State *L, struct cmt_map *map,
                         struct cmt_metric *metric)
{
    struct cmt_summary *summary;
    struct cmt_opts *opts;

    summary = (struct cmt_summary *) map->parent;
    opts = map->opts;

    if (metric->sum_quantiles_set) {
        lua_createtable(L, summary->quantiles_count, 0);
        for (int i = 0; i < summary->quantiles_count; i++) {
            lua_pushnumber(L, summary->quantiles[i]);
            lua_pushnumber(L, cmt_summary_quantile_get_value(metric, i));
            lua_settable(L, -3);
        }
        lua_setfield(L, -2, "quantiles");
    }

    lua_pushnumber(L, cmt_summary_get_sum_value(metric));
    lua_setfield(L, -2, "sum");

    lua_pushnumber(L, cmt_summary_get_count_value(metric));
    lua_setfield(L, -2, "count");
}

static void push_metric(lua_State *L, struct cmt_map *map,
                        struct cmt_metric *metric)
{
    struct cfl_list *head;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;

    /* labels, value, timestamp, count, sum, quantiles, buckets */
    lua_createtable(L, 6, 0);

    push_timestamp(L, map, metric);
    if (map->type == CMT_HISTOGRAM) {
        push_histogram(L, map, metric);
    }
    else if (map->type == CMT_SUMMARY) {
        push_summary(L, map, metric);
    }
    else {
        push_counter_gauge_untyped(L, map, metric);
    }

    if (cfl_list_size(&metric->labels) == 0) {
        return;
    }

    /* labels table */
    label_k
        = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);
    lua_createtable(L, cfl_list_size(&metric->labels), 0);
    cfl_list_foreach(head, &metric->labels)
    {
        label_v = cfl_list_entry(head, struct cmt_map_label, _head);

        lua_pushlstring(L, label_k->name, cfl_sds_len(label_k->name));
        lua_pushlstring(L, label_v->name, cfl_sds_len(label_v->name));
        lua_settable(L, -3);

        label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                      _head, &map->label_keys);
    }
    lua_setfield(L, -2, "labels");
}

static void push_header(lua_State *L, cfl_sds_t fqname, cfl_sds_t description,
                        const char *type)
{
    lua_createtable(L, 4, 0);

    lua_pushlstring(L, fqname, cfl_sds_len(fqname));
    lua_setfield(L, -2, "name");

    lua_pushlstring(L, description, cfl_sds_len(description));
    lua_setfield(L, -2, "help");

    lua_pushstring(L, type);
    lua_setfield(L, -2, "type");
}

static void push_metrics(lua_State *L, struct cmt *cmt, struct cmt_map *map,
                         const char *kind)
{
    struct cfl_list *head;
    struct cmt_metric *metric;
    int metric_count;

    metric_count = cfl_list_size(&map->metrics);
    if (metric_count == 0 && !map->metric_static_set) {
        return;
    }

    /* counter table, 4 keys: name, help, type and metrics array */
    push_header(L, map->opts->fqname, map->opts->description, kind);

    /* metrics array */
    lua_createtable(L, metric_count + 1, 0);

    if (map->metric_static_set) {
        push_metric(L, map, &map->metric);
        lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    }

    if (metric_count) {
        cfl_list_foreach(head, &map->metrics)
        {
            metric = cfl_list_entry(head, struct cmt_metric, _head);
            push_metric(L, map, metric);
            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
        }
    }

    lua_setfield(L, -2, "metrics");
    lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
}

int calyptia_metrics_to_lua(lua_State *L, struct cmt *cmt)
{
    int count;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_untyped *untyped;

    if (cmt == NULL) {
        return -1;
    }

    count = cfl_list_size(&cmt->counters) + cfl_list_size(&cmt->gauges)
            + cfl_list_size(&cmt->summaries) + cfl_list_size(&cmt->histograms)
            + cfl_list_size(&cmt->untypeds);

    /* metrics array */
    lua_createtable(L, count, 0);

    /* Counters */
    cfl_list_foreach(head, &cmt->counters)
    {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        push_metrics(L, cmt, counter->map, "COUNTER");
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges)
    {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        push_metrics(L, cmt, gauge->map, "GAUGE");
    }

    /* Summaries */
    cfl_list_foreach(head, &cmt->summaries)
    {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        push_metrics(L, cmt, summary->map, "SUMMARY");
    }

    /* Histograms */
    cfl_list_foreach(head, &cmt->histograms)
    {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        push_metrics(L, cmt, histogram->map, "HISTOGRAM");
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds)
    {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        push_metrics(L, cmt, untyped->map, "UNTYPED");
    }

    return 0;
}
