/* Fluent Bit: label conversion and cmetrics index regression, Apache-2.0. */
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>

#include "flb_tests_internal.h"

int metrics_map_convert_static_metric(struct cmt_map *map, size_t label_index,
                                      char *label_value);

static void converted_sample_is_indexed(void)
{
    struct cmt *context;
    struct cmt_gauge *gauge;
    struct cmt_metric *converted;
    struct cmt_metric *found;
    char *keys[] = {"region"};
    char *existing[] = {"west"};
    char *added[] = {"east"};

    context = cmt_create();
    TEST_ASSERT(context != NULL);
    gauge = cmt_gauge_create(context, "", "", "series", "test", 1, keys);
    TEST_ASSERT(gauge != NULL);
    TEST_CHECK(cmt_gauge_set(gauge, 1, 10, 1, existing) == 0);
    TEST_CHECK(cmt_gauge_set(gauge, 2, 20, 0, NULL) == 0);
    TEST_ASSERT(gauge->map->last_metric != NULL);

    TEST_CHECK(metrics_map_convert_static_metric(gauge->map, 0, added[0]) == 1);
    converted = cfl_list_entry_first(&gauge->map->metrics, struct cmt_metric, _head);
    found = cmt_map_metric_get(&gauge->opts, gauge->map, 1, added, CMT_FALSE);
    TEST_CHECK(found == converted);
    TEST_CHECK(cmt_gauge_set(gauge, 3, 30, 1, added) == 0);
    TEST_CHECK(cfl_list_size(&gauge->map->metrics) == 2);
    TEST_CHECK(cmt_metric_get_value(converted) == 30);
    cmt_destroy(context);
}

TEST_LIST = {
    {"converted_sample_is_indexed", converted_sample_is_indexed},
    {NULL, NULL}
};
