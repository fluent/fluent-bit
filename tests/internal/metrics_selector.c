/* Fluent Bit: metrics selector failure and ownership tests, Apache-2.0. */
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_map.h>

#include "flb_tests_internal.h"

static int fail_merge;

#ifdef FLB_TEST_CMT_CAT_WRAP
int __real_cmt_cat(struct cmt *destination, struct cmt *source);

int __wrap_cmt_cat(struct cmt *destination, struct cmt *source)
{
    int ret;

    ret = __real_cmt_cat(destination, source);
    /* Emulate failure after the merge has already populated its destination. */
    return fail_merge ? -1 : ret;
}
#endif

static void run_selector(int by_label, int incompatible, int no_match)
{
    int ret;
    double value;
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_processor_instance *instance;
    struct cmt *input;
    struct cmt *output;
    struct cmt_counter *first;
    struct cmt_counter *second;

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "selector_test", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_ASSERT(unit != NULL);
    if (by_label) {
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "context", "delete_label_value") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "label", "missing value") == 0);
    }
    else {
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "metric_name",
                                                       no_match ? "missing" : "series") == 0);
    }
    TEST_ASSERT(flb_processor_init(processor) == 0);
    input = cmt_create();
    TEST_ASSERT(input != NULL);
    first = cmt_counter_create(input, "", "", "series", "test", 0, NULL);
    second = cmt_counter_create(input, "", "", "series", "test", 0, NULL);
    TEST_ASSERT(first != NULL && second != NULL);
    first->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
    second->aggregation_type = incompatible ? CMT_AGGREGATION_TYPE_DELTA :
                                             CMT_AGGREGATION_TYPE_CUMULATIVE;
    TEST_CHECK(cmt_counter_set(first, 1, 10, 0, NULL) == 0);
    TEST_CHECK(cmt_counter_set(second, 2, 20, 0, NULL) == 0);

    /* Call the plugin directly so the engine cannot hide a stale output. */
    instance = unit->ctx;
    output = input;
    ret = instance->p->cb_process_metrics(instance, input, &output, "test", 4);
    if (incompatible || fail_merge) {
        TEST_CHECK(ret == FLB_PROCESSOR_FAILURE);
        TEST_CHECK(output == NULL);
    }
    else {
        TEST_CHECK(ret == FLB_PROCESSOR_SUCCESS);
        TEST_ASSERT(output != NULL && output != input);
        TEST_CHECK(cfl_list_size(&output->counters) == (no_match ? 0 : 1));
        cmt_destroy(output);
    }
    /* Failure and success both leave the caller's input alive and unchanged. */
    TEST_CHECK(cmt_counter_get_val(first, 0, NULL, &value) == 0);
    TEST_CHECK(value == 10);
    TEST_CHECK(cmt_counter_get_val(second, 0, NULL, &value) == 0);
    TEST_CHECK(value == 20);
    cmt_destroy(input);
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

static void name_failure(void)
{
    run_selector(0, 1, 0);
}

static void label_failure(void)
{
    run_selector(1, 1, 0);
}

static void name_success(void)
{
    run_selector(0, 0, 0);
}

static void label_success(void)
{
    run_selector(1, 0, 0);
}

static void name_no_match(void)
{
    run_selector(0, 0, 1);
}

#ifdef FLB_TEST_CMT_CAT_WRAP
static void name_merge_failure(void)
{
    fail_merge = 1;
    run_selector(0, 0, 0);
    fail_merge = 0;
}

static void label_merge_failure(void)
{
    fail_merge = 1;
    run_selector(1, 0, 0);
    fail_merge = 0;
}
#endif

TEST_LIST = {
    {"name_failure", name_failure},
    {"label_failure", label_failure},
    {"name_success", name_success},
    {"label_success", label_success},
    {"name_no_match", name_no_match},
#ifdef FLB_TEST_CMT_CAT_WRAP
    {"name_merge_failure", name_merge_failure},
    {"label_merge_failure", label_merge_failure},
#endif
    {NULL, NULL}
};
