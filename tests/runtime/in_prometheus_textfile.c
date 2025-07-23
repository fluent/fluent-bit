#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

#define DPATH_PROM_TEXTFILE FLB_TESTS_DATA_PATH "/data/prometheus_textfile"

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int num_output = 0;

static int cb_count(void *record, size_t size, void *data)
{
    (void)record;
    (void)size;
    (void)data;

    pthread_mutex_lock(&result_mutex);
    num_output++;
    pthread_mutex_unlock(&result_mutex);
    flb_free(record);
    return 0;
}

static void clear_output()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

struct test_ctx {
    flb_ctx_t *flb;
    int i_ffd;
    int o_ffd;
};

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *cb)
{
    struct test_ctx *ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.2",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    ctx->o_ffd = flb_output(ctx->flb, (char *)"lib", cb);
    if (!TEST_CHECK(ctx->o_ffd >= 0)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void test_prometheus_textfile(void)
{
    struct flb_lib_out_cb cb = {0};
    struct test_ctx *ctx;
    int ret;
    int count = 0;
    struct flb_time start, end, diff;
    uint64_t ms = 0;

    cb.cb = cb_count;
    cb.data = NULL;

    clear_output();

    ctx = test_ctx_create(&cb);
    TEST_CHECK(ctx != NULL);

    ctx->i_ffd = flb_input(ctx->flb, (char *)"prometheus_textfile", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "scrape_interval", "1s",
                        "path", DPATH_PROM_TEXTFILE "/metrics.prom",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_get(&start);
    while (ms < 5000) {
        pthread_mutex_lock(&result_mutex);
        count = num_output;
        pthread_mutex_unlock(&result_mutex);
        if (count > 0) {
            break;
        }
        flb_time_msleep(200);
        flb_time_get(&end);
        flb_time_diff(&end, &start, &diff);
        ms = flb_time_to_nanosec(&diff) / 1000000;
    }

    TEST_CHECK(count > 0);

    test_ctx_destroy(ctx);
}

TEST_LIST = {
    {"prometheus_textfile", test_prometheus_textfile},
    {NULL, NULL}
};

