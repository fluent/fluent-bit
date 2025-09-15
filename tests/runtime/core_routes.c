/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;

static int cb_count_msgpack(void *record, size_t size, void *data)
{
    pthread_mutex_lock(&result_mutex);
    num_output++;
    pthread_mutex_unlock(&result_mutex);

    return 0;
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

void flb_test_basic_functionality_test(void)
{
    int                   output_instances[257];
    size_t                delivery_counter;
    int                   input_instance;
    const char           *log_data = "[0, {\"log\": \"test\"}]";
    int                   cb_context;
    struct flb_lib_out_cb cb_data;
    int                   result;
    size_t                index;
    flb_ctx_t            *ctx;

    cb_context = 0;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &cb_context;

    ctx = flb_create();

    input_instance = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(input_instance >= 0);

    flb_input_set(ctx, input_instance, "tag", "test", NULL);

    for (index = 0 ; index < 257 ; index++) {
        output_instances[index] = flb_output(ctx, (char *) "lib", &cb_data);
        TEST_CHECK(output_instances[index] >= 0);

        flb_output_set(ctx,
                       output_instances[index],
                       "match", "test",
                       "workers", "0",
                       NULL);
    }

    clear_output_num();

    result = flb_start(ctx);
    TEST_CHECK(result == 0);

    flb_lib_push(ctx, input_instance, log_data, strlen(log_data));

    /* minimum flush delta */
    flb_time_msleep(1000);

    delivery_counter = get_output_num();

    for (index = 0 ;
         index < 100 && delivery_counter < 257 ;
         index++) {
        flb_time_msleep(100);

        delivery_counter = get_output_num();
    }

    TEST_CHECK(delivery_counter == 257);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"basic_functionality_test", flb_test_basic_functionality_test},
    {NULL, NULL}
};
