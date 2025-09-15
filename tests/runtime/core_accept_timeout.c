#include <fluent-bit.h>
#include "flb_tests_runtime.h"

void flb_test_downstream_accept_timeout()
{
    struct flb_net_setup net_setup;
    struct mk_event_loop *evl;
    struct flb_config *config;
    struct flb_downstream *ds = NULL;
    struct flb_connection *conn = NULL;
    time_t now;

    flb_engine_evl_init();

    evl = mk_event_loop_create(16);
    TEST_CHECK(evl != NULL);
    if (!evl) {
        TEST_MSG("event loop creation failed");
        return;
    }
    flb_engine_evl_set(evl);

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        mk_event_loop_destroy(evl);
        return;
    }

    flb_net_setup_init(&net_setup);
    net_setup.accept_timeout = 1;
    net_setup.connect_timeout = 0;
    net_setup.accept_timeout_log_error = FLB_FALSE;

    ds = flb_downstream_create(FLB_TRANSPORT_TCP,
                               FLB_IO_TCP,
                               "127.0.0.1",
                               0,
                               NULL,
                               config,
                               &net_setup);
    TEST_CHECK(ds != NULL);
    if (!ds) {
        flb_config_exit(config);
        mk_event_loop_destroy(evl);
        return;
    }

    flb_stream_disable_async_mode(&ds->base);

    conn = flb_connection_create(FLB_INVALID_SOCKET,
                                 FLB_DOWNSTREAM_CONNECTION,
                                 (void *) ds,
                                 evl,
                                 NULL);
    TEST_CHECK(conn != NULL);
    if (!conn) {
        flb_downstream_destroy(ds);
        flb_config_exit(config);
        mk_event_loop_destroy(evl);
        return;
    }

    mk_list_add(&conn->_head, &ds->busy_queue);

    now = time(NULL);
    conn->ts_connect_timeout = now - 1;
    conn->net_error = -1;

    flb_downstream_conn_timeouts(&config->downstreams);

    TEST_CHECK(mk_list_size(&ds->destroy_queue) == 1);

    flb_downstream_destroy(ds);
    flb_config_exit(config);
    mk_event_loop_destroy(evl);
}

TEST_LIST = {
    {"downstream_accept_timeout", flb_test_downstream_accept_timeout},
    {NULL, NULL}
};

