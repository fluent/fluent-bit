/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_output.h>

#include "flb_tests_internal.h"

void test_output_destroy_unregisters_queued_event(void)
{
    int ret;
    struct flb_config *config;
    struct flb_output_instance *output;
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;

    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }
#endif

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        goto cleanup;
    }
    config->evl = mk_event_loop_create(8);
    config->evl_bktq = flb_bucket_queue_create(FLB_ENGINE_PRIORITY_COUNT);
    if (!TEST_CHECK(config->evl != NULL && config->evl_bktq != NULL)) {
        flb_config_exit(config);
        goto cleanup;
    }

    output = flb_output_new(config, "null", NULL, FLB_FALSE);
    if (!TEST_CHECK(output != NULL)) {
        flb_config_exit(config);
        goto cleanup;
    }

    ret = mk_event_channel_create(config->evl, &output->ch_events[0],
                                   &output->ch_events[1], &output->event);
    if (TEST_CHECK(ret == 0)) {
        /* Shutdown may run while an output completion event is still queued. */
        flb_event_load_bucket_queue_event(config->evl_bktq, &output->event);
        TEST_CHECK(!flb_bucket_queue_is_empty(config->evl_bktq));
    }

    flb_output_instance_destroy(output);
    TEST_CHECK(flb_bucket_queue_find_min(config->evl_bktq) == NULL);
    flb_config_exit(config);

cleanup:
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
    return;
}

void test_output_exit_destroys_pending_flushes(void)
{
    int index;
    char *processed_data;
    struct flb_config *config;
    struct flb_output_instance *output;
    struct flb_output_flush *flush;
    struct flb_task task;
    struct flb_event_chunk event_chunk;

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        return;
    }
    output = flb_output_new(config, "null", NULL, FLB_FALSE);
    if (!TEST_CHECK(output != NULL)) {
        flb_config_exit(config);
        return;
    }

    memset(&task, 0, sizeof(task));
    memset(&event_chunk, 0, sizeof(event_chunk));
    event_chunk.type = FLB_EVENT_TYPE_LOGS;
    event_chunk.data = "original";
    event_chunk.size = 8;
    task.event_chunk = &event_chunk;
    flb_coro_thread_init();

    for (index = 0; index < 3; index++) {
        /* The coroutine is prepared but has not run the plugin callback. */
        flush = flb_output_flush_create(&task, NULL, output, config);
        if (!TEST_CHECK(flush != NULL)) {
            break;
        }

        if (index == 0) {
            /* A completed coroutine may also await its completion event. */
            flb_output_flush_prepare_destroy(flush);
            continue;
        }

        processed_data = event_chunk.data;
        if (index == 1) {
            processed_data = flb_strdup("processed");
            if (!TEST_CHECK(processed_data != NULL)) {
                break;
            }
        }
        flush->processed_event_chunk = flb_event_chunk_create(
                                          FLB_EVENT_TYPE_LOGS, 1,
                                          "test", 4, processed_data, 8);
        if (!TEST_CHECK(flush->processed_event_chunk != NULL)) {
            if (processed_data != event_chunk.data) {
                flb_free(processed_data);
            }
            break;
        }
    }

    TEST_CHECK(mk_list_size(&output->flush_list) == 2);
    TEST_CHECK(mk_list_size(&output->flush_list_destroy) == 1);
    /* Valgrind verifies both lists, coroutine stacks and processed buffers. */
    flb_output_exit(config);
    TEST_CHECK(mk_list_is_empty(&config->outputs) == 0);
    flb_config_exit(config);
}

TEST_LIST = {
    {"output_destroy_unregisters_queued_event", test_output_destroy_unregisters_queued_event},
    {"output_exit_destroys_pending_flushes", test_output_exit_destroys_pending_flushes},
    {NULL, NULL}
};
