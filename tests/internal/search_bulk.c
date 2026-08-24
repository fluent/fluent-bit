/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <fluent-bit/flb_search_bulk.h>

#include "flb_tests_internal.h"

#define BULK_PAYLOAD                                                    \
    "{\"create\":{\"_index\":\"logs\",\"_id\":\"one\"}}\n"       \
    "{\"message\":\"one\"}\n"                                      \
    "{\"create\":{\"_index\":\"logs\",\"_id\":\"two\"}}\n"       \
    "{\"message\":\"two\"}\n"                                      \
    "{\"create\":{\"_index\":\"logs\",\"_id\":\"three\"}}\n"     \
    "{\"message\":\"three\"}\n"

#define SECOND_ENTRY                                                    \
    "{\"create\":{\"_index\":\"logs\",\"_id\":\"two\"}}\n"       \
    "{\"message\":\"two\"}\n"

static void test_mixed_response_keeps_only_unresolved(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;

    response = "{\"errors\":true,\"items\":["
               "{\"create\":{\"status\":201}},"
               "{\"create\":{\"status\":429}},"
               "{\"create\":{\"status\":409}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              BULK_PAYLOAD,
                                              strlen(BULK_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_RETRY);
    TEST_CHECK(retry != NULL);
    TEST_CHECK(retry->records == 1);
    TEST_CHECK(retry->size == strlen(SECOND_ENTRY));
    TEST_CHECK(memcmp(retry->payload, SECOND_ENTRY, retry->size) == 0);
    flb_search_bulk_retry_destroy(retry);
}

static void test_create_conflicts_are_complete(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;

    response = "{\"errors\":true,\"items\":["
               "{\"create\":{\"status\":409}},"
               "{\"create\":{\"status\":409}},"
               "{\"create\":{\"status\":409}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              BULK_PAYLOAD,
                                              strlen(BULK_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_COMPLETE);
    TEST_CHECK(retry == NULL);
}

static void test_update_conflict_is_retried(void)
{
    int result;
    const char *payload;
    const char *response;
    struct flb_search_bulk_retry *retry;

    payload = "{\"update\":{\"_index\":\"logs\",\"_id\":\"one\"}}\n"
              "{\"doc\":{\"message\":\"one\"}}\n";
    response = "{\"errors\":true,\"items\":["
               "{\"update\":{\"status\":409}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              payload, strlen(payload),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_RETRY);
    TEST_CHECK(retry != NULL);
    TEST_CHECK(retry->records == 1);
    TEST_CHECK(retry->size == strlen(payload));
    flb_search_bulk_retry_destroy(retry);
}

static void test_update_conflict_is_complete_when_all_conflicts_are_acknowledged(void)
{
    int result;
    const char *payload;
    const char *response;
    struct flb_search_bulk_retry *retry;

    payload = "{\"update\":{\"_index\":\"logs\",\"_id\":\"one\"}}\n"
              "{\"doc\":{\"message\":\"one\"}}\n";
    response = "{\"errors\":true,\"items\":["
               "{\"update\":{\"status\":409}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              payload, strlen(payload),
                                              FLB_SEARCH_BULK_ACK_ALL_CONFLICTS,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_COMPLETE);
    TEST_CHECK(retry == NULL);
}

static void test_truncated_success_response_is_complete(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;

    response = "{\"took\":1,\"errors\":false,\"items\":["
               "{\"create\":{\"status\":201}}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              BULK_PAYLOAD,
                                              strlen(BULK_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_COMPLETE);
    TEST_CHECK(retry == NULL);
}

static void test_item_count_mismatch_is_invalid(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;

    response = "{\"errors\":true,\"items\":["
               "{\"create\":{\"status\":429}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              BULK_PAYLOAD,
                                              strlen(BULK_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_INVALID);
    TEST_CHECK(retry == NULL);
}

TEST_LIST = {
    {"mixed_response_keeps_only_unresolved", test_mixed_response_keeps_only_unresolved},
    {"create_conflicts_are_complete", test_create_conflicts_are_complete},
    {"update_conflict_is_retried", test_update_conflict_is_retried},
    {"update_conflict_is_complete_when_all_conflicts_are_acknowledged",
     test_update_conflict_is_complete_when_all_conflicts_are_acknowledged},
    {"truncated_success_response_is_complete",
     test_truncated_success_response_is_complete},
    {"item_count_mismatch_is_invalid", test_item_count_mismatch_is_invalid},
    {NULL, NULL}
};
