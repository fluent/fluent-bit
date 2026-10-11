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

#define FOUR_ENTRY_BULK_PAYLOAD                                         \
    BULK_PAYLOAD                                                        \
    "{\"create\":{\"_index\":\"logs\",\"_id\":\"four\"}}\n"      \
    "{\"message\":\"four\"}\n"

#define UPSERT_PAYLOAD                                                  \
    "{\"update\":{\"_index\":\"logs\",\"_id\":\"one\"}}\n"       \
    "{\"doc_as_upsert\":true,\"doc\":{\"message\":\"one\"}}\n"       \
    "{\"update\":{\"_index\":\"logs\",\"_id\":\"two\"}}\n"       \
    "{\"doc_as_upsert\":true,\"doc\":{\"message\":\"two\"}}\n"

#define SECOND_UPSERT_ENTRY                                             \
    "{\"update\":{\"_index\":\"logs\",\"_id\":\"two\"}}\n"       \
    "{\"doc_as_upsert\":true,\"doc\":{\"message\":\"two\"}}\n"

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
                                              FLB_FALSE, NULL,
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
                                              FLB_FALSE, NULL,
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
                                              FLB_FALSE, NULL,
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
                                              FLB_FALSE, NULL,
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
                                              FLB_FALSE, NULL,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_COMPLETE);
    TEST_CHECK(retry == NULL);
}

static void test_nested_success_marker_with_top_level_errors_is_invalid(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;

    response = "{\"metadata\":{\"errors\":false,\"items\":[1]},"
               "\"errors\":true,\"items\":[{\"create\":{\"status\":429}}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              BULK_PAYLOAD,
                                              strlen(BULK_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              FLB_FALSE, NULL,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_INVALID);
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
                                              FLB_FALSE, NULL,
                                              &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_INVALID);
    TEST_CHECK(retry == NULL);
}

static void test_mixed_response_populates_stats(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;
    struct flb_search_bulk_stats stats;

    response = "{\"errors\":true,\"items\":["
               "{\"create\":{\"status\":201}},"
               "{\"create\":{\"status\":200}},"
               "{\"create\":{\"status\":400,\"error\":{"
               "\"type\":\"mapper_parsing_exception\","
               "\"reason\":\"strict mapping conflict\"}}},"
               "{\"create\":{\"status\":429,\"error\":{"
               "\"type\":\"es_rejected_execution_exception\","
               "\"reason\":\"queue is full\"}}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              FOUR_ENTRY_BULK_PAYLOAD,
                                              strlen(FOUR_ENTRY_BULK_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              FLB_FALSE, &stats, &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_RETRY);
    TEST_CHECK(retry != NULL);
    TEST_CHECK(retry->records == 2);
    TEST_CHECK(stats.total_items == 4);
    TEST_CHECK(stats.successful_items == 2);
    TEST_CHECK(stats.successful_bytes < strlen(FOUR_ENTRY_BULK_PAYLOAD));
    TEST_CHECK(stats.failed_items == 2);
    TEST_CHECK(stats.retryable_items == 1);
    TEST_CHECK(stats.unrecoverable_items == 1);
    TEST_CHECK(stats.unrecoverable_bytes > 0);
    TEST_CHECK(stats.first_error_status == 400);
    TEST_CHECK(strcmp(stats.first_error_type, "mapper_parsing_exception") == 0);
    TEST_CHECK(strcmp(stats.first_error_reason, "strict mapping conflict") == 0);
    flb_search_bulk_retry_destroy(retry);
}

static void test_drop_unrecoverable_upsert_records(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;
    struct flb_search_bulk_stats stats;

    response = "{\"errors\":true,\"items\":["
               "{\"update\":{\"status\":400,\"error\":{"
               "\"type\":\"illegal_argument_exception\","
               "\"reason\":\"invalid field\"}}},"
               "{\"update\":{\"status\":429}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              UPSERT_PAYLOAD,
                                              strlen(UPSERT_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              FLB_TRUE, &stats, &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_RETRY);
    TEST_CHECK(retry != NULL);
    TEST_CHECK(retry->records == 1);
    TEST_CHECK(retry->size == strlen(SECOND_UPSERT_ENTRY));
    TEST_CHECK(memcmp(retry->payload, SECOND_UPSERT_ENTRY, retry->size) == 0);
    TEST_CHECK(stats.retryable_items == 1);
    TEST_CHECK(stats.unrecoverable_items == 1);
    flb_search_bulk_retry_destroy(retry);

    result = flb_search_bulk_process_response(response, strlen(response),
                                              UPSERT_PAYLOAD,
                                              strlen(UPSERT_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              FLB_FALSE, &stats, &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_RETRY);
    TEST_CHECK(retry != NULL);
    TEST_CHECK(retry->records == 2);
    TEST_CHECK(retry->size == strlen(UPSERT_PAYLOAD));
    TEST_CHECK(memcmp(retry->payload, UPSERT_PAYLOAD, retry->size) == 0);
    flb_search_bulk_retry_destroy(retry);
}

static void test_only_unrecoverable_records_complete_when_dropped(void)
{
    int result;
    const char *response;
    struct flb_search_bulk_retry *retry;
    struct flb_search_bulk_stats stats;

    response = "{\"errors\":true,\"items\":["
               "{\"update\":{\"status\":400}},"
               "{\"update\":{\"status\":422}}]}";

    result = flb_search_bulk_process_response(response, strlen(response),
                                              UPSERT_PAYLOAD,
                                              strlen(UPSERT_PAYLOAD),
                                              FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS,
                                              FLB_TRUE, &stats, &retry);
    TEST_CHECK(result == FLB_SEARCH_BULK_COMPLETE);
    TEST_CHECK(retry == NULL);
    TEST_CHECK(stats.failed_items == 2);
    TEST_CHECK(stats.successful_items == 0);
    TEST_CHECK(stats.successful_bytes == 0);
    TEST_CHECK(stats.retryable_items == 0);
    TEST_CHECK(stats.unrecoverable_items == 2);
    TEST_CHECK(stats.unrecoverable_bytes == strlen(UPSERT_PAYLOAD));
}

TEST_LIST = {
    {"mixed_response_keeps_only_unresolved", test_mixed_response_keeps_only_unresolved},
    {"create_conflicts_are_complete", test_create_conflicts_are_complete},
    {"update_conflict_is_retried", test_update_conflict_is_retried},
    {"update_conflict_is_complete_when_all_conflicts_are_acknowledged",
     test_update_conflict_is_complete_when_all_conflicts_are_acknowledged},
    {"truncated_success_response_is_complete",
     test_truncated_success_response_is_complete},
    {"nested_success_marker_with_top_level_errors_is_invalid",
     test_nested_success_marker_with_top_level_errors_is_invalid},
    {"item_count_mismatch_is_invalid", test_item_count_mismatch_is_invalid},
    {"mixed_response_populates_stats", test_mixed_response_populates_stats},
    {"drop_unrecoverable_upsert_records", test_drop_unrecoverable_upsert_records},
    {"only_unrecoverable_records_complete_when_dropped",
     test_only_unrecoverable_records_complete_when_dropped},
    {NULL, NULL}
};
