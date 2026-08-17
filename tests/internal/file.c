#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_sds.h>
#include <string.h>

#include "flb_tests_internal.h"
#include "fluent-bit/stream_processor/flb_sp.h"

#define TEXT_FILE    FLB_TESTS_DATA_PATH "/data/file/text_file.txt"
#define EMPTY_FILE    FLB_TESTS_DATA_PATH "/data/file/empty_file.txt"

static void check_equals(flb_sds_t result, const char *expected)
{
    size_t expected_len = strlen(expected);
    size_t result_len = flb_sds_len(result);
    TEST_CHECK(expected_len == result_len);
    TEST_MSG("Expected length: %zu", expected_len);
    TEST_MSG("Actual length:   %zu", result_len);
    TEST_CHECK(memcmp(result, expected, expected_len) == 0);
    TEST_MSG("Expected: %s", expected);
    TEST_MSG("Actual:   %s", result);
}

static void test_file_read_text_file()
{
    flb_sds_t result = flb_file_read_contents(TEXT_FILE);
    /* In Windows, \n is replaced with \r\n by git settings. */
    if (strstr(result, "\r\n") != NULL) {
      check_equals(result, "Some text file\r\n\r\nline 3\r\n\r\nline 5\r\n");
    }
    else {
      check_equals(result, "Some text file\n\nline 3\n\nline 5\n");
    }
    flb_sds_destroy(result);
}

static void test_file_read_empty_file()
{
    flb_sds_t result = flb_file_read_contents(EMPTY_FILE);
    check_equals(result, "");
    flb_sds_destroy(result);
}

static void test_file_read_missing()
{
    flb_sds_t result = flb_file_read_contents(TEXT_FILE ".missing");
    TEST_CHECK(result == NULL);
}

TEST_LIST = {
    { "file_read_text_file" , test_file_read_text_file},
    { "file_read_empty_file" , test_file_read_empty_file},
    { "file_read_missing" , test_file_read_missing},
    { 0 }
};
