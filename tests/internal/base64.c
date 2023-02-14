#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_internal.h"

static void b64_basic_test_encode()
{
    char* data = "Hello world";
    char out[100];
    char* expect = "SGVsbG8gd29ybGQ=";
    size_t olen;
    out[16] = 'X';

    flb_base64_encode((unsigned char *) out, 100, &olen, (unsigned char *)data, 11);

    TEST_CHECK(strlen(out) == 16 && olen == 16);
    TEST_MSG("Base64 encode failed to output result of expected length");

    TEST_CHECK(strcmp(out, expect) == 0);
    TEST_MSG("Base64 encode failed to output result of expected value");

    TEST_CHECK(out[16] == 0);
    TEST_MSG("Base64 not null terminated");
    return;
}

static void b64_basic_test_decode()
{
    char* data = "SGVsbG8gd29ybGQ=";
    char out[100] = { 0 };
    char* expect = "Hello world";
    size_t olen;

    flb_base64_decode((unsigned char *) out, 100, &olen, (unsigned char *)data, 16);

    TEST_CHECK(strlen(out) == 11 && olen == 11);
    TEST_MSG("Base64 decode failed to output result of expected length");

    TEST_CHECK(strcmp(out, expect) == 0);
    TEST_MSG("Base64 decode failed to output result of expected value");
    return;
}

TEST_LIST = {
    { "b64_basic_test_encode" , b64_basic_test_encode },
    { "b64_basic_test_decode", b64_basic_test_decode },
    { 0 }
};
