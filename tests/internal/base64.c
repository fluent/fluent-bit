#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_base64.h>
#include <mbedtls/base64.h>
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

static void b64_performance_test_encode()
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb;
    uint64_t elapsed_time_mbedtls;
    double acceptableTimeIncrease = 1.20; /* acceptable to have 20% slower performance */
    char* data = "Hello world";
    char out[100];
    int iter = 100000;
    size_t olen;
    out[16] = 'X';
    int i;

    flb_time_get(&start_time);
    for (i = 0; i < iter; ++i) {
        flb_base64_encode((unsigned char *) out, 100, &olen, (unsigned char *)data, 11);
    }
    flb_time_get(&end_time);
    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_flb = flb_time_to_nanosec(&diff_time);

    flb_time_get(&start_time);
    for (i = 0; i < iter; ++i) {
        mbedtls_base64_encode((unsigned char *) out, 100, &olen, (unsigned char *)data,
                              11);
    }
    flb_time_get(&end_time);
    flb_time_diff(&end_time, &start_time, &diff_time);
    elapsed_time_mbedtls = flb_time_to_nanosec(&diff_time);

    printf("flb_base64_encode %d iterations complete in %lums and %luns\n", iter,
            elapsed_time_flb / 1000000L, elapsed_time_flb % 1000000L);
    printf("flb_mbedtls_encode %d iterations complete in %lums and %luns\n", iter,
            elapsed_time_mbedtls / 1000000L, elapsed_time_mbedtls % 1000000L);

    TEST_CHECK(elapsed_time_flb * acceptableTimeIncrease < elapsed_time_mbedtls);
    TEST_MSG("Base64 mbedtls performance is now similar to fluent bit's. "
             "Revert to mbedtls base64.");
    return;
}

TEST_LIST = {
    { "b64_basic_test_encode" , b64_basic_test_encode },
    { "b64_basic_test_decode", b64_basic_test_decode },
    { "b64_performance_test_encode", b64_performance_test_encode },
    { 0 }
};
