/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_http_retry_after.h>

#include "flb_tests_internal.h"

#include <stdint.h>
#include <string.h>

struct retry_after_case {
    const char *value;
    size_t length;
    int64_t received_wall_time_ms;
    int expected_status;
    uint64_t expected_delay_ms;
};

static void check_case(const struct retry_after_case *test_case)
{
    uint64_t delay_ms;
    int status;

    delay_ms = 123;
    status = flb_http_retry_after_parse(test_case->value, test_case->length,
                                        test_case->received_wall_time_ms,
                                        &delay_ms);
    TEST_CHECK(status == test_case->expected_status);
    if (status == FLB_RETRY_AFTER_VALID || status == FLB_RETRY_AFTER_SATURATED) {
        TEST_CHECK(delay_ms == test_case->expected_delay_ms);
    }
}

static void test_delta_seconds(void)
{
    static const char embedded_nul[] = {'1', '0', '\0', '0'};
    static const struct retry_after_case cases[] = {
        {"0", 1, 0, FLB_RETRY_AFTER_VALID, 0},
        {"  12\t", 5, 0, FLB_RETRY_AFTER_VALID, 12000},
        {"18446744073709551", 17, 0, FLB_RETRY_AFTER_VALID,
         UINT64_C(18446744073709551000)},
        {"18446744073709551615", 20, 0, FLB_RETRY_AFTER_SATURATED, UINT64_MAX},
        {"999999999999999999999999", 24, 0, FLB_RETRY_AFTER_SATURATED, UINT64_MAX},
        {"999999999999999999999999x", 25, 0, FLB_RETRY_AFTER_INVALID, 0},
        {"", 0, 0, FLB_RETRY_AFTER_INVALID, 0},
        {" \t ", 3, 0, FLB_RETRY_AFTER_INVALID, 0},
        {"+1", 2, 0, FLB_RETRY_AFTER_INVALID, 0},
        {"-1", 2, 0, FLB_RETRY_AFTER_INVALID, 0},
        {"1.5", 3, 0, FLB_RETRY_AFTER_INVALID, 0},
        {"1 2", 3, 0, FLB_RETRY_AFTER_INVALID, 0},
        {embedded_nul, sizeof(embedded_nul), 0, FLB_RETRY_AFTER_INVALID, 0}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        check_case(&cases[index]);
    }
}

static void test_http_dates(void)
{
    static const struct retry_after_case cases[] = {
        {"Sun, 06 Nov 1994 08:49:37 GMT", 29, INT64_C(784111772000),
         FLB_RETRY_AFTER_VALID, 5000},
        {"Sunday, 06-Nov-94 08:49:37 GMT", 30, INT64_C(784111772000),
         FLB_RETRY_AFTER_VALID, 5000},
        {"Sun Nov  6 08:49:37 1994", 24, INT64_C(784111772000),
         FLB_RETRY_AFTER_VALID, 5000},
        {"\tWed, 21 Oct 2015 07:28:00 GMT ", 31, INT64_C(1445412470000),
         FLB_RETRY_AFTER_VALID, 10000},
        {"Sat, 29 Feb 2020 00:00:00 GMT", 29, INT64_C(1582934395000),
         FLB_RETRY_AFTER_VALID, 5000},
        {"Sun, 06 Nov 1994 08:49:37 GMT", 29, INT64_C(784111778000),
         FLB_RETRY_AFTER_VALID, 0},
        {"Thu, 29 Feb 2019 00:00:00 GMT", 29, 0,
         FLB_RETRY_AFTER_INVALID, 0},
        {"Mon, 06 Nov 1994 08:49:37 GMT", 29, 0,
         FLB_RETRY_AFTER_INVALID, 0},
        {"Sun, 06 Nov 1994 08:49:37 UTC", 29, 0,
         FLB_RETRY_AFTER_INVALID, 0},
        {"Sun, 06 Nov 1994 08:49", 22, 0, FLB_RETRY_AFTER_INVALID, 0}
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        check_case(&cases[index]);
    }
}

static void test_header_block(void)
{
    const char headers[] =
        "HTTP/1.1 429 Too Many Requests\r\n"
        "retry-after: 5\r\n"
        "X-Test: value\r\n"
        "Retry-After: invalid\r\n"
        "RETRY-AFTER:\t12 \r\n"
        "\r\nbody";
    const char date_header[] =
        "Retry-After: Sun, 06 Nov 1994 08:49:37 GMT\r\n\r\n";
    const char combined_header[] = "Retry-After: 5, 12\r\n\r\n";
    const char absent_header[] = "X-Retry-After: 12\r\n\r\n";
    const char colonless_header[] = "Retry-After\r\n\r\n";
    const char colonless_then_valid_header[] =
        "Retry-After\r\n"
        "Retry-After: 7\r\n\r\n";
    uint64_t delay_ms;
    size_t invalid_count;
    int status;

    status = flb_http_retry_after_parse_headers(headers, sizeof(headers) - 1, 0,
                                                &delay_ms, &invalid_count);
    TEST_CHECK(status == FLB_RETRY_AFTER_VALID);
    TEST_CHECK(delay_ms == 12000);
    TEST_CHECK(invalid_count == 1);

    status = flb_http_retry_after_parse_headers(date_header, sizeof(date_header) - 1,
                                                INT64_C(784111772000), &delay_ms,
                                                &invalid_count);
    TEST_CHECK(status == FLB_RETRY_AFTER_VALID);
    TEST_CHECK(delay_ms == 5000);
    TEST_CHECK(invalid_count == 0);

    status = flb_http_retry_after_parse_headers(combined_header,
                                                sizeof(combined_header) - 1, 0,
                                                &delay_ms, &invalid_count);
    TEST_CHECK(status == FLB_RETRY_AFTER_INVALID);
    TEST_CHECK(invalid_count == 1);

    status = flb_http_retry_after_parse_headers(absent_header,
                                                sizeof(absent_header) - 1, 0,
                                                &delay_ms, &invalid_count);
    TEST_CHECK(status == FLB_RETRY_AFTER_ABSENT);
    TEST_CHECK(invalid_count == 0);

    status = flb_http_retry_after_parse_headers(colonless_header,
                                                sizeof(colonless_header) - 1, 0,
                                                &delay_ms, &invalid_count);
    TEST_CHECK(status == FLB_RETRY_AFTER_ABSENT);
    TEST_CHECK(invalid_count == 0);

    status = flb_http_retry_after_parse_headers(colonless_then_valid_header,
                                                sizeof(colonless_then_valid_header) - 1,
                                                0, &delay_ms, &invalid_count);
    TEST_CHECK(status == FLB_RETRY_AFTER_VALID);
    TEST_CHECK(delay_ms == 7000);
    TEST_CHECK(invalid_count == 0);
}

TEST_LIST = {
    {"delta_seconds", test_delta_seconds},
    {"http_dates", test_http_dates},
    {"header_block", test_header_block},
    {0}
};
