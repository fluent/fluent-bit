/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pal.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "flb_tests_internal.h"

#define BUFSIZE (256)
#define BUFSIZE_SMALL (1)

#if defined(FLB_HAVE_STRERROR_R) || defined(FLB_HAVE_STRERROR_S)
static void test_pal_strerror_r_noerror()
{
    int ret;
    char buf[BUFSIZE];

    ret = flb_strerror_r(0, buf, sizeof(buf));

    TEST_CHECK(0 == ret);
    TEST_CHECK(NULL != memchr(buf, '\0', sizeof(buf)));
    TEST_CHECK(0 < strlen(buf));
}

static void test_pal_strerror_r_error_einval()
{
    int ret;
    char buf[BUFSIZE];

    ret = flb_strerror_r(EINVAL, buf, sizeof(buf));

    TEST_CHECK(0 == ret);
    TEST_CHECK(NULL != memchr(buf, '\0', sizeof(buf)));
    TEST_CHECK(0 < strlen(buf));
}

static void test_pal_strerror_r_smallbuf()
{
    int ret;
    char buf[BUFSIZE_SMALL];

    ret = flb_strerror_r(EINVAL, buf, sizeof(buf));

    /*
     * If the flb_strerror_r() implementation is strerror_s(3), the short
     * buffer cannot be detected; it seems such the condition is not a runtime
     * constraint violation.
     *
     * Only check here that the returned string is terminated as long as the
     * status is successful.
     */
    if (0 == ret) {
        TEST_CHECK(NULL != memchr(buf, '\0', sizeof(buf)));
        TEST_CHECK(0 == strlen(buf));
    }
}

static void test_pal_strerror_r_error_unknown()
{
    char buf[BUFSIZE];

    flb_strerror_r(INT_MAX, buf, sizeof(buf));

    /*
     * The return value upon an unknown errno is not covered by
     * flb_strerror_r(); it is difficult to find the max supported errno value.
     * Just assure that flb_strerror_r() returns a string error message.
     */
    TEST_CHECK(NULL != memchr(buf, '\0', sizeof(buf)));
    TEST_CHECK(0 < strlen(buf));
}
#endif

TEST_LIST = {
#if defined(FLB_HAVE_STRERROR_R) || defined(FLB_HAVE_STRERROR_S)
    { "pal_strerror_r_noerror" , test_pal_strerror_r_noerror},
    { "pal_strerror_r_error_einval" , test_pal_strerror_r_error_einval},
    { "pal_strerror_r_smallbuf" , test_pal_strerror_r_smallbuf},
    { "pal_strerror_r_error_unknown" , test_pal_strerror_r_error_unknown},
#endif
    { 0 }
};
