/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pal.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "flb_tests_internal.h"

#define BUFSIZE (256)
#define BUFSIZE_SMALL (1)

#ifdef FLB_HAVE_STRERROR_R
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

    TEST_CHECK(ERANGE == ret);
    TEST_CHECK(NULL != memchr(buf, '\0', sizeof(buf)));
    TEST_CHECK(0 == strlen(buf));
}

static void test_pal_strerror_r_error_unknown()
{
    int ret;
    char buf[BUFSIZE];

    ret = flb_strerror_r(INT_MAX, buf, sizeof(buf));

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
#ifdef FLB_HAVE_STRERROR_R
    { "pal_strerror_r_noerror" , test_pal_strerror_r_noerror},
    { "pal_strerror_r_error_einval" , test_pal_strerror_r_error_einval},
    { "pal_strerror_r_smallbuf" , test_pal_strerror_r_smallbuf},
    { "pal_strerror_r_error_unknown" , test_pal_strerror_r_error_unknown},
#endif
    { 0 }
};
