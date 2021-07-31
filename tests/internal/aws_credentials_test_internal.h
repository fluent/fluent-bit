/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef AWS_CREDENTIALS_TEST_INTERNAL_H

#define AWS_CREDENTIALS_TEST_INTERNAL_H

#include "flb_tests_internal.h"

#define AWS_TEST_DATA_PATH(FILE_PATH) FLB_TESTS_DATA_PATH "data/aws_credentials/" FILE_PATH

static int unset_profile_env()
{
    int ret;
    ret = unsetenv("HOME");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    ret = unsetenv("AWS_CONFIG_FILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    ret = unsetenv("AWS_SHARED_CREDENTIALS_FILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    ret = unsetenv("AWS_DEFAULT_PROFILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    ret = unsetenv("AWS_PROFILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    return 0;
}

#endif /* AWS_CREDENTIALS_TEST_INTERNAL_H */
