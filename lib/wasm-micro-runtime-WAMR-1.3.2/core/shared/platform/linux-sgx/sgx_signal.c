/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

#ifndef SGX_DISABLE_WASI

#define TRACE_OCALL_FAIL() os_printf("ocall %s failed!\n", __FUNCTION__)

int
ocall_raise(int *p_ret, int sig);

int
raise(int sig)
{
    int ret;

    if (ocall_raise(&ret, sig) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

#endif
