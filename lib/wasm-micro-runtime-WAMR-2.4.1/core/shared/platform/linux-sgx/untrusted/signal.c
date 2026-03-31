/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <signal.h>

int
ocall_raise(int sig)
{
    return raise(sig);
}