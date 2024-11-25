/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIBC_STDBOOL_H
#define _WAMR_LIBC_STDBOOL_H

#define __bool_true_false_are_defined 1

#ifndef __cplusplus

#define bool _Bool
#define false 0
#define true 1

#endif /* __cplusplus */

#endif