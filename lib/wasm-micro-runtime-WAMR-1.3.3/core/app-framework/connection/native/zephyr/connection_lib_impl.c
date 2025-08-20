/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

/*
 * Note:
 * This file implements the linux version connection library which is
 * defined in connection_lib.h.
 * It also provides a reference impl of connections manager.
 */

#include "connection_lib.h"

/* clang-format off */
/*
 * Platform implementation of connection library
 */
connection_interface_t connection_impl = {
    ._open = NULL,
    ._close = NULL,
    ._send = NULL,
    ._config = NULL
};
/* clang-format on */
