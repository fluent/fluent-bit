/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include <string.h>
#include "bh_platform.h"
#include "bh_assert.h"
#include "bh_log.h"
#include "wasm_export.h"

extern void
display_init(void);
extern int
iwasm_main();

void
main(void)
{
    display_init();
    iwasm_main();
    for (;;) {
        k_sleep(Z_TIMEOUT_MS(1000));
    }
}
