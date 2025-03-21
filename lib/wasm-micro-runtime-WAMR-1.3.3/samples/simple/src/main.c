/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

extern void
iwasm_main();

int
main(int argc, char *argv[])
{
    iwasm_main(argc, argv);
    return 0;
}
