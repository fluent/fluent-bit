/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
extern int
iwasm_main(int argc, char *argv[]);
int
main(int argc, char *argv[])
{
    return iwasm_main(argc, argv);
}
