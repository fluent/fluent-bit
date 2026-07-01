/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "stdio.h"

void
print_line(char *str);

int
main()
{
    print_line("Hello World!");
    print_line("Wasm Micro Runtime");
    return 0;
}