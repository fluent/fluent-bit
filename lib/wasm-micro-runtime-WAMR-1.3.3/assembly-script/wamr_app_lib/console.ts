/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

@external("env", "puts")
declare function printf(a: ArrayBuffer): i32;

export function log(a: string): void {
    printf(String.UTF8.encode(a, true));
}

export function log_number(a: number): void {
    printf(String.UTF8.encode(a.toString()));
}