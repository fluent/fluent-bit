/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

/*
 * modified copy-and-paste from:
 * https://github.com/yamt/toywasm/blob/0eaad8cacd0cc7692946ff19b25994f106113be8/lib/fileio.h
 */

int
map_file(const char *filename, void **pp, size_t *szp);
void
unmap_file(void *p, size_t sz);
