/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdint.h>

struct map {
    struct map_entry {
        const char *k;
        uintmax_t v;
    } * entries;
    size_t nentries;
};

void
map_set(struct map *m, const char *k, uintmax_t v);
uintmax_t
map_get(struct map *m, const char *k);
