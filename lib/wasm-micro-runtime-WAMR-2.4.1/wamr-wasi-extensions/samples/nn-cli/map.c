/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "map.h"

static uintmax_t *
map_find_slot(struct map *m, const char *name)
{
    size_t i;
    for (i = 0; i < m->nentries; i++) {
        if (!strcmp(m->entries[i].k, name)) {
            return &m->entries[i].v;
        }
    }
    return NULL;
}

static void
map_append(struct map *m, const char *k, uintmax_t v)
{
    m->entries = realloc(m->entries, (m->nentries + 1) * sizeof(*m->entries));
    if (m->entries == NULL) {
        exit(1);
    }
    struct map_entry *e = &m->entries[m->nentries++];
    e->k = k;
    e->v = v;
}

void
map_set(struct map *m, const char *k, uintmax_t v)
{
    uintmax_t *p = map_find_slot(m, k);
    if (p != NULL) {
        fprintf(stderr, "duplicated id \"%s\"\n", k);
        exit(1);
    }
    map_append(m, k, v);
}

uintmax_t
map_get(struct map *m, const char *k)
{
    uintmax_t *p = map_find_slot(m, k);
    if (p == NULL) {
        fprintf(stderr, "id \"%s\" not found\n", k);
        exit(1);
    }
    return *p;
}
