/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <cfl/cfl_atomic.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_pthread.h>

#include "tail_config.h"
#include "tail_file_budget.h"

#define TAIL_BUDGET_WARNING (UINT64_C(1) << 62)
#define TAIL_BUDGET_FULL    (UINT64_C(1) << 63)
#define TAIL_BUDGET_COUNT   (TAIL_BUDGET_WARNING - 1)

struct flb_tail_file_budget {
    uint64_t limit;
    /* Count and warning latches change together, including during release. */
    uint64_t state;
    size_t users;
};

/* Lifetime is protected here; file admission uses CFL atomics below. */
static pthread_mutex_t budget_lock = PTHREAD_MUTEX_INITIALIZER;
static struct flb_tail_file_budget *shared_budget;

static int configured_limit(struct flb_tail_config *ctx, uint64_t *limit)
{
    long value;
    char *end;
    const char *property;
    struct mk_list *head;
    struct flb_input_instance *ins;

    *limit = 0;

    /* Resolve all inputs before the first input opens any files. */
    mk_list_foreach(head, &ctx->config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (!ins->p || strcmp(ins->p->name, "tail") != 0) {
            continue;
        }

        property = flb_input_get_property("max_open_files", ins);
        if (!property) {
            continue;
        }

        errno = 0;
        value = strtol(property, &end, 10);
        if (errno != 0 || end == property || *end != '\0' || value < 0 || value > INT_MAX) {
            flb_plg_error(ctx->ins, "max_open_files must be >= 0 and <= %i", INT_MAX);
            return -1;
        }
        if (value == 0) {
            continue;
        }
        if (*limit != 0 && *limit != (uint64_t) value) {
            flb_plg_error(ctx->ins, "conflicting max_open_files values: "
                          "all positive Tail limits must agree");
            return -1;
        }
        *limit = value;
    }

    return 0;
}

struct flb_tail_file_budget *flb_tail_file_budget_create(struct flb_tail_config *ctx)
{
    uint64_t limit;
    struct flb_tail_file_budget *budget;

    if (configured_limit(ctx, &limit) != 0 || cfl_atomic_initialize() != 0) {
        return NULL;
    }

    pthread_mutex_lock(&budget_lock);
    budget = shared_budget;
    if (budget && limit != 0 && budget->limit != limit) {
        pthread_mutex_unlock(&budget_lock);
        flb_plg_error(ctx->ins, "max_open_files conflicts with the active shared Tail budget");
        return NULL;
    }
    if (!budget) {
        budget = flb_calloc(1, sizeof(*budget));
        if (!budget) {
            pthread_mutex_unlock(&budget_lock);
            flb_errno();
            return NULL;
        }
        budget->limit = limit;
        cfl_atomic_store(&budget->state, 0);
        shared_budget = budget;
    }
    budget->users++;
    pthread_mutex_unlock(&budget_lock);

    return budget;
}

void flb_tail_file_budget_destroy(struct flb_tail_file_budget *budget)
{
    if (!budget) {
        return;
    }

    pthread_mutex_lock(&budget_lock);
    budget->users--;
    if (budget->users == 0) {
        shared_budget = NULL;
        flb_free(budget);
    }
    pthread_mutex_unlock(&budget_lock);
}

/* Check the shared limit and reserve a slot in a single atomic operation. */
int flb_tail_file_budget_reserve(struct flb_tail_config *ctx)
{
    uint64_t state;
    uint64_t updated;
    uint64_t count;
    uint64_t threshold;
    struct flb_tail_file_budget *budget = ctx->file_budget;

    threshold = budget->limit - budget->limit / 4;
    while (FLB_TRUE) {
        state = cfl_atomic_load(&budget->state);
        count = state & TAIL_BUDGET_COUNT;
        if ((budget->limit > 0 && count >= budget->limit) || count == TAIL_BUDGET_COUNT) {
            ctx->files_deferred = FLB_TRUE;
            if (state & TAIL_BUDGET_FULL) {
                return FLB_FALSE;
            }
            if (!cfl_atomic_compare_exchange(&budget->state, state, state | TAIL_BUDGET_FULL)) {
                continue;
            }
            flb_plg_warn(ctx->ins, "max_open_files=%" PRIu64 " reached; deferring additional files "
                         "until a slot in the shared Tail budget is available at a subsequent scan",
                         budget->limit);
            return FLB_FALSE;
        }
        updated = state + 1;
        if (budget->limit > 0 && count + 1 >= threshold) {
            updated |= TAIL_BUDGET_WARNING;
        }
        if (cfl_atomic_compare_exchange(&budget->state, state, updated)) {
            if (!(state & TAIL_BUDGET_WARNING) && (updated & TAIL_BUDGET_WARNING)) {
                flb_plg_warn(ctx->ins, "open file usage reached 75%% of max_open_files "
                             "(%" PRIu64 "/%" PRIu64 ") across all Tail inputs; "
                             "additional files can open up to the limit",
                             count + 1, budget->limit);
            }
            return FLB_TRUE;
        }
    }
}

void flb_tail_file_budget_release(struct flb_tail_config *ctx)
{
    uint64_t state;
    uint64_t updated;
    uint64_t count;
    struct flb_tail_file_budget *budget = ctx->file_budget;

    while (FLB_TRUE) {
        state = cfl_atomic_load(&budget->state);
        count = state & TAIL_BUDGET_COUNT;
        updated = (state - 1) & ~TAIL_BUDGET_FULL;
        if (budget->limit > 0 && count - 1 < budget->limit - budget->limit / 4) {
            updated &= ~TAIL_BUDGET_WARNING;
        }
        if (cfl_atomic_compare_exchange(&budget->state, state, updated)) {
            return;
        }
    }
}
