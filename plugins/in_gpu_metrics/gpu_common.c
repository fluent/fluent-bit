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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_mem.h>

#include "gpu_common.h"
#include "gpu_metrics.h"

int gpu_read_uint64(const char *path, uint64_t *value)
{
    FILE *fp;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (fscanf(fp, "%" PRIu64, value) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int gpu_read_double(const char *path, double scale, double *value)
{
    uint64_t tmp;
    if (gpu_read_uint64(path, &tmp) != 0) {
        return -1;
    }
    *value = (double) tmp / scale;
    return 0;
}

int gpu_read_line(const char *path, char *buf, size_t size)
{
    FILE *fp;
    char *nl;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (!fgets(buf, size, fp)) {
        fclose(fp);
        return -1;
    }
    // Remove newline
    nl = strchr(buf, '\n');
    if (nl) {
        *nl = '\0';
    }
    fclose(fp);
    return 0;
}

static int match_card_pattern(const char *pattern, int card_id)
{
    char *dup;
    char *token;
    char *saveptr;
    int start;
    int end;

    if (!pattern || pattern[0] == '\0' || strcmp(pattern, "*") == 0) {
        return FLB_TRUE;
    }

    dup = flb_strdup(pattern);
    if (!dup) {
        return FLB_FALSE;
    }

    token = strtok_r(dup, ",", &saveptr);
    while (token) {
        if (sscanf(token, "%d-%d", &start, &end) == 2) {
            if (card_id >= start && card_id <= end) {
                flb_free(dup);
                return FLB_TRUE;
            }
        }
        else {
            if (card_id == atoi(token)) {
                flb_free(dup);
                return FLB_TRUE;
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    flb_free(dup);
    return FLB_FALSE;
}

int gpu_should_include_card(struct in_gpu_metrics *ctx, int card_id)
{
    if (ctx->cards_exclude && ctx->cards_exclude[0] != '\0' &&
        match_card_pattern(ctx->cards_exclude, card_id)) {
        flb_plg_info(ctx->ins, "card%d excluded by exclude pattern", card_id);
        return FLB_FALSE;
    }

    if (ctx->cards_include && ctx->cards_include[0] != '\0' &&
        !match_card_pattern(ctx->cards_include, card_id)) {
        flb_plg_info(ctx->ins, "card%d excluded by include pattern", card_id);
        return FLB_FALSE;
    }

    return FLB_TRUE;
}
