/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_log.h>

#include <string.h>
#include <onigmo.h>


static int
cb_onig_named(const UChar *name, const UChar *name_end,
              int ngroup_num, int *group_nums,
              regex_t *reg, void *data)
{
    int i;
    int gn;
    struct flb_regex_search *s;
    OnigRegion *region;

    s = (struct flb_regex_search *) data;
    region = s->region;

    for (i = 0; i < ngroup_num; i++) {
        gn = group_nums[i];
        onig_name_to_backref_number(reg, name, name_end, region);

        if (s->cb_match) {
            s->cb_match((unsigned char *) name,
                        s->str + region->beg[gn],
                        region->end[gn] - region->beg[gn],
                        s->data);
        }

        if (region->end[gn] >= 0) {
            s->last_pos = region->end[gn];
        }
    }

    return 0;
}

static int str_to_regex(unsigned char *pattern, OnigRegex *reg)
{
    int ret;
    int len;
    unsigned char *start;
    unsigned char *end;
    OnigErrorInfo einfo;

    len = strlen((char *) pattern);
    start = pattern;
    end = pattern + len;

    if (pattern[0] == '/' && pattern[len - 1] == '/') {
        start++;
        end--;
    }

    ret = onig_new(reg, start, end,
                   ONIG_OPTION_DEFAULT,
                   ONIG_ENCODING_UTF8, ONIG_SYNTAX_RUBY, &einfo);

    if (ret != ONIG_NORMAL) {
        return -1;
    }
    return 0;
}

/* Initialize backend library */
int flb_regex_init()
{
    return onig_init();
}

struct flb_regex *flb_regex_create(unsigned char *pattern)
{
    int ret;
    struct flb_regex *r;

    /* Create context */
    r = malloc(sizeof(struct flb_regex));
    if (!r) {
        return NULL;
    }

    /* Compile pattern */
    ret = str_to_regex(pattern, &r->regex);
    if (ret == -1) {
        free(r);
        return NULL;
    }

    return r;
}

ssize_t flb_regex_do(struct flb_regex *r, unsigned char *str, size_t slen,
                     struct flb_regex_search *result)
{
    int ret;
    unsigned char *start;
    unsigned char *end;
    unsigned char *range;
    OnigRegion *region;

    region = onig_region_new();
    if (!region) {
        return -1;
    }

    /* Search scope */
    start = (unsigned char *) str;
    end   = start + slen;
    range = end;

    ret = onig_search(r->regex, str, end, start, range, region, ONIG_OPTION_NONE);
    if (ret == ONIG_MISMATCH) {
        onig_region_free(region, 1);
        return -1;
    }
    else if (ret < 0) {
        onig_region_free(region, 1);
        return -1;
    }

    result->region   = region;
    result->str      = str;

    ret = region->num_regs - 1;

    if (ret == 0) {
        result->region = NULL;
        onig_region_free(region, 1);
    }

    return ret;
}

int flb_regex_parse(struct flb_regex *r, struct flb_regex_search *result,
                    void (*cb_match) (unsigned char *,          /* name  */
                                      unsigned char *, size_t,  /* value */
                                      void *),                  /* caller data */
                    void *data)
{
    int ret;

    result->data = data;
    result->cb_match = cb_match;
    result->last_pos = -1;

    ret = onig_foreach_name(r->regex, cb_onig_named, result);
    onig_region_free(result->region, 1);

    if (ret == 0) {
        return result->last_pos;
    }
    return -1;
}

int flb_regex_destroy(struct flb_regex *r)
{
    onig_free(r->regex);
    free(r);
    return 0;
}

void flb_regex_exit()
{
    onig_end();
}
