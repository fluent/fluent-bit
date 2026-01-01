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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

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
            s->cb_match((const char *)name,
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

static OnigOptionType check_option(const char *start, const char *end, char **new_end)
{
    char *chr = NULL;
    OnigOptionType option = ONIG_OPTION_NONE;

    if (start == NULL || end == NULL || new_end == NULL) {
        return ONIG_OPTION_DEFAULT;
    }
    else if (start[0] != '/') {
        *new_end = NULL;
        return ONIG_OPTION_DEFAULT;
    }

    chr = strrchr(start, '/');
    if (!chr) {
        *new_end = NULL;
        return ONIG_OPTION_DEFAULT;
    }

    if (chr == start || chr == end) {
        *new_end = NULL;
        return ONIG_OPTION_DEFAULT;
    }
    *new_end = chr;

    chr++;
    while(chr != end && *chr != '\0') {
        switch (*chr) {
        case 'm':
            option |= ONIG_OPTION_MULTILINE;
            break;
        case 'i':
            option |= ONIG_OPTION_IGNORECASE;
            break;
        case 'o':
            flb_debug("[regex:%s]: 'o' option is not supported.", __FUNCTION__);
            break;
        case 'x':
            option |= ONIG_OPTION_EXTEND;
            break;
        default:
            flb_debug("[regex:%s]: unknown option. use default.", __FUNCTION__);
            *new_end = NULL;
            return ONIG_OPTION_DEFAULT;
        }
        chr++;
    }

    if (option == ONIG_OPTION_NONE) {
        *new_end = NULL;
        option = ONIG_OPTION_DEFAULT;
    }

    return option;
}

static int str_to_regex(const char *pattern, OnigRegex *reg)
{
    int ret;
    size_t len;
    const char *start;
    const char *end;
    char *new_end = NULL;
    OnigErrorInfo einfo;
    OnigOptionType option;

    len = strlen(pattern);
    start = pattern;
    end = pattern + len;

    option = check_option(start, end, &new_end);

    if (pattern[0] == '/' && pattern[len - 1] == '/') {
        start++;
        end--;
    }

    if (new_end != NULL) {
        /* pattern is /pat/option. new_end indicates a last '/'. */
        start++;
        end = new_end;
    }

    ret = onig_new(reg,
                   (const unsigned char *)start, (const unsigned char *)end,
                   option,
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

struct flb_regex *flb_regex_create(const char *pattern)
{
    int ret;
    struct flb_regex *r;

    /* Create context */
    r = flb_malloc(sizeof(struct flb_regex));
    if (!r) {
        flb_errno();
        return NULL;
    }

    /* Compile pattern */
    ret = str_to_regex(pattern, (OnigRegex*)&r->regex);
    if (ret == -1) {
        flb_free(r);
        return NULL;
    }

    return r;
}

ssize_t flb_regex_do(struct flb_regex *r, const char *str, size_t slen,
                     struct flb_regex_search *result)
{
    int ret;
    const char *start;
    const char *end;
    const char *range;
    OnigRegion *region;

    region = onig_region_new();
    if (!region) {
        flb_errno();
        result->region = NULL;
        return -1;
    }

    /* Search scope */
    start = str;
    end   = start + slen;
    range = end;

    ret = onig_search(r->regex,
                      (const unsigned char *)str,
                      (const unsigned char *)end,
                      (const unsigned char *)start,
                      (const unsigned char *)range,
                      region, ONIG_OPTION_NONE);
    if (ret == ONIG_MISMATCH) {
        result->region = NULL;
        onig_region_free(region, 1);
        return -1;
    }
    else if (ret < 0) {
        result->region = NULL;
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

int flb_regex_results_get(struct flb_regex_search *result, int i,
                          ptrdiff_t *start, ptrdiff_t *end)
{
    OnigRegion *region;

    region = (OnigRegion *) result->region;
    if (!region) {
        return -1;
    }

    if (i >= region->num_regs) {
        return -1;
    }

    *start = region->beg[i];
    *end = region->end[i];

    return 0;
}

void flb_regex_results_release(struct flb_regex_search *result)
{
    onig_region_free(result->region, 1);
}

int flb_regex_results_size(struct flb_regex_search *result)
{
    OnigRegion *region;

    region = (OnigRegion *) result->region;
    if (!region) {
        return -1;
    }

    return region->num_regs;
}

int flb_regex_match(struct flb_regex *r, unsigned char *str, size_t slen)
{
    int ret;
    unsigned char *start;
    unsigned char *end;
    unsigned char *range;

    /* Search scope */
    start = (unsigned char *) str;
    end   = start + slen;
    range = end;

    ret = onig_search(r->regex, str, end, start, range, NULL, ONIG_OPTION_NONE);

    if (ret == ONIG_MISMATCH) {
        return 0;
    }
    else if (ret < 0) {
        return ret;
    }
    return 1;
}


int flb_regex_parse(struct flb_regex *r, struct flb_regex_search *result,
                    void (*cb_match) (const char *,          /* name  */
                                      const char *, size_t,  /* value */
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
    flb_free(r);
    return 0;
}

void flb_regex_exit()
{
    onig_end();
}
