/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_router.h>

#ifdef FLB_HAVE_REGEX
#include <onigmo.h>
#endif

#include <string.h>

/* wildcard support */
/* tag and match should be null terminated. */
static inline int router_match(const char *tag, int tag_len,
                               const char *match,
                               void *match_r)
{
    int ret = FLB_FALSE;
    char *pos = NULL;

#ifdef FLB_HAVE_REGEX
    struct flb_regex *match_regex = match_r;
    int n;
    if (match_regex) {
        n = onig_match(match_regex->regex,
                       (const unsigned char *) tag,
                       (const unsigned char *) tag + tag_len,
                       (const unsigned char *) tag, 0,
                       ONIG_OPTION_NONE);
        if (n > 0) {
            return 1;
        }
    }
#else
    (void) match_r;
#endif

    while (match) {
        if (*match == '*') {
            while (*++match == '*'){
                /* skip successive '*' */
            }
            if (*match == '\0') {
                /*  '*' is last of string */
                ret = 1;
                break;
            }

            while ((pos = strchr(tag, (int) *match))) {
#ifndef FLB_HAVE_REGEX
                if (router_match(pos, tag_len, match, NULL)) {
#else
                /* We don't need to pass the regex recursively,
                 * we matched in order above
                 */
                if (router_match(pos, tag_len, match, NULL)) {
#endif
                    ret = 1;
                    break;
                }
                tag = pos+1;
            }
            break;
        }
        else if (*tag != *match) {
            /* mismatch! */
            break;
        }
        else if (*tag == '\0') {
            /* end of tag. so matched! */
            ret = 1;
            break;
        }
        tag++;
        match++;
    }

    return ret;
}

int flb_router_match(const char *tag, int tag_len, const char *match,
                     void *match_regex)
{
    int ret;
    flb_sds_t t;

    if (tag[tag_len] != '\0') {
        t = flb_sds_create_len(tag, tag_len);
        if (!t) {
            return FLB_FALSE;
        }

        ret = router_match(t, tag_len, match, match_regex);
        flb_sds_destroy(t);
    }
    else {
        ret = router_match(tag, tag_len, match, match_regex);
    }

    return ret;
}

/* Associate and input and output instances due to a previous match */
static int flb_router_connect(struct flb_input_instance *in,
                              struct flb_output_instance *out)
{
    struct flb_router_path *p;

    p = flb_malloc(sizeof(struct flb_router_path));
    if (!p) {
        flb_errno();
        return -1;
    }

    p->ins = out;
    mk_list_add(&p->_head, &in->routes);

    return 0;
}

/*
 * This routine defines static routes for the plugins that have registered
 * tags. It check where data should go before the service start running, each
 * input 'instance' plugin will contain a list of destinations.
 */
int flb_router_io_set(struct flb_config *config)
{
    int in_count = 0;
    int out_count = 0;
    struct mk_list *i_head;
    struct mk_list *o_head;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    /* Quick setup for 1:1 */
    mk_list_foreach(i_head, &config->inputs) {
        in_count++;
    }
    mk_list_foreach(o_head, &config->outputs) {
        out_count++;
    }

    /* Just 1 input and 1 output */
    if (in_count == 1 && out_count == 1) {
        i_ins = mk_list_entry_first(&config->inputs,
                                    struct flb_input_instance, _head);
        o_ins = mk_list_entry_first(&config->outputs,
                                    struct flb_output_instance, _head);
        if (!o_ins->match
#ifdef FLB_HAVE_REGEX
            && !o_ins->match_regex
#endif
            ) {
            flb_debug("[router] default match rule %s:%s",
                      i_ins->name, o_ins->name);
            o_ins->match = flb_sds_create_len("*", 1);
            flb_router_connect(i_ins, o_ins);
            return 0;
        }
    }

    /* N:M case, iterate all input instances */
    mk_list_foreach(i_head, &config->inputs) {
        i_ins = mk_list_entry(i_head, struct flb_input_instance, _head);
        if (!i_ins->p) {
            continue;
        }

        if (!i_ins->tag) {
            flb_warn("[router] NO tag for %s input instance",
                     i_ins->name);
            continue;
        }

        flb_trace("[router] input=%s tag=%s", i_ins->name, i_ins->tag);

        /* Try to find a match with output instances */
        mk_list_foreach(o_head, &config->outputs) {
            o_ins = mk_list_entry(o_head, struct flb_output_instance, _head);
            if (!o_ins->match
#ifdef FLB_HAVE_REGEX
                && !o_ins->match_regex
#endif
                ) {
                flb_warn("[router] NO match for %s output instance",
                          o_ins->name);
                continue;
            }

            if (flb_router_match(i_ins->tag, i_ins->tag_len, o_ins->match
#ifdef FLB_HAVE_REGEX
                , o_ins->match_regex
#else
                , NULL
#endif
            )) {
                flb_debug("[router] match rule %s:%s",
                          i_ins->name, o_ins->name);
                flb_router_connect(i_ins, o_ins);
            }
        }
    }

    return 0;
}

void flb_router_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *r_tmp;
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_input_instance *in;
    struct flb_router_path *r;

    /* Iterate input plugins */
    mk_list_foreach_safe(head, tmp, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);

        /* Iterate instance routes */
        mk_list_foreach_safe(r_head, r_tmp, &in->routes) {
            r = mk_list_entry(r_head, struct flb_router_path, _head);
            mk_list_del(&r->_head);
            flb_free(r);
        }
    }
}

/*
 * Calculate the routes_mask for input chunk with a router_match on tag
 */
uint64_t flb_router_get_routes_mask_by_tag(const char *tag, int tag_len,
                                           struct flb_input_instance *in) {
    uint64_t routes_mask = 0;
    struct mk_list *o_head;
    struct flb_output_instance *o_ins;
    if (!in) {
        return -1;
    }

    /* Find all matching routes for the given tag */
    mk_list_foreach(o_head, &in->config->outputs) {
        o_ins = mk_list_entry(o_head,
                              struct flb_output_instance, _head);

        if (flb_router_match(tag, tag_len, o_ins->match
#ifdef FLB_HAVE_REGEX
                             , o_ins->match_regex
#else
                             , NULL
#endif
                             )) {
            /*
             * mask_id for each output instance is a unique number starting from 1
             * and multple by 2 each time. (e.g 1, 2 ,4 ,8, 16 ...)
             * Let's take a look of the binary of the mask_id:
             *   1:   00000001
             *   2:   00000010
             *   4:   00000100
             *   8:   00001000
             *   16:  00010000
             * We can notice that each binary has only one 1's bit and this also
             * represents the postion of the output instance. Getting the OR of
             * mask_id (given that tag is matched) will tell us the output instances
             * that the given input chunk will flush to.
             *
             * For example: We have two matching output instances with mask_id 1 and 4
             * There are two 1's in the binary with index 0 and 2 (starting from right)
             * and this means that the input chunk will flush to first and third output
             * instances configured in the Fluent Bit configuraion.
             *
             *    0 |= 1 -> 00000 |= 00001 -> 00001
             *    00001 |= 4 -> 00001 |= 00100 -> 00101
             */
            routes_mask |= o_ins->mask_id;
        }
    }

    return routes_mask;
}
