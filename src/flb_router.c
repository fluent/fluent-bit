/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
int flb_router_connect(struct flb_input_instance *in,
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

int flb_router_connect_direct(struct flb_input_instance *in,
                              struct flb_output_instance *out)
{
    struct flb_router_path *p;

    p = flb_malloc(sizeof(struct flb_router_path));
    if (!p) {
        flb_errno();
        return -1;
    }

    p->ins = out;
    mk_list_add(&p->_head, &in->routes_direct);

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
    in_count = mk_list_size(&config->inputs);
    out_count = mk_list_size(&config->outputs);

    /* Mostly used for command line tests */
    if (in_count == 1 && out_count == 1) {
        i_ins = mk_list_entry_first(&config->inputs, struct flb_input_instance, _head);
        o_ins = mk_list_entry_first(&config->outputs, struct flb_output_instance, _head);

        if (!o_ins->match
#ifdef FLB_HAVE_REGEX
            && !o_ins->match_regex
#endif
            ) {

            o_ins->match = flb_sds_create_len("*", 1);
        }
        flb_router_connect(i_ins, o_ins);
        return 0;
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

        /* Iterate instance routes direct */
        mk_list_foreach_safe(r_head, r_tmp, &in->routes_direct) {
            r = mk_list_entry(r_head, struct flb_router_path, _head);
            mk_list_del(&r->_head);
            flb_free(r);
        }
    }
}

static int router_metrics_create(struct flb_router *router)
{
    if (!router || !router->cmt) {
        return -1;
    }

    /* Metrics for Logs
     * ----------------
     * The following metrics are used to track the number of records routed from input to output,
     * the number of bytes routed, and the number of records and bytes dropped during routing.
     *
     * The metrics are defined as follows:
     *
     *   - flb_routing_logs_records_total: Log records routed to outputs
     *   - flb_routing_logs_bytes_total: Total log bytes routed
     *   - flb_routing_logs_drop_records_total: Log records dropped during routing
     *   - flb_routing_logs_drop_bytes_total: Log bytes dropped during routing
     *
     */
    router->logs_records_total = cmt_counter_create(
                                                    router->cmt,
                                                    "fluentbit", "routing_logs", "records_total",
                                                    "Total log records routed from input to output",
                                                    2,
                                                    (char *[]) { "input", "output" });
    if (!router->logs_records_total) {
        return -1;
    }

    router->logs_bytes_total = cmt_counter_create(
                                                 router->cmt,
                                                 "fluentbit", "routing_logs", "bytes_total",
                                                 "Total bytes routed from input to output (logs)",
                                                 2,
                                                 (char *[]) { "input", "output" });
    if (!router->logs_bytes_total) {
        return -1;
    }

    router->logs_drop_records_total = cmt_counter_create(
                                                        router->cmt,
                                                        "fluentbit", "routing_logs", "drop_records_total",
                                                        "Total log records dropped during routing",
                                                        2,
                                                        (char *[]) { "input", "output" });
    if (!router->logs_drop_records_total) {
        return -1;
    }

    router->logs_drop_bytes_total = cmt_counter_create(
                                                       router->cmt,
                                                       "fluentbit", "routing_logs", "drop_bytes_total",
                                                       "Total bytes dropped during routing (logs)",
                                                       2,
                                                       (char *[]) { "input", "output" });
    if (!router->logs_drop_bytes_total) {
        return -1;
    }

    return 0;
}

struct flb_router *flb_router_create(struct flb_config *config)
{
    struct flb_router *router;

    router = flb_calloc(1, sizeof(struct flb_router));
    if (!router) {
        flb_errno();
        return NULL;
    }

    /* create metrics instance */
    router->cmt = cmt_create();
    if (!router->cmt) {
        flb_free(router);
        return NULL;
    }

    if (router_metrics_create(router) != 0) {
        flb_router_destroy(router);
        return NULL;
    }
    return router;
}

void flb_router_destroy(struct flb_router *router)
{
    flb_routes_empty_mask_destroy(router);

    if (router->cmt) {
        cmt_destroy(router->cmt);
    }

    flb_free(router);
    router = NULL;
}

