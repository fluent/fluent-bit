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
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_slist.h>

#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <fluent-bit/multiline/flb_ml_group.h>

struct to_state {
    struct flb_ml_rule *rule;
    struct mk_list _head;
};

struct flb_slist_entry *get_start_state(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_slist_entry *e;

    mk_list_foreach(head, list) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(e->str, "start_state") == 0) {
            return e;
        }
    }

    return NULL;
}

int flb_ml_rule_create(struct flb_ml_parser *ml_parser,
                       flb_sds_t from_states,
                       char *regex_pattern,
                       flb_sds_t to_state,
                       char *end_pattern)
{
    int ret;
    int first_rule = FLB_FALSE;
    struct flb_ml_rule *rule;

    rule = flb_calloc(1, sizeof(struct flb_ml_rule));
    if (!rule) {
        flb_errno();
        return -1;
    }
    flb_slist_create(&rule->from_states);
    mk_list_init(&rule->to_state_map);

    if (mk_list_size(&ml_parser->regex_rules) == 0) {
        first_rule = FLB_TRUE;
    }
    mk_list_add(&rule->_head, &ml_parser->regex_rules);

    /* from_states */
    ret = flb_slist_split_string(&rule->from_states, from_states, ',', -1);
    if (ret <= 0) {
        flb_error("[multiline] rule is empty or has invalid 'from_states' tokens");
        flb_ml_rule_destroy(rule);
        return -1;
    }

    /* Check if the rule contains a 'start_state' */
    if (get_start_state(&rule->from_states)) {
        rule->start_state = FLB_TRUE;
    }
    else if (first_rule) {
        flb_error("[multiline] rule don't contain a 'start_state'");
        flb_ml_rule_destroy(rule);
        return -1;
    }

    /* regex content pattern */
    rule->regex = flb_regex_create(regex_pattern);
    if (!rule->regex) {
        flb_ml_rule_destroy(rule);
        return -1;
    }

    /* to_state */
    if (to_state) {
        rule->to_state = flb_sds_create(to_state);
        if (!rule->to_state) {
            flb_ml_rule_destroy(rule);
            return -1;
        }
    }

    /* regex end pattern */
    if (end_pattern) {
        rule->regex_end = flb_regex_create(end_pattern);
        if (!rule->regex_end) {
            flb_ml_rule_destroy(rule);
            return -1;
        }
    }

    return 0;
}

void flb_ml_rule_destroy(struct flb_ml_rule *rule)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct to_state *st;

    flb_slist_destroy(&rule->from_states);

    if (rule->regex) {
        flb_regex_destroy(rule->regex);
    }


    if (rule->to_state) {
        flb_sds_destroy(rule->to_state);
    }

    mk_list_foreach_safe(head, tmp, &rule->to_state_map) {
        st = mk_list_entry(head, struct to_state, _head);
        mk_list_del(&st->_head);
        flb_free(st);
    }

    if (rule->regex_end) {
        flb_regex_destroy(rule->regex_end);
    }

    mk_list_del(&rule->_head);
    flb_free(rule);
}

void flb_ml_rule_destroy_all(struct flb_ml_parser *ml_parser)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ml_rule *rule;

    mk_list_foreach_safe(head, tmp, &ml_parser->regex_rules) {
        rule = mk_list_entry(head, struct flb_ml_rule, _head);
        flb_ml_rule_destroy(rule);
    }
}

static inline int to_states_exists(struct flb_ml_parser *ml_parser,
                                   flb_sds_t state)
{
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_ml_rule *rule;
    struct flb_slist_entry *e;

    mk_list_foreach(head, &ml_parser->regex_rules) {
        rule = mk_list_entry(head, struct flb_ml_rule, _head);

        mk_list_foreach(r_head, &rule->from_states) {
            e = mk_list_entry(r_head, struct flb_slist_entry, _head);
            if (strcmp(e->str, state) == 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

static inline int to_states_matches_rule(struct flb_ml_rule *rule,
                                         flb_sds_t state)
{
    struct mk_list *head;
    struct flb_slist_entry *e;

    mk_list_foreach(head, &rule->from_states) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(e->str, state) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int set_to_state_map(struct flb_ml_parser *ml_parser,
                            struct flb_ml_rule *rule)
{
    int ret;
    struct to_state *s;
    struct mk_list *head;
    struct flb_ml_rule *r;

    if (!rule->to_state) {
        /* no to_state */
        return 0;
    }

    /* Iterate all rules that matches the to_state */
    mk_list_foreach(head, &ml_parser->regex_rules) {
        r = mk_list_entry(head, struct flb_ml_rule, _head);

        /* Check if rule->to_state, matches an existing (registered) from_state */
        ret = to_states_exists(ml_parser, rule->to_state);
        if (!ret) {
            flb_error("[multiline parser: %s] to_state='%s' is not registered",
                      ml_parser->name, rule->to_state);
            return -1;
        }

        /*
         * A rule can have many 'from_states', check if the current 'rule->to_state'
         * matches any 'r->from_states'
         */
        ret = to_states_matches_rule(r, rule->to_state);
        if (!ret) {
            continue;
        }

        /* We have a match. Create a 'to_state' entry into the 'to_state_map' list */
        s = flb_malloc(sizeof(struct to_state));
        if (!s) {
            flb_errno();
            return -1;
        }
        s->rule = r;
        mk_list_add(&s->_head, &rule->to_state_map);
    }

    return 0;
}

static int try_flushing_buffer(struct flb_ml_parser *ml_parser,
                               struct flb_ml_stream *mst,
                               struct flb_ml_stream_group *group)
{
    int next_start = FLB_FALSE;
    struct mk_list *head;
    struct to_state *st;
    struct flb_ml_rule *rule;

    rule = group->rule_to_state;
    if (!rule) {
        if (flb_sds_len(group->buf) > 0) {
            flb_ml_flush_stream_group(ml_parser, mst, group, FLB_FALSE);
            group->first_line = FLB_TRUE;
        }
        return 0;
    }

    /* Check if any 'to_state_map' referenced rules is a possible start */
    mk_list_foreach(head, &rule->to_state_map) {
        st = mk_list_entry(head, struct to_state, _head);
        if (st->rule->start_state) {
            next_start = FLB_TRUE;
            break;
        }
    }

    if (next_start && flb_sds_len(group->buf) > 0) {
        flb_ml_flush_stream_group(ml_parser, mst, group, FLB_FALSE);
        group->first_line = FLB_TRUE;
    }

    return 0;
}

/* Initialize all rules */
int flb_ml_rule_init(struct flb_ml_parser *ml_parser)
{
    int ret;
    struct mk_list *head;
    struct flb_ml_rule *rule;

    /* FIXME: sort rules by start_state first (let's trust in the caller) */

    /* For each rule, compose it to_state_map list */
    mk_list_foreach(head, &ml_parser->regex_rules) {
        rule = mk_list_entry(head, struct flb_ml_rule, _head);
        /* Populate 'rule->to_state_map' list */
        ret = set_to_state_map(ml_parser, rule);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

/* Search any 'start_state' matching the incoming 'buf_data' */
static struct flb_ml_rule *try_start_state(struct flb_ml_parser *ml_parser,
                                           char *buf_data, size_t buf_size)
{
    int ret = -1;
    struct mk_list *head;
    struct flb_ml_rule *rule = NULL;

    mk_list_foreach(head, &ml_parser->regex_rules) {
        rule = mk_list_entry(head, struct flb_ml_rule, _head);

        /* Is this rule matching a start_state ? */
        if (!rule->start_state) {
            rule = NULL;
            continue;
        }

        /* Matched a start_state. Check if we have a regex match */
        ret = flb_regex_match(rule->regex, (unsigned char *) buf_data, buf_size);
        if (ret) {
            return rule;
        }
    }

    return NULL;
}

int flb_ml_rule_process(struct flb_ml_parser *ml_parser,
                        struct flb_ml_stream *mst,
                        struct flb_ml_stream_group *group,
                        msgpack_object *full_map,
                        void *buf, size_t size, struct flb_time *tm,
                        msgpack_object *val_content,
                        msgpack_object *val_pattern)
{
    int ret;
    int len;
    char *buf_data = NULL;
    size_t buf_size = 0;
    struct mk_list *head;
    struct to_state *st = NULL;
    struct flb_ml_rule *rule = NULL;
    struct flb_ml_rule *tmp_rule = NULL;

    if (val_content) {
        buf_data = (char *) val_content->via.str.ptr;
        buf_size = val_content->via.str.size;
    }
    else {
        buf_data = buf;
        buf_size = size;
    }

    if (group->rule_to_state) {
        /* are we in a continuation ? */
        tmp_rule = group->rule_to_state;

        /* Lookup all possible next rules by state reference */
        rule = NULL;
        mk_list_foreach(head, &tmp_rule->to_state_map) {
            st = mk_list_entry(head, struct to_state, _head);

            /* skip start states */
            if (st->rule->start_state) {
                continue;
            }

            /* Try regex match */
            ret = flb_regex_match(st->rule->regex,
                                  (unsigned char *) buf_data, buf_size);
            if (ret) {
                /* Regex matched */
                len = flb_sds_len(group->buf);
                if (len >= 1 && group->buf[len - 1] != '\n') {
                    flb_sds_cat_safe(&group->buf, "\n", 1);
                }

                if (buf_size == 0) {
                    flb_sds_cat_safe(&group->buf, "\n", 1);
                }
                else {
                    ret = flb_ml_group_cat(group, buf_data, buf_size);
                    if (ret == FLB_MULTILINE_TRUNCATED) {
                        /* Buffer is full. Flush immediately to send the truncated record. */
                        flb_ml_flush_stream_group(ml_parser, mst, group, FLB_FALSE);

                        /* Reset state so no more lines are appended to this record. */
                        group->rule_to_state = NULL;
                        return ret;
                    }
                }
                rule = st->rule;
                break;
            }
            rule = NULL;
        }
    }

    if (!rule) {
        /* Check if we are in a 'start_state' */
        rule = try_start_state(ml_parser, buf_data, buf_size);
        if (rule) {
            /* if the group buffer has any previous data just flush it */
            if (flb_sds_len(group->buf) > 0) {
                flb_ml_flush_stream_group(ml_parser, mst, group, FLB_FALSE);
            }

            /* set the rule state */
            group->rule_to_state = rule;

            /* concatenate the data */
            ret = flb_ml_group_cat(group, buf_data, buf_size);
            if (ret == FLB_MULTILINE_TRUNCATED) {
                return ret;
            }

            /* Copy full map content in stream buffer */
            flb_ml_register_context(group, tm, full_map);
        }
    }

    if (rule) {
        group->rule_to_state = rule;
        try_flushing_buffer(ml_parser, mst, group);
        return 0;
    }

    return -1;
}
