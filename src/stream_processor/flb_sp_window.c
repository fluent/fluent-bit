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

#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_window.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_groupby.h>

void flb_sp_window_prune(struct flb_sp_task *task)
{
    int i;
    int map_entries;
    rb_result_t result;
    struct aggr_node *aggr_node;
    struct aggr_node *aggr_node_hs;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sp_hopping_slot *hs;
    struct rb_tree_node *rb_result;
    struct flb_sp_cmd_key *ckey;
    struct flb_sp_cmd *cmd = task->cmd;

    switch (task->window.type) {
    case FLB_SP_WINDOW_DEFAULT:
    case FLB_SP_WINDOW_TUMBLING:
        if (task->window.records > 0) {
            mk_list_foreach_safe(head, tmp, &task->window.aggr_list) {
                aggr_node = mk_list_entry(head, struct aggr_node, _head);
                mk_list_del(&aggr_node->_head);
                flb_sp_aggr_node_destroy(aggr_node);
            }

            rb_tree_destroy(&task->window.aggr_tree);
            mk_list_init(&task->window.aggr_list);
            rb_tree_new(&task->window.aggr_tree, flb_sp_groupby_compare);
            task->window.records = 0;
        }
        break;
    case FLB_SP_WINDOW_HOPPING:
        if (mk_list_size(&task->window.hopping_slot) == 0) {
            return;
        }

        hs = mk_list_entry_first(&task->window.hopping_slot,
                                 struct flb_sp_hopping_slot, _head);
        mk_list_foreach_safe(head, tmp, &task->window.aggr_list) {
            aggr_node = mk_list_entry(head, struct aggr_node, _head);
            result = rb_tree_find(&hs->aggr_tree, aggr_node, &rb_result);
            if (result == RB_OK) {
                aggr_node_hs = mk_list_entry(rb_result, struct aggr_node, _rb_head);
                if (aggr_node_hs->records == aggr_node->records) {
                    rb_tree_remove(&task->window.aggr_tree, &aggr_node->_rb_head);
                    mk_list_del(&aggr_node->_head);
                    // Destroy aggregation node
                    flb_sp_aggr_node_destroy(aggr_node);
                }
                else {
                    aggr_node->records -= aggr_node_hs->records;
                    map_entries = mk_list_size(&cmd->keys);
                    ckey = mk_list_entry_first(&cmd->keys,
                                               struct flb_sp_cmd_key, _head);
                    for (i = 0; i < map_entries; i++) {
                        switch (ckey->aggr_func) {
                        case FLB_SP_AVG:
                        case FLB_SP_SUM:
                            if (aggr_node->nums[i].type == FLB_SP_NUM_I64) {
                                aggr_node->nums[i].i64 -= aggr_node_hs->nums[i].i64;
                            }
                            else if (aggr_node->nums[i].type == FLB_SP_NUM_F64) {
                                aggr_node->nums[i].f64 -= aggr_node_hs->nums[i].f64;
                            }
                            break;
                        }
                        ckey = mk_list_entry_next(&ckey->_head, struct flb_sp_cmd_key,
                                                  _head, &cmd->keys);
                    }
                }
            }
        }
        task->window.records -= hs->records;

        /* Destroy hopping slot */
        mk_list_foreach_safe(head, tmp, &hs->aggr_list) {
            aggr_node_hs = mk_list_entry(head, struct aggr_node, _head);
            mk_list_del(&aggr_node_hs->_head);
            flb_sp_aggr_node_destroy(aggr_node_hs);
        }
        rb_tree_destroy(&hs->aggr_tree);
        mk_list_del(&hs->_head);
        flb_free(hs);

        break;
    }
}

int flb_sp_window_populate(struct flb_sp_task *task, const char *buf_data,
                           size_t buf_size)
{
    switch (task->window.type) {
    case FLB_SP_WINDOW_DEFAULT:
    case FLB_SP_WINDOW_TUMBLING:
    case FLB_SP_WINDOW_HOPPING:
        break;
    default:
        flb_error("[sp] error populating window for '%s': window type unknown",
                  task->name);
        return -1;
    }

    return 0;
}
