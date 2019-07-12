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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_slist.h>

int flb_slist_create(struct mk_list *list)
{
    mk_list_init(list);
    return 0;
}

/* Append string as a new node into the list */
int flb_slist_add(struct mk_list *head, const char *str)
{
    struct flb_slist_entry *e;

    e = flb_malloc(sizeof(struct flb_slist_entry));
    if (!e) {
        flb_errno();
        return -1;
    }

    e->str = flb_sds_create(str);
    if (!e->str) {
        flb_free(e);
        return -1;
    }

    mk_list_add(&e->_head, head);
    return 0;
}

void flb_slist_destroy(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_slist_entry *e;

    mk_list_foreach_safe(head, tmp, list) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        flb_sds_destroy(e->str);
        mk_list_del(&e->_head);
        flb_free(e);
    }
}
