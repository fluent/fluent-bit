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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_callback.h>

struct flb_callback *flb_callback_create(char *name)
{
    struct flb_callback *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct flb_callback));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, 0);
    if (!ctx->ht) {
        flb_error("[callback] error allocating hash table");
        flb_free(ctx);
        return NULL;
    }
    mk_list_init(&ctx->entries);

    return ctx;
}

int flb_callback_set(struct flb_callback *ctx, char *name,
                     void (*cb)(char *, void *, void *))
{
    int ret;
    int len;
    struct flb_callback_entry *entry;

    entry = flb_malloc(sizeof(struct flb_callback_entry));
    if (!entry) {
        flb_errno();
        return -1;
    }
    entry->name = flb_sds_create(name);
    if (!entry->name) {
        flb_free(entry);
        return -1;
    }
    entry->cb = cb;

    len = strlen(name);
    ret = flb_hash_table_add(ctx->ht, name, len,
                             (char *) &entry, sizeof(struct flb_callback_entry *));
    if (ret == -1) {
        flb_sds_destroy(entry->name);
        flb_free(entry);
        return -1;
    }
    mk_list_add(&entry->_head, &ctx->entries);

    return ret;
}

int flb_callback_exists(struct flb_callback *ctx, char *name)
{
    int ret;
    int len;
    size_t out_size;
    void *cb_addr;

    len = strlen(name);
    ret = flb_hash_table_get(ctx->ht, name, len, &cb_addr, &out_size);
    if (ret == -1) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int flb_callback_do(struct flb_callback *ctx, char *name, void *p1, void *p2)
{
    int ret;
    int len;
    size_t out_size;
    void *cb_addr;
    struct flb_callback_entry *entry;

    if (!ctx) {
        return -1;
    }

    len = strlen(name);
    ret = flb_hash_table_get(ctx->ht, name, len, &cb_addr, &out_size);
    if (ret == -1) {
        return -1;
    }

    memcpy(&entry, cb_addr, sizeof(struct flb_callback_entry *));
    entry->cb(entry->name, p1, p2);
    return 0;
}

void flb_callback_destroy(struct flb_callback *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_callback_entry *entry;

    flb_hash_table_destroy(ctx->ht);

    mk_list_foreach_safe(head, tmp, &ctx->entries) {
        entry = mk_list_entry(head, struct flb_callback_entry, _head);
        mk_list_del(&entry->_head);
        flb_sds_destroy(entry->name);
        flb_free(entry);
    }

    flb_free(ctx);
}
