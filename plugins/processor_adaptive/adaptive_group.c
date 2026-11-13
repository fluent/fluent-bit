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

/*
 * Groups
 * ======
 * 'group_by' splits the stream into partitions that learn and sample on their
 * own. The key of a record is the list of selected values joined by '/'.
 *
 * Memory is bounded by 'max_groups': once that many groups exist, new keys
 * share the "_other" group. A group with no patterns left is removed.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_slist.h>

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

static void selector_destroy(struct adaptive_selector *selector)
{
    int i;

    for (i = 0; i < selector->part_count; i++) {
        cfl_sds_destroy(selector->parts[i]);
    }
    flb_free(selector);
}

static int selector_add_part(struct adaptive_selector *selector, const char *str, size_t len)
{
    if (len == 0 || selector->part_count >= ADAPTIVE_SELECTOR_PARTS) {
        return -1;
    }

    selector->parts[selector->part_count] = cfl_sds_create_len(str, len);
    if (!selector->parts[selector->part_count]) {
        return -1;
    }
    selector->part_count++;

    return 0;
}

/* Accepts: tag, resource:<attribute>, key, $key and $key['sub']['sub'] */
static struct adaptive_selector *selector_create(const char *str)
{
    char quote;
    const char *end;
    struct adaptive_selector *selector;

    selector = flb_calloc(1, sizeof(struct adaptive_selector));
    if (!selector) {
        flb_errno();
        return NULL;
    }

    if (strcasecmp(str, "tag") == 0) {
        selector->type = ADAPTIVE_SELECT_TAG;
        return selector;
    }

    if (strncasecmp(str, "resource:", 9) == 0) {
        selector->type = ADAPTIVE_SELECT_RESOURCE;
        if (selector_add_part(selector, str + 9, strlen(str + 9)) != 0) {
            selector_destroy(selector);
            return NULL;
        }
        return selector;
    }

    selector->type = ADAPTIVE_SELECT_RECORD;
    if (str[0] != '$') {
        if (selector_add_part(selector, str, strlen(str)) != 0) {
            selector_destroy(selector);
            return NULL;
        }
        return selector;
    }

    str++;
    end = strchr(str, '[');
    if (selector_add_part(selector, str, end ? (size_t) (end - str) : strlen(str)) != 0) {
        selector_destroy(selector);
        return NULL;
    }

    while (end) {
        quote = end[1];
        if (quote != '\'' && quote != '"') {
            selector_destroy(selector);
            return NULL;
        }
        str = end + 2;
        end = strchr(str, quote);
        if (!end || end[1] != ']' ||
            selector_add_part(selector, str, end - str) != 0) {
            selector_destroy(selector);
            return NULL;
        }
        end += 2;
        if (*end == '\0') {
            break;
        }
        if (*end != '[') {
            selector_destroy(selector);
            return NULL;
        }
    }

    return selector;
}

int adaptive_selectors_create(struct adaptive_ctx *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct adaptive_selector *selector;

    if (!ctx->group_by) {
        return 0;
    }

    mk_list_foreach(head, ctx->group_by) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        selector = selector_create(entry->str);
        if (!selector) {
            flb_plg_error(ctx->ins, "invalid group_by entry '%s'", entry->str);
            return -1;
        }
        cfl_list_add(&selector->_head, &ctx->selectors);
    }

    return 0;
}

void adaptive_selectors_destroy(struct adaptive_ctx *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct adaptive_selector *selector;

    cfl_list_foreach_safe(head, tmp, &ctx->selectors) {
        selector = cfl_list_entry(head, struct adaptive_selector, _head);
        cfl_list_del(&selector->_head);
        selector_destroy(selector);
    }
}

static struct cfl_variant *kvlist_path(struct cfl_kvlist *kvlist, cfl_sds_t *parts, int count)
{
    int i;
    struct cfl_variant *variant = NULL;

    for (i = 0; i < count; i++) {
        if (!kvlist) {
            return NULL;
        }
        variant = cfl_kvlist_fetch_s(kvlist, parts[i], cfl_sds_len(parts[i]));
        if (!variant) {
            return NULL;
        }
        kvlist = variant->type == CFL_VARIANT_KVLIST ? variant->data.as_kvlist : NULL;
    }

    return variant;
}

/* OTLP groups carry {"resource": {"attributes": {...}}, "scope": {...}} */
static struct cfl_variant *resource_attribute(struct flb_mp_chunk_record *record,
                                              cfl_sds_t name)
{
    struct cfl_variant *variant;

    if (!record->cobj_group_attributes || !record->cobj_group_attributes->variant ||
        record->cobj_group_attributes->variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    variant = cfl_kvlist_fetch_s(record->cobj_group_attributes->variant->data.as_kvlist,
                                 "resource", 8);
    if (!variant || variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    variant = cfl_kvlist_fetch_s(variant->data.as_kvlist, "attributes", 10);
    if (!variant || variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return cfl_kvlist_fetch_s(variant->data.as_kvlist, name, cfl_sds_len(name));
}

size_t adaptive_group_key_append(char *buf, size_t used, const char *str, size_t len)
{
    if (used + len > ADAPTIVE_GROUP_KEY_MAX - 1) {
        len = ADAPTIVE_GROUP_KEY_MAX - 1 - used;
    }
    memcpy(buf + used, str, len);

    return used + len;
}

static size_t key_append_variant(char *buf, size_t used, struct cfl_variant *variant)
{
    int len;
    size_t size;
    char tmp[32];

    if (!variant) {
        return adaptive_group_key_append(buf, used, "-", 1);
    }

    if (variant->type == CFL_VARIANT_STRING && variant->data.as_string) {
        size = cfl_variant_size_get(variant);
        if (size == 0 && !variant->referenced) {
            size = cfl_sds_len(variant->data.as_string);
        }
        return adaptive_group_key_append(buf, used, variant->data.as_string, size);
    }
    else if (variant->type == CFL_VARIANT_INT) {
        len = snprintf(tmp, sizeof(tmp), "%" PRId64, variant->data.as_int64);
    }
    else if (variant->type == CFL_VARIANT_UINT) {
        len = snprintf(tmp, sizeof(tmp), "%" PRIu64, variant->data.as_uint64);
    }
    else if (variant->type == CFL_VARIANT_BOOL) {
        len = snprintf(tmp, sizeof(tmp), "%s", variant->data.as_bool ? "true" : "false");
    }
    else {
        return adaptive_group_key_append(buf, used, "-", 1);
    }

    return adaptive_group_key_append(buf, used, tmp, len);
}

static void pattern_removed(struct adaptive_pattern *pattern, void *data)
{
    struct adaptive_group *group = data;

    group->lost_count += pattern->count - pattern->sum_count;
    group->lost_kept += pattern->kept - pattern->sum_kept;
    group->lost_dropped += pattern->dropped - pattern->sum_dropped;
    group->lost_bytes_dropped += pattern->bytes_dropped - pattern->sum_bytes_dropped;
}

static void group_destroy(struct adaptive_ctx *ctx, struct adaptive_group *group)
{
    if (group->miner) {
        ctx->miner_retired[0] += group->miner->created;
        ctx->miner_retired[1] += group->miner->merged;
        ctx->miner_retired[2] += group->miner->evicted;
        ctx->miner_retired[3] += group->miner->expired;
        adaptive_miner_destroy(group->miner);
    }
    if (group->key) {
        cfl_sds_destroy(group->key);
    }
    if (group->tag) {
        cfl_sds_destroy(group->tag);
    }
    if (ctx->last_group == group) {
        ctx->last_group = NULL;
    }

    cfl_list_del(&group->_head);
    cfl_list_del(&group->_bucket);
    ctx->group_count--;
    flb_free(group);
}

static struct adaptive_group *group_create(struct adaptive_ctx *ctx, const char *key,
                                           size_t len, uint64_t hash)
{
    struct adaptive_group *group;

    group = flb_calloc(1, sizeof(struct adaptive_group));
    if (!group) {
        flb_errno();
        return NULL;
    }
    cfl_list_add(&group->_head, &ctx->groups);
    cfl_list_add(&group->_bucket, &ctx->buckets[hash % ADAPTIVE_GROUP_BUCKETS]);
    ctx->group_count++;

    group->hash = hash;
    group->key = cfl_sds_create_len(key, len);
    group->miner = adaptive_miner_create(ctx->similarity, ctx->depth, ctx->max_children,
                                         ctx->max_tokens, ctx->max_patterns);
    if (!group->key || !group->miner) {
        group_destroy(ctx, group);
        return NULL;
    }

    group->miner->group = group->key;
    group->miner->cb_remove = pattern_removed;
    group->miner->cb_remove_data = group;

    return group;
}

static struct adaptive_group *group_find(struct adaptive_ctx *ctx, const char *key,
                                         size_t len, uint64_t hash)
{
    struct cfl_list *head;
    struct adaptive_group *group;

    cfl_list_foreach(head, &ctx->buckets[hash % ADAPTIVE_GROUP_BUCKETS]) {
        group = cfl_list_entry(head, struct adaptive_group, _bucket);
        if (group->hash == hash && cfl_sds_len(group->key) == len &&
            memcmp(group->key, key, len) == 0) {
            return group;
        }
    }

    return NULL;
}

static struct adaptive_group *group_get(struct adaptive_ctx *ctx, const char *key, size_t len)
{
    uint64_t hash;
    struct adaptive_group *group;

    group = ctx->last_group;
    if (group && cfl_sds_len(group->key) == len && memcmp(group->key, key, len) == 0) {
        return group;
    }

    hash = cfl_hash_64bits(key, len);
    group = group_find(ctx, key, len, hash);
    if (group) {
        return group;
    }

    if (ctx->group_count >= ctx->max_groups) {
        /* too many keys: the ones that arrive late share one group */
        ctx->groups_overflowed++;
        key = ADAPTIVE_GROUP_OTHER;
        len = sizeof(ADAPTIVE_GROUP_OTHER) - 1;
        hash = cfl_hash_64bits(key, len);
        group = group_find(ctx, key, len, hash);
        if (group) {
            return group;
        }
    }

    return group_create(ctx, key, len, hash);
}

/* Used when saved state is loaded: same rules as a key seen in a record */
struct adaptive_group *adaptive_group_restore(struct adaptive_ctx *ctx,
                                              const char *key, size_t len)
{
    if (len > ADAPTIVE_GROUP_KEY_MAX - 1) {
        return NULL;
    }

    return group_get(ctx, key, len);
}

struct adaptive_group *adaptive_group_resolve(struct adaptive_ctx *ctx,
                                              struct flb_mp_chunk_record *record,
                                              struct cfl_kvlist *body,
                                              const char *tag, int tag_len,
                                              uint64_t now)
{
    size_t used = 0;
    char *buf = ctx->group_buf;
    struct cfl_list *head;
    struct cfl_variant *variant;
    struct adaptive_selector *selector;

    cfl_list_foreach(head, &ctx->selectors) {
        selector = cfl_list_entry(head, struct adaptive_selector, _head);

        if (used > 0) {
            used = adaptive_group_key_append(buf, used, "/", 1);
        }

        if (selector->type == ADAPTIVE_SELECT_TAG) {
            used = adaptive_group_key_append(buf, used, tag ? tag : "-", tag ? (size_t) tag_len : 1);
            continue;
        }

        if (selector->type == ADAPTIVE_SELECT_RESOURCE) {
            variant = resource_attribute(record, selector->parts[0]);
        }
        else {
            variant = kvlist_path(body, selector->parts, selector->part_count);
        }
        used = key_append_variant(buf, used, variant);
    }

    return adaptive_group_by_key(ctx, used, tag, tag_len, now);
}

/* The group of the key that was written to ctx->group_buf */
struct adaptive_group *adaptive_group_by_key(struct adaptive_ctx *ctx, size_t key_len,
                                             const char *tag, int tag_len, uint64_t now)
{
    struct adaptive_group *group;

    group = group_get(ctx, ctx->group_buf, key_len);
    if (!group) {
        return NULL;
    }
    ctx->last_group = group;
    group->last_seen = now;

    /* summaries produced by the timer need a tag to travel with */
    if (ctx->ingress && tag && tag_len > 0 &&
        (!group->tag || cfl_sds_len(group->tag) != (size_t) tag_len ||
         memcmp(group->tag, tag, tag_len) != 0)) {
        if (group->tag) {
            cfl_sds_destroy(group->tag);
        }
        group->tag = cfl_sds_create_len(tag, tag_len);
    }

    return group;
}

/* Refresh the totals shown by metrics and the report */
void adaptive_groups_stats(struct adaptive_ctx *ctx)
{
    struct cfl_list *head;
    struct adaptive_group *group;

    memcpy(ctx->miner_events, ctx->miner_retired, sizeof(ctx->miner_events));
    ctx->pattern_count = 0;

    cfl_list_foreach(head, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);
        ctx->miner_events[0] += group->miner->created;
        ctx->miner_events[1] += group->miner->merged;
        ctx->miner_events[2] += group->miner->evicted;
        ctx->miner_events[3] += group->miner->expired;
        ctx->pattern_count += group->miner->pattern_count;
    }
}

void adaptive_groups_expire(struct adaptive_ctx *ctx, uint64_t now)
{
    uint64_t ttl = (uint64_t) ctx->pattern_ttl * 1000000000ULL;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct adaptive_group *group;

    if (ttl == 0 || now <= ttl) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);
        adaptive_miner_expire(group->miner, now - ttl);

        /* what its last patterns dropped still has to reach a summary */
        if (group->miner->pattern_count > 0 || group->last_seen >= now - ttl ||
            (ctx->summary && ctx->enforce && group->lost_dropped > 0)) {
            continue;
        }
        group_destroy(ctx, group);
    }
}

void adaptive_groups_destroy(struct adaptive_ctx *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct adaptive_group *group;

    cfl_list_foreach_safe(head, tmp, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);
        group_destroy(ctx, group);
    }
}
