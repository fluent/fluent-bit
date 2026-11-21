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
 * Keep or drop decisions
 * ======================
 * Decisions are taken per pattern in this order:
 *
 *  1. protected records are always kept
 *  2. a pattern named in the policy file follows its drop rate
 *  3. otherwise the first 'allow' records of a window are kept and the rest
 *     are sampled 1 in N, where N grows with the volume of the pattern
 *  4. a window byte budget caps what the previous steps decided to keep,
 *     except for the first record of each pattern
 *
 * Sampling is systematic, not random: the same input always produces the
 * same output and the kept share is exact.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_compat.h>

#include <msgpack.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#include "adaptive_policy.h"

static const char *reason_names[ADAPTIVE_REASON_COUNT] = {
    "protected", "policy", "allowance", "low_volume",
    "sampled", "budget", "exemplar", "unmatched"
};

const char *adaptive_policy_reason_name(int reason)
{
    if (reason < 0 || reason >= ADAPTIVE_REASON_COUNT) {
        return "unknown";
    }

    return reason_names[reason];
}

int adaptive_policy_sample_mode(const char *name)
{
    if (!name) {
        return -1;
    }

    if (strcasecmp(name, "off") == 0) {
        return ADAPTIVE_SAMPLE_OFF;
    }
    else if (strcasecmp(name, "log") == 0) {
        return ADAPTIVE_SAMPLE_LOG;
    }
    else if (strcasecmp(name, "sqrt") == 0) {
        return ADAPTIVE_SAMPLE_SQRT;
    }
    else if (strcasecmp(name, "suppress") == 0) {
        return ADAPTIVE_SAMPLE_SUPPRESS;
    }

    return -1;
}

static void entry_destroy(struct adaptive_policy_entry *entry)
{
    int i;

    if (entry->tokens) {
        for (i = 0; i < entry->token_count; i++) {
            flb_free(entry->tokens[i]);
        }
        flb_free(entry->tokens);
    }
    if (entry->template_str) {
        cfl_sds_destroy(entry->template_str);
    }
    if (entry->group) {
        cfl_sds_destroy(entry->group);
    }
    flb_free(entry);
}

static void entries_destroy(struct cfl_list *entries)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct adaptive_policy_entry *entry;

    cfl_list_foreach_safe(head, tmp, entries) {
        entry = cfl_list_entry(head, struct adaptive_policy_entry, _head);
        cfl_list_del(&entry->_head);
        entry_destroy(entry);
    }
}

/* Split a template on single spaces, the way the miner joins it */
static int entry_set_template(struct adaptive_policy_entry *entry,
                              const char *str, size_t len)
{
    size_t i;
    size_t start = 0;
    int count = 1;
    int index = 0;

    entry->template_str = cfl_sds_create_len(str, len);
    if (!entry->template_str) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        if (str[i] == ' ') {
            count++;
        }
    }

    entry->tokens = flb_calloc(count, sizeof(char *));
    if (!entry->tokens) {
        flb_errno();
        return -1;
    }

    for (i = 0; i <= len; i++) {
        if (i < len && str[i] != ' ') {
            continue;
        }

        if (i == len && i - start == sizeof(ADAPTIVE_TRUNCATED) - 1 &&
            strncmp(str + start, ADAPTIVE_TRUNCATED, i - start) == 0) {
            entry->truncated = FLB_TRUE;
            break;
        }

        entry->tokens[index] = flb_strndup(str + start, i - start);
        if (!entry->tokens[index]) {
            flb_errno();
            return -1;
        }
        index++;
        entry->token_count = index;
        start = i + 1;
    }

    return 0;
}

static int key_is(msgpack_object *key, const char *name)
{
    size_t len = strlen(name);

    return key->type == MSGPACK_OBJECT_STR && key->via.str.size == len &&
           strncmp(key->via.str.ptr, name, len) == 0;
}

static struct adaptive_policy_entry *entry_from_object(msgpack_object *obj)
{
    uint32_t i;
    int has_rate = FLB_FALSE;
    int has_match = FLB_FALSE;
    char tmp[17];
    char *end;
    msgpack_object *key;
    msgpack_object *val;
    struct adaptive_policy_entry *entry;

    if (obj->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    entry = flb_calloc(1, sizeof(struct adaptive_policy_entry));
    if (!entry) {
        flb_errno();
        return NULL;
    }

    for (i = 0; i < obj->via.map.size; i++) {
        key = &obj->via.map.ptr[i].key;
        val = &obj->via.map.ptr[i].val;

        if (key_is(key, "template") && val->type == MSGPACK_OBJECT_STR && !has_match) {
            if (entry_set_template(entry, val->via.str.ptr, val->via.str.size) != 0) {
                entry_destroy(entry);
                return NULL;
            }
            has_match = FLB_TRUE;
        }
        else if (key_is(key, "id") && val->type == MSGPACK_OBJECT_STR && !has_match) {
            if (val->via.str.size == 0 || val->via.str.size > 16) {
                entry_destroy(entry);
                return NULL;
            }
            memcpy(tmp, val->via.str.ptr, val->via.str.size);
            tmp[val->via.str.size] = '\0';
            errno = 0;
            entry->id = strtoull(tmp, &end, 16);
            if (errno != 0 || *end != '\0') {
                entry_destroy(entry);
                return NULL;
            }
            entry->by_id = FLB_TRUE;
            has_match = FLB_TRUE;
        }
        else if (key_is(key, "group") && val->type == MSGPACK_OBJECT_STR && !entry->group) {
            entry->group = cfl_sds_create_len(val->via.str.ptr, val->via.str.size);
            if (!entry->group) {
                entry_destroy(entry);
                return NULL;
            }
        }
        else if (key_is(key, "drop_rate")) {
            if (val->type == MSGPACK_OBJECT_FLOAT32 || val->type == MSGPACK_OBJECT_FLOAT64) {
                entry->drop_rate = val->via.f64;
            }
            else if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                entry->drop_rate = (double) val->via.u64;
            }
            else {
                entry_destroy(entry);
                return NULL;
            }
            has_rate = FLB_TRUE;
        }
    }

    if (!has_rate || !has_match || !(entry->drop_rate >= 0.0 && entry->drop_rate <= 1.0)) {
        entry_destroy(entry);
        return NULL;
    }

    return entry;
}

/*
 * Replace the active policy with the content of a JSON document:
 *
 *   {"patterns": [{"template": "GET <*> took <NUM>ms", "drop_rate": 0.9},
 *                 {"id": "9f2c41d07a11b3e5", "drop_rate": 0.0},
 *                 {"group": "payments", "template": "ping", "drop_rate": 1}]}
 *
 * An entry without "group" applies to every group.
 *
 * The document is applied as a whole: one invalid entry rejects it and the
 * previous policy stays in place.
 */
int adaptive_policy_load_buffer(struct adaptive_policy *policy,
                                const char *json, size_t len)
{
    int ret;
    int count = 0;
    int root_type;
    int found = FLB_FALSE;
    uint32_t i;
    uint32_t j;
    char *mp_buf = NULL;
    size_t mp_size = 0;
    size_t consumed = 0;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object *root;
    msgpack_object *val;
    struct cfl_list entries;
    struct adaptive_policy_entry *entry;

    ret = flb_pack_json(json, len, &mp_buf, &mp_size, &root_type, &consumed);
    if (ret != 0) {
        return ADAPTIVE_POLICY_ERROR;
    }

    cfl_list_init(&entries);
    msgpack_unpacked_init(&result);

    ret = ADAPTIVE_POLICY_ERROR;
    if (msgpack_unpack_next(&result, mp_buf, mp_size, &off) != MSGPACK_UNPACK_SUCCESS) {
        goto done;
    }

    root = &result.data;
    if (root->type != MSGPACK_OBJECT_MAP) {
        goto done;
    }

    for (i = 0; i < root->via.map.size; i++) {
        if (!key_is(&root->via.map.ptr[i].key, "patterns")) {
            continue;
        }

        val = &root->via.map.ptr[i].val;
        if (val->type != MSGPACK_OBJECT_ARRAY) {
            goto done;
        }

        for (j = 0; j < val->via.array.size; j++) {
            entry = entry_from_object(&val->via.array.ptr[j]);
            if (!entry) {
                goto done;
            }
            cfl_list_add(&entry->_head, &entries);
            count++;
        }
        found = FLB_TRUE;
    }

    if (!found) {
        goto done;
    }

    /* swap: bindings held by patterns are invalidated by the generation */
    entries_destroy(&policy->entries);
    cfl_list_init(&policy->entries);
    if (!cfl_list_is_empty(&entries)) {
        policy->entries = entries;
        policy->entries.next->prev = &policy->entries;
        policy->entries.prev->next = &policy->entries;
        cfl_list_init(&entries);
    }
    policy->entry_count = count;
    policy->generation++;
    ret = ADAPTIVE_POLICY_LOADED;

done:
    entries_destroy(&entries);
    msgpack_unpacked_destroy(&result);
    flb_free(mp_buf);

    return ret;
}

int adaptive_policy_load_file(struct adaptive_policy *policy, const char *path)
{
    int ret;
    char *buf = NULL;
    size_t size = 0;
    struct stat st;

    if (stat(path, &st) != 0) {
        /* a removed file withdraws the policy */
        if (policy->file_loaded) {
            entries_destroy(&policy->entries);
            cfl_list_init(&policy->entries);
            policy->entry_count = 0;
            policy->generation++;
            policy->file_loaded = FLB_FALSE;
            return ADAPTIVE_POLICY_LOADED;
        }
        return ADAPTIVE_POLICY_UNCHANGED;
    }

    if (policy->file_loaded && st.st_mtime == policy->file_mtime &&
        st.st_size == policy->file_size) {
        return ADAPTIVE_POLICY_UNCHANGED;
    }

    /* remember the attempt so a broken file is not parsed on every check */
    policy->file_mtime = st.st_mtime;
    policy->file_size = st.st_size;
    policy->file_loaded = FLB_TRUE;

    ret = flb_utils_read_file((char *) path, &buf, &size);
    if (ret != 0 || !buf) {
        return ADAPTIVE_POLICY_ERROR;
    }

    ret = adaptive_policy_load_buffer(policy, buf, size);
    flb_free(buf);

    return ret;
}

/* 'user=<*>' in the policy covers 'user=alice' in a template */
static int token_match(const char *rule, const char *token)
{
    size_t len;

    if (strcmp(rule, token) == 0 || strcmp(rule, ADAPTIVE_WILDCARD) == 0) {
        return FLB_TRUE;
    }

    len = strlen(rule);
    if (len <= sizeof(ADAPTIVE_WILDCARD) - 1) {
        return FLB_FALSE;
    }
    len -= sizeof(ADAPTIVE_WILDCARD) - 1;
    if (strcmp(rule + len, ADAPTIVE_WILDCARD) != 0 ||
        (rule[len - 1] != '=' && rule[len - 1] != ':')) {
        return FLB_FALSE;
    }

    return strncmp(rule, token, len) == 0;
}

static int entry_match(struct adaptive_policy_entry *entry, struct adaptive_pattern *pattern)
{
    int i;

    if (entry->group &&
        strcmp(entry->group, pattern->group ? pattern->group : "") != 0) {
        return FLB_FALSE;
    }

    if (entry->by_id) {
        return entry->id == pattern->id;
    }

    if (entry->token_count != pattern->token_count ||
        entry->truncated != pattern->truncated) {
        return FLB_FALSE;
    }

    /* a wildcard in the policy covers a template that is still more specific */
    for (i = 0; i < entry->token_count; i++) {
        if (!token_match(entry->tokens[i], pattern->tokens[i])) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static void pattern_bind(struct adaptive_policy *policy, struct adaptive_pattern *pattern)
{
    struct cfl_list *head;
    struct adaptive_policy_entry *entry;

    if (pattern->policy_generation == policy->generation &&
        pattern->policy_template_generation == pattern->generation) {
        return;
    }

    pattern->policy = NULL;
    pattern->policy_generation = policy->generation;
    pattern->policy_template_generation = pattern->generation;

    /* entries are in file order, the first match wins */
    cfl_list_foreach(head, &policy->entries) {
        entry = cfl_list_entry(head, struct adaptive_policy_entry, _head);
        if (entry_match(entry, pattern)) {
            pattern->policy = entry;
            /* start so that the first record is kept for any rate below 1 */
            pattern->policy_acc = entry->drop_rate;
            break;
        }
    }
}

static uint32_t rate_compute(struct adaptive_policy *policy, uint64_t volume)
{
    double value;
    uint32_t rate;

    if (policy->sample_mode == ADAPTIVE_SAMPLE_OFF) {
        return 1;
    }

    if (policy->sample_mode == ADAPTIVE_SAMPLE_SUPPRESS) {
        return 0;
    }

    if (volume < policy->min_events || volume < 2) {
        return 1;
    }

    if (policy->sample_mode == ADAPTIVE_SAMPLE_SQRT) {
        value = ceil(sqrt((double) volume));
    }
    else {
        value = ceil(log((double) volume));
    }

    if (value < 1.0) {
        return 1;
    }
    if (value > (double) policy->max_rate) {
        return policy->max_rate;
    }

    rate = (uint32_t) value;
    return rate;
}

void adaptive_policy_decide(struct adaptive_policy *policy,
                            struct adaptive_pattern *pattern,
                            size_t bytes, uint64_t now, int is_protected,
                            struct adaptive_decision *decision)
{
    int action = ADAPTIVE_KEEP;
    int reason = ADAPTIVE_REASON_ALLOWANCE;
    int budget_exempt = FLB_FALSE;
    uint32_t sample_rate = 1;
    uint64_t window_id;
    double keep_ratio;

    window_id = now / policy->window_ns;

    if (policy->window_id != window_id) {
        policy->window_id = window_id;
        policy->win_kept_bytes = 0;
    }

    if (pattern->window_id != window_id) {
        pattern->prev_count = (window_id == pattern->window_id + 1) ? pattern->win_count : 0;
        pattern->window_id = window_id;
        pattern->win_count = 0;
        pattern->win_kept = 0;
        pattern->sample_seq = 0;
        pattern->rate = rate_compute(policy, pattern->prev_count);
    }

    pattern->count++;
    pattern->bytes += bytes;
    pattern->win_count++;

    /*
     * A pattern that outgrows the previous window is re-rated inside the
     * current one, at each doubling, so a new flood does not get a free window.
     */
    if (pattern->win_count > pattern->prev_count &&
        (pattern->win_count & (pattern->win_count - 1)) == 0) {
        pattern->rate = rate_compute(policy, pattern->win_count);
    }

    pattern_bind(policy, pattern);

    if (is_protected) {
        pattern->protected_count++;
        reason = ADAPTIVE_REASON_PROTECTED;
        budget_exempt = FLB_TRUE;
    }
    else if (pattern->policy) {
        reason = ADAPTIVE_REASON_POLICY;
        keep_ratio = 1.0 - pattern->policy->drop_rate;

        if (keep_ratio >= 1.0) {
            /* an explicit zero drop rate is an exemption */
            budget_exempt = FLB_TRUE;
        }
        else if (keep_ratio <= 0.0) {
            action = ADAPTIVE_DROP;
        }
        else {
            pattern->policy_acc += keep_ratio;
            if (pattern->policy_acc + 1e-9 >= 1.0) {
                pattern->policy_acc -= 1.0;
                sample_rate = (uint32_t) ((1.0 / keep_ratio) + 0.5);
            }
            else {
                action = ADAPTIVE_DROP;
            }
        }
    }
    else if (pattern->win_count <= policy->allow) {
        reason = ADAPTIVE_REASON_ALLOWANCE;
    }
    else if (pattern->rate == 1) {
        reason = ADAPTIVE_REASON_LOW_VOLUME;
    }
    else {
        reason = ADAPTIVE_REASON_SAMPLED;
        if (pattern->rate == 0) {
            action = ADAPTIVE_DROP;
        }
        else {
            if (pattern->sample_seq % pattern->rate != 0) {
                action = ADAPTIVE_DROP;
            }
            pattern->sample_seq++;
            sample_rate = pattern->rate;
        }
    }

    if (action == ADAPTIVE_KEEP && !budget_exempt && policy->budget_bytes > 0 &&
        policy->win_kept_bytes + bytes > policy->budget_bytes) {
        if (pattern->win_kept == 0) {
            reason = ADAPTIVE_REASON_EXEMPLAR;
            sample_rate = 1;
        }
        else {
            action = ADAPTIVE_DROP;
            reason = ADAPTIVE_REASON_BUDGET;
        }
    }

    decision->action = action;
    decision->reason = reason;
    decision->suppressed = 0;
    decision->sample_rate = 1;

    if (action == ADAPTIVE_KEEP) {
        pattern->kept++;
        pattern->win_kept++;
        policy->win_kept_bytes += bytes;
        decision->sample_rate = sample_rate;
        decision->suppressed = pattern->suppressed;
        pattern->suppressed = 0;
    }
    else {
        pattern->dropped++;
        pattern->bytes_dropped += bytes;
        pattern->suppressed++;
    }
}

struct adaptive_policy *adaptive_policy_create(int window_seconds, int allow,
                                               int min_events, int sample_mode,
                                               int max_rate, uint64_t budget_bytes)
{
    struct adaptive_policy *policy;

    if (window_seconds < 1 || allow < 0 || min_events < 0 || max_rate < 1 ||
        sample_mode < ADAPTIVE_SAMPLE_OFF || sample_mode > ADAPTIVE_SAMPLE_SUPPRESS) {
        return NULL;
    }

    policy = flb_calloc(1, sizeof(struct adaptive_policy));
    if (!policy) {
        flb_errno();
        return NULL;
    }
    policy->window_ns = (uint64_t) window_seconds * 1000000000ULL;
    policy->allow = allow;
    policy->min_events = min_events;
    policy->sample_mode = sample_mode;
    policy->max_rate = max_rate;
    policy->budget_bytes = budget_bytes;
    policy->generation = 1;
    cfl_list_init(&policy->entries);

    return policy;
}

void adaptive_policy_destroy(struct adaptive_policy *policy)
{
    if (!policy) {
        return;
    }

    entries_destroy(&policy->entries);
    flb_free(policy);
}
