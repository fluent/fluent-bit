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
 * Online log template mining
 * ==========================
 * This is a fixed depth parse tree in the style of Drain (He et al., 2017).
 * A line is split into tokens, variable looking tokens are replaced by typed
 * placeholders, and the line is routed by token count and by its leading
 * tokens to a leaf that holds a short list of templates. The most similar
 * template absorbs the line, positions that differ become wildcards.
 *
 * Memory is bounded: the number of templates is capped and the least recently
 * used one is evicted, empty tree nodes are pruned on eviction.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>

#include <string.h>

#include "adaptive_miner.h"

/* A masked token can grow by at most this many bytes */
#define TOKEN_GROWTH   8

struct adaptive_node {
    uint64_t key;
    struct adaptive_node *parent;
    uint64_t *keys;
    struct adaptive_node **children;
    int child_count;
    int child_size;
    int pattern_count;
    struct cfl_list patterns;
};

static inline int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static inline int is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline int is_hex(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline int is_open_punct(char c)
{
    return c == '(' || c == '[' || c == '{' || c == '"' || c == '\'' || c == '<';
}

static inline int is_close_punct(char c)
{
    return c == ')' || c == ']' || c == '}' || c == '"' || c == '\'' || c == '>' ||
           c == ',' || c == ';' || c == ':' || c == '.';
}

static int is_ipv4(const char *s, int len)
{
    int i = 0;
    int group;
    int digits;

    for (group = 0; group < 4; group++) {
        digits = 0;
        while (i < len && is_digit(s[i]) && digits < 3) {
            i++;
            digits++;
        }
        if (digits == 0) {
            return FLB_FALSE;
        }
        if (group < 3) {
            if (i >= len || s[i] != '.') {
                return FLB_FALSE;
            }
            i++;
        }
    }

    if (i == len) {
        return FLB_TRUE;
    }

    /* optional port or prefix length */
    if (s[i] != ':' && s[i] != '/') {
        return FLB_FALSE;
    }
    i++;
    if (i == len) {
        return FLB_FALSE;
    }
    while (i < len) {
        if (!is_digit(s[i])) {
            return FLB_FALSE;
        }
        i++;
    }

    return FLB_TRUE;
}

static int is_uuid(const char *s, int len)
{
    int i;

    if (len != 36) {
        return FLB_FALSE;
    }

    for (i = 0; i < len; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') {
                return FLB_FALSE;
            }
        }
        else if (!is_hex(s[i])) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

/*
 * Classify a value. Returns the placeholder that replaces it or NULL when the
 * value is a literal. For numbers followed by a short unit, 'unit_offset'
 * points to the unit so the caller can preserve it.
 */
static const char *classify_value(const char *s, int len, int *unit_offset)
{
    int i = 0;
    int j;
    int digits = 0;
    int fraction = 0;
    int has_digit = FLB_FALSE;
    int all_hex = FLB_TRUE;

    *unit_offset = -1;

    if (len <= 0) {
        return NULL;
    }

    /* number: optional sign, digits, optional fraction, optional unit */
    if (s[0] == '-' || s[0] == '+') {
        i++;
    }
    while (i < len && is_digit(s[i])) {
        i++;
        digits++;
    }
    if (digits > 0) {
        if (i + 1 < len && s[i] == '.' && is_digit(s[i + 1])) {
            j = i + 1;
            while (j < len && is_digit(s[j])) {
                j++;
                fraction++;
            }
            if (fraction > 0 && (j == len || s[j] != '.')) {
                i = j;
            }
        }

        if (i == len) {
            return "<NUM>";
        }

        if (len - i <= 3) {
            for (j = i; j < len; j++) {
                if (!is_alpha(s[j]) && !(s[j] == '%' && len - i == 1)) {
                    break;
                }
            }
            if (j == len) {
                *unit_offset = i;
                return "<NUM>";
            }
        }
    }

    if (is_ipv4(s, len)) {
        return "<IP>";
    }

    if (is_uuid(s, len)) {
        return "<UUID>";
    }

    if (len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        for (i = 2; i < len; i++) {
            if (!is_hex(s[i])) {
                break;
            }
        }
        if (i == len) {
            return "<HEX>";
        }
    }

    for (i = 0; i < len; i++) {
        if (is_digit(s[i])) {
            has_digit = FLB_TRUE;
        }
        else if (!is_hex(s[i])) {
            all_hex = FLB_FALSE;
        }
    }

    if (!has_digit) {
        return NULL;
    }

    if (all_hex && len >= 8) {
        return "<HEX>";
    }

    return ADAPTIVE_WILDCARD;
}

/* A dotted name followed by ':' and digits only, like host.domain:8080 */
static int is_endpoint(const char *s, int separator, int len)
{
    int i;
    int dots = 0;

    for (i = 0; i < separator; i++) {
        if (s[i] == '.') {
            dots++;
        }
    }
    if (dots == 0 || separator + 1 >= len) {
        return FLB_FALSE;
    }

    for (i = separator + 1; i < len; i++) {
        if (!is_digit(s[i])) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

/* Mask one raw token and store the result in the token slot */
static void mask_token(struct adaptive_miner *miner, struct adaptive_token *token,
                       const char *raw, int len, size_t *scratch_used)
{
    int i;
    int start = 0;
    int end = len;
    int value = 0;
    int endpoint = FLB_FALSE;
    int core_len;
    int unit_offset;
    int mask_len;
    size_t used;
    char *out;
    const char *core;
    const char *mask;

    token->str = raw;
    token->len = len;
    token->masked = FLB_FALSE;
    token->key_len = 0;
    token->key_hash_ready = FLB_FALSE;

    while (start < len && is_open_punct(raw[start])) {
        start++;
    }
    while (end > start && is_close_punct(raw[end - 1])) {
        end--;
    }

    core = raw + start;
    core_len = end - start;
    if (core_len == 0) {
        return;
    }

    /* key=value and key:value keep the key when it has no digits */
    for (i = 0; i < core_len; i++) {
        if (is_digit(core[i])) {
            break;
        }
        if ((core[i] == '=' || core[i] == ':') && i > 0 && i + 1 < core_len) {
            value = i + 1;
            if (core[i] == ':' && is_endpoint(core, i, core_len)) {
                endpoint = FLB_TRUE;
                break;
            }
            while (value < core_len - 1 && is_open_punct(core[value])) {
                value++;
            }
            break;
        }
    }

    if (endpoint) {
        /* name.domain:port and file.ext:line vary as a whole */
        used = *scratch_used;
        out = miner->scratch + used;
        memcpy(out, raw, start);
        out += start;
        memcpy(out, ADAPTIVE_WILDCARD ":<NUM>", sizeof(ADAPTIVE_WILDCARD ":<NUM>") - 1);
        out += sizeof(ADAPTIVE_WILDCARD ":<NUM>") - 1;
        memcpy(out, raw + end, len - end);
        out += len - end;

        token->str = miner->scratch + used;
        token->len = out - token->str;
        token->masked = FLB_TRUE;
        *scratch_used = used + token->len;
        return;
    }

    /* the key travels with the token so two values of it can be merged */
    if (value > 0 && start + value <= ADAPTIVE_KEY_MAX) {
        token->key_len = start + value;
    }

    mask = classify_value(core + value, core_len - value, &unit_offset);
    if (mask == NULL) {
        return;
    }

    /* rebuild as: prefix + key + placeholder + unit + suffix */
    used = *scratch_used;
    out = miner->scratch + used;
    mask_len = strlen(mask);

    memcpy(out, raw, start + value);
    out += start + value;
    memcpy(out, mask, mask_len);
    out += mask_len;
    if (unit_offset >= 0) {
        memcpy(out, core + value + unit_offset, core_len - value - unit_offset);
        out += core_len - value - unit_offset;
    }
    memcpy(out, raw + end, len - end);
    out += len - end;

    token->str = miner->scratch + used;
    token->len = out - token->str;
    token->masked = (value == 0);
    *scratch_used = used + token->len;
}

int adaptive_miner_tokenize(struct adaptive_miner *miner,
                            const char *line, size_t len, int *truncated)
{
    int count = 0;
    size_t i = 0;
    size_t start;
    size_t needed;
    size_t scratch_used = 0;
    char *tmp;
    struct adaptive_token *token;

    *truncated = FLB_FALSE;

    needed = len + ((size_t) miner->max_tokens * TOKEN_GROWTH) + 1;
    if (needed > miner->scratch_size) {
        tmp = flb_realloc(miner->scratch, needed);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        miner->scratch = tmp;
        miner->scratch_size = needed;
    }

    while (i < len) {
        while (i < len && (line[i] == ' ' || line[i] == '\t' ||
                           line[i] == '\n' || line[i] == '\r')) {
            i++;
        }
        if (i >= len) {
            break;
        }

        start = i;
        while (i < len && line[i] != ' ' && line[i] != '\t' &&
               line[i] != '\n' && line[i] != '\r') {
            i++;
        }

        if (count >= miner->max_tokens) {
            *truncated = FLB_TRUE;
            break;
        }

        token = &miner->tokens[count];
        mask_token(miner, token, line + start, (int) (i - start), &scratch_used);
        token->hash = cfl_hash_64bits(token->str, token->len);
        count++;
    }

    return count;
}

/* Hash of the token as it reads once its value is a wildcard: key=<*> */
static uint64_t token_key_hash(struct adaptive_token *token)
{
    char buf[ADAPTIVE_KEY_MAX + sizeof(ADAPTIVE_WILDCARD)];

    if (!token->key_hash_ready) {
        memcpy(buf, token->str, token->key_len);
        memcpy(buf + token->key_len, ADAPTIVE_WILDCARD, sizeof(ADAPTIVE_WILDCARD) - 1);
        token->key_hash = cfl_hash_64bits(buf, token->key_len + sizeof(ADAPTIVE_WILDCARD) - 1);
        token->key_hash_ready = FLB_TRUE;
    }

    return token->key_hash;
}

static struct adaptive_node *node_create(struct adaptive_node *parent, uint64_t key)
{
    struct adaptive_node *node;

    node = flb_calloc(1, sizeof(struct adaptive_node));
    if (!node) {
        flb_errno();
        return NULL;
    }
    node->key = key;
    node->parent = parent;
    cfl_list_init(&node->patterns);

    return node;
}

static struct adaptive_node *node_child_get(struct adaptive_node *node, uint64_t key)
{
    int i;

    for (i = 0; i < node->child_count; i++) {
        if (node->keys[i] == key) {
            return node->children[i];
        }
    }

    return NULL;
}

static struct adaptive_node *node_child_add(struct adaptive_node *node, uint64_t key)
{
    int size;
    uint64_t *keys;
    struct adaptive_node **children;
    struct adaptive_node *child;

    if (node->child_count == node->child_size) {
        size = node->child_size == 0 ? 4 : node->child_size * 2;

        keys = flb_realloc(node->keys, sizeof(uint64_t) * size);
        if (!keys) {
            flb_errno();
            return NULL;
        }
        node->keys = keys;

        children = flb_realloc(node->children, sizeof(struct adaptive_node *) * size);
        if (!children) {
            flb_errno();
            return NULL;
        }
        node->children = children;
        node->child_size = size;
    }

    child = node_create(node, key);
    if (!child) {
        return NULL;
    }

    node->keys[node->child_count] = key;
    node->children[node->child_count] = child;
    node->child_count++;

    return child;
}

/* Release a node that holds nothing, then walk up doing the same */
static void node_prune(struct adaptive_miner *miner, struct adaptive_node *node)
{
    int i;
    struct adaptive_node *parent;

    while (node && node != miner->root &&
           node->pattern_count == 0 && node->child_count == 0) {
        parent = node->parent;

        for (i = 0; i < parent->child_count; i++) {
            if (parent->children[i] == node) {
                parent->child_count--;
                parent->keys[i] = parent->keys[parent->child_count];
                parent->children[i] = parent->children[parent->child_count];
                break;
            }
        }

        flb_free(node->keys);
        flb_free(node->children);
        flb_free(node);
        node = parent;
    }
}

static int pattern_template_build(struct adaptive_pattern *pattern)
{
    int i;
    cfl_sds_t buf;

    buf = cfl_sds_create_size(128);
    if (!buf) {
        return -1;
    }

    for (i = 0; i < pattern->token_count; i++) {
        if (i > 0) {
            cfl_sds_cat_safe(&buf, " ", 1);
        }
        cfl_sds_cat_safe(&buf, pattern->tokens[i], strlen(pattern->tokens[i]));
    }

    if (pattern->truncated) {
        if (pattern->token_count > 0) {
            cfl_sds_cat_safe(&buf, " ", 1);
        }
        cfl_sds_cat_safe(&buf, ADAPTIVE_TRUNCATED, sizeof(ADAPTIVE_TRUNCATED) - 1);
    }

    if (pattern->template_str) {
        cfl_sds_destroy(pattern->template_str);
    }
    pattern->template_str = buf;
    pattern->id = cfl_hash_64bits(buf, cfl_sds_len(buf));
    pattern->generation++;

    return 0;
}

static void pattern_destroy(struct adaptive_pattern *pattern)
{
    int i;

    if (pattern->tokens) {
        for (i = 0; i < pattern->token_count; i++) {
            flb_free(pattern->tokens[i]);
        }
        flb_free(pattern->tokens);
    }
    flb_free(pattern->hashes);
    if (pattern->template_str) {
        cfl_sds_destroy(pattern->template_str);
    }
    if (pattern->exemplar) {
        cfl_sds_destroy(pattern->exemplar);
    }
    flb_free(pattern);
}

static void pattern_remove(struct adaptive_miner *miner, struct adaptive_pattern *pattern)
{
    struct adaptive_node *leaf = pattern->leaf;

    if (miner->cb_remove) {
        miner->cb_remove(pattern, miner->cb_remove_data);
    }

    cfl_list_del(&pattern->_head);
    cfl_list_del(&pattern->_lru);
    leaf->pattern_count--;
    miner->pattern_count--;

    pattern_destroy(pattern);
    node_prune(miner, leaf);
}

static struct adaptive_pattern *pattern_create(struct adaptive_miner *miner,
                                               struct adaptive_node *leaf,
                                               int token_count, int truncated)
{
    int i;
    struct adaptive_pattern *pattern;
    struct adaptive_token *token;

    pattern = flb_calloc(1, sizeof(struct adaptive_pattern));
    if (!pattern) {
        flb_errno();
        return NULL;
    }
    pattern->truncated = truncated;
    pattern->rate = 1;
    pattern->group = miner->group;

    if (token_count > 0) {
        pattern->tokens = flb_calloc(token_count, sizeof(char *));
        pattern->hashes = flb_calloc(token_count, sizeof(uint64_t));
        if (!pattern->tokens || !pattern->hashes) {
            flb_errno();
            pattern_destroy(pattern);
            return NULL;
        }
    }

    for (i = 0; i < token_count; i++) {
        token = &miner->tokens[i];
        pattern->tokens[i] = flb_strndup(token->str, token->len);
        if (!pattern->tokens[i]) {
            flb_errno();
            pattern_destroy(pattern);
            return NULL;
        }
        pattern->token_count++;
        pattern->hashes[i] = token->hash;
        if (token->hash == miner->wildcard_hash) {
            pattern->wildcards++;
        }
        else if (token->key_len > 0 && token->hash == token_key_hash(token)) {
            pattern->key_wildcards = FLB_TRUE;
        }
    }

    if (pattern_template_build(pattern) != 0) {
        pattern_destroy(pattern);
        return NULL;
    }

    pattern->serial = ++miner->next_serial;
    pattern->leaf = leaf;
    cfl_list_add(&pattern->_head, &leaf->patterns);
    cfl_list_prepend(&pattern->_lru, &miner->lru);
    leaf->pattern_count++;
    miner->pattern_count++;
    miner->created++;

    return pattern;
}

static inline int token_equal(struct adaptive_pattern *pattern, int i,
                              struct adaptive_token *token)
{
    if (pattern->hashes[i] == token->hash) {
        return FLB_TRUE;
    }

    return pattern->key_wildcards && token->key_len > 0 &&
           pattern->hashes[i] == token_key_hash(token);
}

/*
 * Turn every position that disagrees with the line into a wildcard. Two
 * values of the same key keep the key: user=alice and user=bob become
 * user=<*>.
 */
static int pattern_merge(struct adaptive_miner *miner, struct adaptive_pattern *pattern)
{
    int i;
    int keyed;
    int changed = FLB_FALSE;
    char *wildcard;
    struct adaptive_token *token;

    for (i = 0; i < pattern->token_count; i++) {
        token = &miner->tokens[i];
        if (pattern->hashes[i] == miner->wildcard_hash || token_equal(pattern, i, token)) {
            continue;
        }

        keyed = token->key_len > 0 &&
                strncmp(pattern->tokens[i], token->str, token->key_len) == 0;
        if (keyed) {
            wildcard = flb_malloc(token->key_len + sizeof(ADAPTIVE_WILDCARD));
            if (wildcard) {
                memcpy(wildcard, token->str, token->key_len);
                memcpy(wildcard + token->key_len, ADAPTIVE_WILDCARD, sizeof(ADAPTIVE_WILDCARD));
            }
        }
        else {
            wildcard = flb_strdup(ADAPTIVE_WILDCARD);
        }
        if (!wildcard) {
            flb_errno();
            break;
        }

        flb_free(pattern->tokens[i]);
        pattern->tokens[i] = wildcard;
        if (keyed) {
            pattern->hashes[i] = token_key_hash(token);
            pattern->key_wildcards = FLB_TRUE;
        }
        else {
            pattern->hashes[i] = miner->wildcard_hash;
            pattern->wildcards++;
        }
        changed = FLB_TRUE;
    }

    if (changed) {
        pattern_template_build(pattern);
        miner->merged++;
    }

    return changed;
}

static struct adaptive_node *tree_route(struct adaptive_miner *miner,
                                        int token_count, int truncated)
{
    int i;
    int layers;
    uint64_t key;
    struct adaptive_node *node;
    struct adaptive_node *child;

    /* first layer: token count, truncated lines live in their own bucket */
    key = (uint64_t) token_count | ((uint64_t) (truncated ? 1 : 0) << 32);
    node = node_child_get(miner->root, key);
    if (!node) {
        node = node_child_add(miner->root, key);
        if (!node) {
            return NULL;
        }
    }

    /* next layers: leading tokens, variables share the wildcard branch */
    layers = miner->depth - 2;
    for (i = 0; i < layers && i < token_count; i++) {
        key = miner->tokens[i].masked ? miner->wildcard_hash : miner->tokens[i].hash;

        child = node_child_get(node, key);
        if (!child) {
            if (node->child_count >= miner->max_children && key != miner->wildcard_hash) {
                key = miner->wildcard_hash;
                child = node_child_get(node, key);
            }
            if (!child) {
                child = node_child_add(node, key);
                if (!child) {
                    return NULL;
                }
            }
        }
        node = child;
    }

    return node;
}

struct adaptive_pattern *adaptive_miner_process(struct adaptive_miner *miner,
                                                const char *line, size_t len,
                                                uint64_t now,
                                                int *is_new, int *changed)
{
    int i;
    int equal;
    int truncated;
    int token_count;
    double similarity;
    double best_similarity = -1.0;
    struct cfl_list *head;
    struct adaptive_node *leaf;
    struct adaptive_pattern *pattern;
    struct adaptive_pattern *best = NULL;

    *is_new = FLB_FALSE;
    *changed = FLB_FALSE;

    token_count = adaptive_miner_tokenize(miner, line, len, &truncated);
    if (token_count < 0) {
        return NULL;
    }

    leaf = tree_route(miner, token_count, truncated);
    if (!leaf) {
        return NULL;
    }

    cfl_list_foreach(head, &leaf->patterns) {
        pattern = cfl_list_entry(head, struct adaptive_pattern, _head);
        if (pattern->token_count != token_count) {
            continue;
        }

        equal = 0;
        for (i = 0; i < token_count; i++) {
            if (token_equal(pattern, i, &miner->tokens[i])) {
                equal++;
            }
        }
        similarity = token_count > 0 ? (double) equal / (double) token_count : 1.0;

        if (similarity > best_similarity ||
            (similarity == best_similarity && best && pattern->wildcards > best->wildcards)) {
            best = pattern;
            best_similarity = similarity;
            if (equal == token_count) {
                break;
            }
        }
    }

    if (best && best_similarity >= miner->similarity) {
        *changed = pattern_merge(miner, best);
        if (miner->lru.next != &best->_lru) {
            cfl_list_del(&best->_lru);
            cfl_list_prepend(&best->_lru, &miner->lru);
        }
        best->last_seen = now;
        return best;
    }

    /* make room before adding, the leaf survives because it is not empty yet */
    best = pattern_create(miner, leaf, token_count, truncated);
    if (!best) {
        node_prune(miner, leaf);
        return NULL;
    }
    best->first_seen = now;
    best->last_seen = now;
    *is_new = FLB_TRUE;

    while (miner->pattern_count > miner->max_patterns) {
        pattern = cfl_list_entry_last(&miner->lru, struct adaptive_pattern, _lru);
        if (pattern == best) {
            break;
        }
        pattern_remove(miner, pattern);
        miner->evicted++;
    }

    return best;
}

int adaptive_miner_expire(struct adaptive_miner *miner, uint64_t older_than)
{
    int count = 0;
    struct adaptive_pattern *pattern;

    /* the recency list is ordered, stop at the first live pattern */
    while (!cfl_list_is_empty(&miner->lru)) {
        pattern = cfl_list_entry_last(&miner->lru, struct adaptive_pattern, _lru);
        if (pattern->last_seen >= older_than) {
            break;
        }
        pattern_remove(miner, pattern);
        miner->expired++;
        count++;
    }

    return count;
}

int adaptive_miner_pattern_path(struct adaptive_miner *miner,
                                struct adaptive_pattern *pattern,
                                uint64_t *path, int size)
{
    int i;
    int count = 0;
    struct adaptive_node *node;

    for (node = pattern->leaf; node && node != miner->root; node = node->parent) {
        count++;
    }
    if (count == 0 || count > size) {
        return -1;
    }

    i = count;
    for (node = pattern->leaf; node && node != miner->root; node = node->parent) {
        path[--i] = node->key;
    }

    return count;
}

/* Put back a pattern that was saved, without learning it from a line again */
struct adaptive_pattern *adaptive_miner_restore(struct adaptive_miner *miner,
                                                uint64_t *path, int path_count,
                                                const char **tokens, int *lens,
                                                int token_count, int truncated,
                                                int key_wildcards)
{
    int i;
    struct adaptive_node *node;
    struct adaptive_node *child;
    struct adaptive_token *token;
    struct adaptive_pattern *pattern;
    struct adaptive_pattern *oldest;

    if (path_count < 1 || path_count > miner->depth - 1 ||
        token_count < 0 || token_count > miner->max_tokens) {
        return NULL;
    }

    /* the first layer says how many tokens the lines of this leaf have */
    if (path[0] != ((uint64_t) token_count | ((uint64_t) (truncated ? 1 : 0) << 32))) {
        return NULL;
    }

    for (i = 0; i < token_count; i++) {
        token = &miner->tokens[i];
        memset(token, 0, sizeof(struct adaptive_token));
        token->str = tokens[i];
        token->len = lens[i];
        token->hash = cfl_hash_64bits(tokens[i], lens[i]);
    }

    node = miner->root;
    for (i = 0; i < path_count; i++) {
        child = node_child_get(node, path[i]);
        if (!child) {
            child = node_child_add(node, path[i]);
            if (!child) {
                node_prune(miner, node);
                return NULL;
            }
        }
        node = child;
    }

    pattern = pattern_create(miner, node, token_count, truncated);
    if (!pattern) {
        node_prune(miner, node);
        return NULL;
    }
    pattern->key_wildcards = key_wildcards ? FLB_TRUE : FLB_FALSE;

    /* it was counted as created by the process that learned it */
    miner->created--;

    while (miner->pattern_count > miner->max_patterns) {
        oldest = cfl_list_entry_last(&miner->lru, struct adaptive_pattern, _lru);
        if (oldest == pattern) {
            break;
        }
        pattern_remove(miner, oldest);
        miner->evicted++;
    }

    return pattern;
}

struct adaptive_miner *adaptive_miner_create(double similarity, int depth,
                                             int max_children, int max_tokens,
                                             int max_patterns)
{
    struct adaptive_miner *miner;

    if (similarity < 0.0 || similarity > 1.0 ||
        depth < ADAPTIVE_DEPTH_MIN || depth > ADAPTIVE_DEPTH_MAX ||
        max_children < 1 || max_patterns < 1 ||
        max_tokens < ADAPTIVE_TOKENS_MIN || max_tokens > ADAPTIVE_TOKENS_MAX) {
        return NULL;
    }

    miner = flb_calloc(1, sizeof(struct adaptive_miner));
    if (!miner) {
        flb_errno();
        return NULL;
    }
    miner->similarity = similarity;
    miner->depth = depth;
    miner->max_children = max_children;
    miner->max_tokens = max_tokens;
    miner->max_patterns = max_patterns;
    miner->wildcard_hash = cfl_hash_64bits(ADAPTIVE_WILDCARD, sizeof(ADAPTIVE_WILDCARD) - 1);
    cfl_list_init(&miner->lru);

    miner->tokens = flb_calloc(max_tokens, sizeof(struct adaptive_token));
    miner->root = node_create(NULL, 0);
    if (!miner->tokens || !miner->root) {
        adaptive_miner_destroy(miner);
        return NULL;
    }

    return miner;
}

void adaptive_miner_destroy(struct adaptive_miner *miner)
{
    struct adaptive_pattern *pattern;

    if (!miner) {
        return;
    }

    while (!cfl_list_is_empty(&miner->lru)) {
        pattern = cfl_list_entry_last(&miner->lru, struct adaptive_pattern, _lru);
        pattern_remove(miner, pattern);
    }

    if (miner->root) {
        flb_free(miner->root->keys);
        flb_free(miner->root->children);
        flb_free(miner->root);
    }
    flb_free(miner->tokens);
    flb_free(miner->scratch);
    flb_free(miner);
}
