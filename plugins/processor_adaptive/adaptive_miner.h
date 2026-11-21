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

#ifndef FLB_PROCESSOR_ADAPTIVE_MINER_H
#define FLB_PROCESSOR_ADAPTIVE_MINER_H

#include <fluent-bit/flb_info.h>
#include <cfl/cfl.h>

#include <stdint.h>
#include <stddef.h>

#define ADAPTIVE_WILDCARD            "<*>"
#define ADAPTIVE_TRUNCATED           "<...>"

#define ADAPTIVE_DEPTH_MIN           3
#define ADAPTIVE_DEPTH_MAX           16
#define ADAPTIVE_TOKENS_MIN          4
#define ADAPTIVE_TOKENS_MAX          256
#define ADAPTIVE_EXEMPLAR_MAX        256
#define ADAPTIVE_KEY_MAX             64

struct adaptive_node;
struct adaptive_policy_entry;

/* Transient token produced by the tokenizer, valid until the next call */
struct adaptive_token {
    const char *str;
    int len;
    int masked;                 /* the whole token is a variable        */
    int key_len;                /* bytes of a leading 'key=' or 'key:'  */
    int key_hash_ready;
    uint64_t key_hash;          /* hash of the key followed by <*>      */
    uint64_t hash;
};

/*
 * A pattern is a log template plus the accounting and decision state attached
 * to it. The miner owns the template, the policy engine owns the window and
 * sampling fields.
 */
struct adaptive_pattern {
    uint64_t id;                /* hash of the template text            */
    uint64_t serial;            /* creation order, stable per process   */
    int token_count;
    int truncated;              /* source had more than max_tokens      */
    int wildcards;              /* generic wildcard positions           */
    int key_wildcards;          /* has positions shaped as key=<*>      */
    const char *group;          /* partition name, owned by the group   */
    char **tokens;
    uint64_t *hashes;
    cfl_sds_t template_str;
    cfl_sds_t exemplar;
    uint64_t generation;        /* bumped when the template changes     */

    /* lifetime accounting */
    uint64_t count;
    uint64_t bytes;
    uint64_t kept;
    uint64_t dropped;
    uint64_t bytes_dropped;
    uint64_t protected_count;
    uint64_t first_seen;
    uint64_t last_seen;

    /* decision window state */
    uint64_t window_id;
    uint64_t win_count;
    uint64_t win_kept;
    uint64_t prev_count;
    uint32_t rate;              /* 1 keeps all, 0 drops all, N is 1/N   */
    uint64_t sample_seq;
    uint64_t suppressed;        /* dropped since the last kept record   */

    /* lifetime values at the time of the last summary */
    uint64_t sum_count;
    uint64_t sum_kept;
    uint64_t sum_dropped;
    uint64_t sum_bytes_dropped;

    /* policy binding */
    uint64_t policy_generation;
    uint64_t policy_template_generation;
    struct adaptive_policy_entry *policy;
    double policy_acc;

    struct adaptive_node *leaf;
    struct cfl_list _head;      /* link to the leaf pattern list        */
    struct cfl_list _lru;       /* link to the miner recency list       */
};

struct adaptive_miner {
    double similarity;
    int depth;
    int max_children;
    int max_tokens;
    int max_patterns;

    struct adaptive_node *root;
    struct cfl_list lru;        /* most recently used first             */
    int pattern_count;
    uint64_t wildcard_hash;
    uint64_t next_serial;

    /* counters */
    uint64_t created;
    uint64_t merged;
    uint64_t evicted;
    uint64_t expired;

    /* partition this miner serves and a hook for patterns about to go */
    const char *group;
    void (*cb_remove) (struct adaptive_pattern *pattern, void *data);
    void *cb_remove_data;

    /* scratch space reused by the tokenizer */
    struct adaptive_token *tokens;
    char *scratch;
    size_t scratch_size;
};

struct adaptive_miner *adaptive_miner_create(double similarity, int depth,
                                             int max_children, int max_tokens,
                                             int max_patterns);
void adaptive_miner_destroy(struct adaptive_miner *miner);

/*
 * Split a line and mask its variable parts. Returns the number of tokens
 * stored in miner->tokens or -1 on error.
 */
int adaptive_miner_tokenize(struct adaptive_miner *miner,
                            const char *line, size_t len, int *truncated);

/*
 * Find or create the pattern for a line. 'is_new' is set when the pattern was
 * created by this call and 'changed' when its template was generalized.
 */
struct adaptive_pattern *adaptive_miner_process(struct adaptive_miner *miner,
                                                const char *line, size_t len,
                                                uint64_t now,
                                                int *is_new, int *changed);

/* Remove patterns not seen since 'older_than'. Returns the number removed. */
int adaptive_miner_expire(struct adaptive_miner *miner, uint64_t older_than);

/*
 * Saving and restoring patterns. The path is the list of tree keys from the
 * root down to the leaf that holds the pattern: restoring with the same path
 * puts the pattern where new lines will look for it, as long as the miner
 * settings are the same.
 */
int adaptive_miner_pattern_path(struct adaptive_miner *miner,
                                struct adaptive_pattern *pattern,
                                uint64_t *path, int size);
struct adaptive_pattern *adaptive_miner_restore(struct adaptive_miner *miner,
                                                uint64_t *path, int path_count,
                                                const char **tokens, int *lens,
                                                int token_count, int truncated,
                                                int key_wildcards);

#endif
