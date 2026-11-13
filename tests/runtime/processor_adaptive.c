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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_processor.h>

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "flb_tests_runtime.h"
#include "../../plugins/processor_adaptive/adaptive_miner.h"
#include "../../plugins/processor_adaptive/adaptive_policy.h"

#define SECOND  1000000000ULL
#define T0      (1700000000ULL * SECOND)

/* ---------------------------------------------------------------- miner */

static struct adaptive_pattern *mine(struct adaptive_miner *miner, const char *line)
{
    int is_new;
    int changed;

    return adaptive_miner_process(miner, line, strlen(line), T0, &is_new, &changed);
}

/* Each line gets its own miner so that lines cannot merge with each other */
static void check_template(const char *line, const char *expected)
{
    struct adaptive_miner *miner;
    struct adaptive_pattern *pattern;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    if (!TEST_CHECK(miner != NULL)) {
        return;
    }

    pattern = mine(miner, line);
    if (TEST_CHECK(pattern != NULL) &&
        !TEST_CHECK(strcmp(pattern->template_str, expected) == 0)) {
        TEST_MSG("line:     %s", line);
        TEST_MSG("expected: %s", expected);
        TEST_MSG("got:      %s", pattern->template_str);
    }

    adaptive_miner_destroy(miner);
}

static void test_miner_masking()
{
    check_template("took 35 retries", "took <NUM> retries");
    check_template("load -1.5 now", "load <NUM> now");
    check_template("GET /a done in 35ms", "GET /a done in <NUM>ms");
    check_template("cpu at 97% busy", "cpu at <NUM>% busy");
    check_template("peer 10.1.2.3 up", "peer <IP> up");
    check_template("peer 10.1.2.3:8080 down", "peer <IP> down");
    check_template("net 10.0.0.0/8 added", "net <IP> added");
    check_template("req 3f2b8c1e-9a4d-4e7b-8c21-7d4e5f6a8b90 ok",
                   "req <UUID> ok");
    check_template("ptr 0x7ffdeadbeef freed", "ptr <HEX> freed");
    check_template("commit 9fceb02d0ae598e9 merged", "commit <HEX> merged");
    check_template("pod web-7d9f8 started", "pod <*> started");
    check_template("status=200 path=/x", "status=<NUM> path=/x");
    check_template("user=\"u123\" ok", "user=\"<*>\" ok");
    check_template("connect api.example.com:443 failed",
                   "connect <*>:<NUM> failed");
    check_template("code (404), retry [3]", "code (<NUM>), retry [<NUM>]");
    check_template("plain words only here", "plain words only here");
    /* literals that only look variable stay untouched */
    check_template("word deadbeef kept", "word deadbeef kept");
    /* whitespace is normalized */
    check_template("  two\tspaces   here \n", "two spaces here");
    check_template("", "");
}

static void test_miner_grouping()
{
    struct adaptive_miner *miner;
    struct adaptive_pattern *a;
    struct adaptive_pattern *b;
    struct adaptive_pattern *c;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    TEST_CHECK(miner != NULL);

    /* same shape, different numbers: one pattern, no generalization */
    a = mine(miner, "GET /api/users/17 200 took 12ms");
    b = mine(miner, "GET /api/users/99 500 took 734ms");
    TEST_CHECK(a == b);
    TEST_CHECK(miner->pattern_count == 1);
    TEST_CHECK(miner->merged == 0);

    /* a differing word past the routing prefix becomes a wildcard */
    a = mine(miner, "session opened for alice by root");
    TEST_CHECK(strcmp(a->template_str, "session opened for alice by root") == 0);
    b = mine(miner, "session opened for bob by root");
    TEST_CHECK(a == b);
    TEST_CHECK(strcmp(a->template_str, "session opened for <*> by root") == 0);
    TEST_CHECK(a->wildcards == 1);
    TEST_CHECK(miner->merged == 1);

    /* the id follows the template text */
    c = mine(miner, "session opened for carol by root");
    TEST_CHECK(c == a);
    TEST_CHECK(miner->merged == 1);
    TEST_CHECK(a->id == cfl_hash_64bits("session opened for <*> by root", 30));

    /* different token count never shares a pattern */
    c = mine(miner, "session opened for carol by root again");
    TEST_CHECK(c != a);

    /* too different: below the similarity threshold */
    c = mine(miner, "session closed with error code EPIPE");
    TEST_CHECK(c != a);
    TEST_CHECK(miner->pattern_count == 4);

    adaptive_miner_destroy(miner);
}

static void test_miner_truncation()
{
    int i;
    char line[2048];
    size_t off = 0;
    struct adaptive_miner *miner;
    struct adaptive_pattern *a;
    struct adaptive_pattern *b;

    miner = adaptive_miner_create(0.5, 4, 100, 8, 100);
    TEST_CHECK(miner != NULL);

    for (i = 0; i < 20; i++) {
        off += snprintf(line + off, sizeof(line) - off, "w%c ", 'a' + i);
    }
    a = mine(miner, line);
    TEST_CHECK(a->token_count == 8);
    TEST_CHECK(a->truncated == FLB_TRUE);
    TEST_CHECK(strcmp(a->template_str, "wa wb wc wd we wf wg wh <...>") == 0);

    /* a line with exactly max_tokens is a different pattern */
    b = mine(miner, "wa wb wc wd we wf wg wh");
    TEST_CHECK(b != a);
    TEST_CHECK(b->truncated == FLB_FALSE);

    adaptive_miner_destroy(miner);
}

static void test_miner_bounds()
{
    int i;
    int is_new;
    int changed;
    char line[128];
    struct adaptive_miner *miner;
    struct adaptive_pattern *first;
    struct adaptive_pattern *pattern;

    TEST_CHECK(adaptive_miner_create(1.5, 4, 100, 64, 100) == NULL);
    TEST_CHECK(adaptive_miner_create(0.5, 2, 100, 64, 100) == NULL);
    TEST_CHECK(adaptive_miner_create(0.5, 4, 0, 64, 100) == NULL);
    TEST_CHECK(adaptive_miner_create(0.5, 4, 100, 2, 100) == NULL);
    TEST_CHECK(adaptive_miner_create(0.5, 4, 100, 64, 0) == NULL);

    /* the pattern cap evicts the least recently used template */
    miner = adaptive_miner_create(0.5, 4, 100, 64, 8);
    TEST_CHECK(miner != NULL);

    first = mine(miner, "alpha event zero");
    for (i = 0; i < 100; i++) {
        snprintf(line, sizeof(line), "%c%c unique shape %c%c", 'a' + i % 26,
                 'a' + (i / 26), 'k' + i % 7, 'a' + i % 26);
        pattern = adaptive_miner_process(miner, line, strlen(line), T0 + i,
                                         &is_new, &changed);
        TEST_CHECK(pattern != NULL);
        TEST_CHECK(miner->pattern_count <= 8);

        /* touching the first pattern keeps it alive */
        pattern = adaptive_miner_process(miner, "alpha event zero", 16, T0 + i,
                                         &is_new, &changed);
        TEST_CHECK(pattern == first);
        TEST_CHECK(is_new == FLB_FALSE);
    }
    TEST_CHECK(miner->pattern_count == 8);
    TEST_CHECK(miner->evicted == miner->created - 8);

    /* expiration removes everything not seen since the cut */
    TEST_CHECK(adaptive_miner_expire(miner, T0 + 99) == 6);
    TEST_CHECK(miner->pattern_count == 2);
    TEST_CHECK(adaptive_miner_expire(miner, T0 + 1000) == 2);
    TEST_CHECK(miner->pattern_count == 0);
    TEST_CHECK(cfl_list_is_empty(&miner->lru));

    /* the tree is still usable after being emptied */
    TEST_CHECK(mine(miner, "alpha event zero") != NULL);
    TEST_CHECK(miner->pattern_count == 1);

    adaptive_miner_destroy(miner);
}

/* A wide node sends new leading tokens to the shared wildcard branch */
static void test_miner_key_wildcard()
{
    struct adaptive_miner *miner;
    struct adaptive_pattern *a;
    struct adaptive_pattern *b;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    TEST_CHECK(miner != NULL);

    /* two values of one key keep the key */
    a = mine(miner, "login ok user=alice from=web");
    b = mine(miner, "login ok user=bob from=web");
    TEST_CHECK(a == b);
    if (!TEST_CHECK(strcmp(a->template_str, "login ok user=<*> from=web") == 0)) {
        TEST_MSG("got: %s", a->template_str);
    }
    TEST_CHECK(a->wildcards == 0);
    TEST_CHECK(miner->merged == 1);

    /* a third value matches the keyed wildcard: nothing changes */
    b = mine(miner, "login ok user=carol from=web");
    TEST_CHECK(a == b);
    TEST_CHECK(miner->merged == 1);
    TEST_CHECK(a->id == cfl_hash_64bits("login ok user=<*> from=web", 26));

    /* a value masked by type matches it as well */
    b = mine(miner, "login ok user=u1234x from=web");
    TEST_CHECK(a == b);
    TEST_CHECK(miner->merged == 1);

    /* a different key at that position is a plain wildcard */
    b = mine(miner, "login ok admin=root from=web");
    TEST_CHECK(a == b);
    if (!TEST_CHECK(strcmp(a->template_str, "login ok <*> from=web") == 0)) {
        TEST_MSG("got: %s", a->template_str);
    }
    TEST_CHECK(miner->pattern_count == 1);

    adaptive_miner_destroy(miner);
}

static int removed_calls;
static uint64_t removed_dropped;

static void cb_removed(struct adaptive_pattern *pattern, void *data)
{
    (void) data;

    removed_calls++;
    removed_dropped += pattern->dropped - pattern->sum_dropped;
}

static void test_miner_remove_hook()
{
    struct adaptive_miner *miner;
    struct adaptive_pattern *a;

    removed_calls = 0;
    removed_dropped = 0;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 1);
    TEST_CHECK(miner != NULL);
    miner->group = "payments";
    miner->cb_remove = cb_removed;

    a = mine(miner, "first pattern here");
    TEST_CHECK(a != NULL && a->group != NULL && strcmp(a->group, "payments") == 0);
    a->dropped = 7;
    a->sum_dropped = 2;

    /* the eviction reports what was not summarized yet */
    mine(miner, "another different line");
    TEST_CHECK(removed_calls == 1);
    TEST_CHECK(removed_dropped == 5);

    adaptive_miner_destroy(miner);
    TEST_CHECK(removed_calls == 2);
}

/* Patterns moved to a fresh miner must be found by the lines that made them */
static void test_miner_restore()
{
    int i;
    int j;
    int is_new;
    int changed;
    int count;
    int restored = 0;
    int lens[64];
    const char *tokens[64];
    uint64_t path[ADAPTIVE_DEPTH_MAX];
    struct cfl_list *head;
    struct adaptive_miner *src;
    struct adaptive_miner *dst;
    struct adaptive_pattern *pattern;
    struct adaptive_pattern *copy;
    const char *lines[] = {
        "GET /api/items/17 200 took 12ms",
        "GET /api/items/18 200 took 7ms",
        "login ok user=alice region=eu",
        "login ok user=bob region=eu",
        "cache miss for session token",
        "cache hit for session token",
        "config reloaded by operator",
        "a b c d e f g h i j k l m n o p q r s t"
    };

    src = adaptive_miner_create(0.5, 4, 100, 16, 100);
    dst = adaptive_miner_create(0.5, 4, 100, 16, 100);
    if (!TEST_CHECK(src != NULL && dst != NULL)) {
        return;
    }

    for (i = 0; i < 8; i++) {
        TEST_CHECK(mine(src, lines[i]) != NULL);
    }

    /* oldest first, the order a saved state uses */
    cfl_list_foreach_r(head, &src->lru) {
        pattern = cfl_list_entry(head, struct adaptive_pattern, _lru);
        count = adaptive_miner_pattern_path(src, pattern, path, ADAPTIVE_DEPTH_MAX);
        if (!TEST_CHECK(count > 0)) {
            continue;
        }
        for (j = 0; j < pattern->token_count; j++) {
            tokens[j] = pattern->tokens[j];
            lens[j] = strlen(pattern->tokens[j]);
        }

        copy = adaptive_miner_restore(dst, path, count, tokens, lens, pattern->token_count,
                                      pattern->truncated, pattern->key_wildcards);
        if (!TEST_CHECK(copy != NULL)) {
            continue;
        }
        TEST_CHECK(copy->id == pattern->id);
        TEST_CHECK(copy->wildcards == pattern->wildcards);
        TEST_CHECK(strcmp(copy->template_str, pattern->template_str) == 0);
        restored++;
    }

    TEST_CHECK(restored == src->pattern_count);
    TEST_CHECK(dst->pattern_count == src->pattern_count);
    TEST_CHECK(dst->created == 0);

    /* same recency order */
    pattern = cfl_list_entry_first(&src->lru, struct adaptive_pattern, _lru);
    copy = cfl_list_entry_first(&dst->lru, struct adaptive_pattern, _lru);
    TEST_CHECK(copy->id == pattern->id);

    /* known lines, and new values of the same shapes, create nothing */
    for (i = 0; i < 8; i++) {
        pattern = adaptive_miner_process(dst, lines[i], strlen(lines[i]), T0,
                                         &is_new, &changed);
        TEST_CHECK(pattern != NULL && !is_new && !changed);
    }
    pattern = adaptive_miner_process(dst, "login ok user=carol region=eu", 29, T0,
                                     &is_new, &changed);
    TEST_CHECK(pattern != NULL && !is_new && !changed);
    TEST_CHECK(dst->pattern_count == src->pattern_count);

    /* a path that does not fit the tokens or the tree is refused */
    tokens[0] = "one";
    lens[0] = 3;
    path[0] = 2;
    TEST_CHECK(adaptive_miner_restore(dst, path, 1, tokens, lens, 1, 0, 0) == NULL);
    path[0] = 1;
    TEST_CHECK(adaptive_miner_restore(dst, path, 9, tokens, lens, 1, 0, 0) == NULL);
    TEST_CHECK(adaptive_miner_restore(dst, path, 1, tokens, lens, 17, 0, 0) == NULL);
    TEST_CHECK(dst->pattern_count == src->pattern_count);

    /* a smaller miner keeps the most recent patterns */
    adaptive_miner_destroy(dst);
    dst = adaptive_miner_create(0.5, 4, 100, 16, 2);
    if (TEST_CHECK(dst != NULL)) {
        cfl_list_foreach_r(head, &src->lru) {
            pattern = cfl_list_entry(head, struct adaptive_pattern, _lru);
            count = adaptive_miner_pattern_path(src, pattern, path, ADAPTIVE_DEPTH_MAX);
            for (j = 0; j < pattern->token_count; j++) {
                tokens[j] = pattern->tokens[j];
                lens[j] = strlen(pattern->tokens[j]);
            }
            adaptive_miner_restore(dst, path, count, tokens, lens, pattern->token_count,
                                   pattern->truncated, pattern->key_wildcards);
        }
        TEST_CHECK(dst->pattern_count == 2);
        pattern = cfl_list_entry_first(&src->lru, struct adaptive_pattern, _lru);
        copy = cfl_list_entry_first(&dst->lru, struct adaptive_pattern, _lru);
        TEST_CHECK(copy->id == pattern->id);
        adaptive_miner_destroy(dst);
    }

    adaptive_miner_destroy(src);
}

static void test_miner_max_children()
{
    int i;
    char line[64];
    struct adaptive_miner *miner;

    miner = adaptive_miner_create(0.5, 4, 4, 64, 1000);
    TEST_CHECK(miner != NULL);

    for (i = 0; i < 26; i++) {
        snprintf(line, sizeof(line), "%cx job finished cleanly today", 'a' + i);
        TEST_CHECK(mine(miner, line) != NULL);
    }

    /* 4 literal branches keep their own pattern, the other 22 share one */
    TEST_CHECK(miner->pattern_count == 5);

    adaptive_miner_destroy(miner);
}

/* --------------------------------------------------------------- policy */

struct tally {
    uint64_t kept;
    uint64_t dropped;
    uint64_t suppressed;
    uint64_t by_reason[2][ADAPTIVE_REASON_COUNT];
};

static void feed(struct adaptive_policy *policy, struct adaptive_pattern *pattern,
                 int count, size_t bytes, uint64_t now, int is_protected,
                 struct tally *tally)
{
    int i;
    struct adaptive_decision decision;

    for (i = 0; i < count; i++) {
        adaptive_policy_decide(policy, pattern, bytes, now, is_protected, &decision);
        tally->by_reason[decision.action][decision.reason]++;
        if (decision.action == ADAPTIVE_KEEP) {
            tally->kept++;
            tally->suppressed += decision.suppressed;
        }
        else {
            tally->dropped++;
        }
    }
}

static void test_policy_allowance_and_sampling()
{
    struct tally tally;
    struct adaptive_miner *miner;
    struct adaptive_policy *policy;
    struct adaptive_pattern *pattern;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    policy = adaptive_policy_create(10, 5, 30, ADAPTIVE_SAMPLE_LOG, 100, 0);
    TEST_CHECK(miner != NULL && policy != NULL);
    pattern = mine(miner, "heartbeat ok");

    /* below min_events nothing is sampled */
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 20, 12, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 20);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_ALLOWANCE] == 5);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_LOW_VOLUME] == 15);

    /* a flood is re-rated inside its first window, at each doubling */
    feed(policy, pattern, 980, 12, T0, FLB_FALSE, &tally);
    TEST_CHECK(pattern->win_count == 1000);
    TEST_CHECK(pattern->rate == 7);         /* ceil(ln(512)) */
    TEST_CHECK(tally.dropped > 700);
    TEST_CHECK(tally.kept + tally.dropped == 1000);

    /* next window: 1000 events seen before, rate is ceil(ln(1000)) = 7 */
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 705, 12, T0 + 10 * SECOND, FLB_FALSE, &tally);
    TEST_CHECK(pattern->prev_count == 1000);
    TEST_CHECK(pattern->rate == 7);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_ALLOWANCE] == 5);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_SAMPLED] == 100);
    TEST_CHECK(tally.by_reason[ADAPTIVE_DROP][ADAPTIVE_REASON_SAMPLED] == 600);

    /* an idle gap forgets the previous volume */
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 20, 12, T0 + 50 * SECOND, FLB_FALSE, &tally);
    TEST_CHECK(pattern->prev_count == 0);
    TEST_CHECK(tally.kept == 20);

    adaptive_policy_destroy(policy);
    adaptive_miner_destroy(miner);
}

static void test_policy_modes()
{
    struct tally tally;
    struct adaptive_miner *miner;
    struct adaptive_policy *policy;
    struct adaptive_pattern *pattern;

    TEST_CHECK(adaptive_policy_sample_mode("LOG") == ADAPTIVE_SAMPLE_LOG);
    TEST_CHECK(adaptive_policy_sample_mode("sqrt") == ADAPTIVE_SAMPLE_SQRT);
    TEST_CHECK(adaptive_policy_sample_mode("suppress") == ADAPTIVE_SAMPLE_SUPPRESS);
    TEST_CHECK(adaptive_policy_sample_mode("off") == ADAPTIVE_SAMPLE_OFF);
    TEST_CHECK(adaptive_policy_sample_mode("random") == -1);
    TEST_CHECK(adaptive_policy_create(0, 5, 30, ADAPTIVE_SAMPLE_LOG, 100, 0) == NULL);
    TEST_CHECK(adaptive_policy_create(10, -1, 30, ADAPTIVE_SAMPLE_LOG, 100, 0) == NULL);
    TEST_CHECK(adaptive_policy_create(10, 5, 30, ADAPTIVE_SAMPLE_LOG, 0, 0) == NULL);

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    pattern = mine(miner, "heartbeat ok");

    /* suppress: exactly the allowance per window */
    policy = adaptive_policy_create(10, 3, 30, ADAPTIVE_SAMPLE_SUPPRESS, 100, 0);
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 500, 12, T0, FLB_FALSE, &tally);
    feed(policy, pattern, 500, 12, T0 + 10 * SECOND, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 6);
    TEST_CHECK(tally.dropped == 994);
    adaptive_policy_destroy(policy);

    /* off: nothing is dropped automatically */
    pattern = mine(miner, "second pattern here");
    policy = adaptive_policy_create(10, 3, 30, ADAPTIVE_SAMPLE_OFF, 100, 0);
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 5000, 12, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 5000);
    adaptive_policy_destroy(policy);

    /* sqrt is capped by max_sample_rate */
    pattern = mine(miner, "third pattern over here");
    policy = adaptive_policy_create(10, 0, 30, ADAPTIVE_SAMPLE_SQRT, 50, 0);
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 100000, 12, T0, FLB_FALSE, &tally);
    TEST_CHECK(pattern->rate == 50);
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 100000, 12, T0 + 10 * SECOND, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 2000);
    TEST_CHECK(tally.dropped == 98000);
    adaptive_policy_destroy(policy);

    adaptive_miner_destroy(miner);
}

/* Every dropped record is reported by a later kept record of its pattern */
static void test_policy_accounting()
{
    int i;
    uint64_t now = T0;
    struct tally tally;
    struct adaptive_miner *miner;
    struct adaptive_policy *policy;
    struct adaptive_pattern *pattern;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    policy = adaptive_policy_create(5, 2, 10, ADAPTIVE_SAMPLE_SQRT, 100, 0);
    pattern = mine(miner, "noisy line");

    memset(&tally, 0, sizeof(tally));
    for (i = 0; i < 400; i++) {
        feed(policy, pattern, 137, 10, now, FLB_FALSE, &tally);
        now += SECOND;
    }

    TEST_CHECK(tally.kept + tally.dropped == 400 * 137);
    TEST_CHECK(tally.dropped > tally.kept);
    TEST_CHECK(tally.suppressed + pattern->suppressed == tally.dropped);
    TEST_CHECK(pattern->count == 400 * 137);
    TEST_CHECK(pattern->kept == tally.kept);
    TEST_CHECK(pattern->dropped == tally.dropped);
    TEST_CHECK(pattern->bytes == 400 * 137 * 10);
    TEST_CHECK(pattern->bytes_dropped == tally.dropped * 10);

    adaptive_policy_destroy(policy);
    adaptive_miner_destroy(miner);
}

static void test_policy_protected_and_budget()
{
    struct tally tally;
    struct adaptive_decision decision;
    struct adaptive_miner *miner;
    struct adaptive_policy *policy;
    struct adaptive_pattern *noisy;
    struct adaptive_pattern *quiet;

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    policy = adaptive_policy_create(10, 0, 30, ADAPTIVE_SAMPLE_SUPPRESS, 100, 1000);
    noisy = mine(miner, "noisy line");
    quiet = mine(miner, "quiet line of another shape");

    /* protected records ignore sampling and the budget */
    memset(&tally, 0, sizeof(tally));
    feed(policy, noisy, 500, 100, T0, FLB_TRUE, &tally);
    TEST_CHECK(tally.kept == 500);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_PROTECTED] == 500);
    TEST_CHECK(noisy->protected_count == 500);
    adaptive_policy_destroy(policy);

    /* budget: 1000 bytes per window, 100 bytes per record */
    policy = adaptive_policy_create(10, 0, 30, ADAPTIVE_SAMPLE_OFF, 100, 1000);
    noisy = mine(miner, "budget line");
    memset(&tally, 0, sizeof(tally));
    feed(policy, noisy, 50, 100, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 10);
    TEST_CHECK(tally.by_reason[ADAPTIVE_DROP][ADAPTIVE_REASON_BUDGET] == 40);

    /* a pattern not seen yet in the window still gets one record through */
    adaptive_policy_decide(policy, quiet, 100, T0, FLB_FALSE, &decision);
    TEST_CHECK(decision.action == ADAPTIVE_KEEP);
    TEST_CHECK(decision.reason == ADAPTIVE_REASON_EXEMPLAR);
    adaptive_policy_decide(policy, quiet, 100, T0, FLB_FALSE, &decision);
    TEST_CHECK(decision.action == ADAPTIVE_DROP);
    TEST_CHECK(decision.reason == ADAPTIVE_REASON_BUDGET);

    /* the budget is restored by the next window */
    memset(&tally, 0, sizeof(tally));
    feed(policy, noisy, 50, 100, T0 + 10 * SECOND, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 10);

    adaptive_policy_destroy(policy);
    adaptive_miner_destroy(miner);
}

static void test_policy_file_rules()
{
    int ret;
    struct tally tally;
    struct adaptive_miner *miner;
    struct adaptive_policy *policy;
    struct adaptive_pattern *get;
    struct adaptive_pattern *login;
    struct adaptive_pattern *other;
    char by_id[128];
    const char *rules =
        "{\"patterns\":["
        "{\"template\":\"GET <*> took <NUM>ms\",\"drop_rate\":0.9},"
        "{\"template\":\"login <*> from <*>\",\"drop_rate\":1},"
        "{\"template\":\"GET <*> took <NUM>ms\",\"drop_rate\":0.0}"
        "]}";

    miner = adaptive_miner_create(0.5, 4, 100, 64, 100);
    policy = adaptive_policy_create(10, 5, 30, ADAPTIVE_SAMPLE_OFF, 100, 0);

    ret = adaptive_policy_load_buffer(policy, rules, strlen(rules));
    TEST_CHECK(ret == ADAPTIVE_POLICY_LOADED);
    TEST_CHECK(policy->entry_count == 3);

    /* the local template is more specific than the rule and still matches */
    get = mine(miner, "GET /index took 12ms");
    TEST_CHECK(strcmp(get->template_str, "GET /index took <NUM>ms") == 0);
    memset(&tally, 0, sizeof(tally));
    feed(policy, get, 1000, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 100);
    TEST_CHECK(tally.dropped == 900);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_POLICY] == 100);
    TEST_CHECK(get->policy != NULL && get->policy->drop_rate == 0.9);

    /* drop rate 1 removes everything that is not protected */
    login = mine(miner, "login alice from console");
    memset(&tally, 0, sizeof(tally));
    feed(policy, login, 50, 20, T0, FLB_FALSE, &tally);
    feed(policy, login, 5, 20, T0, FLB_TRUE, &tally);
    TEST_CHECK(tally.dropped == 50);
    TEST_CHECK(tally.kept == 5);

    /* patterns without a rule keep the automatic behaviour */
    other = mine(miner, "something else entirely happened");
    memset(&tally, 0, sizeof(tally));
    feed(policy, other, 50, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 50);
    TEST_CHECK(other->policy == NULL);

    /* a rule can target the pattern id, a new policy replaces the old one */
    snprintf(by_id, sizeof(by_id),
             "{\"patterns\":[{\"id\":\"%016" PRIx64 "\",\"drop_rate\":0.5}]}", other->id);
    ret = adaptive_policy_load_buffer(policy, by_id, strlen(by_id));
    TEST_CHECK(ret == ADAPTIVE_POLICY_LOADED);
    memset(&tally, 0, sizeof(tally));
    feed(policy, other, 100, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 50);
    memset(&tally, 0, sizeof(tally));
    feed(policy, get, 100, 20, T0 + 10 * SECOND, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 100);
    TEST_CHECK(get->policy == NULL);

    /* an empty list is valid and clears the rules */
    ret = adaptive_policy_load_buffer(policy, "{\"patterns\":[]}", 15);
    TEST_CHECK(ret == ADAPTIVE_POLICY_LOADED);
    TEST_CHECK(policy->entry_count == 0);

    adaptive_policy_destroy(policy);
    adaptive_miner_destroy(miner);
}

static void test_policy_file_groups()
{
    const char *doc =
        "{\"patterns\":["
        "{\"group\":\"payments\",\"template\":\"ping from <*>\",\"drop_rate\":1},"
        "{\"template\":\"login user=<*> ok\",\"drop_rate\":1}]}";
    struct adaptive_miner *payments;
    struct adaptive_miner *search;
    struct adaptive_policy *policy;
    struct adaptive_pattern *pattern;
    struct tally tally;

    payments = adaptive_miner_create(0.5, 4, 100, 64, 100);
    search = adaptive_miner_create(0.5, 4, 100, 64, 100);
    policy = adaptive_policy_create(30, 1000, 0, ADAPTIVE_SAMPLE_OFF, 100, 0);
    TEST_CHECK(payments != NULL && search != NULL && policy != NULL);
    payments->group = "payments";
    search->group = "search";

    TEST_CHECK(adaptive_policy_load_buffer(policy, doc, strlen(doc)) == ADAPTIVE_POLICY_LOADED);
    TEST_CHECK(policy->entry_count == 2);

    /* the rule with a group only applies inside it */
    pattern = mine(payments, "ping from gateway");
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 10, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.dropped == 10);
    TEST_CHECK(tally.by_reason[ADAPTIVE_DROP][ADAPTIVE_REASON_POLICY] == 10);

    pattern = mine(search, "ping from gateway");
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 10, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 10);
    TEST_CHECK(tally.by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_POLICY] == 0);

    /* a rule without a group applies everywhere, key=<*> covers a value */
    pattern = mine(search, "login user=alice ok");
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 10, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.dropped == 10);

    pattern = mine(payments, "login user=bob ok");
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 10, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.dropped == 10);

    pattern = mine(payments, "login admin=bob ok");
    memset(&tally, 0, sizeof(tally));
    feed(policy, pattern, 10, 20, T0, FLB_FALSE, &tally);
    TEST_CHECK(tally.kept == 10);

    adaptive_policy_destroy(policy);
    adaptive_miner_destroy(payments);
    adaptive_miner_destroy(search);
}

static void test_policy_file_invalid()
{
    int i;
    int ret;
    struct adaptive_policy *policy;
    const char *good = "{\"patterns\":[{\"template\":\"a b\",\"drop_rate\":0.25}]}";
    const char *bad[] = {
        "",
        "not json",
        "[]",
        "{}",
        "{\"patterns\":{}}",
        "{\"patterns\":[42]}",
        "{\"patterns\":[{\"template\":\"a b\"}]}",
        "{\"patterns\":[{\"drop_rate\":0.5}]}",
        "{\"patterns\":[{\"template\":\"a b\",\"drop_rate\":1.5}]}",
        "{\"patterns\":[{\"template\":\"a b\",\"drop_rate\":-0.5}]}",
        "{\"patterns\":[{\"template\":\"a b\",\"drop_rate\":\"high\"}]}",
        "{\"patterns\":[{\"id\":\"nothex\",\"drop_rate\":0.5}]}",
        "{\"patterns\":[{\"id\":\"00112233445566778899\",\"drop_rate\":0.5}]}",
        "{\"patterns\":[{\"template\":\"a b\",\"drop_rate\":0.5},{\"template\":7}]}",
        NULL
    };

    policy = adaptive_policy_create(10, 5, 30, ADAPTIVE_SAMPLE_LOG, 100, 0);
    ret = adaptive_policy_load_buffer(policy, good, strlen(good));
    TEST_CHECK(ret == ADAPTIVE_POLICY_LOADED);
    TEST_CHECK(policy->generation == 2);

    /* a rejected document leaves the previous policy untouched */
    for (i = 0; bad[i] != NULL; i++) {
        ret = adaptive_policy_load_buffer(policy, bad[i], strlen(bad[i]));
        if (!TEST_CHECK(ret == ADAPTIVE_POLICY_ERROR)) {
            TEST_MSG("accepted: %s", bad[i]);
        }
        TEST_CHECK(policy->entry_count == 1);
        TEST_CHECK(policy->generation == 2);
    }

    adaptive_policy_destroy(policy);
}

/* ----------------------------------------------------------- end to end */

struct sink {
    pthread_mutex_t lock;
    int records;
    int errors;
    int annotated;
    int would_drop;
    int64_t suppressed;
    int with_template;
    int maps;
    int summaries;
    int64_t summary_dropped;
    int64_t summary_count;
    int events;
    int msgs;
    int svc_b;
    int group_b;
};

static int64_t sum_field(const char *haystack, const char *field)
{
    int64_t total = 0;
    size_t len = strlen(field);
    const char *p = haystack;

    while ((p = strstr(p, field)) != NULL) {
        p += len;
        total += strtoll(p, NULL, 10);
    }

    return total;
}

static int count_substr(const char *haystack, const char *needle)
{
    int count = 0;
    size_t len = strlen(needle);
    const char *p = haystack;

    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += len;
    }

    return count;
}

static int cb_sink(void *record, size_t size, void *data)
{
    char *p;
    struct sink *sink = data;

    (void) size;

    pthread_mutex_lock(&sink->lock);
    sink->records += count_substr(record, "\"log\":");
    sink->errors += count_substr(record, "\"level\":\"error\"");
    sink->annotated += count_substr(record, "\"pattern_id\":\"");
    sink->would_drop += count_substr(record, "\"decision\":\"drop\"");
    sink->with_template += count_substr(record, "\"template\":\"");
    sink->maps += count_substr(record, "\"adaptive\":{");
    sink->summaries += count_substr(record, "\"summary\":true");
    sink->summary_dropped += sum_field(record, "\"dropped\":");
    sink->summary_count += sum_field(record, "\"count\":");
    sink->events += count_substr(record, "\"event\":");
    sink->msgs += count_substr(record, "\"msg\":");
    sink->svc_b += count_substr(record, "\"svc\":\"b\"");
    sink->group_b += count_substr(record, "\"group\":\"b\"");

    p = record;
    while ((p = strstr(p, "\"suppressed\":")) != NULL) {
        p += 13;
        sink->suppressed += strtoll(p, NULL, 10);
    }
    pthread_mutex_unlock(&sink->lock);

    flb_free(record);
    return 0;
}

struct pipeline {
    flb_ctx_t *flb;
    int i_ffd;
    int o_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb;
    struct sink sink;
};

/* The end to end tests run on the fast path unless this is cleared */
static int pipeline_fast_path = FLB_TRUE;

static int pipeline_create(struct pipeline *p, int on_output)
{
    int ret;

    memset(p, 0, sizeof(struct pipeline));
    pthread_mutex_init(&p->sink.lock, NULL);
    p->cb.cb = cb_sink;
    p->cb.data = &p->sink;

    p->flb = flb_create();
    flb_service_set(p->flb, "Flush", "0.200000000", "Grace", "1",
                    "Log_Level", "error", NULL);

    p->proc = flb_processor_create(p->flb->config, "unit_test", NULL, 0);
    if (!TEST_CHECK(p->proc != NULL)) {
        return -1;
    }

    p->i_ffd = flb_input(p->flb, (char *) "lib", NULL);
    TEST_CHECK(p->i_ffd >= 0);
    flb_input_set(p->flb, p->i_ffd, "tag", "test", NULL);

    p->o_ffd = flb_output(p->flb, (char *) "lib", (void *) &p->cb);
    TEST_CHECK(p->o_ffd >= 0);
    flb_output_set(p->flb, p->o_ffd, "match", "test", "format", "json", NULL);

    p->pu = flb_processor_unit_create(p->proc, FLB_PROCESSOR_LOGS, "adaptive");
    if (!TEST_CHECK(p->pu != NULL)) {
        return -1;
    }
    if (!pipeline_fast_path) {
        TEST_CHECK(flb_processor_unit_set_property_str(p->pu, "fast_path", "false") == 0);
    }

    if (on_output) {
        ret = flb_output_set_processor(p->flb, p->o_ffd, p->proc);
    }
    else {
        ret = flb_input_set_processor(p->flb, p->i_ffd, p->proc);
    }
    TEST_CHECK(ret == 0);

    return ret;
}

static void pipeline_set(struct pipeline *p, const char *key, const char *value)
{
    int ret;

    ret = flb_processor_unit_set_property_str(p->pu, key, value);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cannot set %s=%s", key, value);
    }
}

static void pipeline_push(struct pipeline *p, int noisy, int errors, int rare)
{
    int i;
    int len;
    char buf[256];

    for (i = 0; i < noisy; i++) {
        len = snprintf(buf, sizeof(buf),
                       "[%d, {\"level\":\"info\",\"log\":\"GET /api/items/%d 200 took %dms\"}]",
                       1700000000 + i, i, i % 97);
        TEST_CHECK(flb_lib_push(p->flb, p->i_ffd, buf, len) == len);
    }
    for (i = 0; i < errors; i++) {
        len = snprintf(buf, sizeof(buf),
                       "[%d, {\"level\":\"error\",\"log\":\"GET /api/items/%d 500 took %dms\"}]",
                       1700000000 + i, i, i % 97);
        TEST_CHECK(flb_lib_push(p->flb, p->i_ffd, buf, len) == len);
    }
    for (i = 0; i < rare; i++) {
        len = snprintf(buf, sizeof(buf),
                       "[%d, {\"level\":\"info\",\"log\":\"config reloaded by operator\"}]",
                       1700000000 + i);
        TEST_CHECK(flb_lib_push(p->flb, p->i_ffd, buf, len) == len);
    }
}

static void pipeline_destroy(struct pipeline *p)
{
    flb_time_msleep(1500);
    flb_stop(p->flb);
    flb_destroy(p->flb);
    pthread_mutex_destroy(&p->sink.lock);
}

static void run_enforce(int on_output)
{
    struct pipeline p;

    if (pipeline_create(&p, on_output) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate_pattern_id", "true");
    TEST_CHECK(flb_start(p.flb) == 0);

    pipeline_push(&p, 500, 20, 3);
    pipeline_destroy(&p);

    /* 5 of the noisy pattern, every error, every rare line */
    if (!TEST_CHECK(p.sink.records == 5 + 20 + 3)) {
        TEST_MSG("records delivered: %d", p.sink.records);
    }
    TEST_CHECK(p.sink.errors == 20);
    TEST_CHECK(p.sink.annotated == p.sink.records);
    TEST_CHECK(p.sink.would_drop == 0);
    /* the errors arrive after the flood and report what was suppressed */
    if (!TEST_CHECK(p.sink.suppressed == 495)) {
        TEST_MSG("suppressed reported: %" PRId64, p.sink.suppressed);
    }
}

static void test_e2e_enforce_input()
{
    run_enforce(FLB_FALSE);
}

static void test_e2e_enforce_output()
{
    run_enforce(FLB_TRUE);
}

static void test_e2e_observe()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "mode", "observe");
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate_template", "true");
    TEST_CHECK(flb_start(p.flb) == 0);

    pipeline_push(&p, 500, 20, 3);
    pipeline_destroy(&p);

    /* nothing is removed, the would-be drops are marked */
    TEST_CHECK(p.sink.records == 523);
    TEST_CHECK(p.sink.would_drop == 495);
    TEST_CHECK(p.sink.annotated == 0);
    TEST_CHECK(p.sink.with_template == 523);
}

/* By default only the records that stand for dropped ones are touched */
static void test_e2e_lean_annotation()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    TEST_CHECK(flb_start(p.flb) == 0);

    pipeline_push(&p, 500, 20, 3);
    pipeline_destroy(&p);

    TEST_CHECK(p.sink.records == 28);
    TEST_CHECK(p.sink.annotated == 0);
    TEST_CHECK(p.sink.with_template == 0);
    /* one record reports the 495 drops, the other 27 carry no map at all */
    TEST_CHECK(p.sink.suppressed == 495);
    if (!TEST_CHECK(p.sink.maps == 1)) {
        TEST_MSG("annotation maps: %d", p.sink.maps);
    }
}

static void test_e2e_no_annotation_and_missing_key()
{
    int i;
    int len;
    char buf[128];
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "1");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate", "false");
    pipeline_set(&p, "key", "message");
    pipeline_set(&p, "structured", "false");
    TEST_CHECK(flb_start(p.flb) == 0);

    /* with 'structured' off, records without the key pass untouched */
    pipeline_push(&p, 50, 0, 0);
    /* a non string value under the key passes too */
    for (i = 0; i < 10; i++) {
        len = snprintf(buf, sizeof(buf), "[%d, {\"log\":\"x\",\"message\":%d}]",
                       1700000000 + i, i);
        TEST_CHECK(flb_lib_push(p.flb, p.i_ffd, buf, len) == len);
    }
    /* records with the key are reduced */
    for (i = 0; i < 40; i++) {
        len = snprintf(buf, sizeof(buf),
                       "[%d, {\"log\":\"x\",\"message\":\"tick %d\"}]", 1700000000 + i, i);
        TEST_CHECK(flb_lib_push(p.flb, p.i_ffd, buf, len) == len);
    }
    pipeline_destroy(&p);

    TEST_CHECK(p.sink.records == 50 + 10 + 1);
    TEST_CHECK(p.sink.annotated == 0);
}

static void test_e2e_protect_regex()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "0");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "protect_levels", "none");
    pipeline_set(&p, "protect_regex", " 500 took");
    TEST_CHECK(flb_start(p.flb) == 0);

    pipeline_push(&p, 200, 20, 0);
    pipeline_destroy(&p);

    /* only the lines matching the regex survive */
    TEST_CHECK(p.sink.records == 20);
    TEST_CHECK(p.sink.errors == 20);
}

static void push_fmt(struct pipeline *p, const char *fmt, int count)
{
    int i;
    int len;
    char buf[512];

    for (i = 0; i < count; i++) {
        len = snprintf(buf, sizeof(buf), fmt, 1700000000 + i, i, i % 97);
        TEST_CHECK(flb_lib_push(p->flb, p->i_ffd, buf, len) == len);
    }
}

static char *file_read(const char *path)
{
    long size;
    char *buf;
    FILE *fp;

    fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = flb_calloc(1, size + 1);
    if (buf && fread(buf, 1, size, fp) != (size_t) size) {
        flb_free(buf);
        buf = NULL;
    }
    fclose(fp);

    return buf;
}

static void run_group_by(int grouped)
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    if (grouped) {
        pipeline_set(&p, "group_by", "$svc");
    }
    TEST_CHECK(flb_start(p.flb) == 0);

    /* a loud service, then a quiet one that logs the same line */
    push_fmt(&p, "[%d, {\"svc\":\"a\",\"log\":\"GET /api/items/%d 200 took %dms\"}]", 300);
    push_fmt(&p, "[%d, {\"svc\":\"b\",\"log\":\"GET /api/items/%d 200 took %dms\"}]", 3);
    pipeline_destroy(&p);

    if (grouped) {
        /* each service has its own allowance */
        TEST_CHECK(p.sink.records == 5 + 3);
        TEST_CHECK(p.sink.svc_b == 3);
    }
    else {
        /* one shared pattern: the quiet service pays for the loud one */
        TEST_CHECK(p.sink.records == 5);
        TEST_CHECK(p.sink.svc_b == 0);
    }
}

static void test_e2e_group_by()
{
    run_group_by(FLB_FALSE);
    run_group_by(FLB_TRUE);
}

static void test_e2e_group_limit()
{
    char path[128];
    char *report;
    struct pipeline p;

    snprintf(path, sizeof(path), "/tmp/flb-rt-adaptive-groups-%d.json", (int) getpid());

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "group_by", "$meta['svc'],tag");
    pipeline_set(&p, "max_groups", "2");
    pipeline_set(&p, "report_file", path);
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"meta\":{\"svc\":\"a\"},\"log\":\"tick %d %d\"}]", 4);
    push_fmt(&p, "[%d, {\"meta\":{\"svc\":\"b\"},\"log\":\"tick %d %d\"}]", 4);
    push_fmt(&p, "[%d, {\"meta\":{\"svc\":\"c\"},\"log\":\"tick %d %d\"}]", 4);
    push_fmt(&p, "[%d, {\"meta\":{\"svc\":\"d\"},\"log\":\"tick %d %d\"}]", 4);
    push_fmt(&p, "[%d, {\"log\":\"tick %d %d\"}]", 4);
    pipeline_destroy(&p);

    TEST_CHECK(p.sink.records == 20);

    report = file_read(path);
    if (TEST_CHECK(report != NULL)) {
        /* nested key plus tag, a missing value reads as '-' */
        TEST_CHECK(strstr(report, "\"group\":\"a/test\"") != NULL);
        TEST_CHECK(strstr(report, "\"group\":\"b/test\"") != NULL);
        TEST_CHECK(strstr(report, "\"group\":\"c/test\"") == NULL);
        TEST_CHECK(strstr(report, "\"group\":\"-/test\"") == NULL);
        /* the keys that came after the limit share one group */
        TEST_CHECK(count_substr(report, "\"group\":\"_other\"") == 1);
        TEST_CHECK(strstr(report, "\"groups\":3,\"groups_overflowed\":12") != NULL);
        flb_free(report);
    }
    remove(path);
}

static void test_e2e_structured_json()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    TEST_CHECK(flb_start(p.flb) == 0);

    /* the message and the severity are found inside the JSON text */
    push_fmt(&p, "[%d, {\"log\":\"{\\\"level\\\":\\\"info\\\",\\\"rid\\\":\\\"r-%d\\\","
             "\\\"msg\\\":\\\"GET /api/items 200 took %dms\\\"}\"}]", 200);
    push_fmt(&p, "[%d, {\"log\":\"{\\\"level\\\":\\\"error\\\",\\\"rid\\\":\\\"r-%d\\\","
             "\\\"msg\\\":\\\"GET /api/items 500 took %dms\\\"}\"}]", 20);
    /* no message inside: the fields are the pattern, the word is its identity */
    push_fmt(&p, "[%d, {\"log\":\"{\\\"event\\\":\\\"login\\\",\\\"user\\\":\\\"u%d\\\","
             "\\\"ms\\\":%d,\\\"meta\\\":{\\\"ok\\\":true}}\"}]", 100);
    push_fmt(&p, "[%d, {\"log\":\"{\\\"event\\\":\\\"logout\\\",\\\"user\\\":\\\"u%d\\\","
             "\\\"ms\\\":%d,\\\"meta\\\":{\\\"ok\\\":true}}\"}]", 3);
    /* looks like JSON but is not: mined as plain text */
    push_fmt(&p, "[%d, {\"log\":\"{broken %d %d}\"}]", 50);
    pipeline_destroy(&p);

    if (!TEST_CHECK(p.sink.records == 5 + 20 + 5 + 3 + 5)) {
        TEST_MSG("records delivered: %d", p.sink.records);
    }
}

static void test_e2e_structured_fields()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "60s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    TEST_CHECK(flb_start(p.flb) == 0);

    /* records with no message at all, as an OTLP map body arrives */
    push_fmt(&p, "[%d, {\"event\":\"login\",\"user\":\"u%d\",\"ms\":%d,\"ok\":true}]", 100);
    push_fmt(&p, "[%d, {\"event\":\"logout\",\"user\":\"u%d\",\"ms\":%d,\"ok\":true}]", 3);
    push_fmt(&p, "[%d, {\"level\":\"error\",\"event\":\"login\",\"user\":\"u%d\",\"ms\":%d}]", 20);
    /* a map under the message key: its message and severity are used */
    push_fmt(&p, "[%d, {\"log\":{\"level\":\"info\",\"msg\":\"tick %d of %d\"}}]", 100);
    push_fmt(&p, "[%d, {\"log\":{\"level\":\"fatal\",\"msg\":\"tick %d of %d\"}}]", 10);
    pipeline_destroy(&p);

    if (!TEST_CHECK(p.sink.events == 5 + 3 + 20)) {
        TEST_MSG("events delivered: %d", p.sink.events);
    }
    if (!TEST_CHECK(p.sink.msgs == 5 + 10)) {
        TEST_MSG("nested messages delivered: %d", p.sink.msgs);
    }
}

/* Kept records plus what the summaries report must equal what was sent */
static void check_summary(struct pipeline *p, int sent, int counted)
{
    int kept = p->sink.records - p->sink.summaries;

    TEST_CHECK(p->sink.summaries >= 1);
    if (!TEST_CHECK(kept + p->sink.summary_dropped == sent)) {
        TEST_MSG("kept %d, summaries %d, dropped in summaries %" PRId64,
                 kept, p->sink.summaries, p->sink.summary_dropped);
    }
    TEST_CHECK(p->sink.summary_count == counted);
}

static void test_e2e_summary_input()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "1s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate", "false");
    pipeline_set(&p, "summary", "true");
    pipeline_set(&p, "group_by", "$svc");
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"svc\":\"b\",\"log\":\"GET /api/items/%d 200 took %dms\"}]", 200);

    /* nothing else arrives: the timer has to send the summary */
    flb_time_msleep(2500);
    pipeline_destroy(&p);

    check_summary(&p, 200, 200);
    TEST_CHECK(p.sink.group_b == p.sink.summaries);
    TEST_CHECK(p.sink.with_template == 0);
}

static void test_e2e_summary_output()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_TRUE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "1s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate", "false");
    pipeline_set(&p, "summary", "true");
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"log\":\"GET /api/items/%d 200 took %dms\"}]", 200);

    /* on an output the summary of the last window travels with the next chunk */
    flb_time_msleep(2200);
    push_fmt(&p, "[%d, {\"log\":\"config reloaded by operator %d %d\"}]", 1);
    pipeline_destroy(&p);

    /* the rare line lost nothing, so no summary counts it */
    check_summary(&p, 201, 200);
}

static void test_e2e_summary_observe_off()
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "mode", "observe");
    pipeline_set(&p, "window", "1s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "summary", "true");
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"log\":\"GET /api/items/%d 200 took %dms\"}]", 100);
    flb_time_msleep(2200);
    pipeline_destroy(&p);

    /* nothing was removed, so there is nothing to account for */
    TEST_CHECK(p.sink.records == 100);
    TEST_CHECK(p.sink.summaries == 0);
}

static void test_e2e_timer_report()
{
    char path[128];
    char *report;
    struct pipeline p;

    snprintf(path, sizeof(path), "/tmp/flb-rt-adaptive-timer-%d.json", (int) getpid());
    remove(path);

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "report_file", path);
    pipeline_set(&p, "report_interval", "1s");
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"log\":\"GET /api/items/%d 200 took %dms\"}]", 10);

    /* the stream is idle: only the timer can write this report */
    flb_time_msleep(2500);
    report = file_read(path);
    if (TEST_CHECK(report != NULL)) {
        TEST_CHECK(strstr(report, "\"records\":10") != NULL);
        flb_free(report);
    }

    pipeline_destroy(&p);
    remove(path);
}

/* ------------------------------------------------------------ fast path */

/* The same behavior is expected when records are decoded into objects */
static void test_e2e_decoded_path()
{
    pipeline_fast_path = FLB_FALSE;

    run_enforce(FLB_FALSE);
    run_enforce(FLB_TRUE);
    test_e2e_observe();
    test_e2e_lean_annotation();
    test_e2e_protect_regex();
    run_group_by(FLB_TRUE);
    test_e2e_structured_json();
    test_e2e_structured_fields();
    test_e2e_summary_output();

    pipeline_fast_path = FLB_TRUE;
}

struct raw_unit {
    flb_ctx_t *flb;
    struct flb_processor *proc;
    struct flb_processor_unit *unit;
    struct flb_processor_instance *ins;
};

static int raw_unit_create(struct raw_unit *u, const char *key, const char *value)
{
    u->flb = flb_create();
    u->proc = flb_processor_create(u->flb->config, "raw_test", NULL, 0);
    u->unit = flb_processor_unit_create(u->proc, FLB_PROCESSOR_LOGS, "adaptive");
    if (!TEST_CHECK(u->unit != NULL)) {
        return -1;
    }
    TEST_CHECK(flb_processor_unit_set_property_str(u->unit, "window", "1d") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u->unit, "allow_per_window", "5") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u->unit, "sample_mode", "suppress") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u->unit, "min_events", "0") == 0);
    if (key) {
        TEST_CHECK(flb_processor_unit_set_property_str(u->unit, key, value) == 0);
    }
    if (!TEST_CHECK(flb_processor_init(u->proc) == 0)) {
        return -1;
    }
    u->ins = u->unit->ctx;

    return 0;
}

static void raw_unit_destroy(struct raw_unit *u)
{
    flb_processor_destroy(u->proc);
    flb_destroy(u->flb);
}

/* Append one JSON document to a chunk under construction */
static void chunk_json(msgpack_sbuffer *sbuf, const char *json)
{
    int root_type;
    char *buf;
    size_t size;

    if (TEST_CHECK(flb_pack_json(json, strlen(json), &buf, &size, &root_type, NULL) == 0)) {
        msgpack_sbuffer_write(sbuf, buf, size);
        flb_free(buf);
    }
}

/* Append a group opener (-1) or closer (-2), the way the encoder writes them */
static void chunk_marker(msgpack_sbuffer *sbuf, int type, const char *body)
{
    char ext[8] = {0};
    msgpack_packer pck;

    msgpack_packer_init(&pck, sbuf, msgpack_sbuffer_write);

    /* seconds are 0xffffffff or 0xfffffffe, nanoseconds zero */
    memset(ext, 0xff, 4);
    if (type == -2) {
        ext[3] = (char) 0xfe;
    }

    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    msgpack_pack_ext(&pck, 8, 0);
    msgpack_pack_ext_body(&pck, ext, 8);
    msgpack_pack_map(&pck, 0);
    chunk_json(sbuf, body);
}

/* A chunk of 'count' request lines, optionally inside one group */
static void raw_chunk(char **data, size_t *bytes, int count, int grouped, const char *level)
{
    int i;
    char json[256];
    msgpack_sbuffer sbuf;

    msgpack_sbuffer_init(&sbuf);
    if (grouped) {
        chunk_marker(&sbuf, -1, "{\"resource\":{\"attributes\":{\"svc\":\"a\"}}}");
    }
    for (i = 0; i < count; i++) {
        snprintf(json, sizeof(json),
                 "[[%d,{}],{\"level\":\"%s\",\"log\":\"GET /api/items/%d 200 took %dms\"}]",
                 1700000000 + i, level, i, i % 97);
        chunk_json(&sbuf, json);
    }
    if (grouped) {
        chunk_marker(&sbuf, -2, "{}");
    }

    *data = sbuf.data;
    *bytes = sbuf.size;
}

/* Records and group markers of a buffer */
static void raw_count(void *data, size_t bytes, int *records, int *starts, int *ends)
{
    int32_t type;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    *records = 0;
    *starts = 0;
    *ends = 0;

    if (bytes == 0 ||
        flb_log_event_decoder_init(&decoder, data, bytes) != FLB_EVENT_DECODER_SUCCESS) {
        return;
    }
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        flb_log_event_decoder_get_record_type(&event, &type);
        if (type == FLB_LOG_EVENT_GROUP_START) {
            (*starts)++;
        }
        else if (type == FLB_LOG_EVENT_GROUP_END) {
            (*ends)++;
        }
        else {
            (*records)++;
        }
    }
    flb_log_event_decoder_destroy(&decoder);
}

static int raw_call(struct raw_unit *u, void *data, size_t bytes, void **out, size_t *out_size)
{
    *out = NULL;
    *out_size = 0;

    return u->ins->p->cb_process_logs_raw(&u->ins, 1, data, bytes, out, out_size, "test", 4);
}

/* What the fast path returns for chunks that are kept, thinned and emptied */
static void test_raw_results()
{
    int ret;
    int records;
    int starts;
    int ends;
    char *data;
    char *small;
    void *out;
    size_t bytes;
    size_t small_bytes;
    size_t out_size;
    struct raw_unit u;

    if (raw_unit_create(&u, NULL, NULL) != 0) {
        return;
    }
    TEST_CHECK(u.ins->logs_raw_enabled == FLB_TRUE);

    /* inside the allowance: the chunk is not rewritten at all */
    raw_chunk(&small, &small_bytes, 3, FLB_TRUE, "info");
    ret = raw_call(&u, small, small_bytes, &out, &out_size);
    TEST_CHECK(ret == FLB_PROCESSOR_RAW_NOTOUCH);
    TEST_CHECK(out == NULL && out_size == 0);

    /* two more pass, and they are the bytes that came in */
    raw_chunk(&data, &bytes, 10, FLB_TRUE, "info");
    ret = raw_call(&u, data, bytes, &out, &out_size);
    TEST_CHECK(ret == FLB_PROCESSOR_RAW_MODIFIED);
    raw_count(out, out_size, &records, &starts, &ends);
    TEST_CHECK(records == 2 && starts == 1 && ends == 1);
    if (TEST_CHECK(out != NULL && out_size > 12 && out_size < bytes)) {
        TEST_CHECK(memcmp(out, data, out_size - 12) == 0);
    }
    flb_free(out);

    /* nothing passes: no records, and no group left around them */
    ret = raw_call(&u, data, bytes, &out, &out_size);
    TEST_CHECK(ret == FLB_PROCESSOR_RAW_MODIFIED);
    TEST_CHECK(out != NULL && out_size == 0);
    flb_free(out);

    /* the runner turns that into an empty result */
    out = data;
    out_size = bytes;
    records = -1;
    TEST_CHECK(flb_processor_run_with_count(u.proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                                            data, bytes, &out, &out_size, 10, &records) == 0);
    TEST_CHECK(out == NULL && out_size == 0 && records == 0);
    flb_free(data);

    /* a protected record is kept, packed again with what it stands for */
    raw_chunk(&data, &bytes, 1, FLB_FALSE, "error");
    ret = raw_call(&u, data, bytes, &out, &out_size);
    TEST_CHECK(ret == FLB_PROCESSOR_RAW_MODIFIED);
    raw_count(out, out_size, &records, &starts, &ends);
    TEST_CHECK(records == 1 && starts == 0 && ends == 0);
    if (TEST_CHECK(out != NULL && out_size > bytes)) {
        TEST_CHECK(memmem(out, out_size, "suppressed", 10) != NULL);
        TEST_CHECK(memmem(out, out_size, "GET /api/items/0 200 took 0ms", 29) != NULL);
    }
    flb_free(out);
    flb_free(data);

    /* a buffer cut in the middle of a record keeps the bytes it cannot read */
    raw_chunk(&data, &bytes, 4, FLB_FALSE, "info");
    ret = raw_call(&u, data, bytes - 3, &out, &out_size);
    TEST_CHECK(ret == FLB_PROCESSOR_RAW_MODIFIED);
    raw_count(out, out_size, &records, &starts, &ends);
    TEST_CHECK(records == 0 && out_size > 0 && out_size < bytes / 2);
    flb_free(out);
    flb_free(data);

    flb_free(small);
    raw_unit_destroy(&u);
}

/* Records are grouped and protected from what MessagePack holds */
static void test_raw_groups_and_levels()
{
    int ret;
    int records;
    int starts;
    int ends;
    char *data;
    void *out;
    size_t bytes;
    size_t out_size;
    struct raw_unit u;
    msgpack_sbuffer sbuf;

    u.flb = flb_create();
    u.proc = flb_processor_create(u.flb->config, "raw_test", NULL, 0);
    u.unit = flb_processor_unit_create(u.proc, FLB_PROCESSOR_LOGS, "adaptive");
    TEST_CHECK(flb_processor_unit_set_property_str(u.unit, "window", "1d") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u.unit, "allow_per_window", "1") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u.unit, "sample_mode", "suppress") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u.unit, "min_events", "0") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u.unit, "group_by", "resource:svc") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(u.unit, "annotate", "false") == 0);
    if (!TEST_CHECK(flb_processor_init(u.proc) == 0)) {
        return;
    }
    u.ins = u.unit->ctx;

    msgpack_sbuffer_init(&sbuf);
    chunk_marker(&sbuf, -1, "{\"resource\":{\"attributes\":{\"svc\":\"a\"}}}");
    chunk_json(&sbuf, "[[1,{}],{\"log\":\"ping from 10.0.0.1\"}]");
    chunk_json(&sbuf, "[[2,{}],{\"log\":\"ping from 10.0.0.2\"}]");
    chunk_json(&sbuf, "[[3,{}],{\"log\":\"ping from 10.0.0.3\"}]");
    chunk_marker(&sbuf, -2, "{}");
    chunk_marker(&sbuf, -1, "{\"resource\":{\"attributes\":{\"svc\":\"b\"}}}");
    chunk_json(&sbuf, "[[4,{}],{\"log\":\"ping from 10.0.0.4\"}]");
    chunk_json(&sbuf, "[[5,{\"otlp\":{\"severity_number\":17}}],"
                      "{\"log\":\"ping from 10.0.0.5\"}]");
    chunk_json(&sbuf, "[[6,{}],{\"log\":{\"msg\":\"ping from 10.0.0.6\",\"level\":\"fatal\"}}]");
    chunk_json(&sbuf, "[[7,{}],{\"log\":\"ping from 10.0.0.7\"}]");
    chunk_marker(&sbuf, -2, "{}");
    chunk_marker(&sbuf, -1, "{\"resource\":{\"attributes\":{\"svc\":\"b\"}}}");
    chunk_json(&sbuf, "[[8,{}],{\"log\":\"ping from 10.0.0.8\"}]");
    chunk_marker(&sbuf, -2, "{}");
    data = sbuf.data;
    bytes = sbuf.size;

    ret = raw_call(&u, data, bytes, &out, &out_size);
    TEST_CHECK(ret == FLB_PROCESSOR_RAW_MODIFIED);
    raw_count(out, out_size, &records, &starts, &ends);

    /*
     * A third group loses its only record and is not written. Of the rest:
     * one line of each service by allowance, then the two protected ones:
     * the OTLP severity number and the level next to a nested message.
     */
    if (!TEST_CHECK(records == 4)) {
        TEST_MSG("records kept: %d", records);
    }
    TEST_CHECK(starts == 2 && ends == 2);
    if (out) {
        TEST_CHECK(memmem(out, out_size, "10.0.0.1", 8) != NULL);
        TEST_CHECK(memmem(out, out_size, "10.0.0.2", 8) == NULL);
        TEST_CHECK(memmem(out, out_size, "10.0.0.4", 8) != NULL);
        TEST_CHECK(memmem(out, out_size, "10.0.0.5", 8) != NULL);
        TEST_CHECK(memmem(out, out_size, "10.0.0.6", 8) != NULL);
        TEST_CHECK(memmem(out, out_size, "10.0.0.7", 8) == NULL);
    }

    flb_free(out);
    flb_free(data);
    raw_unit_destroy(&u);

    /* the option turns the fast path off */
    if (raw_unit_create(&u, "fast_path", "false") == 0) {
        TEST_CHECK(u.ins->logs_raw_enabled == FLB_FALSE);
        raw_unit_destroy(&u);
    }
}

/* ---------------------------------------------------------------- state */

static void check_init_fails(const char *key, const char *value);

static char state_found[512];
static int state_files;

/* Visit a directory tree: count the snapshot files, or remove everything */
static void state_walk(const char *path, int do_remove)
{
    char child[512];
    DIR *dir;
    struct dirent *entry;
    struct stat st;

    dir = opendir(path);
    if (!dir) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (lstat(child, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            state_walk(child, do_remove);
        }
        else if (do_remove) {
            remove(child);
        }
        else if (strncmp(entry->d_name, "snapshot-", 9) == 0) {
            snprintf(state_found, sizeof(state_found), "%s", child);
            state_files++;
        }
    }
    closedir(dir);

    if (do_remove) {
        rmdir(path);
    }
}

static void state_dir_remove(const char *path)
{
    state_walk(path, FLB_TRUE);
}

static void state_dir(char *path, size_t size, const char *name)
{
    snprintf(path, size, "/tmp/flb-rt-adaptive-state-%s-%d", name, (int) getpid());
    state_dir_remove(path);
}

/* Number of snapshot files under a state directory, the last one is kept */
static int state_snapshots(const char *path)
{
    state_files = 0;
    state_found[0] = '\0';
    state_walk(path, FLB_FALSE);

    return state_files;
}

/* One run of a flood against a state directory, returns the records kept */
static int state_run(const char *dir, const char *key, const char *value,
                     const char *report, int records)
{
    int kept;
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return -1;
    }
    pipeline_set(&p, "window", "1d");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "state_path", dir);
    if (key) {
        pipeline_set(&p, key, value);
    }
    if (report) {
        pipeline_set(&p, "report_file", report);
    }
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"log\":\"GET /api/items/%d 200 took %dms\"}]", records);
    pipeline_destroy(&p);
    kept = p.sink.records;

    return kept;
}

/* What a run learned and counted has to be there for the next run */
static void test_e2e_state_restart()
{
    int kept;
    char dir[128];
    char path[160];
    char *report;

    state_dir(dir, sizeof(dir), "restart");
    snprintf(path, sizeof(path), "%s-report.json", dir);

    kept = state_run(dir, NULL, NULL, NULL, 200);
    TEST_CHECK(kept == 5);
    TEST_CHECK(state_snapshots(dir) == 1);

    /* the allowance of this window is spent: without state 5 more would pass */
    kept = state_run(dir, NULL, NULL, path, 200);
    if (!TEST_CHECK(kept == 0)) {
        TEST_MSG("records kept after the restart: %d", kept);
    }
    TEST_CHECK(state_snapshots(dir) == 1);
    TEST_CHECK(strstr(state_found, "snapshot-00000000000000000002") != NULL);

    report = file_read(path);
    if (TEST_CHECK(report != NULL)) {
        TEST_CHECK(strstr(report, "\"records\":400") != NULL);
        TEST_CHECK(strstr(report, "\"count\":400") != NULL);
        TEST_CHECK(strstr(report, "\"dropped\":395") != NULL);
        flb_free(report);
    }

    remove(path);
    state_dir_remove(dir);
}

/* Each periodic save replaces the snapshot before it */
static void test_e2e_state_interval()
{
    char dir[128];
    struct pipeline p;

    state_dir(dir, sizeof(dir), "interval");

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "state_path", dir);
    pipeline_set(&p, "state_interval", "1s");
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"log\":\"GET /api/items/%d 200 took %dms\"}]", 10);

    /* idle stream: the timer saves, and only one file is ever left */
    flb_time_msleep(3600);
    TEST_CHECK(state_snapshots(dir) == 1);
    if (!TEST_CHECK(strstr(state_found, "snapshot-00000000000000000001") == NULL)) {
        TEST_MSG("snapshot on disk: %s", state_found);
    }

    pipeline_destroy(&p);
    TEST_CHECK(state_snapshots(dir) == 1);

    state_dir_remove(dir);
}

/* State that cannot be trusted or does not fit is ignored, never fatal */
static void test_e2e_state_ignored()
{
    int kept;
    char dir[128];
    FILE *fp;

    /* a damaged snapshot */
    state_dir(dir, sizeof(dir), "damaged");
    TEST_CHECK(state_run(dir, NULL, NULL, NULL, 200) == 5);
    if (TEST_CHECK(state_snapshots(dir) == 1)) {
        fp = fopen(state_found, "r+b");
        if (TEST_CHECK(fp != NULL)) {
            /* past the file header and its metadata, inside the content */
            fseek(fp, 96, SEEK_SET);
            fputc(0x5a, fp);
            fputc(0xa5, fp);
            fclose(fp);
        }
    }
    kept = state_run(dir, NULL, NULL, NULL, 200);
    if (!TEST_CHECK(kept == 5)) {
        TEST_MSG("records kept with a damaged snapshot: %d", kept);
    }
    TEST_CHECK(state_snapshots(dir) == 1);
    state_dir_remove(dir);

    /* a snapshot taken with another tree shape */
    state_dir(dir, sizeof(dir), "settings");
    TEST_CHECK(state_run(dir, NULL, NULL, NULL, 200) == 5);
    kept = state_run(dir, "tree_depth", "5", NULL, 200);
    if (!TEST_CHECK(kept == 5)) {
        TEST_MSG("records kept after changing tree_depth: %d", kept);
    }
    TEST_CHECK(state_snapshots(dir) == 1);
    state_dir_remove(dir);

    /* a snapshot older than the patterns are allowed to live */
    state_dir(dir, sizeof(dir), "expired");
    TEST_CHECK(state_run(dir, "pattern_ttl", "1s", NULL, 200) == 5);
    flb_time_msleep(1200);
    kept = state_run(dir, "pattern_ttl", "1s", NULL, 200);
    if (!TEST_CHECK(kept == 5)) {
        TEST_MSG("records kept with an expired snapshot: %d", kept);
    }
    state_dir_remove(dir);
}

/* Records dropped right before a stop are reported by the next run */
static void test_e2e_state_summary()
{
    char dir[128];
    struct flb_time now;
    struct pipeline p;

    state_dir(dir, sizeof(dir), "summary");

    /* start early in a window so the first run ends inside it */
    flb_time_get(&now);
    flb_time_msleep((6 - (now.tm.tv_sec % 6)) * 1000 - now.tm.tv_nsec / 1000000 + 100);

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "6s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate", "false");
    pipeline_set(&p, "summary", "true");
    pipeline_set(&p, "group_by", "$svc");
    pipeline_set(&p, "state_path", dir);
    TEST_CHECK(flb_start(p.flb) == 0);

    push_fmt(&p, "[%d, {\"svc\":\"b\",\"log\":\"GET /api/items/%d 200 took %dms\"}]", 200);
    pipeline_destroy(&p);

    TEST_CHECK(p.sink.records == 5);
    TEST_CHECK(p.sink.summaries == 0);

    /* nothing is pushed in the second run: all it sends comes from the state */
    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, "window", "6s");
    pipeline_set(&p, "allow_per_window", "5");
    pipeline_set(&p, "sample_mode", "suppress");
    pipeline_set(&p, "annotate", "false");
    pipeline_set(&p, "summary", "true");
    pipeline_set(&p, "group_by", "$svc");
    pipeline_set(&p, "state_path", dir);
    TEST_CHECK(flb_start(p.flb) == 0);

    flb_time_msleep(6500);
    pipeline_destroy(&p);

    if (!TEST_CHECK(p.sink.summaries == 1)) {
        TEST_MSG("summaries after the restart: %d", p.sink.summaries);
    }
    TEST_CHECK(p.sink.summary_dropped == 195);
    TEST_CHECK(p.sink.summary_count == 200);
    TEST_CHECK(p.sink.group_b == 1);

    state_dir_remove(dir);
}

static void test_e2e_state_unusable_path()
{
    check_init_fails("state_path", "/proc/flb-rt-adaptive-no-such-place");
}

static void check_init_fails(const char *key, const char *value)
{
    struct pipeline p;

    if (pipeline_create(&p, FLB_FALSE) != 0) {
        return;
    }
    pipeline_set(&p, key, value);
    if (!TEST_CHECK(flb_start(p.flb) != 0)) {
        TEST_MSG("started with %s=%s", key, value);
        flb_stop(p.flb);
    }
    flb_destroy(p.flb);
    pthread_mutex_destroy(&p.sink.lock);
}

static void test_config_validation()
{
    check_init_fails("mode", "delete");
    check_init_fails("sample_mode", "random");
    check_init_fails("similarity_threshold", "1.5");
    check_init_fails("tree_depth", "1");
    check_init_fails("max_tokens", "1");
    check_init_fails("max_patterns", "0");
    check_init_fails("window", "0");
    check_init_fails("max_sample_rate", "0");
    check_init_fails("allow_per_window", "-1");
    check_init_fails("protect_regex", "(unclosed");
    check_init_fails("key", "");
    check_init_fails("max_groups", "0");
    check_init_fails("group_by", "$kubernetes[namespace]");
    check_init_fails("group_by", "resource:");
    check_init_fails("state_interval", "0");
}

TEST_LIST = {
    {"miner_masking",              test_miner_masking},
    {"miner_grouping",             test_miner_grouping},
    {"miner_truncation",           test_miner_truncation},
    {"miner_bounds",               test_miner_bounds},
    {"miner_max_children",         test_miner_max_children},
    {"miner_key_wildcard",         test_miner_key_wildcard},
    {"miner_remove_hook",          test_miner_remove_hook},
    {"miner_restore",              test_miner_restore},
    {"policy_allowance_sampling",  test_policy_allowance_and_sampling},
    {"policy_modes",               test_policy_modes},
    {"policy_accounting",          test_policy_accounting},
    {"policy_protected_budget",    test_policy_protected_and_budget},
    {"policy_file_rules",          test_policy_file_rules},
    {"policy_file_invalid",        test_policy_file_invalid},
    {"policy_file_groups",         test_policy_file_groups},
    {"e2e_enforce_input",          test_e2e_enforce_input},
    {"e2e_enforce_output",         test_e2e_enforce_output},
    {"e2e_observe",                test_e2e_observe},
    {"e2e_lean_annotation",        test_e2e_lean_annotation},
    {"e2e_no_annotation_missing_key", test_e2e_no_annotation_and_missing_key},
    {"e2e_protect_regex",          test_e2e_protect_regex},
    {"e2e_group_by",               test_e2e_group_by},
    {"e2e_group_limit",            test_e2e_group_limit},
    {"e2e_structured_json",        test_e2e_structured_json},
    {"e2e_structured_fields",      test_e2e_structured_fields},
    {"e2e_summary_input",          test_e2e_summary_input},
    {"e2e_summary_output",         test_e2e_summary_output},
    {"e2e_summary_observe_off",    test_e2e_summary_observe_off},
    {"e2e_timer_report",           test_e2e_timer_report},
    {"e2e_decoded_path",           test_e2e_decoded_path},
    {"raw_results",                test_raw_results},
    {"raw_groups_and_levels",      test_raw_groups_and_levels},
    {"e2e_state_restart",          test_e2e_state_restart},
    {"e2e_state_interval",         test_e2e_state_interval},
    {"e2e_state_ignored",          test_e2e_state_ignored},
    {"e2e_state_summary",          test_e2e_state_summary},
    {"e2e_state_unusable_path",    test_e2e_state_unusable_path},
    {"config_validation",          test_config_validation},
    {NULL, NULL}
};
