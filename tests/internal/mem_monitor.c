/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mem_monitor.h>

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/stat.h>
#endif

#include "flb_tests_internal.h"

#define MB(x) ((uint64_t) (x) * 1000 * 1000)

struct test_context {
    struct flb_config *config;
    struct flb_input_instance *in_local;    /* not a network server */
    struct flb_input_instance *in_server;   /* network server */
    struct flb_mem_monitor *mm;
    uint64_t usage;
    int reclaim_calls;
    int reclaim_ret;
    uint64_t reclaim_release;
};

static int cb_test_usage(struct flb_mem_monitor *mm, uint64_t *usage)
{
    struct test_context *ctx = mm->cb_data;

    *usage = ctx->usage;
    return 0;
}

static int cb_test_reclaim(struct flb_mem_monitor *mm)
{
    struct test_context *ctx = mm->cb_data;

    ctx->reclaim_calls++;
    if (ctx->reclaim_ret == 0 && ctx->usage >= ctx->reclaim_release) {
        ctx->usage -= ctx->reclaim_release;
    }

    return ctx->reclaim_ret;
}

static int test_context_init(struct test_context *ctx, const char *limit)
{
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
#endif

    memset(ctx, 0, sizeof(struct test_context));
    ctx->reclaim_ret = -1;

    ctx->config = flb_config_init();
    if (ctx->config == NULL) {
        return -1;
    }

    ctx->config->evl = mk_event_loop_create(8);
    if (ctx->config->evl == NULL) {
        flb_config_exit(ctx->config);
        return -1;
    }

    ctx->config->sched = flb_sched_create(ctx->config, ctx->config->evl);
    if (ctx->config->sched == NULL) {
        flb_config_exit(ctx->config);
        return -1;
    }

    ctx->in_local = flb_input_new(ctx->config, "dummy", NULL, FLB_FALSE);
    ctx->in_server = flb_input_new(ctx->config, "tcp", NULL, FLB_FALSE);
    if (ctx->in_local == NULL || ctx->in_server == NULL) {
        flb_input_exit_all(ctx->config);
        flb_config_exit(ctx->config);
        return -1;
    }

    if (limit != NULL) {
        ctx->config->mem_limit = flb_strdup(limit);
    }
    ctx->config->is_running = FLB_TRUE;
    ctx->config->is_ingestion_active = FLB_TRUE;

    ctx->mm = flb_mem_monitor_create(ctx->config);
    if (ctx->mm == NULL) {
        flb_input_exit_all(ctx->config);
        flb_config_exit(ctx->config);
        return -1;
    }

    /* drive the monitor with a known usage value */
    ctx->mm->cb_usage = cb_test_usage;
    ctx->mm->cb_reclaim = cb_test_reclaim;
    ctx->mm->cb_data = ctx;

    return 0;
}

static void test_context_destroy(struct test_context *ctx)
{
    flb_input_exit_all(ctx->config);
    flb_mem_monitor_destroy(ctx->mm);
    flb_config_exit(ctx->config);
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

static void test_parse_size()
{
    int ret;
    uint64_t out;

    ret = flb_mem_monitor_parse_size("512M", 0, &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == MB(512));

    ret = flb_mem_monitor_parse_size("1024", 0, &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == 1024);

    ret = flb_mem_monitor_parse_size("80%", MB(1000), &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == MB(800));

    ret = flb_mem_monitor_parse_size("12.5 % ", MB(1000), &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == MB(125));

    ret = flb_mem_monitor_parse_size("100%", MB(1000), &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == MB(1000));

    /* a percentage needs a known total */
    TEST_CHECK(flb_mem_monitor_parse_size("80%", 0, &out) == -1);

    TEST_CHECK(flb_mem_monitor_parse_size("0%", MB(1000), &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("-5%", MB(1000), &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("101%", MB(1000), &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("%", MB(1000), &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("abc%", MB(1000), &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("10x%", MB(1000), &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("", 0, &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("  ", 0, &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("0", 0, &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size("abc", 0, &out) == -1);
    TEST_CHECK(flb_mem_monitor_parse_size(NULL, 0, &out) == -1);
}

static void test_set_limits()
{
    int ret;
    struct flb_mem_monitor mm;

    memset(&mm, 0, sizeof(mm));

    ret = flb_mem_monitor_set_limits(&mm, MB(1000), MB(200));
    TEST_CHECK(ret == 0);
    TEST_CHECK(mm.threshold_reclaim == MB(700));
    TEST_CHECK(mm.threshold_throttle == MB(800));
    TEST_CHECK(mm.threshold_refuse == MB(950));
    TEST_CHECK(mm.hysteresis == MB(50));

    /* the reserve can take up to half of the limit */
    TEST_CHECK(flb_mem_monitor_set_limits(&mm, MB(1000), MB(500)) == 0);
    TEST_CHECK(mm.threshold_reclaim == MB(250));

    TEST_CHECK(flb_mem_monitor_set_limits(&mm, MB(1000), MB(501)) == -1);
    TEST_CHECK(flb_mem_monitor_set_limits(&mm, MB(1000), 0) == -1);
    TEST_CHECK(flb_mem_monitor_set_limits(&mm, 0, MB(1)) == -1);
}

static void test_state_next()
{
    int state;
    struct flb_mem_monitor mm;

    memset(&mm, 0, sizeof(mm));

    /* reclaim >= 700, throttle >= 800, refuse >= 950, hysteresis 50 */
    flb_mem_monitor_set_limits(&mm, MB(1000), MB(200));

    state = FLB_MEM_MONITOR_NORMAL;

    state = flb_mem_monitor_state_next(&mm, state, MB(699));
    TEST_CHECK(state == FLB_MEM_MONITOR_NORMAL);

    state = flb_mem_monitor_state_next(&mm, state, MB(700));
    TEST_CHECK(state == FLB_MEM_MONITOR_RECLAIM);

    state = flb_mem_monitor_state_next(&mm, state, MB(800));
    TEST_CHECK(state == FLB_MEM_MONITOR_THROTTLE);

    /* within the hysteresis margin: no change */
    state = flb_mem_monitor_state_next(&mm, state, MB(751));
    TEST_CHECK(state == FLB_MEM_MONITOR_THROTTLE);

    state = flb_mem_monitor_state_next(&mm, state, MB(749));
    TEST_CHECK(state == FLB_MEM_MONITOR_RECLAIM);

    state = flb_mem_monitor_state_next(&mm, state, MB(651));
    TEST_CHECK(state == FLB_MEM_MONITOR_RECLAIM);

    state = flb_mem_monitor_state_next(&mm, state, MB(649));
    TEST_CHECK(state == FLB_MEM_MONITOR_NORMAL);

    /* escalation can skip states */
    state = flb_mem_monitor_state_next(&mm, state, MB(2000));
    TEST_CHECK(state == FLB_MEM_MONITOR_REFUSE);

    state = flb_mem_monitor_state_next(&mm, state, MB(901));
    TEST_CHECK(state == FLB_MEM_MONITOR_REFUSE);

    state = flb_mem_monitor_state_next(&mm, state, MB(899));
    TEST_CHECK(state == FLB_MEM_MONITOR_THROTTLE);

    /* a large drop goes down several states at once */
    state = FLB_MEM_MONITOR_REFUSE;
    state = flb_mem_monitor_state_next(&mm, state, MB(100));
    TEST_CHECK(state == FLB_MEM_MONITOR_NORMAL);

    /* but never below the state the usage belongs to */
    state = FLB_MEM_MONITOR_REFUSE;
    state = flb_mem_monitor_state_next(&mm, state, MB(710));
    TEST_CHECK(state == FLB_MEM_MONITOR_RECLAIM);
}

static void test_disabled_without_limit()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx, NULL);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    TEST_CHECK(ctx.mm->enabled == FLB_FALSE);

    ctx.usage = MB(100000);
    ret = flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_NORMAL);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_FALSE);
    TEST_CHECK(flb_input_paused(ctx.in_server) == FLB_FALSE);

    /* nothing gets scheduled when there is no limit */
    TEST_CHECK(flb_mem_monitor_start(ctx.mm) == 0);
    TEST_CHECK(ctx.mm->timer == NULL);

    test_context_destroy(&ctx);
}

static void test_invalid_config()
{
    struct flb_config *config;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    config->mem_limit = flb_strdup("not-a-size");
    TEST_CHECK(flb_mem_monitor_create(config) == NULL);

    flb_free(config->mem_limit);
    config->mem_limit = flb_strdup("100M");
    config->mem_spike_reserve = flb_strdup("90%");
    TEST_CHECK(flb_mem_monitor_create(config) == NULL);

    flb_config_exit(config);
}

static void test_inputs_pause_resume()
{
    int ret;
    struct test_context ctx;

    /* reclaim >= 700M, throttle >= 800M, refuse >= 950M */
    ret = test_context_init(&ctx, "1000M");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

#ifndef __linux__
    /* enforcement needs a platform sampler, enable it by hand elsewhere */
    ctx.mm->enabled = FLB_TRUE;
    flb_mem_monitor_set_limits(ctx.mm, MB(1000), MB(200));
#endif
    TEST_CHECK(ctx.mm->enabled == FLB_TRUE);
    TEST_CHECK(ctx.mm->limit == MB(1000));
    TEST_CHECK((ctx.in_server->p->flags & FLB_INPUT_NET_SERVER) != 0);
    TEST_CHECK((ctx.in_local->p->flags & FLB_INPUT_NET_SERVER) == 0);

    ctx.usage = MB(100);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_NORMAL);
    TEST_CHECK(ctx.mm->paused_inputs == 0);
    TEST_CHECK(ctx.reclaim_calls == 0);

    /* reclaim: nobody is paused */
    ctx.usage = MB(720);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_RECLAIM);
    TEST_CHECK(ctx.reclaim_calls == 1);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_FALSE);
    TEST_CHECK(flb_input_paused(ctx.in_server) == FLB_FALSE);

    /* throttle: only the input that is not a network server is paused */
    ctx.usage = MB(820);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_THROTTLE);
    TEST_CHECK(ctx.in_local->mem_monitor_status == FLB_INPUT_PAUSED);
    TEST_CHECK(flb_input_buf_paused(ctx.in_local) == FLB_TRUE);
    TEST_CHECK(flb_input_paused(ctx.in_server) == FLB_FALSE);
    TEST_CHECK(ctx.mm->paused_inputs == 1);

    /* refuse: everything is paused */
    ctx.usage = MB(960);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_REFUSE);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_TRUE);
    TEST_CHECK(flb_input_paused(ctx.in_server) == FLB_TRUE);
    TEST_CHECK(ctx.mm->paused_inputs == 2);

    /* back to throttle: the network server is resumed first */
    ctx.usage = MB(850);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_THROTTLE);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_TRUE);
    TEST_CHECK(flb_input_paused(ctx.in_server) == FLB_FALSE);

    ctx.usage = MB(100);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_NORMAL);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_FALSE);
    TEST_CHECK(flb_input_paused(ctx.in_server) == FLB_FALSE);
    TEST_CHECK(ctx.mm->paused_inputs == 0);

    test_context_destroy(&ctx);
}

/* an input paused by its own buffer limit must not be resumed by the monitor */
static void test_other_pause_reasons_are_kept()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx, "1000M");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

#ifndef __linux__
    ctx.mm->enabled = FLB_TRUE;
    flb_mem_monitor_set_limits(ctx.mm, MB(1000), MB(200));
#endif

    ctx.in_local->mem_buf_status = FLB_INPUT_PAUSED;

    ctx.usage = MB(990);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.in_local->mem_monitor_status == FLB_INPUT_PAUSED);

    ctx.usage = MB(100);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.in_local->mem_monitor_status == FLB_INPUT_RUNNING);
    TEST_CHECK(ctx.in_local->mem_buf_status == FLB_INPUT_PAUSED);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_TRUE);

    /* the monitor does nothing once the service is stopping */
    ctx.in_local->mem_buf_status = FLB_INPUT_RUNNING;
    ctx.config->is_ingestion_active = FLB_FALSE;
    ctx.usage = MB(990);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.mm->state == FLB_MEM_MONITOR_NORMAL);
    TEST_CHECK(flb_input_paused(ctx.in_local) == FLB_FALSE);

    test_context_destroy(&ctx);
}

static void test_reclaim_pacing()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx, "1000M");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

#ifndef __linux__
    ctx.mm->enabled = FLB_TRUE;
    flb_mem_monitor_set_limits(ctx.mm, MB(1000), MB(200));
#endif

    /* a reclaim that releases nothing doubles the wait time */
    ctx.usage = MB(720);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.reclaim_calls == 1);
    TEST_CHECK(ctx.mm->reclaim_interval == FLB_MEM_MONITOR_RECLAIM_INTERVAL_MIN * 2);

    /* and it is not retried before that time has passed */
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.reclaim_calls == 1);

    /* an effective reclaim resets the wait time and updates the usage */
    ctx.mm->reclaim_last = 0;
    ctx.reclaim_ret = 0;
    ctx.reclaim_release = MB(100);
    flb_mem_monitor_check(ctx.mm);
    TEST_CHECK(ctx.reclaim_calls == 2);
    TEST_CHECK(ctx.mm->reclaim_count == 2);
    TEST_CHECK(ctx.mm->usage == MB(620));
    TEST_CHECK(ctx.mm->reclaim_interval == FLB_MEM_MONITOR_RECLAIM_INTERVAL_MIN);

    test_context_destroy(&ctx);
}

#ifdef __linux__
static int write_file(const char *path, const char *content)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    fputs(content, fp);
    fclose(fp);

    return 0;
}

static void remove_tree(const char *root)
{
    char path[512];

    snprintf(path, sizeof(path), "%s/proc_cgroup", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/a/b/memory.max", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/a/memory.max", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/memory.max", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/a/b", root);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/a", root);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/memory/pod/memory.limit_in_bytes", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/memory/memory.limit_in_bytes", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/memory/pod", root);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/memory", root);
    rmdir(path);
    rmdir(root);
}

static void test_cgroup_limit()
{
    int ret;
    char root[] = "/tmp/flb-mem-monitor-XXXXXX";
    char proc[512];
    char path[512];
    uint64_t limit;

    if (!TEST_CHECK(mkdtemp(root) != NULL)) {
        return;
    }

    snprintf(proc, sizeof(proc), "%s/proc_cgroup", root);

    snprintf(path, sizeof(path), "%s/a", root);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/a/b", root);
    mkdir(path, 0700);

    /* cgroup v2: no limit anywhere */
    write_file(proc, "0::/a/b\n");
    snprintf(path, sizeof(path), "%s/a/b/memory.max", root);
    write_file(path, "max\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == -1);

    /* cgroup v2: limit in the process group */
    write_file(path, "536870912\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == 0);
    TEST_CHECK(limit == 536870912);

    /* cgroup v2: a parent group is more restrictive */
    snprintf(path, sizeof(path), "%s/a/memory.max", root);
    write_file(path, "268435456\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == 0);
    TEST_CHECK(limit == 268435456);

    /* cgroup v2: namespaced root, the limit is at the mount point */
    write_file(proc, "0::/\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == -1);

    snprintf(path, sizeof(path), "%s/memory.max", root);
    write_file(path, "134217728\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == 0);
    TEST_CHECK(limit == 134217728);

    /* cgroup v2: path not visible from the mount point */
    write_file(proc, "0::/not/visible\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == 0);
    TEST_CHECK(limit == 134217728);

    /* cgroup v1: memory controller, 'unlimited' is a very large number */
    snprintf(path, sizeof(path), "%s/memory", root);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/memory/pod", root);
    mkdir(path, 0700);

    write_file(proc, "12:cpu,cpuacct:/pod\n5:memory:/pod\n");
    snprintf(path, sizeof(path), "%s/memory/pod/memory.limit_in_bytes", root);
    write_file(path, "9223372036854771712\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == -1);

    write_file(path, "104857600\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == 0);
    TEST_CHECK(limit == 104857600);

    /* missing or malformed process file */
    ret = flb_mem_monitor_cgroup_limit("/nonexistent/cgroup", root, &limit);
    TEST_CHECK(ret == -1);

    write_file(proc, "garbage\n0:nopath\n");
    ret = flb_mem_monitor_cgroup_limit(proc, root, &limit);
    TEST_CHECK(ret == -1);

    remove_tree(root);
}

static void test_process_usage()
{
    int ret;
    size_t i;
    size_t size = 64 * 1024 * 1024;
    char *buf;
    uint64_t before;
    uint64_t after;
    uint64_t total;

    ret = flb_mem_monitor_process_usage(&before);
    TEST_CHECK(ret == 0);
    TEST_CHECK(before > 0);

    /* touch every page so the memory becomes resident */
    buf = flb_malloc(size);
    TEST_CHECK(buf != NULL);
    if (buf == NULL) {
        return;
    }
    for (i = 0; i < size; i += 1024) {
        buf[i] = (char) i;
    }

    ret = flb_mem_monitor_process_usage(&after);
    TEST_CHECK(ret == 0);
    TEST_CHECK(after >= before + (size / 2));
    TEST_MSG("before=%llu after=%llu buf=%d",
             (unsigned long long) before, (unsigned long long) after, buf[1024]);

    flb_free(buf);

    ret = flb_mem_monitor_system_limit(&total);
    TEST_CHECK(ret == 0);
    TEST_CHECK(total > 0);
}
#endif

TEST_LIST = {
    {"parse_size", test_parse_size},
    {"set_limits", test_set_limits},
    {"state_next", test_state_next},
    {"disabled_without_limit", test_disabled_without_limit},
    {"invalid_config", test_invalid_config},
    {"inputs_pause_resume", test_inputs_pause_resume},
    {"other_pause_reasons_are_kept", test_other_pause_reasons_are_kept},
    {"reclaim_pacing", test_reclaim_pacing},
#ifdef __linux__
    {"cgroup_limit", test_cgroup_limit},
    {"process_usage", test_process_usage},
#endif
    {0}
};
