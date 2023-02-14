/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#define _CRT_RAND_S  // rand_s() on MSVC
#include <stdarg.h>
#include "test.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <direct.h> /* _getcwd */
#else
#include <sys/wait.h> /* waitpid */
#endif

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"

int test_level = 2;
int test_seed  = 0;

char test_mode[64]                     = "bare";
char test_scenario[64]                 = "default";
static volatile sig_atomic_t test_exit = 0;
static char test_topic_prefix[128]     = "rdkafkatest";
static int test_topic_random           = 0;
int tests_running_cnt                  = 0;
int test_concurrent_max                = 5;
int test_assert_on_fail                = 0;
double test_timeout_multiplier         = 1.0;
static char *test_sql_cmd              = NULL;
int test_session_timeout_ms            = 6000;
int test_broker_version;
static const char *test_broker_version_str = "2.4.0.0";
int test_flags                             = 0;
int test_neg_flags                         = TEST_F_KNOWN_ISSUE;
/* run delete-test-topics.sh between each test (when concurrent_max = 1) */
static int test_delete_topics_between = 0;
static const char *test_git_version   = "HEAD";
static const char *test_sockem_conf   = "";
int test_on_ci = 0; /* Tests are being run on CI, be more forgiving
                     * with regards to timeouts, etc. */
int test_quick               = 0; /** Run tests quickly */
int test_idempotent_producer = 0;
int test_rusage              = 0; /**< Check resource usage */
/**< CPU speed calibration for rusage threshold checks.
 *   >1.0: CPU is slower than base line system,
 *   <1.0: CPU is faster than base line system. */
double test_rusage_cpu_calibration = 1.0;
static const char *tests_to_run    = NULL; /* all */
static const char *subtests_to_run = NULL; /* all */
static const char *tests_to_skip   = NULL; /* none */
int test_write_report              = 0;    /**< Write test report file */

static int show_summary = 1;
static int test_summary(int do_lock);

/**
 * Protects shared state, such as tests[]
 */
mtx_t test_mtx;
cnd_t test_cnd;

static const char *test_states[] = {
    "DNS", "SKIPPED", "RUNNING", "PASSED", "FAILED",
};



#define _TEST_DECL(NAME) extern int main_##NAME(int, char **)
#define _TEST(NAME, FLAGS, ...)                                                \
        { .name = #NAME, .mainfunc = main_##NAME, .flags = FLAGS, __VA_ARGS__ }


/**
 * Declare all tests here
 */
_TEST_DECL(0000_unittests);
_TEST_DECL(0001_multiobj);
_TEST_DECL(0002_unkpart);
_TEST_DECL(0003_msgmaxsize);
_TEST_DECL(0004_conf);
_TEST_DECL(0005_order);
_TEST_DECL(0006_symbols);
_TEST_DECL(0007_autotopic);
_TEST_DECL(0008_reqacks);
_TEST_DECL(0009_mock_cluster);
_TEST_DECL(0011_produce_batch);
_TEST_DECL(0012_produce_consume);
_TEST_DECL(0013_null_msgs);
_TEST_DECL(0014_reconsume_191);
_TEST_DECL(0015_offsets_seek);
_TEST_DECL(0016_client_swname);
_TEST_DECL(0017_compression);
_TEST_DECL(0018_cgrp_term);
_TEST_DECL(0019_list_groups);
_TEST_DECL(0020_destroy_hang);
_TEST_DECL(0021_rkt_destroy);
_TEST_DECL(0022_consume_batch);
_TEST_DECL(0022_consume_batch_local);
_TEST_DECL(0025_timers);
_TEST_DECL(0026_consume_pause);
_TEST_DECL(0028_long_topicnames);
_TEST_DECL(0029_assign_offset);
_TEST_DECL(0030_offset_commit);
_TEST_DECL(0031_get_offsets);
_TEST_DECL(0033_regex_subscribe);
_TEST_DECL(0033_regex_subscribe_local);
_TEST_DECL(0034_offset_reset);
_TEST_DECL(0034_offset_reset_mock);
_TEST_DECL(0035_api_version);
_TEST_DECL(0036_partial_fetch);
_TEST_DECL(0037_destroy_hang_local);
_TEST_DECL(0038_performance);
_TEST_DECL(0039_event_dr);
_TEST_DECL(0039_event_log);
_TEST_DECL(0039_event);
_TEST_DECL(0040_io_event);
_TEST_DECL(0041_fetch_max_bytes);
_TEST_DECL(0042_many_topics);
_TEST_DECL(0043_no_connection);
_TEST_DECL(0044_partition_cnt);
_TEST_DECL(0045_subscribe_update);
_TEST_DECL(0045_subscribe_update_topic_remove);
_TEST_DECL(0045_subscribe_update_non_exist_and_partchange);
_TEST_DECL(0045_subscribe_update_mock);
_TEST_DECL(0046_rkt_cache);
_TEST_DECL(0047_partial_buf_tmout);
_TEST_DECL(0048_partitioner);
_TEST_DECL(0049_consume_conn_close);
_TEST_DECL(0050_subscribe_adds);
_TEST_DECL(0051_assign_adds);
_TEST_DECL(0052_msg_timestamps);
_TEST_DECL(0053_stats_timing);
_TEST_DECL(0053_stats);
_TEST_DECL(0054_offset_time);
_TEST_DECL(0055_producer_latency);
_TEST_DECL(0056_balanced_group_mt);
_TEST_DECL(0057_invalid_topic);
_TEST_DECL(0058_log);
_TEST_DECL(0059_bsearch);
_TEST_DECL(0060_op_prio);
_TEST_DECL(0061_consumer_lag);
_TEST_DECL(0062_stats_event);
_TEST_DECL(0063_clusterid);
_TEST_DECL(0064_interceptors);
_TEST_DECL(0065_yield);
_TEST_DECL(0066_plugins);
_TEST_DECL(0067_empty_topic);
_TEST_DECL(0068_produce_timeout);
_TEST_DECL(0069_consumer_add_parts);
_TEST_DECL(0070_null_empty);
_TEST_DECL(0072_headers_ut);
_TEST_DECL(0073_headers);
_TEST_DECL(0074_producev);
_TEST_DECL(0075_retry);
_TEST_DECL(0076_produce_retry);
_TEST_DECL(0077_compaction);
_TEST_DECL(0078_c_from_cpp);
_TEST_DECL(0079_fork);
_TEST_DECL(0080_admin_ut);
_TEST_DECL(0081_admin);
_TEST_DECL(0082_fetch_max_bytes);
_TEST_DECL(0083_cb_event);
_TEST_DECL(0084_destroy_flags_local);
_TEST_DECL(0084_destroy_flags);
_TEST_DECL(0085_headers);
_TEST_DECL(0086_purge_local);
_TEST_DECL(0086_purge_remote);
_TEST_DECL(0088_produce_metadata_timeout);
_TEST_DECL(0089_max_poll_interval);
_TEST_DECL(0090_idempotence);
_TEST_DECL(0091_max_poll_interval_timeout);
_TEST_DECL(0092_mixed_msgver);
_TEST_DECL(0093_holb_consumer);
_TEST_DECL(0094_idempotence_msg_timeout);
_TEST_DECL(0095_all_brokers_down);
_TEST_DECL(0097_ssl_verify);
_TEST_DECL(0097_ssl_verify_local);
_TEST_DECL(0098_consumer_txn);
_TEST_DECL(0099_commit_metadata);
_TEST_DECL(0100_thread_interceptors);
_TEST_DECL(0101_fetch_from_follower);
_TEST_DECL(0102_static_group_rebalance);
_TEST_DECL(0103_transactions_local);
_TEST_DECL(0103_transactions);
_TEST_DECL(0104_fetch_from_follower_mock);
_TEST_DECL(0105_transactions_mock);
_TEST_DECL(0106_cgrp_sess_timeout);
_TEST_DECL(0107_topic_recreate);
_TEST_DECL(0109_auto_create_topics);
_TEST_DECL(0110_batch_size);
_TEST_DECL(0111_delay_create_topics);
_TEST_DECL(0112_assign_unknown_part);
_TEST_DECL(0113_cooperative_rebalance_local);
_TEST_DECL(0113_cooperative_rebalance);
_TEST_DECL(0114_sticky_partitioning);
_TEST_DECL(0115_producer_auth);
_TEST_DECL(0116_kafkaconsumer_close);
_TEST_DECL(0117_mock_errors);
_TEST_DECL(0118_commit_rebalance);
_TEST_DECL(0119_consumer_auth);
_TEST_DECL(0120_asymmetric_subscription);
_TEST_DECL(0121_clusterid);
_TEST_DECL(0122_buffer_cleaning_after_rebalance);
_TEST_DECL(0123_connections_max_idle);
_TEST_DECL(0124_openssl_invalid_engine);
_TEST_DECL(0125_immediate_flush);
_TEST_DECL(0126_oauthbearer_oidc);
_TEST_DECL(0128_sasl_callback_queue);
_TEST_DECL(0129_fetch_aborted_msgs);
_TEST_DECL(0130_store_offsets);
_TEST_DECL(0131_connect_timeout);
_TEST_DECL(0132_strategy_ordering);

/* Manual tests */
_TEST_DECL(8000_idle);


/* Define test resource usage thresholds if the default limits
 * are not tolerable.
 *
 * Fields:
 *  .ucpu  - Max User CPU percentage  (double)
 *  .scpu  - Max System/Kernel CPU percentage  (double)
 *  .rss   - Max RSS (memory) in megabytes  (double)
 *  .ctxsw - Max number of voluntary context switches  (int)
 *
 * Also see test_rusage_check_thresholds() in rusage.c
 *
 * Make a comment in the _THRES() below why the extra thresholds are required.
 *
 * Usage:
 *  _TEST(00...., ...,
 *        _THRES(.ucpu = 15.0)),  <--  Max 15% User CPU usage
 */
#define _THRES(...) .rusage_thres = {__VA_ARGS__}

/**
 * Define all tests here
 */
struct test tests[] = {
    /* Special MAIN test to hold over-all timings, etc. */
    {.name = "<MAIN>", .flags = TEST_F_LOCAL},
    _TEST(0000_unittests,
          TEST_F_LOCAL,
          /* The msgq insert order tests are heavy on
           * user CPU (memory scan), RSS, and
           * system CPU (lots of allocations -> madvise(2)). */
          _THRES(.ucpu = 100.0, .scpu = 20.0, .rss = 900.0)),
    _TEST(0001_multiobj, 0),
    _TEST(0002_unkpart, 0),
    _TEST(0003_msgmaxsize, 0),
    _TEST(0004_conf, TEST_F_LOCAL),
    _TEST(0005_order, 0),
    _TEST(0006_symbols, TEST_F_LOCAL),
    _TEST(0007_autotopic, 0),
    _TEST(0008_reqacks, 0),
    _TEST(0009_mock_cluster,
          TEST_F_LOCAL,
          /* Mock cluster requires MsgVersion 2 */
          TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0011_produce_batch,
          0,
          /* Produces a lot of messages */
          _THRES(.ucpu = 40.0, .scpu = 8.0)),
    _TEST(0012_produce_consume, 0),
    _TEST(0013_null_msgs, 0),
    _TEST(0014_reconsume_191, 0),
    _TEST(0015_offsets_seek, 0),
    _TEST(0016_client_swname, 0),
    _TEST(0017_compression, 0),
    _TEST(0018_cgrp_term, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0019_list_groups, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0020_destroy_hang, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0021_rkt_destroy, 0),
    _TEST(0022_consume_batch, 0),
    _TEST(0022_consume_batch_local, TEST_F_LOCAL),
    _TEST(0025_timers, TEST_F_LOCAL),
    _TEST(0026_consume_pause, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0028_long_topicnames,
          TEST_F_KNOWN_ISSUE,
          TEST_BRKVER(0, 9, 0, 0),
          .extra = "https://github.com/edenhill/librdkafka/issues/529"),
    _TEST(0029_assign_offset, 0),
    _TEST(0030_offset_commit,
          0,
          TEST_BRKVER(0, 9, 0, 0),
          /* Loops over committed() until timeout */
          _THRES(.ucpu = 10.0, .scpu = 5.0)),
    _TEST(0031_get_offsets, 0),
    _TEST(0033_regex_subscribe, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0033_regex_subscribe_local, TEST_F_LOCAL),
    _TEST(0034_offset_reset, 0),
    _TEST(0034_offset_reset_mock, TEST_F_LOCAL),
    _TEST(0035_api_version, 0),
    _TEST(0036_partial_fetch, 0),
    _TEST(0037_destroy_hang_local, TEST_F_LOCAL),
    _TEST(0038_performance,
          0,
          /* Produces and consumes a lot of messages */
          _THRES(.ucpu = 150.0, .scpu = 10)),
    _TEST(0039_event_dr, 0),
    _TEST(0039_event_log, TEST_F_LOCAL),
    _TEST(0039_event, TEST_F_LOCAL),
    _TEST(0040_io_event, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0041_fetch_max_bytes,
          0,
          /* Re-fetches large messages multiple times */
          _THRES(.ucpu = 20.0, .scpu = 10.0)),
    _TEST(0042_many_topics, 0),
    _TEST(0043_no_connection, TEST_F_LOCAL),
    _TEST(0044_partition_cnt,
          0,
          TEST_BRKVER(1, 0, 0, 0),
          /* Produces a lot of messages */
          _THRES(.ucpu = 30.0)),
    _TEST(0045_subscribe_update, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0045_subscribe_update_topic_remove,
          0,
          TEST_BRKVER(0, 9, 0, 0),
          .scenario = "noautocreate"),
    _TEST(0045_subscribe_update_non_exist_and_partchange,
          0,
          TEST_BRKVER(0, 9, 0, 0),
          .scenario = "noautocreate"),
    _TEST(0045_subscribe_update_mock, TEST_F_LOCAL),
    _TEST(0046_rkt_cache, TEST_F_LOCAL),
    _TEST(0047_partial_buf_tmout, TEST_F_KNOWN_ISSUE),
    _TEST(0048_partitioner,
          0,
          /* Produces many small messages */
          _THRES(.ucpu = 10.0, .scpu = 5.0)),
#if WITH_SOCKEM
    _TEST(0049_consume_conn_close, TEST_F_SOCKEM, TEST_BRKVER(0, 9, 0, 0)),
#endif
    _TEST(0050_subscribe_adds, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0051_assign_adds, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0052_msg_timestamps, 0, TEST_BRKVER(0, 10, 0, 0)),
    _TEST(0053_stats_timing, TEST_F_LOCAL),
    _TEST(0053_stats, 0),
    _TEST(0054_offset_time, 0, TEST_BRKVER(0, 10, 1, 0)),
    _TEST(0055_producer_latency, TEST_F_KNOWN_ISSUE_WIN32),
    _TEST(0056_balanced_group_mt, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0057_invalid_topic, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0058_log, TEST_F_LOCAL),
    _TEST(0059_bsearch, 0, TEST_BRKVER(0, 10, 0, 0)),
    _TEST(0060_op_prio, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0061_consumer_lag, 0),
    _TEST(0062_stats_event, TEST_F_LOCAL),
    _TEST(0063_clusterid, 0, TEST_BRKVER(0, 10, 1, 0)),
    _TEST(0064_interceptors, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0065_yield, 0),
    _TEST(0066_plugins,
          TEST_F_LOCAL | TEST_F_KNOWN_ISSUE_WIN32 | TEST_F_KNOWN_ISSUE_OSX,
          .extra =
              "dynamic loading of tests might not be fixed for this platform"),
    _TEST(0067_empty_topic, 0),
#if WITH_SOCKEM
    _TEST(0068_produce_timeout, TEST_F_SOCKEM),
#endif
    _TEST(0069_consumer_add_parts,
          TEST_F_KNOWN_ISSUE_WIN32,
          TEST_BRKVER(1, 0, 0, 0)),
    _TEST(0070_null_empty, 0),
    _TEST(0072_headers_ut, TEST_F_LOCAL),
    _TEST(0073_headers, 0, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0074_producev, TEST_F_LOCAL),
#if WITH_SOCKEM
    _TEST(0075_retry, TEST_F_SOCKEM),
#endif
    _TEST(0076_produce_retry, TEST_F_SOCKEM),
    _TEST(0077_compaction,
          0,
          /* The test itself requires message headers */
          TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0078_c_from_cpp, TEST_F_LOCAL),
    _TEST(0079_fork,
          TEST_F_LOCAL | TEST_F_KNOWN_ISSUE,
          .extra = "using a fork():ed rd_kafka_t is not supported and will "
                   "most likely hang"),
    _TEST(0080_admin_ut, TEST_F_LOCAL),
    _TEST(0081_admin, 0, TEST_BRKVER(0, 10, 2, 0)),
    _TEST(0082_fetch_max_bytes, 0, TEST_BRKVER(0, 10, 1, 0)),
    _TEST(0083_cb_event, 0, TEST_BRKVER(0, 9, 0, 0)),
    _TEST(0084_destroy_flags_local, TEST_F_LOCAL),
    _TEST(0084_destroy_flags, 0),
    _TEST(0085_headers, 0, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0086_purge_local, TEST_F_LOCAL),
    _TEST(0086_purge_remote, 0),
#if WITH_SOCKEM
    _TEST(0088_produce_metadata_timeout, TEST_F_SOCKEM),
#endif
    _TEST(0089_max_poll_interval, 0, TEST_BRKVER(0, 10, 1, 0)),
    _TEST(0090_idempotence, 0, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0091_max_poll_interval_timeout, 0, TEST_BRKVER(0, 10, 1, 0)),
    _TEST(0092_mixed_msgver, 0, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0093_holb_consumer, 0, TEST_BRKVER(0, 10, 1, 0)),
#if WITH_SOCKEM
    _TEST(0094_idempotence_msg_timeout,
          TEST_F_SOCKEM,
          TEST_BRKVER(0, 11, 0, 0)),
#endif
    _TEST(0095_all_brokers_down, TEST_F_LOCAL),
    _TEST(0097_ssl_verify, 0),
    _TEST(0097_ssl_verify_local, TEST_F_LOCAL),
    _TEST(0098_consumer_txn, 0, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0099_commit_metadata, 0),
    _TEST(0100_thread_interceptors, TEST_F_LOCAL),
    _TEST(0101_fetch_from_follower, 0, TEST_BRKVER(2, 4, 0, 0)),
    _TEST(0102_static_group_rebalance, 0, TEST_BRKVER(2, 3, 0, 0)),
    _TEST(0103_transactions_local, TEST_F_LOCAL),
    _TEST(0103_transactions,
          0,
          TEST_BRKVER(0, 11, 0, 0),
          .scenario = "default,ak23"),
    _TEST(0104_fetch_from_follower_mock, TEST_F_LOCAL, TEST_BRKVER(2, 4, 0, 0)),
    _TEST(0105_transactions_mock, TEST_F_LOCAL, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0106_cgrp_sess_timeout, TEST_F_LOCAL, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0107_topic_recreate,
          0,
          TEST_BRKVER_TOPIC_ADMINAPI,
          .scenario = "noautocreate"),
    _TEST(0109_auto_create_topics, 0),
    _TEST(0110_batch_size, 0),
    _TEST(0111_delay_create_topics,
          0,
          TEST_BRKVER_TOPIC_ADMINAPI,
          .scenario = "noautocreate"),
    _TEST(0112_assign_unknown_part, 0),
    _TEST(0113_cooperative_rebalance_local,
          TEST_F_LOCAL,
          TEST_BRKVER(2, 4, 0, 0)),
    _TEST(0113_cooperative_rebalance, 0, TEST_BRKVER(2, 4, 0, 0)),
    _TEST(0114_sticky_partitioning, 0),
    _TEST(0115_producer_auth, 0, TEST_BRKVER(2, 1, 0, 0)),
    _TEST(0116_kafkaconsumer_close, TEST_F_LOCAL),
    _TEST(0117_mock_errors, TEST_F_LOCAL),
    _TEST(0118_commit_rebalance, 0),
    _TEST(0119_consumer_auth, 0, TEST_BRKVER(2, 1, 0, 0)),
    _TEST(0120_asymmetric_subscription, TEST_F_LOCAL),
    _TEST(0121_clusterid, TEST_F_LOCAL),
    _TEST(0122_buffer_cleaning_after_rebalance, 0, TEST_BRKVER(2, 4, 0, 0)),
    _TEST(0123_connections_max_idle, 0),
    _TEST(0124_openssl_invalid_engine, TEST_F_LOCAL),
    _TEST(0125_immediate_flush, 0),
    _TEST(0126_oauthbearer_oidc, 0, TEST_BRKVER(3, 1, 0, 0)),
    _TEST(0128_sasl_callback_queue, TEST_F_LOCAL, TEST_BRKVER(2, 0, 0, 0)),
    _TEST(0129_fetch_aborted_msgs, 0, TEST_BRKVER(0, 11, 0, 0)),
    _TEST(0130_store_offsets, 0),
    _TEST(0131_connect_timeout, TEST_F_LOCAL),
    _TEST(0132_strategy_ordering, 0, TEST_BRKVER(2, 4, 0, 0)),

    /* Manual tests */
    _TEST(8000_idle, TEST_F_MANUAL),

    {NULL}};


RD_TLS struct test *test_curr = &tests[0];



#if WITH_SOCKEM
/**
 * Socket network emulation with sockem
 */

static void test_socket_add(struct test *test, sockem_t *skm) {
        TEST_LOCK();
        rd_list_add(&test->sockets, skm);
        TEST_UNLOCK();
}

static void test_socket_del(struct test *test, sockem_t *skm, int do_lock) {
        if (do_lock)
                TEST_LOCK();
        /* Best effort, skm might not have been added if connect_cb failed */
        rd_list_remove(&test->sockets, skm);
        if (do_lock)
                TEST_UNLOCK();
}

int test_socket_sockem_set_all(const char *key, int val) {
        int i;
        sockem_t *skm;
        int cnt = 0;

        TEST_LOCK();

        cnt = rd_list_cnt(&test_curr->sockets);
        TEST_SAY("Setting sockem %s=%d on %s%d socket(s)\n", key, val,
                 cnt > 0 ? "" : _C_RED, cnt);

        RD_LIST_FOREACH(skm, &test_curr->sockets, i) {
                if (sockem_set(skm, key, val, NULL) == -1)
                        TEST_FAIL("sockem_set(%s, %d) failed", key, val);
        }

        TEST_UNLOCK();

        return cnt;
}

void test_socket_sockem_set(int s, const char *key, int value) {
        sockem_t *skm;

        TEST_LOCK();
        skm = sockem_find(s);
        if (skm)
                sockem_set(skm, key, value, NULL);
        TEST_UNLOCK();
}

void test_socket_close_all(struct test *test, int reinit) {
        TEST_LOCK();
        rd_list_destroy(&test->sockets);
        if (reinit)
                rd_list_init(&test->sockets, 16, (void *)sockem_close);
        TEST_UNLOCK();
}


static int test_connect_cb(int s,
                           const struct sockaddr *addr,
                           int addrlen,
                           const char *id,
                           void *opaque) {
        struct test *test = opaque;
        sockem_t *skm;
        int r;

        skm = sockem_connect(s, addr, addrlen, test_sockem_conf, 0, NULL);
        if (!skm)
                return errno;

        if (test->connect_cb) {
                r = test->connect_cb(test, skm, id);
                if (r)
                        return r;
        }

        test_socket_add(test, skm);

        return 0;
}

static int test_closesocket_cb(int s, void *opaque) {
        struct test *test = opaque;
        sockem_t *skm;

        TEST_LOCK();
        skm = sockem_find(s);
        if (skm) {
                /* Close sockem's sockets */
                sockem_close(skm);
                test_socket_del(test, skm, 0 /*nolock*/);
        }
        TEST_UNLOCK();

        /* Close librdkafka's socket */
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif

        return 0;
}


void test_socket_enable(rd_kafka_conf_t *conf) {
        rd_kafka_conf_set_connect_cb(conf, test_connect_cb);
        rd_kafka_conf_set_closesocket_cb(conf, test_closesocket_cb);
        rd_kafka_conf_set_opaque(conf, test_curr);
}
#endif /* WITH_SOCKEM */

/**
 * @brief For use as the is_fatal_cb(), treating no errors as test-fatal.
 */
int test_error_is_not_fatal_cb(rd_kafka_t *rk,
                               rd_kafka_resp_err_t err,
                               const char *reason) {
        return 0;
}

static void
test_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque) {
        if (test_curr->is_fatal_cb &&
            !test_curr->is_fatal_cb(rk, err, reason)) {
                TEST_SAY(_C_YEL "%s rdkafka error (non-testfatal): %s: %s\n",
                         rd_kafka_name(rk), rd_kafka_err2str(err), reason);
        } else {
                if (err == RD_KAFKA_RESP_ERR__FATAL) {
                        char errstr[512];
                        TEST_SAY(_C_RED "%s Fatal error: %s\n",
                                 rd_kafka_name(rk), reason);

                        err = rd_kafka_fatal_error(rk, errstr, sizeof(errstr));

                        if (test_curr->is_fatal_cb &&
                            !test_curr->is_fatal_cb(rk, err, reason))
                                TEST_SAY(_C_YEL
                                         "%s rdkafka ignored FATAL error: "
                                         "%s: %s\n",
                                         rd_kafka_name(rk),
                                         rd_kafka_err2str(err), errstr);
                        else
                                TEST_FAIL("%s rdkafka FATAL error: %s: %s",
                                          rd_kafka_name(rk),
                                          rd_kafka_err2str(err), errstr);

                } else {
                        TEST_FAIL("%s rdkafka error: %s: %s", rd_kafka_name(rk),
                                  rd_kafka_err2str(err), reason);
                }
        }
}

static int
test_stats_cb(rd_kafka_t *rk, char *json, size_t json_len, void *opaque) {
        struct test *test = test_curr;
        if (test->stats_fp)
                fprintf(test->stats_fp,
                        "{\"test\": \"%s\", \"instance\":\"%s\", "
                        "\"stats\": %s}\n",
                        test->name, rd_kafka_name(rk), json);
        return 0;
}


/**
 * @brief Limit the test run time (in seconds)
 */
void test_timeout_set(int timeout) {
        TEST_LOCK();
        TEST_SAY("Setting test timeout to %ds * %.1f\n", timeout,
                 test_timeout_multiplier);
        timeout            = (int)((double)timeout * test_timeout_multiplier);
        test_curr->timeout = test_clock() + ((int64_t)timeout * 1000000);
        TEST_UNLOCK();
}

int tmout_multip(int msecs) {
        int r;
        TEST_LOCK();
        r = (int)(((double)(msecs)) * test_timeout_multiplier);
        TEST_UNLOCK();
        return r;
}



#ifdef _WIN32
static void test_init_win32(void) {
        /* Enable VT emulation to support colored output. */
        HANDLE hOut  = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;

        if (hOut == INVALID_HANDLE_VALUE || !GetConsoleMode(hOut, &dwMode))
                return;

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x4
#endif
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
}
#endif


static void test_init(void) {
        int seed;
        const char *tmp;


        if (test_seed)
                return;

        if ((tmp = test_getenv("TEST_LEVEL", NULL)))
                test_level = atoi(tmp);
        if ((tmp = test_getenv("TEST_MODE", NULL)))
                strncpy(test_mode, tmp, sizeof(test_mode) - 1);
        if ((tmp = test_getenv("TEST_SCENARIO", NULL)))
                strncpy(test_scenario, tmp, sizeof(test_scenario) - 1);
        if ((tmp = test_getenv("TEST_SOCKEM", NULL)))
                test_sockem_conf = tmp;
        if ((tmp = test_getenv("TEST_SEED", NULL)))
                seed = atoi(tmp);
        else
                seed = test_clock() & 0xffffffff;
        if ((tmp = test_getenv("TEST_CPU_CALIBRATION", NULL))) {
                test_rusage_cpu_calibration = strtod(tmp, NULL);
                if (test_rusage_cpu_calibration < 0.00001) {
                        fprintf(stderr,
                                "%% Invalid CPU calibration "
                                "value (from TEST_CPU_CALIBRATION env): %s\n",
                                tmp);
                        exit(1);
                }
        }

#ifdef _WIN32
        test_init_win32();
        {
                LARGE_INTEGER cycl;
                QueryPerformanceCounter(&cycl);
                seed = (int)cycl.QuadPart;
        }
#endif
        srand(seed);
        test_seed = seed;
}


const char *test_mk_topic_name(const char *suffix, int randomized) {
        static RD_TLS char ret[512];

        /* Strip main_ prefix (caller is using __FUNCTION__) */
        if (!strncmp(suffix, "main_", 5))
                suffix += 5;

        if (test_topic_random || randomized)
                rd_snprintf(ret, sizeof(ret), "%s_rnd%" PRIx64 "_%s",
                            test_topic_prefix, test_id_generate(), suffix);
        else
                rd_snprintf(ret, sizeof(ret), "%s_%s", test_topic_prefix,
                            suffix);

        TEST_SAY("Using topic \"%s\"\n", ret);

        return ret;
}


/**
 * @brief Set special test config property
 * @returns 1 if property was known, else 0.
 */
int test_set_special_conf(const char *name, const char *val, int *timeoutp) {
        if (!strcmp(name, "test.timeout.multiplier")) {
                TEST_LOCK();
                test_timeout_multiplier = strtod(val, NULL);
                TEST_UNLOCK();
                *timeoutp = tmout_multip((*timeoutp) * 1000) / 1000;
        } else if (!strcmp(name, "test.topic.prefix")) {
                rd_snprintf(test_topic_prefix, sizeof(test_topic_prefix), "%s",
                            val);
        } else if (!strcmp(name, "test.topic.random")) {
                if (!strcmp(val, "true") || !strcmp(val, "1"))
                        test_topic_random = 1;
                else
                        test_topic_random = 0;
        } else if (!strcmp(name, "test.concurrent.max")) {
                TEST_LOCK();
                test_concurrent_max = (int)strtod(val, NULL);
                TEST_UNLOCK();
        } else if (!strcmp(name, "test.sql.command")) {
                TEST_LOCK();
                if (test_sql_cmd)
                        rd_free(test_sql_cmd);
                test_sql_cmd = rd_strdup(val);
                TEST_UNLOCK();
        } else
                return 0;

        return 1;
}

static void test_read_conf_file(const char *conf_path,
                                rd_kafka_conf_t *conf,
                                rd_kafka_topic_conf_t *topic_conf,
                                int *timeoutp) {
        FILE *fp;
        char buf[1024];
        int line = 0;

#ifndef _WIN32
        fp = fopen(conf_path, "r");
#else
        fp    = NULL;
        errno = fopen_s(&fp, conf_path, "r");
#endif
        if (!fp) {
                if (errno == ENOENT) {
                        TEST_SAY("Test config file %s not found\n", conf_path);
                        return;
                } else
                        TEST_FAIL("Failed to read %s: %s", conf_path,
                                  strerror(errno));
        }

        while (fgets(buf, sizeof(buf) - 1, fp)) {
                char *t;
                char *b                 = buf;
                rd_kafka_conf_res_t res = RD_KAFKA_CONF_UNKNOWN;
                char *name, *val;
                char errstr[512];

                line++;
                if ((t = strchr(b, '\n')))
                        *t = '\0';

                if (*b == '#' || !*b)
                        continue;

                if (!(t = strchr(b, '=')))
                        TEST_FAIL("%s:%i: expected name=value format\n",
                                  conf_path, line);

                name = b;
                *t   = '\0';
                val  = t + 1;

                if (test_set_special_conf(name, val, timeoutp))
                        continue;

                if (!strncmp(name, "topic.", strlen("topic."))) {
                        name += strlen("topic.");
                        if (topic_conf)
                                res = rd_kafka_topic_conf_set(topic_conf, name,
                                                              val, errstr,
                                                              sizeof(errstr));
                        else
                                res = RD_KAFKA_CONF_OK;
                        name -= strlen("topic.");
                }

                if (res == RD_KAFKA_CONF_UNKNOWN) {
                        if (conf)
                                res = rd_kafka_conf_set(conf, name, val, errstr,
                                                        sizeof(errstr));
                        else
                                res = RD_KAFKA_CONF_OK;
                }

                if (res != RD_KAFKA_CONF_OK)
                        TEST_FAIL("%s:%i: %s\n", conf_path, line, errstr);
        }

        fclose(fp);
}

/**
 * @brief Get path to test config file
 */
const char *test_conf_get_path(void) {
        return test_getenv("RDKAFKA_TEST_CONF", "test.conf");
}

const char *test_getenv(const char *env, const char *def) {
        return rd_getenv(env, def);
}

void test_conf_common_init(rd_kafka_conf_t *conf, int timeout) {
        if (conf) {
                const char *tmp = test_getenv("TEST_DEBUG", NULL);
                if (tmp)
                        test_conf_set(conf, "debug", tmp);
        }

        if (timeout)
                test_timeout_set(timeout);
}


/**
 * Creates and sets up kafka configuration objects.
 * Will read "test.conf" file if it exists.
 */
void test_conf_init(rd_kafka_conf_t **conf,
                    rd_kafka_topic_conf_t **topic_conf,
                    int timeout) {
        const char *test_conf = test_conf_get_path();

        if (conf) {
                *conf = rd_kafka_conf_new();
                rd_kafka_conf_set(*conf, "client.id", test_curr->name, NULL, 0);
                if (test_idempotent_producer)
                        test_conf_set(*conf, "enable.idempotence", "true");
                rd_kafka_conf_set_error_cb(*conf, test_error_cb);
                rd_kafka_conf_set_stats_cb(*conf, test_stats_cb);

                /* Allow higher request timeouts on CI */
                if (test_on_ci)
                        test_conf_set(*conf, "request.timeout.ms", "10000");

#ifdef SIGIO
                {
                        char buf[64];

                        /* Quick termination */
                        rd_snprintf(buf, sizeof(buf), "%i", SIGIO);
                        rd_kafka_conf_set(*conf, "internal.termination.signal",
                                          buf, NULL, 0);
                        signal(SIGIO, SIG_IGN);
                }
#endif
        }

#if WITH_SOCKEM
        if (*test_sockem_conf && conf)
                test_socket_enable(*conf);
#endif

        if (topic_conf)
                *topic_conf = rd_kafka_topic_conf_new();

        /* Open and read optional local test configuration file, if any. */
        test_read_conf_file(test_conf, conf ? *conf : NULL,
                            topic_conf ? *topic_conf : NULL, &timeout);

        test_conf_common_init(conf ? *conf : NULL, timeout);
}


static RD_INLINE unsigned int test_rand(void) {
        unsigned int r;
#ifdef _WIN32
        rand_s(&r);
#else
        r     = rand();
#endif
        return r;
}
/**
 * Generate a "unique" test id.
 */
uint64_t test_id_generate(void) {
        return (((uint64_t)test_rand()) << 32) | (uint64_t)test_rand();
}


/**
 * Generate a "unique" string id
 */
char *test_str_id_generate(char *dest, size_t dest_size) {
        rd_snprintf(dest, dest_size, "%" PRId64, test_id_generate());
        return dest;
}

/**
 * Same as test_str_id_generate but returns a temporary string.
 */
const char *test_str_id_generate_tmp(void) {
        static RD_TLS char ret[64];
        return test_str_id_generate(ret, sizeof(ret));
}

/**
 * Format a message token.
 * Pad's to dest_size.
 */
void test_msg_fmt(char *dest,
                  size_t dest_size,
                  uint64_t testid,
                  int32_t partition,
                  int msgid) {
        size_t of;

        of = rd_snprintf(dest, dest_size,
                         "testid=%" PRIu64 ", partition=%" PRId32 ", msg=%i\n",
                         testid, partition, msgid);
        if (of < dest_size - 1) {
                memset(dest + of, '!', dest_size - of);
                dest[dest_size - 1] = '\0';
        }
}

/**
 * @brief Prepare message value and key for test produce.
 */
void test_prepare_msg(uint64_t testid,
                      int32_t partition,
                      int msg_id,
                      char *val,
                      size_t val_size,
                      char *key,
                      size_t key_size) {
        size_t of = 0;

        test_msg_fmt(key, key_size, testid, partition, msg_id);

        while (of < val_size) {
                /* Copy-repeat key into val until val_size */
                size_t len = RD_MIN(val_size - of, key_size);
                memcpy(val + of, key, len);
                of += len;
        }
}



/**
 * Parse a message token
 */
void test_msg_parse00(const char *func,
                      int line,
                      uint64_t testid,
                      int32_t exp_partition,
                      int *msgidp,
                      const char *topic,
                      int32_t partition,
                      int64_t offset,
                      const char *key,
                      size_t key_size) {
        char buf[128];
        uint64_t in_testid;
        int in_part;

        if (!key)
                TEST_FAIL("%s:%i: Message (%s [%" PRId32 "] @ %" PRId64
                          ") "
                          "has empty key\n",
                          func, line, topic, partition, offset);

        rd_snprintf(buf, sizeof(buf), "%.*s", (int)key_size, key);

        if (sscanf(buf, "testid=%" SCNu64 ", partition=%i, msg=%i\n",
                   &in_testid, &in_part, msgidp) != 3)
                TEST_FAIL("%s:%i: Incorrect key format: %s", func, line, buf);


        if (testid != in_testid ||
            (exp_partition != -1 && exp_partition != in_part))
                TEST_FAIL("%s:%i: Our testid %" PRIu64
                          ", part %i did "
                          "not match message: \"%s\"\n",
                          func, line, testid, (int)exp_partition, buf);
}

void test_msg_parse0(const char *func,
                     int line,
                     uint64_t testid,
                     rd_kafka_message_t *rkmessage,
                     int32_t exp_partition,
                     int *msgidp) {
        test_msg_parse00(func, line, testid, exp_partition, msgidp,
                         rd_kafka_topic_name(rkmessage->rkt),
                         rkmessage->partition, rkmessage->offset,
                         (const char *)rkmessage->key, rkmessage->key_len);
}


struct run_args {
        struct test *test;
        int argc;
        char **argv;
};

static int run_test0(struct run_args *run_args) {
        struct test *test = run_args->test;
        test_timing_t t_run;
        int r;
        char stats_file[256];

        rd_snprintf(stats_file, sizeof(stats_file), "stats_%s_%" PRIu64 ".json",
                    test->name, test_id_generate());
        if (!(test->stats_fp = fopen(stats_file, "w+")))
                TEST_SAY("=== Failed to create stats file %s: %s ===\n",
                         stats_file, strerror(errno));

        test_curr = test;

#if WITH_SOCKEM
        rd_list_init(&test->sockets, 16, (void *)sockem_close);
#endif
        /* Don't check message status by default */
        test->exp_dr_status = (rd_kafka_msg_status_t)-1;

        TEST_SAY("================= Running test %s =================\n",
                 test->name);
        if (test->stats_fp)
                TEST_SAY("==== Stats written to file %s ====\n", stats_file);

        test_rusage_start(test_curr);
        TIMING_START(&t_run, "%s", test->name);
        test->start = t_run.ts_start;

        /* Run test main function */
        r = test->mainfunc(run_args->argc, run_args->argv);

        TIMING_STOP(&t_run);
        test_rusage_stop(test_curr,
                         (double)TIMING_DURATION(&t_run) / 1000000.0);

        TEST_LOCK();
        test->duration = TIMING_DURATION(&t_run);

        if (test->state == TEST_SKIPPED) {
                TEST_SAY(
                    "================= Test %s SKIPPED "
                    "=================\n",
                    run_args->test->name);
        } else if (r) {
                test->state = TEST_FAILED;
                TEST_SAY(
                    "\033[31m"
                    "================= Test %s FAILED ================="
                    "\033[0m\n",
                    run_args->test->name);
        } else {
                test->state = TEST_PASSED;
                TEST_SAY(
                    "\033[32m"
                    "================= Test %s PASSED ================="
                    "\033[0m\n",
                    run_args->test->name);
        }
        TEST_UNLOCK();

        cnd_broadcast(&test_cnd);

#if WITH_SOCKEM
        test_socket_close_all(test, 0);
#endif

        if (test->stats_fp) {
                long pos = ftell(test->stats_fp);
                fclose(test->stats_fp);
                test->stats_fp = NULL;
                /* Delete file if nothing was written */
                if (pos == 0) {
#ifndef _WIN32
                        unlink(stats_file);
#else
                        _unlink(stats_file);
#endif
                }
        }

        if (test_delete_topics_between && test_concurrent_max == 1)
                test_delete_all_test_topics(60 * 1000);

        return r;
}



static int run_test_from_thread(void *arg) {
        struct run_args *run_args = arg;

        thrd_detach(thrd_current());

        run_test0(run_args);

        TEST_LOCK();
        tests_running_cnt--;
        TEST_UNLOCK();

        free(run_args);

        return 0;
}


/**
 * @brief Check running tests for timeouts.
 * @locks TEST_LOCK MUST be held
 */
static void check_test_timeouts(void) {
        int64_t now = test_clock();
        struct test *test;

        for (test = tests; test->name; test++) {
                if (test->state != TEST_RUNNING)
                        continue;

                /* Timeout check */
                if (now > test->timeout) {
                        struct test *save_test = test_curr;
                        test_curr              = test;
                        test->state            = TEST_FAILED;
                        test_summary(0 /*no-locks*/);
                        TEST_FAIL0(
                            __FILE__, __LINE__, 0 /*nolock*/, 0 /*fail-later*/,
                            "Test %s%s%s%s timed out "
                            "(timeout set to %d seconds)\n",
                            test->name, *test->subtest ? " (" : "",
                            test->subtest, *test->subtest ? ")" : "",
                            (int)(test->timeout - test->start) / 1000000);
                        test_curr = save_test;
                        tests_running_cnt--; /* fail-later misses this*/
#ifdef _WIN32
                        TerminateThread(test->thrd, -1);
#else
                        pthread_kill(test->thrd, SIGKILL);
#endif
                }
        }
}


static int run_test(struct test *test, int argc, char **argv) {
        struct run_args *run_args = calloc(1, sizeof(*run_args));
        int wait_cnt              = 0;

        run_args->test = test;
        run_args->argc = argc;
        run_args->argv = argv;

        TEST_LOCK();
        while (tests_running_cnt >= test_concurrent_max) {
                if (!(wait_cnt++ % 100))
                        TEST_SAY(
                            "Too many tests running (%d >= %d): "
                            "postponing %s start...\n",
                            tests_running_cnt, test_concurrent_max, test->name);
                cnd_timedwait_ms(&test_cnd, &test_mtx, 100);

                check_test_timeouts();
        }
        tests_running_cnt++;
        test->timeout = test_clock() +
                        (int64_t)(30.0 * 1000000.0 * test_timeout_multiplier);
        test->state = TEST_RUNNING;
        TEST_UNLOCK();

        if (thrd_create(&test->thrd, run_test_from_thread, run_args) !=
            thrd_success) {
                TEST_LOCK();
                tests_running_cnt--;
                test->state = TEST_FAILED;
                TEST_UNLOCK();

                TEST_FAIL("Failed to start thread for test %s\n", test->name);
        }

        return 0;
}

static void run_tests(int argc, char **argv) {
        struct test *test;

        for (test = tests; test->name; test++) {
                char testnum[128];
                char *t;
                const char *skip_reason = NULL;
                rd_bool_t skip_silent   = rd_false;
                char tmp[128];
                const char *scenario =
                    test->scenario ? test->scenario : "default";

                if (!test->mainfunc)
                        continue;

                /* Extract test number, as string */
                strncpy(testnum, test->name, sizeof(testnum) - 1);
                testnum[sizeof(testnum) - 1] = '\0';
                if ((t = strchr(testnum, '_')))
                        *t = '\0';

                if ((test_flags && (test_flags & test->flags) != test_flags)) {
                        skip_reason = "filtered due to test flags";
                        skip_silent = rd_true;
                }
                if ((test_neg_flags & ~test_flags) & test->flags)
                        skip_reason = "Filtered due to negative test flags";
                if (test_broker_version &&
                    (test->minver > test_broker_version ||
                     (test->maxver && test->maxver < test_broker_version))) {
                        rd_snprintf(tmp, sizeof(tmp),
                                    "not applicable for broker "
                                    "version %d.%d.%d.%d",
                                    TEST_BRKVER_X(test_broker_version, 0),
                                    TEST_BRKVER_X(test_broker_version, 1),
                                    TEST_BRKVER_X(test_broker_version, 2),
                                    TEST_BRKVER_X(test_broker_version, 3));
                        skip_reason = tmp;
                }

                if (!strstr(scenario, test_scenario)) {
                        rd_snprintf(tmp, sizeof(tmp),
                                    "requires test scenario %s", scenario);
                        skip_silent = rd_true;
                        skip_reason = tmp;
                }

                if (tests_to_run && !strstr(tests_to_run, testnum)) {
                        skip_reason = "not included in TESTS list";
                        skip_silent = rd_true;
                } else if (!tests_to_run && (test->flags & TEST_F_MANUAL)) {
                        skip_reason = "manual test";
                        skip_silent = rd_true;
                } else if (tests_to_skip && strstr(tests_to_skip, testnum))
                        skip_reason = "included in TESTS_SKIP list";

                if (!skip_reason) {
                        run_test(test, argc, argv);
                } else {
                        if (skip_silent) {
                                TEST_SAYL(3,
                                          "================= Skipping test %s "
                                          "(%s) ================\n",
                                          test->name, skip_reason);
                                TEST_LOCK();
                                test->state = TEST_SKIPPED;
                                TEST_UNLOCK();
                        } else {
                                test_curr = test;
                                TEST_SKIP("%s\n", skip_reason);
                                test_curr = &tests[0];
                        }
                }
        }
}

/**
 * @brief Print summary for all tests.
 *
 * @returns the number of failed tests.
 */
static int test_summary(int do_lock) {
        struct test *test;
        FILE *report_fp = NULL;
        char report_path[128];
        time_t t;
        struct tm *tm;
        char datestr[64];
        int64_t total_duration = 0;
        int tests_run          = 0;
        int tests_failed       = 0;
        int tests_failed_known = 0;
        int tests_passed       = 0;
        FILE *sql_fp           = NULL;
        const char *tmp;

        t  = time(NULL);
        tm = localtime(&t);
        strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%S", tm);

        if ((tmp = test_getenv("TEST_REPORT", NULL)))
                rd_snprintf(report_path, sizeof(report_path), "%s", tmp);
        else if (test_write_report)
                rd_snprintf(report_path, sizeof(report_path),
                            "test_report_%s.json", datestr);
        else
                report_path[0] = '\0';

        if (*report_path) {
                report_fp = fopen(report_path, "w+");
                if (!report_fp)
                        TEST_WARN("Failed to create report file %s: %s\n",
                                  report_path, strerror(errno));
                else
                        fprintf(report_fp,
                                "{ \"id\": \"%s_%s\", \"mode\": \"%s\", "
                                "\"scenario\": \"%s\", "
                                "\"date\": \"%s\", "
                                "\"git_version\": \"%s\", "
                                "\"broker_version\": \"%s\", "
                                "\"tests\": {",
                                datestr, test_mode, test_mode, test_scenario,
                                datestr, test_git_version,
                                test_broker_version_str);
        }

        if (do_lock)
                TEST_LOCK();

        if (test_sql_cmd) {
#ifdef _WIN32
                sql_fp = _popen(test_sql_cmd, "w");
#else
                sql_fp = popen(test_sql_cmd, "w");
#endif

                fprintf(sql_fp,
                        "CREATE TABLE IF NOT EXISTS "
                        "runs(runid text PRIMARY KEY, mode text, "
                        "date datetime, cnt int, passed int, failed int, "
                        "duration numeric);\n"
                        "CREATE TABLE IF NOT EXISTS "
                        "tests(runid text, mode text, name text, state text, "
                        "extra text, duration numeric);\n");
        }

        if (show_summary)
                printf(
                    "TEST %s (%s, scenario %s) SUMMARY\n"
                    "#========================================================="
                    "=========#\n",
                    datestr, test_mode, test_scenario);

        for (test = tests; test->name; test++) {
                const char *color;
                int64_t duration;
                char extra[128] = "";
                int do_count    = 1;

                if (!(duration = test->duration) && test->start > 0)
                        duration = test_clock() - test->start;

                if (test == tests) {
                        /* <MAIN> test:
                         * test accounts for total runtime.
                         * dont include in passed/run/failed counts. */
                        total_duration = duration;
                        do_count       = 0;
                }

                switch (test->state) {
                case TEST_PASSED:
                        color = _C_GRN;
                        if (do_count) {
                                tests_passed++;
                                tests_run++;
                        }
                        break;
                case TEST_FAILED:
                        if (test->flags & TEST_F_KNOWN_ISSUE) {
                                rd_snprintf(extra, sizeof(extra),
                                            " <-- known issue%s%s",
                                            test->extra ? ": " : "",
                                            test->extra ? test->extra : "");
                                if (do_count)
                                        tests_failed_known++;
                        }
                        color = _C_RED;
                        if (do_count) {
                                tests_failed++;
                                tests_run++;
                        }
                        break;
                case TEST_RUNNING:
                        color = _C_MAG;
                        if (do_count) {
                                tests_failed++; /* All tests should be finished
                                                 */
                                tests_run++;
                        }
                        break;
                case TEST_NOT_STARTED:
                        color = _C_YEL;
                        if (test->extra)
                                rd_snprintf(extra, sizeof(extra), " %s",
                                            test->extra);
                        break;
                default:
                        color = _C_CYA;
                        break;
                }

                if (show_summary &&
                    (test->state != TEST_SKIPPED || *test->failstr ||
                     (tests_to_run && !strncmp(tests_to_run, test->name,
                                               strlen(tests_to_run))))) {
                        printf("|%s %-40s | %10s | %7.3fs %s|", color,
                               test->name, test_states[test->state],
                               (double)duration / 1000000.0, _C_CLR);
                        if (test->state == TEST_FAILED)
                                printf(_C_RED " %s" _C_CLR, test->failstr);
                        else if (test->state == TEST_SKIPPED)
                                printf(_C_CYA " %s" _C_CLR, test->failstr);
                        printf("%s\n", extra);
                }

                if (report_fp) {
                        int i;
                        fprintf(report_fp,
                                "%s\"%s\": {"
                                "\"name\": \"%s\", "
                                "\"state\": \"%s\", "
                                "\"known_issue\": %s, "
                                "\"extra\": \"%s\", "
                                "\"duration\": %.3f, "
                                "\"report\": [ ",
                                test == tests ? "" : ", ", test->name,
                                test->name, test_states[test->state],
                                test->flags & TEST_F_KNOWN_ISSUE ? "true"
                                                                 : "false",
                                test->extra ? test->extra : "",
                                (double)duration / 1000000.0);

                        for (i = 0; i < test->report_cnt; i++) {
                                fprintf(report_fp, "%s%s ", i == 0 ? "" : ",",
                                        test->report_arr[i]);
                        }

                        fprintf(report_fp, "] }");
                }

                if (sql_fp)
                        fprintf(sql_fp,
                                "INSERT INTO tests VALUES("
                                "'%s_%s', '%s', '%s', '%s', '%s', %f);\n",
                                datestr, test_mode, test_mode, test->name,
                                test_states[test->state],
                                test->extra ? test->extra : "",
                                (double)duration / 1000000.0);
        }
        if (do_lock)
                TEST_UNLOCK();

        if (show_summary)
                printf(
                    "#========================================================="
                    "=========#\n");

        if (report_fp) {
                fprintf(report_fp,
                        "}, "
                        "\"tests_run\": %d, "
                        "\"tests_passed\": %d, "
                        "\"tests_failed\": %d, "
                        "\"duration\": %.3f"
                        "}\n",
                        tests_run, tests_passed, tests_failed,
                        (double)total_duration / 1000000.0);

                fclose(report_fp);
                TEST_SAY("# Test report written to %s\n", report_path);
        }

        if (sql_fp) {
                fprintf(sql_fp,
                        "INSERT INTO runs VALUES('%s_%s', '%s', datetime(), "
                        "%d, %d, %d, %f);\n",
                        datestr, test_mode, test_mode, tests_run, tests_passed,
                        tests_failed, (double)total_duration / 1000000.0);
                fclose(sql_fp);
        }

        return tests_failed - tests_failed_known;
}

#ifndef _WIN32
static void test_sig_term(int sig) {
        if (test_exit)
                exit(1);
        fprintf(stderr,
                "Exiting tests, waiting for running tests to finish.\n");
        test_exit = 1;
}
#endif

/**
 * Wait 'timeout' seconds for rdkafka to kill all its threads and clean up.
 */
static void test_wait_exit(int timeout) {
        int r;
        time_t start = time(NULL);

        while ((r = rd_kafka_thread_cnt()) && timeout-- >= 0) {
                TEST_SAY("%i thread(s) in use by librdkafka, waiting...\n", r);
                rd_sleep(1);
        }

        TEST_SAY("%i thread(s) in use by librdkafka\n", r);

        if (r > 0)
                TEST_FAIL("%i thread(s) still active in librdkafka", r);

        timeout -= (int)(time(NULL) - start);
        if (timeout > 0) {
                TEST_SAY(
                    "Waiting %d seconds for all librdkafka memory "
                    "to be released\n",
                    timeout);
                if (rd_kafka_wait_destroyed(timeout * 1000) == -1)
                        TEST_FAIL(
                            "Not all internal librdkafka "
                            "objects destroyed\n");
        }
}



/**
 * @brief Test framework cleanup before termination.
 */
static void test_cleanup(void) {
        struct test *test;

        /* Free report arrays */
        for (test = tests; test->name; test++) {
                int i;
                if (!test->report_arr)
                        continue;
                for (i = 0; i < test->report_cnt; i++)
                        rd_free(test->report_arr[i]);
                rd_free(test->report_arr);
                test->report_arr = NULL;
        }

        if (test_sql_cmd)
                rd_free(test_sql_cmd);
}


int main(int argc, char **argv) {
        int i, r;
        test_timing_t t_all;
        int a, b, c, d;
        const char *tmpver;

        mtx_init(&test_mtx, mtx_plain);
        cnd_init(&test_cnd);

        test_init();

#ifndef _WIN32
        signal(SIGINT, test_sig_term);
#endif
        tests_to_run    = test_getenv("TESTS", NULL);
        subtests_to_run = test_getenv("SUBTESTS", NULL);
        tests_to_skip   = test_getenv("TESTS_SKIP", NULL);
        tmpver          = test_getenv("TEST_KAFKA_VERSION", NULL);
        if (!tmpver)
                tmpver = test_getenv("KAFKA_VERSION", test_broker_version_str);
        test_broker_version_str = tmpver;

        test_git_version = test_getenv("RDKAFKA_GITVER", "HEAD");

        /* Are we running on CI? */
        if (test_getenv("CI", NULL)) {
                test_on_ci          = 1;
                test_concurrent_max = 3;
        }

        test_conf_init(NULL, NULL, 10);

        for (i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-p", 2) && strlen(argv[i]) > 2) {
                        if (test_rusage) {
                                fprintf(stderr,
                                        "%% %s ignored: -R takes preceedence\n",
                                        argv[i]);
                                continue;
                        }
                        test_concurrent_max = (int)strtod(argv[i] + 2, NULL);
                } else if (!strcmp(argv[i], "-l"))
                        test_flags |= TEST_F_LOCAL;
                else if (!strcmp(argv[i], "-L"))
                        test_neg_flags |= TEST_F_LOCAL;
                else if (!strcmp(argv[i], "-a"))
                        test_assert_on_fail = 1;
                else if (!strcmp(argv[i], "-k"))
                        test_flags |= TEST_F_KNOWN_ISSUE;
                else if (!strcmp(argv[i], "-K"))
                        test_neg_flags |= TEST_F_KNOWN_ISSUE;
                else if (!strcmp(argv[i], "-E"))
                        test_neg_flags |= TEST_F_SOCKEM;
                else if (!strcmp(argv[i], "-V") && i + 1 < argc)
                        test_broker_version_str = argv[++i];
                else if (!strcmp(argv[i], "-s") && i + 1 < argc)
                        strncpy(test_scenario, argv[++i],
                                sizeof(test_scenario) - 1);
                else if (!strcmp(argv[i], "-S"))
                        show_summary = 0;
                else if (!strcmp(argv[i], "-D"))
                        test_delete_topics_between = 1;
                else if (!strcmp(argv[i], "-P"))
                        test_idempotent_producer = 1;
                else if (!strcmp(argv[i], "-Q"))
                        test_quick = 1;
                else if (!strcmp(argv[i], "-r"))
                        test_write_report = 1;
                else if (!strncmp(argv[i], "-R", 2)) {
                        test_rusage         = 1;
                        test_concurrent_max = 1;
                        if (strlen(argv[i]) > strlen("-R")) {
                                test_rusage_cpu_calibration =
                                    strtod(argv[i] + 2, NULL);
                                if (test_rusage_cpu_calibration < 0.00001) {
                                        fprintf(stderr,
                                                "%% Invalid CPU calibration "
                                                "value: %s\n",
                                                argv[i] + 2);
                                        exit(1);
                                }
                        }
                } else if (*argv[i] != '-')
                        tests_to_run = argv[i];
                else {
                        printf(
                            "Unknown option: %s\n"
                            "\n"
                            "Usage: %s [options] [<test-match-substr>]\n"
                            "Options:\n"
                            "  -p<N>  Run N tests in parallel\n"
                            "  -l/-L  Only/dont run local tests (no broker "
                            "needed)\n"
                            "  -k/-K  Only/dont run tests with known issues\n"
                            "  -E     Don't run sockem tests\n"
                            "  -a     Assert on failures\n"
                            "  -r     Write test_report_...json file.\n"
                            "  -S     Dont show test summary\n"
                            "  -s <scenario> Test scenario.\n"
                            "  -V <N.N.N.N> Broker version.\n"
                            "  -D     Delete all test topics between each test "
                            "(-p1) or after all tests\n"
                            "  -P     Run all tests with "
                            "`enable.idempotency=true`\n"
                            "  -Q     Run tests in quick mode: faster tests, "
                            "fewer iterations, less data.\n"
                            "  -R     Check resource usage thresholds.\n"
                            "  -R<C>  Check resource usage thresholds but "
                            "adjust CPU thresholds by C (float):\n"
                            "            C < 1.0: CPU is faster than base line "
                            "system.\n"
                            "            C > 1.0: CPU is slower than base line "
                            "system.\n"
                            "            E.g. -R2.5 = CPU is 2.5x slower than "
                            "base line system.\n"
                            "\n"
                            "Environment variables:\n"
                            "  TESTS - substring matched test to run (e.g., "
                            "0033)\n"
                            "  SUBTESTS - substring matched subtest to run "
                            "(e.g., n_wildcard)\n"
                            "  TEST_KAFKA_VERSION - broker version (e.g., "
                            "0.9.0.1)\n"
                            "  TEST_SCENARIO - Test scenario\n"
                            "  TEST_LEVEL - Test verbosity level\n"
                            "  TEST_MODE - bare, helgrind, valgrind\n"
                            "  TEST_SEED - random seed\n"
                            "  RDKAFKA_TEST_CONF - test config file "
                            "(test.conf)\n"
                            "  KAFKA_PATH - Path to kafka source dir\n"
                            "  ZK_ADDRESS - Zookeeper address\n"
                            "\n",
                            argv[i], argv[0]);
                        exit(1);
                }
        }

        TEST_SAY("Git version: %s\n", test_git_version);

        if (!strcmp(test_broker_version_str, "trunk"))
                test_broker_version_str = "9.9.9.9"; /* for now */

        d = 0;
        if (sscanf(test_broker_version_str, "%d.%d.%d.%d", &a, &b, &c, &d) <
            3) {
                printf(
                    "%% Expected broker version to be in format "
                    "N.N.N (N=int), not %s\n",
                    test_broker_version_str);
                exit(1);
        }
        test_broker_version = TEST_BRKVER(a, b, c, d);
        TEST_SAY("Broker version: %s (%d.%d.%d.%d)\n", test_broker_version_str,
                 TEST_BRKVER_X(test_broker_version, 0),
                 TEST_BRKVER_X(test_broker_version, 1),
                 TEST_BRKVER_X(test_broker_version, 2),
                 TEST_BRKVER_X(test_broker_version, 3));

        /* Set up fake "<MAIN>" test for all operations performed in
         * the main thread rather than the per-test threads.
         * Nice side effect is that we get timing and status for main as well.*/
        test_curr        = &tests[0];
        test_curr->state = TEST_PASSED;
        test_curr->start = test_clock();

        if (test_on_ci) {
                TEST_LOCK();
                test_timeout_multiplier += 2;
                TEST_UNLOCK();
        }

        if (!strcmp(test_mode, "helgrind") || !strcmp(test_mode, "drd")) {
                TEST_LOCK();
                test_timeout_multiplier += 5;
                TEST_UNLOCK();
        } else if (!strcmp(test_mode, "valgrind")) {
                TEST_LOCK();
                test_timeout_multiplier += 3;
                TEST_UNLOCK();
        }

        /* Broker version 0.9 and api.version.request=true (which is default)
         * will cause a 10s stall per connection. Instead of fixing
         * that for each affected API in every test we increase the timeout
         * multiplier accordingly instead. The typical consume timeout is 5
         * seconds, so a multiplier of 3 should be good. */
        if ((test_broker_version & 0xffff0000) == 0x00090000)
                test_timeout_multiplier += 3;

        if (test_concurrent_max > 1)
                test_timeout_multiplier += (double)test_concurrent_max / 3;

        TEST_SAY("Tests to run : %s\n", tests_to_run ? tests_to_run : "all");
        if (subtests_to_run)
                TEST_SAY("Sub tests    : %s\n", subtests_to_run);
        if (tests_to_skip)
                TEST_SAY("Skip tests   : %s\n", tests_to_skip);
        TEST_SAY("Test mode    : %s%s%s\n", test_quick ? "quick, " : "",
                 test_mode, test_on_ci ? ", CI" : "");
        TEST_SAY("Test scenario: %s\n", test_scenario);
        TEST_SAY("Test filter  : %s\n", (test_flags & TEST_F_LOCAL)
                                            ? "local tests only"
                                            : "no filter");
        TEST_SAY("Test timeout multiplier: %.1f\n", test_timeout_multiplier);
        TEST_SAY("Action on test failure: %s\n",
                 test_assert_on_fail ? "assert crash" : "continue other tests");
        if (test_rusage)
                TEST_SAY("Test rusage : yes (%.2fx CPU calibration)\n",
                         test_rusage_cpu_calibration);
        if (test_idempotent_producer)
                TEST_SAY("Test Idempotent Producer: enabled\n");

        {
                char cwd[512], *pcwd;
#ifdef _WIN32
                pcwd = _getcwd(cwd, sizeof(cwd) - 1);
#else
                pcwd   = getcwd(cwd, sizeof(cwd) - 1);
#endif
                if (pcwd)
                        TEST_SAY("Current directory: %s\n", cwd);
        }

        test_timeout_set(30);

        TIMING_START(&t_all, "ALL-TESTS");

        /* Run tests */
        run_tests(argc, argv);

        TEST_LOCK();
        while (tests_running_cnt > 0 && !test_exit) {
                struct test *test;

                if (!test_quick && test_level >= 2) {
                        TEST_SAY("%d test(s) running:", tests_running_cnt);

                        for (test = tests; test->name; test++) {
                                if (test->state != TEST_RUNNING)
                                        continue;

                                TEST_SAY0(" %s", test->name);
                        }

                        TEST_SAY0("\n");
                }

                check_test_timeouts();

                TEST_UNLOCK();

                if (test_quick)
                        rd_usleep(200 * 1000, NULL);
                else
                        rd_sleep(1);
                TEST_LOCK();
        }

        TIMING_STOP(&t_all);

        test_curr           = &tests[0];
        test_curr->duration = test_clock() - test_curr->start;

        TEST_UNLOCK();

        if (test_delete_topics_between)
                test_delete_all_test_topics(60 * 1000);

        r = test_summary(1 /*lock*/) ? 1 : 0;

        /* Wait for everything to be cleaned up since broker destroys are
         * handled in its own thread. */
        test_wait_exit(0);

        /* If we havent failed at this point then
         * there were no threads leaked */
        if (r == 0)
                TEST_SAY("\n============== ALL TESTS PASSED ==============\n");

        test_cleanup();

        if (r > 0)
                TEST_FAIL("%d test(s) failed, see previous errors", r);

        return r;
}



/******************************************************************************
 *
 * Helpers
 *
 ******************************************************************************/

void test_dr_msg_cb(rd_kafka_t *rk,
                    const rd_kafka_message_t *rkmessage,
                    void *opaque) {
        int *remainsp                     = rkmessage->_private;
        static const char *status_names[] = {
            [RD_KAFKA_MSG_STATUS_NOT_PERSISTED]      = "NotPersisted",
            [RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED] = "PossiblyPersisted",
            [RD_KAFKA_MSG_STATUS_PERSISTED]          = "Persisted"};

        TEST_SAYL(4,
                  "Delivery report: %s (%s) to %s [%" PRId32
                  "] "
                  "at offset %" PRId64 " latency %.2fms\n",
                  rd_kafka_err2str(rkmessage->err),
                  status_names[rd_kafka_message_status(rkmessage)],
                  rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition,
                  rkmessage->offset,
                  (float)rd_kafka_message_latency(rkmessage) / 1000.0);

        if (!test_curr->produce_sync) {
                if (!test_curr->ignore_dr_err &&
                    rkmessage->err != test_curr->exp_dr_err)
                        TEST_FAIL("Message delivery (to %s [%" PRId32
                                  "]) "
                                  "failed: expected %s, got %s",
                                  rd_kafka_topic_name(rkmessage->rkt),
                                  rkmessage->partition,
                                  rd_kafka_err2str(test_curr->exp_dr_err),
                                  rd_kafka_err2str(rkmessage->err));

                if ((int)test_curr->exp_dr_status != -1) {
                        rd_kafka_msg_status_t status =
                            rd_kafka_message_status(rkmessage);

                        TEST_ASSERT(status == test_curr->exp_dr_status,
                                    "Expected message status %s, not %s",
                                    status_names[test_curr->exp_dr_status],
                                    status_names[status]);
                }

                /* Add message to msgver */
                if (!rkmessage->err && test_curr->dr_mv)
                        test_msgver_add_msg(rk, test_curr->dr_mv, rkmessage);
        }

        if (remainsp) {
                TEST_ASSERT(*remainsp > 0,
                            "Too many messages delivered (remains %i)",
                            *remainsp);

                (*remainsp)--;
        }

        if (test_curr->produce_sync)
                test_curr->produce_sync_err = rkmessage->err;
}


rd_kafka_t *test_create_handle(int mode, rd_kafka_conf_t *conf) {
        rd_kafka_t *rk;
        char errstr[512];

        if (!conf) {
                test_conf_init(&conf, NULL, 0);
#if WITH_SOCKEM
                if (*test_sockem_conf)
                        test_socket_enable(conf);
#endif
        } else {
                if (!strcmp(test_conf_get(conf, "client.id"), "rdkafka"))
                        test_conf_set(conf, "client.id", test_curr->name);
        }



        /* Creat kafka instance */
        rk = rd_kafka_new(mode, conf, errstr, sizeof(errstr));
        if (!rk)
                TEST_FAIL("Failed to create rdkafka instance: %s\n", errstr);

        TEST_SAY("Created    kafka instance %s\n", rd_kafka_name(rk));

        return rk;
}


rd_kafka_t *test_create_producer(void) {
        rd_kafka_conf_t *conf;

        test_conf_init(&conf, NULL, 0);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        return test_create_handle(RD_KAFKA_PRODUCER, conf);
}


/**
 * Create topic_t object with va-arg list as key-value config pairs
 * terminated by NULL.
 */
rd_kafka_topic_t *
test_create_topic_object(rd_kafka_t *rk, const char *topic, ...) {
        rd_kafka_topic_t *rkt;
        rd_kafka_topic_conf_t *topic_conf;
        va_list ap;
        const char *name, *val;

        test_conf_init(NULL, &topic_conf, 0);

        va_start(ap, topic);
        while ((name = va_arg(ap, const char *)) &&
               (val = va_arg(ap, const char *))) {
                test_topic_conf_set(topic_conf, name, val);
        }
        va_end(ap);

        rkt = rd_kafka_topic_new(rk, topic, topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_kafka_err2str(rd_kafka_last_error()));

        return rkt;
}


rd_kafka_topic_t *
test_create_producer_topic(rd_kafka_t *rk, const char *topic, ...) {
        rd_kafka_topic_t *rkt;
        rd_kafka_topic_conf_t *topic_conf;
        char errstr[512];
        va_list ap;
        const char *name, *val;

        test_conf_init(NULL, &topic_conf, 0);

        va_start(ap, topic);
        while ((name = va_arg(ap, const char *)) &&
               (val = va_arg(ap, const char *))) {
                if (rd_kafka_topic_conf_set(topic_conf, name, val, errstr,
                                            sizeof(errstr)) != RD_KAFKA_CONF_OK)
                        TEST_FAIL("Conf failed: %s\n", errstr);
        }
        va_end(ap);

        /* Make sure all replicas are in-sync after producing
         * so that consume test wont fail. */
        rd_kafka_topic_conf_set(topic_conf, "request.required.acks", "-1",
                                errstr, sizeof(errstr));


        rkt = rd_kafka_topic_new(rk, topic, topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_kafka_err2str(rd_kafka_last_error()));

        return rkt;
}



/**
 * Produces \p cnt messages and returns immediately.
 * Does not wait for delivery.
 * \p msgcounterp is incremented for each produced messages and passed
 * as \p msg_opaque which is later used in test_dr_msg_cb to decrement
 * the counter on delivery.
 *
 * If \p payload is NULL the message key and payload will be formatted
 * according to standard test format, otherwise the key will be NULL and
 * payload send as message payload.
 *
 * Default message size is 128 bytes, if \p size is non-zero and \p payload
 * is NULL the message size of \p size will be used.
 */
void test_produce_msgs_nowait(rd_kafka_t *rk,
                              rd_kafka_topic_t *rkt,
                              uint64_t testid,
                              int32_t partition,
                              int msg_base,
                              int cnt,
                              const char *payload,
                              size_t size,
                              int msgrate,
                              int *msgcounterp) {
        int msg_id;
        test_timing_t t_all, t_poll;
        char key[128];
        void *buf;
        int64_t tot_bytes     = 0;
        int64_t tot_time_poll = 0;
        int64_t per_msg_wait  = 0;

        if (msgrate > 0)
                per_msg_wait = 1000000 / (int64_t)msgrate;


        if (payload)
                buf = (void *)payload;
        else {
                if (size == 0)
                        size = 128;
                buf = calloc(1, size);
        }

        TEST_SAY("Produce to %s [%" PRId32 "]: messages #%d..%d\n",
                 rd_kafka_topic_name(rkt), partition, msg_base, msg_base + cnt);

        TIMING_START(&t_all, "PRODUCE");
        TIMING_START(&t_poll, "SUM(POLL)");

        for (msg_id = msg_base; msg_id < msg_base + cnt; msg_id++) {
                int wait_time = 0;

                if (!payload)
                        test_prepare_msg(testid, partition, msg_id, buf, size,
                                         key, sizeof(key));


                if (rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY, buf,
                                     size, !payload ? key : NULL,
                                     !payload ? strlen(key) : 0,
                                     msgcounterp) == -1)
                        TEST_FAIL(
                            "Failed to produce message %i "
                            "to partition %i: %s",
                            msg_id, (int)partition,
                            rd_kafka_err2str(rd_kafka_last_error()));

                (*msgcounterp)++;
                tot_bytes += size;

                TIMING_RESTART(&t_poll);
                do {
                        if (per_msg_wait) {
                                wait_time = (int)(per_msg_wait -
                                                  TIMING_DURATION(&t_poll)) /
                                            1000;
                                if (wait_time < 0)
                                        wait_time = 0;
                        }
                        rd_kafka_poll(rk, wait_time);
                } while (wait_time > 0);

                tot_time_poll = TIMING_DURATION(&t_poll);

                if (TIMING_EVERY(&t_all, 3 * 1000000))
                        TEST_SAY(
                            "produced %3d%%: %d/%d messages "
                            "(%d msgs/s, %d bytes/s)\n",
                            ((msg_id - msg_base) * 100) / cnt,
                            msg_id - msg_base, cnt,
                            (int)((msg_id - msg_base) /
                                  (TIMING_DURATION(&t_all) / 1000000)),
                            (int)((tot_bytes) /
                                  (TIMING_DURATION(&t_all) / 1000000)));
        }

        if (!payload)
                free(buf);

        t_poll.duration = tot_time_poll;
        TIMING_STOP(&t_poll);
        TIMING_STOP(&t_all);
}

/**
 * Waits for the messages tracked by counter \p msgcounterp to be delivered.
 */
void test_wait_delivery(rd_kafka_t *rk, int *msgcounterp) {
        test_timing_t t_all;
        int start_cnt = *msgcounterp;

        TIMING_START(&t_all, "PRODUCE.DELIVERY.WAIT");

        /* Wait for messages to be delivered */
        while (*msgcounterp > 0 && rd_kafka_outq_len(rk) > 0) {
                rd_kafka_poll(rk, 10);
                if (TIMING_EVERY(&t_all, 3 * 1000000)) {
                        int delivered = start_cnt - *msgcounterp;
                        TEST_SAY(
                            "wait_delivery: "
                            "%d/%d messages delivered: %d msgs/s\n",
                            delivered, start_cnt,
                            (int)(delivered /
                                  (TIMING_DURATION(&t_all) / 1000000)));
                }
        }

        TIMING_STOP(&t_all);

        TEST_ASSERT(*msgcounterp == 0,
                    "Not all messages delivered: msgcounter still at %d, "
                    "outq_len %d",
                    *msgcounterp, rd_kafka_outq_len(rk));
}

/**
 * Produces \p cnt messages and waits for succesful delivery
 */
void test_produce_msgs(rd_kafka_t *rk,
                       rd_kafka_topic_t *rkt,
                       uint64_t testid,
                       int32_t partition,
                       int msg_base,
                       int cnt,
                       const char *payload,
                       size_t size) {
        int remains = 0;

        test_produce_msgs_nowait(rk, rkt, testid, partition, msg_base, cnt,
                                 payload, size, 0, &remains);

        test_wait_delivery(rk, &remains);
}


/**
 * @brief Produces \p cnt messages and waits for succesful delivery
 */
void test_produce_msgs2(rd_kafka_t *rk,
                        const char *topic,
                        uint64_t testid,
                        int32_t partition,
                        int msg_base,
                        int cnt,
                        const char *payload,
                        size_t size) {
        int remains           = 0;
        rd_kafka_topic_t *rkt = test_create_topic_object(rk, topic, NULL);

        test_produce_msgs_nowait(rk, rkt, testid, partition, msg_base, cnt,
                                 payload, size, 0, &remains);

        test_wait_delivery(rk, &remains);

        rd_kafka_topic_destroy(rkt);
}

/**
 * @brief Produces \p cnt messages without waiting for delivery.
 */
void test_produce_msgs2_nowait(rd_kafka_t *rk,
                               const char *topic,
                               uint64_t testid,
                               int32_t partition,
                               int msg_base,
                               int cnt,
                               const char *payload,
                               size_t size,
                               int *remainsp) {
        rd_kafka_topic_t *rkt = test_create_topic_object(rk, topic, NULL);

        test_produce_msgs_nowait(rk, rkt, testid, partition, msg_base, cnt,
                                 payload, size, 0, remainsp);

        rd_kafka_topic_destroy(rkt);
}


/**
 * Produces \p cnt messages at \p msgs/s, and waits for succesful delivery
 */
void test_produce_msgs_rate(rd_kafka_t *rk,
                            rd_kafka_topic_t *rkt,
                            uint64_t testid,
                            int32_t partition,
                            int msg_base,
                            int cnt,
                            const char *payload,
                            size_t size,
                            int msgrate) {
        int remains = 0;

        test_produce_msgs_nowait(rk, rkt, testid, partition, msg_base, cnt,
                                 payload, size, msgrate, &remains);

        test_wait_delivery(rk, &remains);
}



/**
 * Create producer, produce \p msgcnt messages to \p topic \p partition,
 * destroy consumer, and returns the used testid.
 */
uint64_t test_produce_msgs_easy_size(const char *topic,
                                     uint64_t testid,
                                     int32_t partition,
                                     int msgcnt,
                                     size_t size) {
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        test_timing_t t_produce;

        if (!testid)
                testid = test_id_generate();
        rk  = test_create_producer();
        rkt = test_create_producer_topic(rk, topic, NULL);

        TIMING_START(&t_produce, "PRODUCE");
        test_produce_msgs(rk, rkt, testid, partition, 0, msgcnt, NULL, size);
        TIMING_STOP(&t_produce);
        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        return testid;
}

rd_kafka_resp_err_t test_produce_sync(rd_kafka_t *rk,
                                      rd_kafka_topic_t *rkt,
                                      uint64_t testid,
                                      int32_t partition) {
        test_curr->produce_sync = 1;
        test_produce_msgs(rk, rkt, testid, partition, 0, 1, NULL, 0);
        test_curr->produce_sync = 0;
        return test_curr->produce_sync_err;
}


/**
 * @brief Easy produce function.
 *
 * @param ... is a NULL-terminated list of key, value config property pairs.
 */
void test_produce_msgs_easy_v(const char *topic,
                              uint64_t testid,
                              int32_t partition,
                              int msg_base,
                              int cnt,
                              size_t size,
                              ...) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *p;
        rd_kafka_topic_t *rkt;
        va_list ap;
        const char *key, *val;

        test_conf_init(&conf, NULL, 0);

        va_start(ap, size);
        while ((key = va_arg(ap, const char *)) &&
               (val = va_arg(ap, const char *)))
                test_conf_set(conf, key, val);
        va_end(ap);

        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rkt = test_create_producer_topic(p, topic, NULL);

        test_produce_msgs(p, rkt, testid, partition, msg_base, cnt, NULL, size);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(p);
}


/**
 * @brief Produce messages to multiple topic-partitions.
 *
 * @param ...vararg is a tuple of:
 *           const char *topic
 *           int32_t partition (or UA)
 *           int msg_base
 *           int msg_cnt
 *
 * End with a NULL topic
 */
void test_produce_msgs_easy_multi(uint64_t testid, ...) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *p;
        va_list ap;
        const char *topic;
        int msgcounter = 0;

        test_conf_init(&conf, NULL, 0);

        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        va_start(ap, testid);
        while ((topic = va_arg(ap, const char *))) {
                int32_t partition = va_arg(ap, int32_t);
                int msg_base      = va_arg(ap, int);
                int msg_cnt       = va_arg(ap, int);
                rd_kafka_topic_t *rkt;

                rkt = test_create_producer_topic(p, topic, NULL);

                test_produce_msgs_nowait(p, rkt, testid, partition, msg_base,
                                         msg_cnt, NULL, 0, 0, &msgcounter);

                rd_kafka_topic_destroy(rkt);
        }
        va_end(ap);

        test_flush(p, tmout_multip(10 * 1000));

        rd_kafka_destroy(p);
}



/**
 * @brief A standard incremental rebalance callback.
 */
void test_incremental_rebalance_cb(rd_kafka_t *rk,
                                   rd_kafka_resp_err_t err,
                                   rd_kafka_topic_partition_list_t *parts,
                                   void *opaque) {
        TEST_SAY("%s: incremental rebalance: %s: %d partition(s)%s\n",
                 rd_kafka_name(rk), rd_kafka_err2name(err), parts->cnt,
                 rd_kafka_assignment_lost(rk) ? ", assignment lost" : "");

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                test_consumer_incremental_assign("rebalance_cb", rk, parts);
                break;
        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                test_consumer_incremental_unassign("rebalance_cb", rk, parts);
                break;
        default:
                TEST_FAIL("Unknown rebalance event: %s",
                          rd_kafka_err2name(err));
                break;
        }
}

/**
 * @brief A standard rebalance callback.
 */
void test_rebalance_cb(rd_kafka_t *rk,
                       rd_kafka_resp_err_t err,
                       rd_kafka_topic_partition_list_t *parts,
                       void *opaque) {

        if (!strcmp(rd_kafka_rebalance_protocol(rk), "COOPERATIVE")) {
                test_incremental_rebalance_cb(rk, err, parts, opaque);
                return;
        }

        TEST_SAY("%s: Rebalance: %s: %d partition(s)\n", rd_kafka_name(rk),
                 rd_kafka_err2name(err), parts->cnt);

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                test_consumer_assign("assign", rk, parts);
                break;
        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                test_consumer_unassign("unassign", rk);
                break;
        default:
                TEST_FAIL("Unknown rebalance event: %s",
                          rd_kafka_err2name(err));
                break;
        }
}



rd_kafka_t *test_create_consumer(
    const char *group_id,
    void (*rebalance_cb)(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *partitions,
                         void *opaque),
    rd_kafka_conf_t *conf,
    rd_kafka_topic_conf_t *default_topic_conf) {
        rd_kafka_t *rk;
        char tmp[64];

        if (!conf)
                test_conf_init(&conf, NULL, 0);

        if (group_id) {
                test_conf_set(conf, "group.id", group_id);

                rd_snprintf(tmp, sizeof(tmp), "%d", test_session_timeout_ms);
                test_conf_set(conf, "session.timeout.ms", tmp);

                if (rebalance_cb)
                        rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);
        } else {
                TEST_ASSERT(!rebalance_cb);
        }

        if (default_topic_conf)
                rd_kafka_conf_set_default_topic_conf(conf, default_topic_conf);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        if (group_id)
                rd_kafka_poll_set_consumer(rk);

        return rk;
}

rd_kafka_topic_t *test_create_consumer_topic(rd_kafka_t *rk,
                                             const char *topic) {
        rd_kafka_topic_t *rkt;
        rd_kafka_topic_conf_t *topic_conf;

        test_conf_init(NULL, &topic_conf, 0);

        rkt = rd_kafka_topic_new(rk, topic, topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_kafka_err2str(rd_kafka_last_error()));

        return rkt;
}


void test_consumer_start(const char *what,
                         rd_kafka_topic_t *rkt,
                         int32_t partition,
                         int64_t start_offset) {

        TEST_SAY("%s: consumer_start: %s [%" PRId32 "] at offset %" PRId64 "\n",
                 what, rd_kafka_topic_name(rkt), partition, start_offset);

        if (rd_kafka_consume_start(rkt, partition, start_offset) == -1)
                TEST_FAIL("%s: consume_start failed: %s\n", what,
                          rd_kafka_err2str(rd_kafka_last_error()));
}

void test_consumer_stop(const char *what,
                        rd_kafka_topic_t *rkt,
                        int32_t partition) {

        TEST_SAY("%s: consumer_stop: %s [%" PRId32 "]\n", what,
                 rd_kafka_topic_name(rkt), partition);

        if (rd_kafka_consume_stop(rkt, partition) == -1)
                TEST_FAIL("%s: consume_stop failed: %s\n", what,
                          rd_kafka_err2str(rd_kafka_last_error()));
}

void test_consumer_seek(const char *what,
                        rd_kafka_topic_t *rkt,
                        int32_t partition,
                        int64_t offset) {
        int err;

        TEST_SAY("%s: consumer_seek: %s [%" PRId32 "] to offset %" PRId64 "\n",
                 what, rd_kafka_topic_name(rkt), partition, offset);

        if ((err = rd_kafka_seek(rkt, partition, offset, 2000)))
                TEST_FAIL("%s: consume_seek(%s, %" PRId32 ", %" PRId64
                          ") "
                          "failed: %s\n",
                          what, rd_kafka_topic_name(rkt), partition, offset,
                          rd_kafka_err2str(err));
}



/**
 * Returns offset of the last message consumed
 */
int64_t test_consume_msgs(const char *what,
                          rd_kafka_topic_t *rkt,
                          uint64_t testid,
                          int32_t partition,
                          int64_t offset,
                          int exp_msg_base,
                          int exp_cnt,
                          int parse_fmt) {
        int cnt             = 0;
        int msg_next        = exp_msg_base;
        int fails           = 0;
        int64_t offset_last = -1;
        int64_t tot_bytes   = 0;
        test_timing_t t_first, t_all;

        TEST_SAY("%s: consume_msgs: %s [%" PRId32
                 "]: expect msg #%d..%d "
                 "at offset %" PRId64 "\n",
                 what, rd_kafka_topic_name(rkt), partition, exp_msg_base,
                 exp_msg_base + exp_cnt, offset);

        if (offset != TEST_NO_SEEK) {
                rd_kafka_resp_err_t err;
                test_timing_t t_seek;

                TIMING_START(&t_seek, "SEEK");
                if ((err = rd_kafka_seek(rkt, partition, offset, 5000)))
                        TEST_FAIL("%s: consume_msgs: %s [%" PRId32
                                  "]: "
                                  "seek to %" PRId64 " failed: %s\n",
                                  what, rd_kafka_topic_name(rkt), partition,
                                  offset, rd_kafka_err2str(err));
                TIMING_STOP(&t_seek);
                TEST_SAY("%s: seeked to offset %" PRId64 "\n", what, offset);
        }

        TIMING_START(&t_first, "FIRST MSG");
        TIMING_START(&t_all, "ALL MSGS");

        while (cnt < exp_cnt) {
                rd_kafka_message_t *rkmessage;
                int msg_id;

                rkmessage =
                    rd_kafka_consume(rkt, partition, tmout_multip(5000));

                if (TIMING_EVERY(&t_all, 3 * 1000000))
                        TEST_SAY(
                            "%s: "
                            "consumed %3d%%: %d/%d messages "
                            "(%d msgs/s, %d bytes/s)\n",
                            what, cnt * 100 / exp_cnt, cnt, exp_cnt,
                            (int)(cnt / (TIMING_DURATION(&t_all) / 1000000)),
                            (int)(tot_bytes /
                                  (TIMING_DURATION(&t_all) / 1000000)));

                if (!rkmessage)
                        TEST_FAIL("%s: consume_msgs: %s [%" PRId32
                                  "]: "
                                  "expected msg #%d (%d/%d): timed out\n",
                                  what, rd_kafka_topic_name(rkt), partition,
                                  msg_next, cnt, exp_cnt);

                if (rkmessage->err)
                        TEST_FAIL("%s: consume_msgs: %s [%" PRId32
                                  "]: "
                                  "expected msg #%d (%d/%d): got error: %s\n",
                                  what, rd_kafka_topic_name(rkt), partition,
                                  msg_next, cnt, exp_cnt,
                                  rd_kafka_err2str(rkmessage->err));

                if (cnt == 0)
                        TIMING_STOP(&t_first);

                if (parse_fmt)
                        test_msg_parse(testid, rkmessage, partition, &msg_id);
                else
                        msg_id = 0;

                if (test_level >= 3)
                        TEST_SAY("%s: consume_msgs: %s [%" PRId32
                                 "]: "
                                 "got msg #%d at offset %" PRId64
                                 " (expect #%d at offset %" PRId64 ")\n",
                                 what, rd_kafka_topic_name(rkt), partition,
                                 msg_id, rkmessage->offset, msg_next,
                                 offset >= 0 ? offset + cnt : -1);

                if (parse_fmt && msg_id != msg_next) {
                        TEST_SAY("%s: consume_msgs: %s [%" PRId32
                                 "]: "
                                 "expected msg #%d (%d/%d): got msg #%d\n",
                                 what, rd_kafka_topic_name(rkt), partition,
                                 msg_next, cnt, exp_cnt, msg_id);
                        fails++;
                }

                cnt++;
                tot_bytes += rkmessage->len;
                msg_next++;
                offset_last = rkmessage->offset;

                rd_kafka_message_destroy(rkmessage);
        }

        TIMING_STOP(&t_all);

        if (fails)
                TEST_FAIL("%s: consume_msgs: %s [%" PRId32 "]: %d failures\n",
                          what, rd_kafka_topic_name(rkt), partition, fails);

        TEST_SAY("%s: consume_msgs: %s [%" PRId32
                 "]: "
                 "%d/%d messages consumed succesfully\n",
                 what, rd_kafka_topic_name(rkt), partition, cnt, exp_cnt);
        return offset_last;
}


/**
 * Create high-level consumer subscribing to \p topic from BEGINNING
 * and expects \d exp_msgcnt with matching \p testid
 * Destroys consumer when done.
 *
 * @param txn If true, isolation.level is set to read_committed.
 * @param partition If -1 the topic will be subscribed to, otherwise the
 *                  single partition will be assigned immediately.
 *
 * If \p group_id is NULL a new unique group is generated
 */
void test_consume_msgs_easy_mv0(const char *group_id,
                                const char *topic,
                                rd_bool_t txn,
                                int32_t partition,
                                uint64_t testid,
                                int exp_eofcnt,
                                int exp_msgcnt,
                                rd_kafka_topic_conf_t *tconf,
                                test_msgver_t *mv) {
        rd_kafka_t *rk;
        char grpid0[64];
        rd_kafka_conf_t *conf;

        test_conf_init(&conf, tconf ? NULL : &tconf, 0);

        if (!group_id)
                group_id = test_str_id_generate(grpid0, sizeof(grpid0));

        if (txn)
                test_conf_set(conf, "isolation.level", "read_committed");

        test_topic_conf_set(tconf, "auto.offset.reset", "smallest");
        if (exp_eofcnt != -1)
                test_conf_set(conf, "enable.partition.eof", "true");
        rk = test_create_consumer(group_id, NULL, conf, tconf);

        rd_kafka_poll_set_consumer(rk);

        if (partition == -1) {
                TEST_SAY(
                    "Subscribing to topic %s in group %s "
                    "(expecting %d msgs with testid %" PRIu64 ")\n",
                    topic, group_id, exp_msgcnt, testid);

                test_consumer_subscribe(rk, topic);
        } else {
                rd_kafka_topic_partition_list_t *plist;

                TEST_SAY("Assign topic %s [%" PRId32
                         "] in group %s "
                         "(expecting %d msgs with testid %" PRIu64 ")\n",
                         topic, partition, group_id, exp_msgcnt, testid);

                plist = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(plist, topic, partition);
                test_consumer_assign("consume_easy_mv", rk, plist);
                rd_kafka_topic_partition_list_destroy(plist);
        }

        /* Consume messages */
        test_consumer_poll("consume.easy", rk, testid, exp_eofcnt, -1,
                           exp_msgcnt, mv);

        test_consumer_close(rk);

        rd_kafka_destroy(rk);
}

void test_consume_msgs_easy(const char *group_id,
                            const char *topic,
                            uint64_t testid,
                            int exp_eofcnt,
                            int exp_msgcnt,
                            rd_kafka_topic_conf_t *tconf) {
        test_msgver_t mv;

        test_msgver_init(&mv, testid);

        test_consume_msgs_easy_mv(group_id, topic, -1, testid, exp_eofcnt,
                                  exp_msgcnt, tconf, &mv);

        test_msgver_clear(&mv);
}


void test_consume_txn_msgs_easy(const char *group_id,
                                const char *topic,
                                uint64_t testid,
                                int exp_eofcnt,
                                int exp_msgcnt,
                                rd_kafka_topic_conf_t *tconf) {
        test_msgver_t mv;

        test_msgver_init(&mv, testid);

        test_consume_msgs_easy_mv0(group_id, topic, rd_true /*txn*/, -1, testid,
                                   exp_eofcnt, exp_msgcnt, tconf, &mv);

        test_msgver_clear(&mv);
}


/**
 * @brief Waits for up to \p timeout_ms for consumer to receive assignment.
 *        If no assignment received without the timeout the test fails.
 *
 * @warning This method will poll the consumer and might thus read messages.
 *          Set \p do_poll to false to use a sleep rather than poll.
 */
void test_consumer_wait_assignment(rd_kafka_t *rk, rd_bool_t do_poll) {
        rd_kafka_topic_partition_list_t *assignment = NULL;
        int i;

        while (1) {
                rd_kafka_resp_err_t err;

                err = rd_kafka_assignment(rk, &assignment);
                TEST_ASSERT(!err, "rd_kafka_assignment() failed: %s",
                            rd_kafka_err2str(err));

                if (assignment->cnt > 0)
                        break;

                rd_kafka_topic_partition_list_destroy(assignment);

                if (do_poll)
                        test_consumer_poll_once(rk, NULL, 1000);
                else
                        rd_usleep(1000 * 1000, NULL);
        }

        TEST_SAY("%s: Assignment (%d partition(s)): ", rd_kafka_name(rk),
                 assignment->cnt);
        for (i = 0; i < assignment->cnt; i++)
                TEST_SAY0("%s%s[%" PRId32 "]", i == 0 ? "" : ", ",
                          assignment->elems[i].topic,
                          assignment->elems[i].partition);
        TEST_SAY0("\n");

        rd_kafka_topic_partition_list_destroy(assignment);
}


/**
 * @brief Verify that the consumer's assignment matches the expected assignment.
 *
 * The va-list is a NULL-terminated list of (const char *topic, int partition)
 * tuples.
 *
 * Fails the test on mismatch, unless \p fail_immediately is false.
 */
void test_consumer_verify_assignment0(const char *func,
                                      int line,
                                      rd_kafka_t *rk,
                                      int fail_immediately,
                                      ...) {
        va_list ap;
        int cnt = 0;
        const char *topic;
        rd_kafka_topic_partition_list_t *assignment;
        rd_kafka_resp_err_t err;
        int i;

        if ((err = rd_kafka_assignment(rk, &assignment)))
                TEST_FAIL("%s:%d: Failed to get assignment for %s: %s", func,
                          line, rd_kafka_name(rk), rd_kafka_err2str(err));

        TEST_SAY("%s assignment (%d partition(s)):\n", rd_kafka_name(rk),
                 assignment->cnt);
        for (i = 0; i < assignment->cnt; i++)
                TEST_SAY(" %s [%" PRId32 "]\n", assignment->elems[i].topic,
                         assignment->elems[i].partition);

        va_start(ap, fail_immediately);
        while ((topic = va_arg(ap, const char *))) {
                int partition = va_arg(ap, int);
                cnt++;

                if (!rd_kafka_topic_partition_list_find(assignment, topic,
                                                        partition))
                        TEST_FAIL_LATER(
                            "%s:%d: Expected %s [%d] not found in %s's "
                            "assignment (%d partition(s))",
                            func, line, topic, partition, rd_kafka_name(rk),
                            assignment->cnt);
        }
        va_end(ap);

        if (cnt != assignment->cnt)
                TEST_FAIL_LATER(
                    "%s:%d: "
                    "Expected %d assigned partition(s) for %s, not %d",
                    func, line, cnt, rd_kafka_name(rk), assignment->cnt);

        if (fail_immediately)
                TEST_LATER_CHECK();

        rd_kafka_topic_partition_list_destroy(assignment);
}



/**
 * @brief Start subscribing for 'topic'
 */
void test_consumer_subscribe(rd_kafka_t *rk, const char *topic) {
        rd_kafka_topic_partition_list_t *topics;
        rd_kafka_resp_err_t err;

        topics = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(topics, topic, RD_KAFKA_PARTITION_UA);

        err = rd_kafka_subscribe(rk, topics);
        if (err)
                TEST_FAIL("%s: Failed to subscribe to %s: %s\n",
                          rd_kafka_name(rk), topic, rd_kafka_err2str(err));

        rd_kafka_topic_partition_list_destroy(topics);
}


void test_consumer_assign(const char *what,
                          rd_kafka_t *rk,
                          rd_kafka_topic_partition_list_t *partitions) {
        rd_kafka_resp_err_t err;
        test_timing_t timing;

        TIMING_START(&timing, "ASSIGN.PARTITIONS");
        err = rd_kafka_assign(rk, partitions);
        TIMING_STOP(&timing);
        if (err)
                TEST_FAIL("%s: failed to assign %d partition(s): %s\n", what,
                          partitions->cnt, rd_kafka_err2str(err));
        else
                TEST_SAY("%s: assigned %d partition(s)\n", what,
                         partitions->cnt);
}


void test_consumer_incremental_assign(
    const char *what,
    rd_kafka_t *rk,
    rd_kafka_topic_partition_list_t *partitions) {
        rd_kafka_error_t *error;
        test_timing_t timing;

        TIMING_START(&timing, "INCREMENTAL.ASSIGN.PARTITIONS");
        error = rd_kafka_incremental_assign(rk, partitions);
        TIMING_STOP(&timing);
        if (error) {
                TEST_FAIL(
                    "%s: incremental assign of %d partition(s) failed: "
                    "%s",
                    what, partitions->cnt, rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        } else
                TEST_SAY("%s: incremental assign of %d partition(s) done\n",
                         what, partitions->cnt);
}


void test_consumer_unassign(const char *what, rd_kafka_t *rk) {
        rd_kafka_resp_err_t err;
        test_timing_t timing;

        TIMING_START(&timing, "UNASSIGN.PARTITIONS");
        err = rd_kafka_assign(rk, NULL);
        TIMING_STOP(&timing);
        if (err)
                TEST_FAIL("%s: failed to unassign current partitions: %s\n",
                          what, rd_kafka_err2str(err));
        else
                TEST_SAY("%s: unassigned current partitions\n", what);
}


void test_consumer_incremental_unassign(
    const char *what,
    rd_kafka_t *rk,
    rd_kafka_topic_partition_list_t *partitions) {
        rd_kafka_error_t *error;
        test_timing_t timing;

        TIMING_START(&timing, "INCREMENTAL.UNASSIGN.PARTITIONS");
        error = rd_kafka_incremental_unassign(rk, partitions);
        TIMING_STOP(&timing);
        if (error) {
                TEST_FAIL(
                    "%s: incremental unassign of %d partition(s) "
                    "failed: %s",
                    what, partitions->cnt, rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        } else
                TEST_SAY("%s: incremental unassign of %d partition(s) done\n",
                         what, partitions->cnt);
}


/**
 * @brief Assign a single partition with an optional starting offset
 */
void test_consumer_assign_partition(const char *what,
                                    rd_kafka_t *rk,
                                    const char *topic,
                                    int32_t partition,
                                    int64_t offset) {
        rd_kafka_topic_partition_list_t *part;

        part = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(part, topic, partition)->offset =
            offset;

        test_consumer_assign(what, rk, part);

        rd_kafka_topic_partition_list_destroy(part);
}


void test_consumer_pause_resume_partition(rd_kafka_t *rk,
                                          const char *topic,
                                          int32_t partition,
                                          rd_bool_t pause) {
        rd_kafka_topic_partition_list_t *part;
        rd_kafka_resp_err_t err;

        part = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(part, topic, partition);

        if (pause)
                err = rd_kafka_pause_partitions(rk, part);
        else
                err = rd_kafka_resume_partitions(rk, part);

        TEST_ASSERT(!err, "Failed to %s %s [%" PRId32 "]: %s",
                    pause ? "pause" : "resume", topic, partition,
                    rd_kafka_err2str(err));

        rd_kafka_topic_partition_list_destroy(part);
}


/**
 * Message verification services
 *
 */

void test_msgver_init(test_msgver_t *mv, uint64_t testid) {
        memset(mv, 0, sizeof(*mv));
        mv->testid = testid;
        /* Max warning logs before suppressing. */
        mv->log_max = (test_level + 1) * 100;
}

void test_msgver_ignore_eof(test_msgver_t *mv) {
        mv->ignore_eof = rd_true;
}

#define TEST_MV_WARN(mv, ...)                                                  \
        do {                                                                   \
                if ((mv)->log_cnt++ > (mv)->log_max)                           \
                        (mv)->log_suppr_cnt++;                                 \
                else                                                           \
                        TEST_WARN(__VA_ARGS__);                                \
        } while (0)



static void test_mv_mvec_grow(struct test_mv_mvec *mvec, int tot_size) {
        if (tot_size <= mvec->size)
                return;
        mvec->size = tot_size;
        mvec->m    = realloc(mvec->m, sizeof(*mvec->m) * mvec->size);
}

/**
 * Make sure there is room for at least \p cnt messages, else grow mvec.
 */
static void test_mv_mvec_reserve(struct test_mv_mvec *mvec, int cnt) {
        test_mv_mvec_grow(mvec, mvec->cnt + cnt);
}

void test_mv_mvec_init(struct test_mv_mvec *mvec, int exp_cnt) {
        TEST_ASSERT(mvec->m == NULL, "mvec not cleared");

        if (!exp_cnt)
                return;

        test_mv_mvec_grow(mvec, exp_cnt);
}


void test_mv_mvec_clear(struct test_mv_mvec *mvec) {
        if (mvec->m)
                free(mvec->m);
}

void test_msgver_clear(test_msgver_t *mv) {
        int i;
        for (i = 0; i < mv->p_cnt; i++) {
                struct test_mv_p *p = mv->p[i];
                free(p->topic);
                test_mv_mvec_clear(&p->mvec);
                free(p);
        }

        free(mv->p);

        test_msgver_init(mv, mv->testid);
}

struct test_mv_p *test_msgver_p_get(test_msgver_t *mv,
                                    const char *topic,
                                    int32_t partition,
                                    int do_create) {
        int i;
        struct test_mv_p *p;

        for (i = 0; i < mv->p_cnt; i++) {
                p = mv->p[i];
                if (p->partition == partition && !strcmp(p->topic, topic))
                        return p;
        }

        if (!do_create)
                TEST_FAIL("Topic %s [%d] not found in msgver", topic,
                          partition);

        if (mv->p_cnt == mv->p_size) {
                mv->p_size = (mv->p_size + 4) * 2;
                mv->p      = realloc(mv->p, sizeof(*mv->p) * mv->p_size);
        }

        mv->p[mv->p_cnt++] = p = calloc(1, sizeof(*p));

        p->topic      = rd_strdup(topic);
        p->partition  = partition;
        p->eof_offset = RD_KAFKA_OFFSET_INVALID;

        return p;
}


/**
 * Add (room for) message to message vector.
 * Resizes the vector as needed.
 */
static struct test_mv_m *test_mv_mvec_add(struct test_mv_mvec *mvec) {
        if (mvec->cnt == mvec->size) {
                test_mv_mvec_grow(mvec, (mvec->size ? mvec->size * 2 : 10000));
        }

        mvec->cnt++;

        return &mvec->m[mvec->cnt - 1];
}

/**
 * Returns message at index \p mi
 */
static RD_INLINE struct test_mv_m *test_mv_mvec_get(struct test_mv_mvec *mvec,
                                                    int mi) {
        if (mi >= mvec->cnt)
                return NULL;
        return &mvec->m[mi];
}

/**
 * @returns the message with msgid \p msgid, or NULL.
 */
static struct test_mv_m *test_mv_mvec_find_by_msgid(struct test_mv_mvec *mvec,
                                                    int msgid) {
        int mi;

        for (mi = 0; mi < mvec->cnt; mi++)
                if (mvec->m[mi].msgid == msgid)
                        return &mvec->m[mi];

        return NULL;
}


/**
 * Print message list to \p fp
 */
static RD_UNUSED void test_mv_mvec_dump(FILE *fp,
                                        const struct test_mv_mvec *mvec) {
        int mi;

        fprintf(fp, "*** Dump mvec with %d messages (capacity %d): ***\n",
                mvec->cnt, mvec->size);
        for (mi = 0; mi < mvec->cnt; mi++)
                fprintf(fp, "  msgid %d, offset %" PRId64 "\n",
                        mvec->m[mi].msgid, mvec->m[mi].offset);
        fprintf(fp, "*** Done ***\n");
}

static void test_mv_mvec_sort(struct test_mv_mvec *mvec,
                              int (*cmp)(const void *, const void *)) {
        qsort(mvec->m, mvec->cnt, sizeof(*mvec->m), cmp);
}


/**
 * @brief Adds a message to the msgver service.
 *
 * @returns 1 if message is from the expected testid, else 0 (not added)
 */
int test_msgver_add_msg00(const char *func,
                          int line,
                          const char *clientname,
                          test_msgver_t *mv,
                          uint64_t testid,
                          const char *topic,
                          int32_t partition,
                          int64_t offset,
                          int64_t timestamp,
                          int32_t broker_id,
                          rd_kafka_resp_err_t err,
                          int msgnum) {
        struct test_mv_p *p;
        struct test_mv_m *m;

        if (testid != mv->testid) {
                TEST_SAYL(3,
                          "%s:%d: %s: mismatching testid %" PRIu64
                          " != %" PRIu64 "\n",
                          func, line, clientname, testid, mv->testid);
                return 0; /* Ignore message */
        }

        if (err == RD_KAFKA_RESP_ERR__PARTITION_EOF && mv->ignore_eof) {
                TEST_SAYL(3, "%s:%d: %s: ignoring EOF for %s [%" PRId32 "]\n",
                          func, line, clientname, topic, partition);
                return 0; /* Ignore message */
        }

        p = test_msgver_p_get(mv, topic, partition, 1);

        if (err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                p->eof_offset = offset;
                return 1;
        }

        m = test_mv_mvec_add(&p->mvec);

        m->offset    = offset;
        m->msgid     = msgnum;
        m->timestamp = timestamp;
        m->broker_id = broker_id;

        if (test_level > 2) {
                TEST_SAY(
                    "%s:%d: %s: "
                    "Recv msg %s [%" PRId32 "] offset %" PRId64
                    " msgid %d "
                    "timestamp %" PRId64 " broker %" PRId32 "\n",
                    func, line, clientname, p->topic, p->partition, m->offset,
                    m->msgid, m->timestamp, m->broker_id);
        }

        mv->msgcnt++;

        return 1;
}

/**
 * Adds a message to the msgver service.
 *
 * Message must be a proper message or PARTITION_EOF.
 *
 * @param override_topic if non-NULL, overrides the rkmessage's topic
 *                       with this one.
 *
 * @returns 1 if message is from the expected testid, else 0 (not added).
 */
int test_msgver_add_msg0(const char *func,
                         int line,
                         const char *clientname,
                         test_msgver_t *mv,
                         const rd_kafka_message_t *rkmessage,
                         const char *override_topic) {
        uint64_t in_testid;
        int in_part;
        int in_msgnum = -1;
        char buf[128];
        const void *val;
        size_t valsize;

        if (mv->fwd)
                test_msgver_add_msg0(func, line, clientname, mv->fwd, rkmessage,
                                     override_topic);

        if (rd_kafka_message_status(rkmessage) ==
                RD_KAFKA_MSG_STATUS_NOT_PERSISTED &&
            rkmessage->err) {
                if (rkmessage->err != RD_KAFKA_RESP_ERR__PARTITION_EOF)
                        return 0; /* Ignore error */

                in_testid = mv->testid;

        } else {

                if (!mv->msgid_hdr) {
                        rd_snprintf(buf, sizeof(buf), "%.*s",
                                    (int)rkmessage->len,
                                    (char *)rkmessage->payload);
                        val = buf;
                } else {
                        /* msgid is in message header */
                        rd_kafka_headers_t *hdrs;

                        if (rd_kafka_message_headers(rkmessage, &hdrs) ||
                            rd_kafka_header_get_last(hdrs, mv->msgid_hdr, &val,
                                                     &valsize)) {
                                TEST_SAYL(3,
                                          "%s:%d: msgid expected in header %s "
                                          "but %s exists for "
                                          "message at offset %" PRId64
                                          " has no headers\n",
                                          func, line, mv->msgid_hdr,
                                          hdrs ? "no such header"
                                               : "no headers",
                                          rkmessage->offset);

                                return 0;
                        }
                }

                if (sscanf(val, "testid=%" SCNu64 ", partition=%i, msg=%i\n",
                           &in_testid, &in_part, &in_msgnum) != 3)
                        TEST_FAIL(
                            "%s:%d: Incorrect format at offset %" PRId64 ": %s",
                            func, line, rkmessage->offset, (const char *)val);
        }

        return test_msgver_add_msg00(
            func, line, clientname, mv, in_testid,
            override_topic ? override_topic
                           : rd_kafka_topic_name(rkmessage->rkt),
            rkmessage->partition, rkmessage->offset,
            rd_kafka_message_timestamp(rkmessage, NULL),
            rd_kafka_message_broker_id(rkmessage), rkmessage->err, in_msgnum);
        return 1;
}



/**
 * Verify that all messages were received in order.
 *
 * - Offsets need to occur without gaps
 * - msgids need to be increasing: but may have gaps, e.g., using partitioner)
 */
static int test_mv_mvec_verify_order(test_msgver_t *mv,
                                     int flags,
                                     struct test_mv_p *p,
                                     struct test_mv_mvec *mvec,
                                     struct test_mv_vs *vs) {
        int mi;
        int fails = 0;

        for (mi = 1 /*skip first*/; mi < mvec->cnt; mi++) {
                struct test_mv_m *prev = test_mv_mvec_get(mvec, mi - 1);
                struct test_mv_m *this = test_mv_mvec_get(mvec, mi);

                if (((flags & TEST_MSGVER_BY_OFFSET) &&
                     prev->offset + 1 != this->offset) ||
                    ((flags & TEST_MSGVER_BY_MSGID) &&
                     prev->msgid > this->msgid)) {
                        TEST_MV_WARN(mv,
                                     " %s [%" PRId32
                                     "] msg rcvidx #%d/%d: "
                                     "out of order (prev vs this): "
                                     "offset %" PRId64 " vs %" PRId64
                                     ", "
                                     "msgid %d vs %d\n",
                                     p ? p->topic : "*", p ? p->partition : -1,
                                     mi, mvec->cnt, prev->offset, this->offset,
                                     prev->msgid, this->msgid);
                        fails++;
                } else if ((flags & TEST_MSGVER_BY_BROKER_ID) &&
                           this->broker_id != vs->broker_id) {
                        TEST_MV_WARN(mv,
                                     " %s [%" PRId32
                                     "] msg rcvidx #%d/%d: "
                                     "broker id mismatch: expected %" PRId32
                                     ", not %" PRId32 "\n",
                                     p ? p->topic : "*", p ? p->partition : -1,
                                     mi, mvec->cnt, vs->broker_id,
                                     this->broker_id);
                        fails++;
                }
        }

        return fails;
}


/**
 * @brief Verify that messages correspond to 'correct' msgver.
 */
static int test_mv_mvec_verify_corr(test_msgver_t *mv,
                                    int flags,
                                    struct test_mv_p *p,
                                    struct test_mv_mvec *mvec,
                                    struct test_mv_vs *vs) {
        int mi;
        int fails                = 0;
        struct test_mv_p *corr_p = NULL;
        struct test_mv_mvec *corr_mvec;
        int verifycnt = 0;

        TEST_ASSERT(vs->corr);

        /* Get correct mvec for comparison. */
        if (p)
                corr_p = test_msgver_p_get(vs->corr, p->topic, p->partition, 0);
        if (!corr_p) {
                TEST_MV_WARN(mv,
                             " %s [%" PRId32
                             "]: "
                             "no corresponding correct partition found\n",
                             p ? p->topic : "*", p ? p->partition : -1);
                return 1;
        }

        corr_mvec = &corr_p->mvec;

        for (mi = 0; mi < mvec->cnt; mi++) {
                struct test_mv_m *this = test_mv_mvec_get(mvec, mi);
                const struct test_mv_m *corr;


                if (flags & TEST_MSGVER_SUBSET)
                        corr =
                            test_mv_mvec_find_by_msgid(corr_mvec, this->msgid);
                else
                        corr = test_mv_mvec_get(corr_mvec, mi);

                if (0)
                        TEST_MV_WARN(mv,
                                     "msg #%d: msgid %d, offset %" PRId64 "\n",
                                     mi, this->msgid, this->offset);
                if (!corr) {
                        if (!(flags & TEST_MSGVER_SUBSET)) {
                                TEST_MV_WARN(
                                    mv,
                                    " %s [%" PRId32
                                    "] msg rcvidx #%d/%d: "
                                    "out of range: correct mvec has "
                                    "%d messages: "
                                    "message offset %" PRId64 ", msgid %d\n",
                                    p ? p->topic : "*", p ? p->partition : -1,
                                    mi, mvec->cnt, corr_mvec->cnt, this->offset,
                                    this->msgid);
                                fails++;
                        }
                        continue;
                }

                if (((flags & TEST_MSGVER_BY_OFFSET) &&
                     this->offset != corr->offset) ||
                    ((flags & TEST_MSGVER_BY_MSGID) &&
                     this->msgid != corr->msgid) ||
                    ((flags & TEST_MSGVER_BY_TIMESTAMP) &&
                     this->timestamp != corr->timestamp) ||
                    ((flags & TEST_MSGVER_BY_BROKER_ID) &&
                     this->broker_id != corr->broker_id)) {
                        TEST_MV_WARN(
                            mv,
                            " %s [%" PRId32
                            "] msg rcvidx #%d/%d: "
                            "did not match correct msg: "
                            "offset %" PRId64 " vs %" PRId64
                            ", "
                            "msgid %d vs %d, "
                            "timestamp %" PRId64 " vs %" PRId64
                            ", "
                            "broker %" PRId32 " vs %" PRId32 " (fl 0x%x)\n",
                            p ? p->topic : "*", p ? p->partition : -1, mi,
                            mvec->cnt, this->offset, corr->offset, this->msgid,
                            corr->msgid, this->timestamp, corr->timestamp,
                            this->broker_id, corr->broker_id, flags);
                        fails++;
                } else {
                        verifycnt++;
                }
        }

        if (verifycnt != corr_mvec->cnt && !(flags & TEST_MSGVER_SUBSET)) {
                TEST_MV_WARN(mv,
                             " %s [%" PRId32
                             "]: of %d input messages, "
                             "only %d/%d matched correct messages\n",
                             p ? p->topic : "*", p ? p->partition : -1,
                             mvec->cnt, verifycnt, corr_mvec->cnt);
                fails++;
        }

        return fails;
}



static int test_mv_m_cmp_offset(const void *_a, const void *_b) {
        const struct test_mv_m *a = _a, *b = _b;

        return RD_CMP(a->offset, b->offset);
}

static int test_mv_m_cmp_msgid(const void *_a, const void *_b) {
        const struct test_mv_m *a = _a, *b = _b;

        return RD_CMP(a->msgid, b->msgid);
}


/**
 * Verify that there are no duplicate message.
 *
 * - Offsets are checked
 * - msgids are checked
 *
 * * NOTE: This sorts the message (.m) array, first by offset, then by msgid
 *         and leaves the message array sorted (by msgid)
 */
static int test_mv_mvec_verify_dup(test_msgver_t *mv,
                                   int flags,
                                   struct test_mv_p *p,
                                   struct test_mv_mvec *mvec,
                                   struct test_mv_vs *vs) {
        int mi;
        int fails = 0;
        enum { _P_OFFSET, _P_MSGID } pass;

        for (pass = _P_OFFSET; pass <= _P_MSGID; pass++) {

                if (pass == _P_OFFSET) {
                        if (!(flags & TEST_MSGVER_BY_OFFSET))
                                continue;
                        test_mv_mvec_sort(mvec, test_mv_m_cmp_offset);
                } else if (pass == _P_MSGID) {
                        if (!(flags & TEST_MSGVER_BY_MSGID))
                                continue;
                        test_mv_mvec_sort(mvec, test_mv_m_cmp_msgid);
                }

                for (mi = 1 /*skip first*/; mi < mvec->cnt; mi++) {
                        struct test_mv_m *prev = test_mv_mvec_get(mvec, mi - 1);
                        struct test_mv_m *this = test_mv_mvec_get(mvec, mi);
                        int is_dup             = 0;

                        if (pass == _P_OFFSET)
                                is_dup = prev->offset == this->offset;
                        else if (pass == _P_MSGID)
                                is_dup = prev->msgid == this->msgid;

                        if (!is_dup)
                                continue;

                        TEST_MV_WARN(mv,
                                     " %s [%" PRId32
                                     "] "
                                     "duplicate msg (prev vs this): "
                                     "offset %" PRId64 " vs %" PRId64
                                     ", "
                                     "msgid %d vs %d\n",
                                     p ? p->topic : "*", p ? p->partition : -1,
                                     prev->offset, this->offset, prev->msgid,
                                     this->msgid);
                        fails++;
                }
        }

        return fails;
}



/**
 * Verify that \p mvec contains the expected range:
 *  - TEST_MSGVER_BY_MSGID: msgid within \p vs->msgid_min .. \p vs->msgid_max
 *  - TEST_MSGVER_BY_TIMESTAMP: timestamp with \p vs->timestamp_min .. _max
 *
 * * NOTE: TEST_MSGVER_BY_MSGID is required
 *
 * * NOTE: This sorts the message (.m) array by msgid
 *         and leaves the message array sorted (by msgid)
 */
static int test_mv_mvec_verify_range(test_msgver_t *mv,
                                     int flags,
                                     struct test_mv_p *p,
                                     struct test_mv_mvec *mvec,
                                     struct test_mv_vs *vs) {
        int mi;
        int fails    = 0;
        int cnt      = 0;
        int exp_cnt  = vs->msgid_max - vs->msgid_min + 1;
        int skip_cnt = 0;

        if (!(flags & TEST_MSGVER_BY_MSGID))
                return 0;

        test_mv_mvec_sort(mvec, test_mv_m_cmp_msgid);

        // test_mv_mvec_dump(stdout, mvec);

        for (mi = 0; mi < mvec->cnt; mi++) {
                struct test_mv_m *prev =
                    mi ? test_mv_mvec_get(mvec, mi - 1) : NULL;
                struct test_mv_m *this = test_mv_mvec_get(mvec, mi);

                if (this->msgid < vs->msgid_min) {
                        skip_cnt++;
                        continue;
                } else if (this->msgid > vs->msgid_max)
                        break;

                if (flags & TEST_MSGVER_BY_TIMESTAMP) {
                        if (this->timestamp < vs->timestamp_min ||
                            this->timestamp > vs->timestamp_max) {
                                TEST_MV_WARN(
                                    mv,
                                    " %s [%" PRId32
                                    "] range check: "
                                    "msgid #%d (at mi %d): "
                                    "timestamp %" PRId64
                                    " outside "
                                    "expected range %" PRId64 "..%" PRId64 "\n",
                                    p ? p->topic : "*", p ? p->partition : -1,
                                    this->msgid, mi, this->timestamp,
                                    vs->timestamp_min, vs->timestamp_max);
                                fails++;
                        }
                }

                if ((flags & TEST_MSGVER_BY_BROKER_ID) &&
                    this->broker_id != vs->broker_id) {
                        TEST_MV_WARN(
                            mv,
                            " %s [%" PRId32
                            "] range check: "
                            "msgid #%d (at mi %d): "
                            "expected broker id %" PRId32 ", not %" PRId32 "\n",
                            p ? p->topic : "*", p ? p->partition : -1,
                            this->msgid, mi, vs->broker_id, this->broker_id);
                        fails++;
                }

                if (cnt++ == 0) {
                        if (this->msgid != vs->msgid_min) {
                                TEST_MV_WARN(mv,
                                             " %s [%" PRId32
                                             "] range check: "
                                             "first message #%d (at mi %d) "
                                             "is not first in "
                                             "expected range %d..%d\n",
                                             p ? p->topic : "*",
                                             p ? p->partition : -1, this->msgid,
                                             mi, vs->msgid_min, vs->msgid_max);
                                fails++;
                        }
                } else if (cnt > exp_cnt) {
                        TEST_MV_WARN(mv,
                                     " %s [%" PRId32
                                     "] range check: "
                                     "too many messages received (%d/%d) at "
                                     "msgid %d for expected range %d..%d\n",
                                     p ? p->topic : "*", p ? p->partition : -1,
                                     cnt, exp_cnt, this->msgid, vs->msgid_min,
                                     vs->msgid_max);
                        fails++;
                }

                if (!prev) {
                        skip_cnt++;
                        continue;
                }

                if (prev->msgid + 1 != this->msgid) {
                        TEST_MV_WARN(mv,
                                     " %s [%" PRId32
                                     "] range check: "
                                     " %d message(s) missing between "
                                     "msgid %d..%d in expected range %d..%d\n",
                                     p ? p->topic : "*", p ? p->partition : -1,
                                     this->msgid - prev->msgid - 1,
                                     prev->msgid + 1, this->msgid - 1,
                                     vs->msgid_min, vs->msgid_max);
                        fails++;
                }
        }

        if (cnt != exp_cnt) {
                TEST_MV_WARN(mv,
                             " %s [%" PRId32
                             "] range check: "
                             " wrong number of messages seen, wanted %d got %d "
                             "in expected range %d..%d (%d messages skipped)\n",
                             p ? p->topic : "*", p ? p->partition : -1, exp_cnt,
                             cnt, vs->msgid_min, vs->msgid_max, skip_cnt);
                fails++;
        }

        return fails;
}



/**
 * Run verifier \p f for all partitions.
 */
#define test_mv_p_verify_f(mv, flags, f, vs)                                   \
        test_mv_p_verify_f0(mv, flags, f, #f, vs)
static int test_mv_p_verify_f0(test_msgver_t *mv,
                               int flags,
                               int (*f)(test_msgver_t *mv,
                                        int flags,
                                        struct test_mv_p *p,
                                        struct test_mv_mvec *mvec,
                                        struct test_mv_vs *vs),
                               const char *f_name,
                               struct test_mv_vs *vs) {
        int i;
        int fails = 0;

        for (i = 0; i < mv->p_cnt; i++) {
                TEST_SAY("Verifying %s [%" PRId32 "] %d msgs with %s\n",
                         mv->p[i]->topic, mv->p[i]->partition,
                         mv->p[i]->mvec.cnt, f_name);
                fails += f(mv, flags, mv->p[i], &mv->p[i]->mvec, vs);
        }

        return fails;
}


/**
 * Collect all messages from all topics and partitions into vs->mvec
 */
static void test_mv_collect_all_msgs(test_msgver_t *mv, struct test_mv_vs *vs) {
        int i;

        for (i = 0; i < mv->p_cnt; i++) {
                struct test_mv_p *p = mv->p[i];
                int mi;

                test_mv_mvec_reserve(&vs->mvec, p->mvec.cnt);
                for (mi = 0; mi < p->mvec.cnt; mi++) {
                        struct test_mv_m *m = test_mv_mvec_get(&p->mvec, mi);
                        struct test_mv_m *m_new = test_mv_mvec_add(&vs->mvec);
                        *m_new                  = *m;
                }
        }
}


/**
 * Verify that all messages (by msgid) in range msg_base+exp_cnt were received
 * and received only once.
 * This works across all partitions.
 */
static int
test_msgver_verify_range(test_msgver_t *mv, int flags, struct test_mv_vs *vs) {
        int fails = 0;

        /**
         * Create temporary array to hold expected message set,
         * then traverse all topics and partitions and move matching messages
         * to that set. Then verify the message set.
         */

        test_mv_mvec_init(&vs->mvec, vs->exp_cnt);

        /* Collect all msgs into vs mvec */
        test_mv_collect_all_msgs(mv, vs);

        fails += test_mv_mvec_verify_range(mv, TEST_MSGVER_BY_MSGID | flags,
                                           NULL, &vs->mvec, vs);
        fails += test_mv_mvec_verify_dup(mv, TEST_MSGVER_BY_MSGID | flags, NULL,
                                         &vs->mvec, vs);

        test_mv_mvec_clear(&vs->mvec);

        return fails;
}


/**
 * Verify that \p exp_cnt messages were received for \p topic and \p partition
 * starting at msgid base \p msg_base.
 */
int test_msgver_verify_part0(const char *func,
                             int line,
                             const char *what,
                             test_msgver_t *mv,
                             int flags,
                             const char *topic,
                             int partition,
                             int msg_base,
                             int exp_cnt) {
        int fails            = 0;
        struct test_mv_vs vs = {.msg_base = msg_base, .exp_cnt = exp_cnt};
        struct test_mv_p *p;

        TEST_SAY(
            "%s:%d: %s: Verifying %d received messages (flags 0x%x) "
            "in %s [%d]: expecting msgids %d..%d (%d)\n",
            func, line, what, mv->msgcnt, flags, topic, partition, msg_base,
            msg_base + exp_cnt, exp_cnt);

        p = test_msgver_p_get(mv, topic, partition, 0);

        /* Per-partition checks */
        if (flags & TEST_MSGVER_ORDER)
                fails += test_mv_mvec_verify_order(mv, flags, p, &p->mvec, &vs);
        if (flags & TEST_MSGVER_DUP)
                fails += test_mv_mvec_verify_dup(mv, flags, p, &p->mvec, &vs);

        if (mv->msgcnt < vs.exp_cnt) {
                TEST_MV_WARN(mv,
                             "%s:%d: "
                             "%s [%" PRId32
                             "] expected %d messages but only "
                             "%d received\n",
                             func, line, p ? p->topic : "*",
                             p ? p->partition : -1, vs.exp_cnt, mv->msgcnt);
                fails++;
        }


        if (mv->log_suppr_cnt > 0)
                TEST_WARN("%s:%d: %s: %d message warning logs suppressed\n",
                          func, line, what, mv->log_suppr_cnt);

        if (fails)
                TEST_FAIL(
                    "%s:%d: %s: Verification of %d received messages "
                    "failed: "
                    "expected msgids %d..%d (%d): see previous errors\n",
                    func, line, what, mv->msgcnt, msg_base, msg_base + exp_cnt,
                    exp_cnt);
        else
                TEST_SAY(
                    "%s:%d: %s: Verification of %d received messages "
                    "succeeded: "
                    "expected msgids %d..%d (%d)\n",
                    func, line, what, mv->msgcnt, msg_base, msg_base + exp_cnt,
                    exp_cnt);

        return fails;
}

/**
 * Verify that \p exp_cnt messages were received starting at
 * msgid base \p msg_base.
 */
int test_msgver_verify0(const char *func,
                        int line,
                        const char *what,
                        test_msgver_t *mv,
                        int flags,
                        struct test_mv_vs vs) {
        int fails = 0;

        TEST_SAY(
            "%s:%d: %s: Verifying %d received messages (flags 0x%x): "
            "expecting msgids %d..%d (%d)\n",
            func, line, what, mv->msgcnt, flags, vs.msg_base,
            vs.msg_base + vs.exp_cnt, vs.exp_cnt);
        if (flags & TEST_MSGVER_BY_TIMESTAMP) {
                assert((flags & TEST_MSGVER_BY_MSGID)); /* Required */
                TEST_SAY(
                    "%s:%d: %s: "
                    " and expecting timestamps %" PRId64 "..%" PRId64 "\n",
                    func, line, what, vs.timestamp_min, vs.timestamp_max);
        }

        /* Per-partition checks */
        if (flags & TEST_MSGVER_ORDER)
                fails += test_mv_p_verify_f(mv, flags,
                                            test_mv_mvec_verify_order, &vs);
        if (flags & TEST_MSGVER_DUP)
                fails +=
                    test_mv_p_verify_f(mv, flags, test_mv_mvec_verify_dup, &vs);

        /* Checks across all partitions */
        if ((flags & TEST_MSGVER_RANGE) && vs.exp_cnt > 0) {
                vs.msgid_min = vs.msg_base;
                vs.msgid_max = vs.msgid_min + vs.exp_cnt - 1;
                fails += test_msgver_verify_range(mv, flags, &vs);
        }

        if (mv->log_suppr_cnt > 0)
                TEST_WARN("%s:%d: %s: %d message warning logs suppressed\n",
                          func, line, what, mv->log_suppr_cnt);

        if (vs.exp_cnt != mv->msgcnt) {
                if (!(flags & TEST_MSGVER_SUBSET)) {
                        TEST_WARN("%s:%d: %s: expected %d messages, got %d\n",
                                  func, line, what, vs.exp_cnt, mv->msgcnt);
                        fails++;
                }
        }

        if (fails)
                TEST_FAIL(
                    "%s:%d: %s: Verification of %d received messages "
                    "failed: "
                    "expected msgids %d..%d (%d): see previous errors\n",
                    func, line, what, mv->msgcnt, vs.msg_base,
                    vs.msg_base + vs.exp_cnt, vs.exp_cnt);
        else
                TEST_SAY(
                    "%s:%d: %s: Verification of %d received messages "
                    "succeeded: "
                    "expected msgids %d..%d (%d)\n",
                    func, line, what, mv->msgcnt, vs.msg_base,
                    vs.msg_base + vs.exp_cnt, vs.exp_cnt);

        return fails;
}



void test_verify_rkmessage0(const char *func,
                            int line,
                            rd_kafka_message_t *rkmessage,
                            uint64_t testid,
                            int32_t partition,
                            int msgnum) {
        uint64_t in_testid;
        int in_part;
        int in_msgnum;
        char buf[128];

        rd_snprintf(buf, sizeof(buf), "%.*s", (int)rkmessage->len,
                    (char *)rkmessage->payload);

        if (sscanf(buf, "testid=%" SCNu64 ", partition=%i, msg=%i\n",
                   &in_testid, &in_part, &in_msgnum) != 3)
                TEST_FAIL("Incorrect format: %s", buf);

        if (testid != in_testid || (partition != -1 && partition != in_part) ||
            (msgnum != -1 && msgnum != in_msgnum) || in_msgnum < 0)
                goto fail_match;

        if (test_level > 2) {
                TEST_SAY("%s:%i: Our testid %" PRIu64
                         ", part %i (%i), msg %i\n",
                         func, line, testid, (int)partition,
                         (int)rkmessage->partition, msgnum);
        }


        return;

fail_match:
        TEST_FAIL("%s:%i: Our testid %" PRIu64
                  ", part %i, msg %i did "
                  "not match message: \"%s\"\n",
                  func, line, testid, (int)partition, msgnum, buf);
}


/**
 * @brief Verify that \p mv is identical to \p corr according to flags.
 */
void test_msgver_verify_compare0(const char *func,
                                 int line,
                                 const char *what,
                                 test_msgver_t *mv,
                                 test_msgver_t *corr,
                                 int flags) {
        struct test_mv_vs vs;
        int fails = 0;

        memset(&vs, 0, sizeof(vs));

        TEST_SAY(
            "%s:%d: %s: Verifying %d received messages (flags 0x%x) by "
            "comparison to correct msgver (%d messages)\n",
            func, line, what, mv->msgcnt, flags, corr->msgcnt);

        vs.corr = corr;

        /* Per-partition checks */
        fails += test_mv_p_verify_f(mv, flags, test_mv_mvec_verify_corr, &vs);

        if (mv->log_suppr_cnt > 0)
                TEST_WARN("%s:%d: %s: %d message warning logs suppressed\n",
                          func, line, what, mv->log_suppr_cnt);

        if (corr->msgcnt != mv->msgcnt) {
                if (!(flags & TEST_MSGVER_SUBSET)) {
                        TEST_WARN("%s:%d: %s: expected %d messages, got %d\n",
                                  func, line, what, corr->msgcnt, mv->msgcnt);
                        fails++;
                }
        }

        if (fails)
                TEST_FAIL(
                    "%s:%d: %s: Verification of %d received messages "
                    "failed: expected %d messages: see previous errors\n",
                    func, line, what, mv->msgcnt, corr->msgcnt);
        else
                TEST_SAY(
                    "%s:%d: %s: Verification of %d received messages "
                    "succeeded: matching %d messages from correct msgver\n",
                    func, line, what, mv->msgcnt, corr->msgcnt);
}


/**
 * Consumer poll but dont expect any proper messages for \p timeout_ms.
 */
void test_consumer_poll_no_msgs(const char *what,
                                rd_kafka_t *rk,
                                uint64_t testid,
                                int timeout_ms) {
        int64_t tmout = test_clock() + ((int64_t)timeout_ms * 1000);
        int cnt       = 0;
        test_timing_t t_cons;
        test_msgver_t mv;

        test_msgver_init(&mv, testid);

        if (what)
                TEST_SAY("%s: not expecting any messages for %dms\n", what,
                         timeout_ms);

        TIMING_START(&t_cons, "CONSUME");

        do {
                rd_kafka_message_t *rkmessage;

                rkmessage = rd_kafka_consumer_poll(rk, timeout_ms);
                if (!rkmessage)
                        continue;

                if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                        TEST_SAY("%s [%" PRId32
                                 "] reached EOF at "
                                 "offset %" PRId64 "\n",
                                 rd_kafka_topic_name(rkmessage->rkt),
                                 rkmessage->partition, rkmessage->offset);
                        test_msgver_add_msg(rk, &mv, rkmessage);

                } else if (rkmessage->err) {
                        TEST_FAIL(
                            "%s [%" PRId32 "] error (offset %" PRId64 "): %s",
                            rkmessage->rkt ? rd_kafka_topic_name(rkmessage->rkt)
                                           : "(no-topic)",
                            rkmessage->partition, rkmessage->offset,
                            rd_kafka_message_errstr(rkmessage));

                } else {
                        if (test_msgver_add_msg(rk, &mv, rkmessage)) {
                                TEST_MV_WARN(
                                    &mv,
                                    "Received unexpected message on "
                                    "%s [%" PRId32
                                    "] at offset "
                                    "%" PRId64 "\n",
                                    rd_kafka_topic_name(rkmessage->rkt),
                                    rkmessage->partition, rkmessage->offset);
                                cnt++;
                        }
                }

                rd_kafka_message_destroy(rkmessage);
        } while (test_clock() <= tmout);

        if (what)
                TIMING_STOP(&t_cons);

        test_msgver_verify(what, &mv, TEST_MSGVER_ALL, 0, 0);
        test_msgver_clear(&mv);

        TEST_ASSERT(cnt == 0, "Expected 0 messages, got %d", cnt);
}

/**
 * @brief Consumer poll with expectation that a \p err will be reached
 * within \p timeout_ms.
 */
void test_consumer_poll_expect_err(rd_kafka_t *rk,
                                   uint64_t testid,
                                   int timeout_ms,
                                   rd_kafka_resp_err_t err) {
        int64_t tmout = test_clock() + ((int64_t)timeout_ms * 1000);

        TEST_SAY("%s: expecting error %s within %dms\n", rd_kafka_name(rk),
                 rd_kafka_err2name(err), timeout_ms);

        do {
                rd_kafka_message_t *rkmessage;
                rkmessage = rd_kafka_consumer_poll(rk, timeout_ms);
                if (!rkmessage)
                        continue;

                if (rkmessage->err == err) {
                        TEST_SAY("Got expected error: %s: %s\n",
                                 rd_kafka_err2name(rkmessage->err),
                                 rd_kafka_message_errstr(rkmessage));
                        rd_kafka_message_destroy(rkmessage);

                        return;
                } else if (rkmessage->err) {
                        TEST_FAIL("%s [%" PRId32
                                  "] unexpected error "
                                  "(offset %" PRId64 "): %s",
                                  rkmessage->rkt
                                      ? rd_kafka_topic_name(rkmessage->rkt)
                                      : "(no-topic)",
                                  rkmessage->partition, rkmessage->offset,
                                  rd_kafka_err2name(rkmessage->err));
                }

                rd_kafka_message_destroy(rkmessage);
        } while (test_clock() <= tmout);
        TEST_FAIL("Expected error %s not seen in %dms", rd_kafka_err2name(err),
                  timeout_ms);
}

/**
 * Call consumer poll once and then return.
 * Messages are handled.
 *
 * \p mv is optional
 *
 * @returns 0 on timeout, 1 if a message was received or .._PARTITION_EOF
 *          if EOF was reached.
 *          TEST_FAIL()s on all errors.
 */
int test_consumer_poll_once(rd_kafka_t *rk, test_msgver_t *mv, int timeout_ms) {
        rd_kafka_message_t *rkmessage;

        rkmessage = rd_kafka_consumer_poll(rk, timeout_ms);
        if (!rkmessage)
                return 0;

        if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                TEST_SAY("%s [%" PRId32
                         "] reached EOF at "
                         "offset %" PRId64 "\n",
                         rd_kafka_topic_name(rkmessage->rkt),
                         rkmessage->partition, rkmessage->offset);
                if (mv)
                        test_msgver_add_msg(rk, mv, rkmessage);
                rd_kafka_message_destroy(rkmessage);
                return RD_KAFKA_RESP_ERR__PARTITION_EOF;

        } else if (rkmessage->err) {
                TEST_FAIL("%s [%" PRId32 "] error (offset %" PRId64 "): %s",
                          rkmessage->rkt ? rd_kafka_topic_name(rkmessage->rkt)
                                         : "(no-topic)",
                          rkmessage->partition, rkmessage->offset,
                          rd_kafka_message_errstr(rkmessage));

        } else {
                if (mv)
                        test_msgver_add_msg(rk, mv, rkmessage);
        }

        rd_kafka_message_destroy(rkmessage);
        return 1;
}


/**
 * @param exact Require exact exp_eof_cnt (unless -1) and exp_cnt (unless -1).
 *              If false: poll until either one is reached.
 */
int test_consumer_poll_exact(const char *what,
                             rd_kafka_t *rk,
                             uint64_t testid,
                             int exp_eof_cnt,
                             int exp_msg_base,
                             int exp_cnt,
                             rd_bool_t exact,
                             test_msgver_t *mv) {
        int eof_cnt = 0;
        int cnt     = 0;
        test_timing_t t_cons;

        TEST_SAY("%s: consume %s%d messages\n", what, exact ? "exactly " : "",
                 exp_cnt);

        TIMING_START(&t_cons, "CONSUME");

        while ((!exact && ((exp_eof_cnt <= 0 || eof_cnt < exp_eof_cnt) &&
                           (exp_cnt <= 0 || cnt < exp_cnt))) ||
               (exact && (eof_cnt < exp_eof_cnt || cnt < exp_cnt))) {
                rd_kafka_message_t *rkmessage;

                rkmessage = rd_kafka_consumer_poll(rk, tmout_multip(10 * 1000));
                if (!rkmessage) /* Shouldn't take this long to get a msg */
                        TEST_FAIL(
                            "%s: consumer_poll() timeout "
                            "(%d/%d eof, %d/%d msgs)\n",
                            what, eof_cnt, exp_eof_cnt, cnt, exp_cnt);


                if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                        TEST_SAY("%s [%" PRId32
                                 "] reached EOF at "
                                 "offset %" PRId64 "\n",
                                 rd_kafka_topic_name(rkmessage->rkt),
                                 rkmessage->partition, rkmessage->offset);
                        TEST_ASSERT(exp_eof_cnt != 0, "expected no EOFs");
                        if (mv)
                                test_msgver_add_msg(rk, mv, rkmessage);
                        eof_cnt++;

                } else if (rkmessage->err) {
                        TEST_FAIL(
                            "%s [%" PRId32 "] error (offset %" PRId64 "): %s",
                            rkmessage->rkt ? rd_kafka_topic_name(rkmessage->rkt)
                                           : "(no-topic)",
                            rkmessage->partition, rkmessage->offset,
                            rd_kafka_message_errstr(rkmessage));

                } else {
                        TEST_SAYL(4,
                                  "%s: consumed message on %s [%" PRId32
                                  "] "
                                  "at offset %" PRId64 "\n",
                                  what, rd_kafka_topic_name(rkmessage->rkt),
                                  rkmessage->partition, rkmessage->offset);

                        if (!mv || test_msgver_add_msg(rk, mv, rkmessage))
                                cnt++;
                }

                rd_kafka_message_destroy(rkmessage);
        }

        TIMING_STOP(&t_cons);

        TEST_SAY("%s: consumed %d/%d messages (%d/%d EOFs)\n", what, cnt,
                 exp_cnt, eof_cnt, exp_eof_cnt);

        TEST_ASSERT(!exact || ((exp_cnt == -1 || exp_cnt == cnt) &&
                               (exp_eof_cnt == -1 || exp_eof_cnt == eof_cnt)),
                    "%s: mismatch between exact expected counts and actual: "
                    "%d/%d EOFs, %d/%d msgs",
                    what, eof_cnt, exp_eof_cnt, cnt, exp_cnt);

        if (exp_cnt == 0)
                TEST_ASSERT(cnt == 0 && eof_cnt == exp_eof_cnt,
                            "%s: expected no messages and %d EOFs: "
                            "got %d messages and %d EOFs",
                            what, exp_eof_cnt, cnt, eof_cnt);
        return cnt;
}


int test_consumer_poll(const char *what,
                       rd_kafka_t *rk,
                       uint64_t testid,
                       int exp_eof_cnt,
                       int exp_msg_base,
                       int exp_cnt,
                       test_msgver_t *mv) {
        return test_consumer_poll_exact(what, rk, testid, exp_eof_cnt,
                                        exp_msg_base, exp_cnt,
                                        rd_false /*not exact */, mv);
}

void test_consumer_close(rd_kafka_t *rk) {
        rd_kafka_resp_err_t err;
        test_timing_t timing;

        TEST_SAY("Closing consumer %s\n", rd_kafka_name(rk));

        TIMING_START(&timing, "CONSUMER.CLOSE");
        err = rd_kafka_consumer_close(rk);
        TIMING_STOP(&timing);
        if (err)
                TEST_FAIL("Failed to close consumer: %s\n",
                          rd_kafka_err2str(err));
}


void test_flush(rd_kafka_t *rk, int timeout_ms) {
        test_timing_t timing;
        rd_kafka_resp_err_t err;

        TEST_SAY("%s: Flushing %d messages\n", rd_kafka_name(rk),
                 rd_kafka_outq_len(rk));
        TIMING_START(&timing, "FLUSH");
        err = rd_kafka_flush(rk, timeout_ms);
        TIMING_STOP(&timing);
        if (err)
                TEST_FAIL("Failed to flush(%s, %d): %s: len() = %d\n",
                          rd_kafka_name(rk), timeout_ms, rd_kafka_err2str(err),
                          rd_kafka_outq_len(rk));
}


void test_conf_set(rd_kafka_conf_t *conf, const char *name, const char *val) {
        char errstr[512];
        if (rd_kafka_conf_set(conf, name, val, errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK)
                TEST_FAIL("Failed to set config \"%s\"=\"%s\": %s\n", name, val,
                          errstr);
}

/**
 * @brief Get configuration value for property \p name.
 *
 * @param conf Configuration to get value from. If NULL the test.conf (if any)
 *             configuration will be used.
 */
char *test_conf_get(const rd_kafka_conf_t *conf, const char *name) {
        static RD_TLS char ret[256];
        size_t ret_sz             = sizeof(ret);
        rd_kafka_conf_t *def_conf = NULL;

        if (!conf) /* Use the current test.conf */
                test_conf_init(&def_conf, NULL, 0);

        if (rd_kafka_conf_get(conf ? conf : def_conf, name, ret, &ret_sz) !=
            RD_KAFKA_CONF_OK)
                TEST_FAIL("Failed to get config \"%s\": %s\n", name,
                          "unknown property");

        if (def_conf)
                rd_kafka_conf_destroy(def_conf);

        return ret;
}


char *test_topic_conf_get(const rd_kafka_topic_conf_t *tconf,
                          const char *name) {
        static RD_TLS char ret[256];
        size_t ret_sz = sizeof(ret);
        if (rd_kafka_topic_conf_get(tconf, name, ret, &ret_sz) !=
            RD_KAFKA_CONF_OK)
                TEST_FAIL("Failed to get topic config \"%s\": %s\n", name,
                          "unknown property");
        return ret;
}


/**
 * @brief Check if property \name matches \p val in \p conf.
 *        If \p conf is NULL the test config will be used. */
int test_conf_match(rd_kafka_conf_t *conf, const char *name, const char *val) {
        char *real;
        int free_conf = 0;

        if (!conf) {
                test_conf_init(&conf, NULL, 0);
                free_conf = 1;
        }

        real = test_conf_get(conf, name);

        if (free_conf)
                rd_kafka_conf_destroy(conf);

        return !strcmp(real, val);
}


void test_topic_conf_set(rd_kafka_topic_conf_t *tconf,
                         const char *name,
                         const char *val) {
        char errstr[512];
        if (rd_kafka_topic_conf_set(tconf, name, val, errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK)
                TEST_FAIL("Failed to set topic config \"%s\"=\"%s\": %s\n",
                          name, val, errstr);
}

/**
 * @brief First attempt to set topic level property, then global.
 */
void test_any_conf_set(rd_kafka_conf_t *conf,
                       rd_kafka_topic_conf_t *tconf,
                       const char *name,
                       const char *val) {
        rd_kafka_conf_res_t res = RD_KAFKA_CONF_UNKNOWN;
        char errstr[512]        = {"Missing conf_t"};

        if (tconf)
                res = rd_kafka_topic_conf_set(tconf, name, val, errstr,
                                              sizeof(errstr));
        if (res == RD_KAFKA_CONF_UNKNOWN && conf)
                res =
                    rd_kafka_conf_set(conf, name, val, errstr, sizeof(errstr));

        if (res != RD_KAFKA_CONF_OK)
                TEST_FAIL("Failed to set any config \"%s\"=\"%s\": %s\n", name,
                          val, errstr);
}


/**
 * @returns true if test clients need to be configured for authentication
 *          or other security measures (SSL), else false for unauthed plaintext.
 */
int test_needs_auth(void) {
        rd_kafka_conf_t *conf;
        const char *sec;

        test_conf_init(&conf, NULL, 0);

        sec = test_conf_get(conf, "security.protocol");

        rd_kafka_conf_destroy(conf);

        return strcmp(sec, "plaintext");
}


void test_print_partition_list(
    const rd_kafka_topic_partition_list_t *partitions) {
        int i;
        for (i = 0; i < partitions->cnt; i++) {
                TEST_SAY(" %s [%" PRId32 "] offset %" PRId64 "%s%s\n",
                         partitions->elems[i].topic,
                         partitions->elems[i].partition,
                         partitions->elems[i].offset,
                         partitions->elems[i].err ? ": " : "",
                         partitions->elems[i].err
                             ? rd_kafka_err2str(partitions->elems[i].err)
                             : "");
        }
}

/**
 * @brief Compare two lists, returning 0 if equal.
 *
 * @remark The lists may be sorted by this function.
 */
int test_partition_list_cmp(rd_kafka_topic_partition_list_t *al,
                            rd_kafka_topic_partition_list_t *bl) {
        int i;

        if (al->cnt < bl->cnt)
                return -1;
        else if (al->cnt > bl->cnt)
                return 1;
        else if (al->cnt == 0)
                return 0;

        rd_kafka_topic_partition_list_sort(al, NULL, NULL);
        rd_kafka_topic_partition_list_sort(bl, NULL, NULL);

        for (i = 0; i < al->cnt; i++) {
                const rd_kafka_topic_partition_t *a = &al->elems[i];
                const rd_kafka_topic_partition_t *b = &bl->elems[i];
                if (a->partition != b->partition || strcmp(a->topic, b->topic))
                        return -1;
        }

        return 0;
}


/**
 * @brief Execute script from the Kafka distribution bin/ path.
 */
void test_kafka_cmd(const char *fmt, ...) {
#ifdef _WIN32
        TEST_FAIL("%s not supported on Windows, yet", __FUNCTION__);
#else
        char cmd[1024];
        int r;
        va_list ap;
        test_timing_t t_cmd;
        const char *kpath;

        kpath = test_getenv("KAFKA_PATH", NULL);

        if (!kpath)
                TEST_FAIL("%s: KAFKA_PATH must be set", __FUNCTION__);

        r = rd_snprintf(cmd, sizeof(cmd), "%s/bin/", kpath);
        TEST_ASSERT(r < (int)sizeof(cmd));

        va_start(ap, fmt);
        rd_vsnprintf(cmd + r, sizeof(cmd) - r, fmt, ap);
        va_end(ap);

        TEST_SAY("Executing: %s\n", cmd);
        TIMING_START(&t_cmd, "exec");
        r = system(cmd);
        TIMING_STOP(&t_cmd);

        if (r == -1)
                TEST_FAIL("system(\"%s\") failed: %s", cmd, strerror(errno));
        else if (WIFSIGNALED(r))
                TEST_FAIL("system(\"%s\") terminated by signal %d\n", cmd,
                          WTERMSIG(r));
        else if (WEXITSTATUS(r))
                TEST_FAIL("system(\"%s\") failed with exit status %d\n", cmd,
                          WEXITSTATUS(r));
#endif
}

/**
 * @brief Execute kafka-topics.sh from the Kafka distribution.
 */
void test_kafka_topics(const char *fmt, ...) {
#ifdef _WIN32
        TEST_FAIL("%s not supported on Windows, yet", __FUNCTION__);
#else
        char cmd[1024];
        int r, bytes_left;
        va_list ap;
        test_timing_t t_cmd;
        const char *kpath, *bootstrap_env, *flag, *bootstrap_srvs;

        if (test_broker_version >= TEST_BRKVER(3, 0, 0, 0)) {
                bootstrap_env = "BROKERS";
                flag          = "--bootstrap-server";
        } else {
                bootstrap_env = "ZK_ADDRESS";
                flag          = "--zookeeper";
        }

        kpath          = test_getenv("KAFKA_PATH", NULL);
        bootstrap_srvs = test_getenv(bootstrap_env, NULL);

        if (!kpath || !bootstrap_srvs)
                TEST_FAIL("%s: KAFKA_PATH and %s must be set", __FUNCTION__,
                          bootstrap_env);

        r = rd_snprintf(cmd, sizeof(cmd), "%s/bin/kafka-topics.sh %s %s ",
                        kpath, flag, bootstrap_srvs);
        TEST_ASSERT(r > 0 && r < (int)sizeof(cmd));

        bytes_left = sizeof(cmd) - r;

        va_start(ap, fmt);
        r = rd_vsnprintf(cmd + r, bytes_left, fmt, ap);
        va_end(ap);
        TEST_ASSERT(r > 0 && r < bytes_left);

        TEST_SAY("Executing: %s\n", cmd);
        TIMING_START(&t_cmd, "exec");
        r = system(cmd);
        TIMING_STOP(&t_cmd);

        if (r == -1)
                TEST_FAIL("system(\"%s\") failed: %s", cmd, strerror(errno));
        else if (WIFSIGNALED(r))
                TEST_FAIL("system(\"%s\") terminated by signal %d\n", cmd,
                          WTERMSIG(r));
        else if (WEXITSTATUS(r))
                TEST_FAIL("system(\"%s\") failed with exit status %d\n", cmd,
                          WEXITSTATUS(r));
#endif
}



/**
 * @brief Create topic using Topic Admin API
 *
 * @param configs is an optional key-value tuple array of
 *                   topic configs (or NULL).
 */
void test_admin_create_topic(rd_kafka_t *use_rk,
                             const char *topicname,
                             int partition_cnt,
                             int replication_factor,
                             const char **configs) {
        rd_kafka_t *rk;
        rd_kafka_NewTopic_t *newt[1];
        const size_t newt_cnt = 1;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *rkqu;
        rd_kafka_event_t *rkev;
        const rd_kafka_CreateTopics_result_t *res;
        const rd_kafka_topic_result_t **terr;
        int timeout_ms = tmout_multip(10000);
        size_t res_cnt;
        rd_kafka_resp_err_t err;
        char errstr[512];
        test_timing_t t_create;

        if (!(rk = use_rk))
                rk = test_create_producer();

        rkqu = rd_kafka_queue_new(rk);

        newt[0] =
            rd_kafka_NewTopic_new(topicname, partition_cnt, replication_factor,
                                  errstr, sizeof(errstr));
        TEST_ASSERT(newt[0] != NULL, "%s", errstr);

        if (configs) {
                int i;

                for (i = 0; configs[i] && configs[i + 1]; i += 2)
                        TEST_CALL_ERR__(rd_kafka_NewTopic_set_config(
                            newt[0], configs[i], configs[i + 1]));
        }

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_CREATETOPICS);
        err     = rd_kafka_AdminOptions_set_operation_timeout(
            options, timeout_ms, errstr, sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);

        TEST_SAY(
            "Creating topic \"%s\" "
            "(partitions=%d, replication_factor=%d, timeout=%d)\n",
            topicname, partition_cnt, replication_factor, timeout_ms);

        TIMING_START(&t_create, "CreateTopics");
        rd_kafka_CreateTopics(rk, newt, newt_cnt, options, rkqu);

        /* Wait for result */
        rkev = rd_kafka_queue_poll(rkqu, timeout_ms + 2000);
        TEST_ASSERT(rkev, "Timed out waiting for CreateTopics result");

        TIMING_STOP(&t_create);

        TEST_ASSERT(!rd_kafka_event_error(rkev), "CreateTopics failed: %s",
                    rd_kafka_event_error_string(rkev));

        res = rd_kafka_event_CreateTopics_result(rkev);
        TEST_ASSERT(res, "Expected CreateTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        terr = rd_kafka_CreateTopics_result_topics(res, &res_cnt);
        TEST_ASSERT(terr, "CreateTopics_result_topics returned NULL");
        TEST_ASSERT(res_cnt == newt_cnt,
                    "CreateTopics_result_topics returned %" PRIusz
                    " topics, "
                    "not the expected %" PRIusz,
                    res_cnt, newt_cnt);

        TEST_ASSERT(!rd_kafka_topic_result_error(terr[0]) ||
                        rd_kafka_topic_result_error(terr[0]) ==
                            RD_KAFKA_RESP_ERR_TOPIC_ALREADY_EXISTS,
                    "Topic %s result error: %s",
                    rd_kafka_topic_result_name(terr[0]),
                    rd_kafka_topic_result_error_string(terr[0]));

        rd_kafka_event_destroy(rkev);

        rd_kafka_queue_destroy(rkqu);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_NewTopic_destroy(newt[0]);

        if (!use_rk)
                rd_kafka_destroy(rk);
}



/**
 * @brief Create topic using kafka-topics.sh --create
 */
static void test_create_topic_sh(const char *topicname,
                                 int partition_cnt,
                                 int replication_factor) {
        test_kafka_topics(
            "--create --topic \"%s\" "
            "--replication-factor %d --partitions %d",
            topicname, replication_factor, partition_cnt);
}


/**
 * @brief Create topic
 */
void test_create_topic(rd_kafka_t *use_rk,
                       const char *topicname,
                       int partition_cnt,
                       int replication_factor) {
        if (test_broker_version < TEST_BRKVER(0, 10, 2, 0))
                test_create_topic_sh(topicname, partition_cnt,
                                     replication_factor);
        else
                test_admin_create_topic(use_rk, topicname, partition_cnt,
                                        replication_factor, NULL);
}


/**
 * @brief Create topic using kafka-topics.sh --delete
 */
static void test_delete_topic_sh(const char *topicname) {
        test_kafka_topics("--delete --topic \"%s\" ", topicname);
}


/**
 * @brief Delete topic using Topic Admin API
 */
static void test_admin_delete_topic(rd_kafka_t *use_rk, const char *topicname) {
        rd_kafka_t *rk;
        rd_kafka_DeleteTopic_t *delt[1];
        const size_t delt_cnt = 1;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *rkqu;
        rd_kafka_event_t *rkev;
        const rd_kafka_DeleteTopics_result_t *res;
        const rd_kafka_topic_result_t **terr;
        int timeout_ms = tmout_multip(10000);
        size_t res_cnt;
        rd_kafka_resp_err_t err;
        char errstr[512];
        test_timing_t t_create;

        if (!(rk = use_rk))
                rk = test_create_producer();

        rkqu = rd_kafka_queue_new(rk);

        delt[0] = rd_kafka_DeleteTopic_new(topicname);

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETETOPICS);
        err     = rd_kafka_AdminOptions_set_operation_timeout(
            options, timeout_ms, errstr, sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);

        TEST_SAY(
            "Deleting topic \"%s\" "
            "(timeout=%d)\n",
            topicname, timeout_ms);

        TIMING_START(&t_create, "DeleteTopics");
        rd_kafka_DeleteTopics(rk, delt, delt_cnt, options, rkqu);

        /* Wait for result */
        rkev = rd_kafka_queue_poll(rkqu, timeout_ms + 2000);
        TEST_ASSERT(rkev, "Timed out waiting for DeleteTopics result");

        TIMING_STOP(&t_create);

        res = rd_kafka_event_DeleteTopics_result(rkev);
        TEST_ASSERT(res, "Expected DeleteTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        terr = rd_kafka_DeleteTopics_result_topics(res, &res_cnt);
        TEST_ASSERT(terr, "DeleteTopics_result_topics returned NULL");
        TEST_ASSERT(res_cnt == delt_cnt,
                    "DeleteTopics_result_topics returned %" PRIusz
                    " topics, "
                    "not the expected %" PRIusz,
                    res_cnt, delt_cnt);

        TEST_ASSERT(!rd_kafka_topic_result_error(terr[0]),
                    "Topic %s result error: %s",
                    rd_kafka_topic_result_name(terr[0]),
                    rd_kafka_topic_result_error_string(terr[0]));

        rd_kafka_event_destroy(rkev);

        rd_kafka_queue_destroy(rkqu);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_DeleteTopic_destroy(delt[0]);

        if (!use_rk)
                rd_kafka_destroy(rk);
}


/**
 * @brief Delete a topic
 */
void test_delete_topic(rd_kafka_t *use_rk, const char *topicname) {
        if (test_broker_version < TEST_BRKVER(0, 10, 2, 0))
                test_delete_topic_sh(topicname);
        else
                test_admin_delete_topic(use_rk, topicname);
}


/**
 * @brief Create additional partitions for a topic using Admin API
 */
static void test_admin_create_partitions(rd_kafka_t *use_rk,
                                         const char *topicname,
                                         int new_partition_cnt) {
        rd_kafka_t *rk;
        rd_kafka_NewPartitions_t *newp[1];
        const size_t newp_cnt = 1;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *rkqu;
        rd_kafka_event_t *rkev;
        const rd_kafka_CreatePartitions_result_t *res;
        const rd_kafka_topic_result_t **terr;
        int timeout_ms = tmout_multip(10000);
        size_t res_cnt;
        rd_kafka_resp_err_t err;
        char errstr[512];
        test_timing_t t_create;

        if (!(rk = use_rk))
                rk = test_create_producer();

        rkqu = rd_kafka_queue_new(rk);

        newp[0] = rd_kafka_NewPartitions_new(topicname, new_partition_cnt,
                                             errstr, sizeof(errstr));
        TEST_ASSERT(newp[0] != NULL, "%s", errstr);

        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_CREATEPARTITIONS);
        err = rd_kafka_AdminOptions_set_operation_timeout(
            options, timeout_ms, errstr, sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);

        TEST_SAY("Creating %d (total) partitions for topic \"%s\"\n",
                 new_partition_cnt, topicname);

        TIMING_START(&t_create, "CreatePartitions");
        rd_kafka_CreatePartitions(rk, newp, newp_cnt, options, rkqu);

        /* Wait for result */
        rkev = rd_kafka_queue_poll(rkqu, timeout_ms + 2000);
        TEST_ASSERT(rkev, "Timed out waiting for CreatePartitions result");

        TIMING_STOP(&t_create);

        res = rd_kafka_event_CreatePartitions_result(rkev);
        TEST_ASSERT(res, "Expected CreatePartitions_result, not %s",
                    rd_kafka_event_name(rkev));

        terr = rd_kafka_CreatePartitions_result_topics(res, &res_cnt);
        TEST_ASSERT(terr, "CreatePartitions_result_topics returned NULL");
        TEST_ASSERT(res_cnt == newp_cnt,
                    "CreatePartitions_result_topics returned %" PRIusz
                    " topics, not the expected %" PRIusz,
                    res_cnt, newp_cnt);

        TEST_ASSERT(!rd_kafka_topic_result_error(terr[0]),
                    "Topic %s result error: %s",
                    rd_kafka_topic_result_name(terr[0]),
                    rd_kafka_topic_result_error_string(terr[0]));

        rd_kafka_event_destroy(rkev);

        rd_kafka_queue_destroy(rkqu);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_NewPartitions_destroy(newp[0]);

        if (!use_rk)
                rd_kafka_destroy(rk);
}


/**
 * @brief Create partitions for topic
 */
void test_create_partitions(rd_kafka_t *use_rk,
                            const char *topicname,
                            int new_partition_cnt) {
        if (test_broker_version < TEST_BRKVER(0, 10, 2, 0))
                test_kafka_topics("--alter --topic %s --partitions %d",
                                  topicname, new_partition_cnt);
        else
                test_admin_create_partitions(use_rk, topicname,
                                             new_partition_cnt);
}


int test_get_partition_count(rd_kafka_t *rk,
                             const char *topicname,
                             int timeout_ms) {
        rd_kafka_t *use_rk;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_t *rkt;
        int64_t abs_timeout = test_clock() + ((int64_t)timeout_ms * 1000);
        int ret             = -1;

        if (!rk)
                use_rk = test_create_producer();
        else
                use_rk = rk;

        rkt = rd_kafka_topic_new(use_rk, topicname, NULL);

        do {
                const struct rd_kafka_metadata *metadata;

                err = rd_kafka_metadata(use_rk, 0, rkt, &metadata,
                                        tmout_multip(15000));
                if (err)
                        TEST_WARN("metadata() for %s failed: %s\n",
                                  rkt ? rd_kafka_topic_name(rkt)
                                      : "(all-local)",
                                  rd_kafka_err2str(err));
                else {
                        if (metadata->topic_cnt == 1) {
                                if (metadata->topics[0].err == 0 ||
                                    metadata->topics[0].partition_cnt > 0) {
                                        int32_t cnt;
                                        cnt = metadata->topics[0].partition_cnt;
                                        rd_kafka_metadata_destroy(metadata);
                                        ret = (int)cnt;
                                        break;
                                }
                                TEST_SAY(
                                    "metadata(%s) returned %s: retrying\n",
                                    rd_kafka_topic_name(rkt),
                                    rd_kafka_err2str(metadata->topics[0].err));
                        }
                        rd_kafka_metadata_destroy(metadata);
                        rd_sleep(1);
                }
        } while (test_clock() < abs_timeout);

        rd_kafka_topic_destroy(rkt);

        if (!rk)
                rd_kafka_destroy(use_rk);

        return ret;
}

/**
 * @brief Let the broker auto-create the topic for us.
 */
rd_kafka_resp_err_t test_auto_create_topic_rkt(rd_kafka_t *rk,
                                               rd_kafka_topic_t *rkt,
                                               int timeout_ms) {
        const struct rd_kafka_metadata *metadata;
        rd_kafka_resp_err_t err;
        test_timing_t t;
        int64_t abs_timeout = test_clock() + ((int64_t)timeout_ms * 1000);

        do {
                TIMING_START(&t, "auto_create_topic");
                err = rd_kafka_metadata(rk, 0, rkt, &metadata,
                                        tmout_multip(15000));
                TIMING_STOP(&t);
                if (err)
                        TEST_WARN("metadata() for %s failed: %s\n",
                                  rkt ? rd_kafka_topic_name(rkt)
                                      : "(all-local)",
                                  rd_kafka_err2str(err));
                else {
                        if (metadata->topic_cnt == 1) {
                                if (metadata->topics[0].err == 0 ||
                                    metadata->topics[0].partition_cnt > 0) {
                                        rd_kafka_metadata_destroy(metadata);
                                        return 0;
                                }
                                TEST_SAY(
                                    "metadata(%s) returned %s: retrying\n",
                                    rd_kafka_topic_name(rkt),
                                    rd_kafka_err2str(metadata->topics[0].err));
                        }
                        rd_kafka_metadata_destroy(metadata);
                        rd_sleep(1);
                }
        } while (test_clock() < abs_timeout);

        return err;
}

rd_kafka_resp_err_t
test_auto_create_topic(rd_kafka_t *rk, const char *name, int timeout_ms) {
        rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, name, NULL);
        rd_kafka_resp_err_t err;
        if (!rkt)
                return rd_kafka_last_error();
        err = test_auto_create_topic_rkt(rk, rkt, timeout_ms);
        rd_kafka_topic_destroy(rkt);
        return err;
}


/**
 * @brief Check if topic auto creation works.
 * @returns 1 if it does, else 0.
 */
int test_check_auto_create_topic(void) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_resp_err_t err;
        const char *topic = test_mk_topic_name("autocreatetest", 1);

        test_conf_init(&conf, NULL, 0);
        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        err = test_auto_create_topic(rk, topic, tmout_multip(5000));
        if (err)
                TEST_SAY("Auto topic creation of \"%s\" failed: %s\n", topic,
                         rd_kafka_err2str(err));
        rd_kafka_destroy(rk);

        return err ? 0 : 1;
}


/**
 * @brief Builds and runs a Java application from the java/ directory.
 *
 *        The application is started in the background, use
 *        test_waitpid() to await its demise.
 *
 * @param cls The app class to run using java/run-class.sh
 *
 * @returns -1 if the application could not be started, else the pid.
 */
int test_run_java(const char *cls, const char **argv) {
#ifdef _WIN32
        TEST_WARN("%s(%s) not supported Windows, yet", __FUNCTION__, cls);
        return -1;
#else
        int r;
        const char *kpath;
        pid_t pid;
        const char **full_argv, **p;
        int cnt;
        extern char **environ;

        kpath = test_getenv("KAFKA_PATH", NULL);

        if (!kpath) {
                TEST_WARN("%s(%s): KAFKA_PATH must be set\n", __FUNCTION__,
                          cls);
                return -1;
        }

        /* Build */
        r = system("make -s java");

        if (r == -1 || WIFSIGNALED(r) || WEXITSTATUS(r)) {
                TEST_WARN("%s(%s): failed to build java class (code %d)\n",
                          __FUNCTION__, cls, r);
                return -1;
        }

        /* For child process and run cls */
        pid = fork();
        if (pid == -1) {
                TEST_WARN("%s(%s): failed to fork: %s\n", __FUNCTION__, cls,
                          strerror(errno));
                return -1;
        }

        if (pid > 0)
                return (int)pid; /* In parent process */

        /* In child process */

        /* Reconstruct argv to contain run-class.sh and the cls */
        for (cnt = 0; argv[cnt]; cnt++)
                ;

        cnt += 3; /* run-class.sh, cls, .., NULL */
        full_argv    = malloc(sizeof(*full_argv) * cnt);
        full_argv[0] = "java/run-class.sh";
        full_argv[1] = (const char *)cls;

        /* Copy arguments */
        for (p = &full_argv[2]; *argv; p++, argv++)
                *p = *argv;
        *p = NULL;

        /* Run */
        r = execve(full_argv[0], (char *const *)full_argv, environ);

        TEST_WARN("%s(%s): failed to execute run-class.sh: %s\n", __FUNCTION__,
                  cls, strerror(errno));
        exit(2);

        return -1; /* NOTREACHED */
#endif
}


/**
 * @brief Wait for child-process \p pid to exit.
 *
 * @returns -1 if the child process exited successfully, else -1.
 */
int test_waitpid(int pid) {
#ifdef _WIN32
        TEST_WARN("%s() not supported Windows, yet", __FUNCTION__);
        return -1;
#else
        pid_t r;
        int status = 0;

        r = waitpid((pid_t)pid, &status, 0);

        if (r == -1) {
                TEST_WARN("waitpid(%d) failed: %s\n", pid, strerror(errno));
                return -1;
        }

        if (WIFSIGNALED(status)) {
                TEST_WARN("Process %d terminated by signal %d\n", pid,
                          WTERMSIG(status));
                return -1;
        } else if (WEXITSTATUS(status)) {
                TEST_WARN("Process %d exited with status %d\n", pid,
                          WEXITSTATUS(status));
                return -1;
        }

        return 0;
#endif
}


/**
 * @brief Check if \p feature is builtin to librdkafka.
 * @returns returns 1 if feature is built in, else 0.
 */
int test_check_builtin(const char *feature) {
        rd_kafka_conf_t *conf;
        char errstr[128];
        int r;

        conf = rd_kafka_conf_new();
        if (rd_kafka_conf_set(conf, "builtin.features", feature, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                TEST_SAY("Feature \"%s\" not built-in: %s\n", feature, errstr);
                r = 0;
        } else {
                TEST_SAY("Feature \"%s\" is built-in\n", feature);
                r = 1;
        }

        rd_kafka_conf_destroy(conf);
        return r;
}


char *tsprintf(const char *fmt, ...) {
        static RD_TLS char ret[8][512];
        static RD_TLS int i;
        va_list ap;


        i = (i + 1) % 8;

        va_start(ap, fmt);
        rd_vsnprintf(ret[i], sizeof(ret[i]), fmt, ap);
        va_end(ap);

        return ret[i];
}


/**
 * @brief Add a test report JSON object.
 * These will be written as a JSON array to the test report file.
 */
void test_report_add(struct test *test, const char *fmt, ...) {
        va_list ap;
        char buf[512];

        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        if (test->report_cnt == test->report_size) {
                if (test->report_size == 0)
                        test->report_size = 8;
                else
                        test->report_size *= 2;

                test->report_arr =
                    realloc(test->report_arr,
                            sizeof(*test->report_arr) * test->report_size);
        }

        test->report_arr[test->report_cnt++] = rd_strdup(buf);

        TEST_SAYL(1, "Report #%d: %s\n", test->report_cnt - 1, buf);
}

/**
 * Returns 1 if KAFKA_PATH and BROKERS (or ZK_ADDRESS) is set to se we can use
 * the kafka-topics.sh script to manually create topics.
 *
 * If \p skip is set TEST_SKIP() will be called with a helpful message.
 */
int test_can_create_topics(int skip) {
#ifndef _WIN32
        const char *bootstrap;
#endif

        /* Has AdminAPI */
        if (test_broker_version >= TEST_BRKVER(0, 10, 2, 0))
                return 1;

#ifdef _WIN32
        if (skip)
                TEST_SKIP("Cannot create topics on Win32\n");
        return 0;
#else

        bootstrap = test_broker_version >= TEST_BRKVER(3, 0, 0, 0)
                        ? "BROKERS"
                        : "ZK_ADDRESS";

        if (!test_getenv("KAFKA_PATH", NULL) || !test_getenv(bootstrap, NULL)) {
                if (skip)
                        TEST_SKIP(
                            "Cannot create topics "
                            "(set KAFKA_PATH and %s)\n",
                            bootstrap);
                return 0;
        }


        return 1;
#endif
}


/**
 * Wait for \p event_type, discarding all other events prior to it.
 */
rd_kafka_event_t *test_wait_event(rd_kafka_queue_t *eventq,
                                  rd_kafka_event_type_t event_type,
                                  int timeout_ms) {
        test_timing_t t_w;
        int64_t abs_timeout = test_clock() + ((int64_t)timeout_ms * 1000);

        TIMING_START(&t_w, "wait_event");
        while (test_clock() < abs_timeout) {
                rd_kafka_event_t *rkev;

                rkev = rd_kafka_queue_poll(
                    eventq, (int)(abs_timeout - test_clock()) / 1000);

                if (rd_kafka_event_type(rkev) == event_type) {
                        TIMING_STOP(&t_w);
                        return rkev;
                }

                if (!rkev)
                        continue;

                if (rd_kafka_event_error(rkev))
                        TEST_SAY("discarding ignored event %s: %s\n",
                                 rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));
                else
                        TEST_SAY("discarding ignored event %s\n",
                                 rd_kafka_event_name(rkev));
                rd_kafka_event_destroy(rkev);
        }
        TIMING_STOP(&t_w);

        return NULL;
}


void test_SAY(const char *file, int line, int level, const char *str) {
        TEST_SAYL(level, "%s", str);
}

void test_SKIP(const char *file, int line, const char *str) {
        TEST_WARN("SKIPPING TEST: %s", str);
        TEST_LOCK();
        test_curr->state = TEST_SKIPPED;
        if (!*test_curr->failstr) {
                rd_snprintf(test_curr->failstr, sizeof(test_curr->failstr),
                            "%s", str);
                rtrim(test_curr->failstr);
        }
        TEST_UNLOCK();
}

const char *test_curr_name(void) {
        return test_curr->name;
}


/**
 * @brief Dump/print message haders
 */
void test_headers_dump(const char *what,
                       int lvl,
                       const rd_kafka_headers_t *hdrs) {
        size_t idx = 0;
        const char *name, *value;
        size_t size;

        while (!rd_kafka_header_get_all(hdrs, idx++, &name,
                                        (const void **)&value, &size))
                TEST_SAYL(lvl, "%s: Header #%" PRIusz ": %s='%s'\n", what,
                          idx - 1, name, value ? value : "(NULL)");
}


/**
 * @brief Retrieve and return the list of broker ids in the cluster.
 *
 * @param rk Optional instance to use.
 * @param cntp Will be updated to the number of brokers returned.
 *
 * @returns a malloc:ed list of int32_t broker ids.
 */
int32_t *test_get_broker_ids(rd_kafka_t *use_rk, size_t *cntp) {
        int32_t *ids;
        rd_kafka_t *rk;
        const rd_kafka_metadata_t *md;
        rd_kafka_resp_err_t err;
        size_t i;

        if (!(rk = use_rk))
                rk = test_create_producer();

        err = rd_kafka_metadata(rk, 0, NULL, &md, tmout_multip(5000));
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        TEST_ASSERT(md->broker_cnt > 0, "%d brokers, expected > 0",
                    md->broker_cnt);

        ids = malloc(sizeof(*ids) * md->broker_cnt);

        for (i = 0; i < (size_t)md->broker_cnt; i++)
                ids[i] = md->brokers[i].id;

        *cntp = md->broker_cnt;

        rd_kafka_metadata_destroy(md);

        if (!use_rk)
                rd_kafka_destroy(rk);

        return ids;
}



/**
 * @brief Verify that all topics in \p topics are reported in metadata,
 *        and that none of the topics in \p not_topics are reported.
 *
 * @returns the number of failures (but does not FAIL).
 */
static int verify_topics_in_metadata(rd_kafka_t *rk,
                                     rd_kafka_metadata_topic_t *topics,
                                     size_t topic_cnt,
                                     rd_kafka_metadata_topic_t *not_topics,
                                     size_t not_topic_cnt) {
        const rd_kafka_metadata_t *md;
        rd_kafka_resp_err_t err;
        int ti;
        size_t i;
        int fails = 0;

        /* Mark topics with dummy error which is overwritten
         * when topic is found in metadata, allowing us to check
         * for missed topics. */
        for (i = 0; i < topic_cnt; i++)
                topics[i].err = 12345;

        err = rd_kafka_metadata(rk, 1 /*all_topics*/, NULL, &md,
                                tmout_multip(5000));
        TEST_ASSERT(!err, "metadata failed: %s", rd_kafka_err2str(err));

        for (ti = 0; ti < md->topic_cnt; ti++) {
                const rd_kafka_metadata_topic_t *mdt = &md->topics[ti];

                for (i = 0; i < topic_cnt; i++) {
                        int pi;
                        rd_kafka_metadata_topic_t *exp_mdt;

                        if (strcmp(topics[i].topic, mdt->topic))
                                continue;

                        exp_mdt = &topics[i];

                        exp_mdt->err = mdt->err; /* indicate found */
                        if (mdt->err) {
                                TEST_SAY(
                                    "metadata: "
                                    "Topic %s has error %s\n",
                                    mdt->topic, rd_kafka_err2str(mdt->err));
                                fails++;
                        }

                        if (exp_mdt->partition_cnt > 0 &&
                            mdt->partition_cnt != exp_mdt->partition_cnt) {
                                TEST_SAY(
                                    "metadata: "
                                    "Topic %s, expected %d partitions"
                                    ", not %d\n",
                                    mdt->topic, exp_mdt->partition_cnt,
                                    mdt->partition_cnt);
                                fails++;
                                continue;
                        }

                        /* Verify per-partition values */
                        for (pi = 0;
                             exp_mdt->partitions && pi < exp_mdt->partition_cnt;
                             pi++) {
                                const rd_kafka_metadata_partition_t *mdp =
                                    &mdt->partitions[pi];
                                const rd_kafka_metadata_partition_t *exp_mdp =
                                    &exp_mdt->partitions[pi];

                                if (mdp->id != exp_mdp->id) {
                                        TEST_SAY(
                                            "metadata: "
                                            "Topic %s, "
                                            "partition %d, "
                                            "partition list out of order,"
                                            " expected %d, not %d\n",
                                            mdt->topic, pi, exp_mdp->id,
                                            mdp->id);
                                        fails++;
                                        continue;
                                }

                                if (exp_mdp->replicas) {
                                        if (mdp->replica_cnt !=
                                            exp_mdp->replica_cnt) {
                                                TEST_SAY(
                                                    "metadata: "
                                                    "Topic %s, "
                                                    "partition %d, "
                                                    "expected %d replicas,"
                                                    " not %d\n",
                                                    mdt->topic, pi,
                                                    exp_mdp->replica_cnt,
                                                    mdp->replica_cnt);
                                                fails++;
                                        } else if (
                                            memcmp(
                                                mdp->replicas,
                                                exp_mdp->replicas,
                                                mdp->replica_cnt *
                                                    sizeof(*mdp->replicas))) {
                                                int ri;

                                                TEST_SAY(
                                                    "metadata: "
                                                    "Topic %s, "
                                                    "partition %d, "
                                                    "replica mismatch:\n",
                                                    mdt->topic, pi);

                                                for (ri = 0;
                                                     ri < mdp->replica_cnt;
                                                     ri++) {
                                                        TEST_SAY(
                                                            " #%d: "
                                                            "expected "
                                                            "replica %d, "
                                                            "not %d\n",
                                                            ri,
                                                            exp_mdp
                                                                ->replicas[ri],
                                                            mdp->replicas[ri]);
                                                }

                                                fails++;
                                        }
                                }
                        }
                }

                for (i = 0; i < not_topic_cnt; i++) {
                        if (strcmp(not_topics[i].topic, mdt->topic))
                                continue;

                        TEST_SAY(
                            "metadata: "
                            "Topic %s found in metadata, unexpected\n",
                            mdt->topic);
                        fails++;
                }
        }

        for (i = 0; i < topic_cnt; i++) {
                if ((int)topics[i].err == 12345) {
                        TEST_SAY(
                            "metadata: "
                            "Topic %s not seen in metadata\n",
                            topics[i].topic);
                        fails++;
                }
        }

        if (fails > 0)
                TEST_SAY("Metadata verification for %" PRIusz
                         " topics failed "
                         "with %d errors (see above)\n",
                         topic_cnt, fails);
        else
                TEST_SAY(
                    "Metadata verification succeeded: "
                    "%" PRIusz
                    " desired topics seen, "
                    "%" PRIusz " undesired topics not seen\n",
                    topic_cnt, not_topic_cnt);

        rd_kafka_metadata_destroy(md);

        return fails;
}



/**
 * @brief Wait for metadata to reflect expected and not expected topics
 */
void test_wait_metadata_update(rd_kafka_t *rk,
                               rd_kafka_metadata_topic_t *topics,
                               size_t topic_cnt,
                               rd_kafka_metadata_topic_t *not_topics,
                               size_t not_topic_cnt,
                               int tmout) {
        int64_t abs_timeout;
        test_timing_t t_md;
        rd_kafka_t *our_rk = NULL;

        if (!rk)
                rk = our_rk = test_create_handle(RD_KAFKA_PRODUCER, NULL);

        abs_timeout = test_clock() + ((int64_t)tmout * 1000);

        TEST_SAY("Waiting for up to %dms for metadata update\n", tmout);

        TIMING_START(&t_md, "METADATA.WAIT");
        do {
                int md_fails;

                md_fails = verify_topics_in_metadata(rk, topics, topic_cnt,
                                                     not_topics, not_topic_cnt);

                if (!md_fails) {
                        TEST_SAY(
                            "All expected topics (not?) "
                            "seen in metadata\n");
                        abs_timeout = 0;
                        break;
                }

                rd_sleep(1);
        } while (test_clock() < abs_timeout);
        TIMING_STOP(&t_md);

        if (our_rk)
                rd_kafka_destroy(our_rk);

        if (abs_timeout)
                TEST_FAIL("Expected topics not seen in given time.");
}

/**
 * @brief Wait for topic to be available in metadata
 */
void test_wait_topic_exists(rd_kafka_t *rk, const char *topic, int tmout) {
        rd_kafka_metadata_topic_t topics = {.topic = (char *)topic};

        test_wait_metadata_update(rk, &topics, 1, NULL, 0, tmout);

        /* Wait an additional second for the topic to propagate in
         * the cluster. This is not perfect but a cheap workaround for
         * the asynchronous nature of topic creations in Kafka. */
        rd_sleep(1);
}



/**
 * @brief Wait for up to \p tmout for any type of admin result.
 * @returns the event
 */
rd_kafka_event_t *test_wait_admin_result(rd_kafka_queue_t *q,
                                         rd_kafka_event_type_t evtype,
                                         int tmout) {
        rd_kafka_event_t *rkev;

        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout);
                if (!rkev)
                        TEST_FAIL("Timed out waiting for admin result (%d)\n",
                                  evtype);

                if (rd_kafka_event_type(rkev) == evtype)
                        return rkev;


                if (rd_kafka_event_type(rkev) == RD_KAFKA_EVENT_ERROR) {
                        TEST_WARN(
                            "Received error event while waiting for %d: "
                            "%s: ignoring",
                            evtype, rd_kafka_event_error_string(rkev));
                        continue;
                }


                TEST_ASSERT(rd_kafka_event_type(rkev) == evtype,
                            "Expected event type %d, got %d (%s)", evtype,
                            rd_kafka_event_type(rkev),
                            rd_kafka_event_name(rkev));
        }

        return NULL;
}

/**
 * @brief Wait for up to \p tmout for an admin API result and return the
 *        distilled error code.
 *
 *        Supported APIs:
 *        - AlterConfigs
 *        - CreatePartitions
 *        - CreateTopics
 *        - DeleteGroups
 *        - DeleteRecords
 *        - DeleteTopics
 *        - DeleteConsumerGroupOffsets
 *        - DescribeConfigs
 *        - CreateAcls
 */
rd_kafka_resp_err_t test_wait_topic_admin_result(rd_kafka_queue_t *q,
                                                 rd_kafka_event_type_t evtype,
                                                 rd_kafka_event_t **retevent,
                                                 int tmout) {
        rd_kafka_event_t *rkev;
        size_t i;
        const rd_kafka_topic_result_t **terr   = NULL;
        size_t terr_cnt                        = 0;
        const rd_kafka_ConfigResource_t **cres = NULL;
        size_t cres_cnt                        = 0;
        const rd_kafka_acl_result_t **aclres   = NULL;
        size_t aclres_cnt                      = 0;
        int errcnt                             = 0;
        rd_kafka_resp_err_t err;
        const rd_kafka_group_result_t **gres           = NULL;
        size_t gres_cnt                                = 0;
        const rd_kafka_topic_partition_list_t *offsets = NULL;

        rkev = test_wait_admin_result(q, evtype, tmout);

        if ((err = rd_kafka_event_error(rkev))) {
                TEST_WARN("%s failed: %s\n", rd_kafka_event_name(rkev),
                          rd_kafka_event_error_string(rkev));
                rd_kafka_event_destroy(rkev);
                return err;
        }

        if (evtype == RD_KAFKA_EVENT_CREATETOPICS_RESULT) {
                const rd_kafka_CreateTopics_result_t *res;
                if (!(res = rd_kafka_event_CreateTopics_result(rkev)))
                        TEST_FAIL("Expected a CreateTopics result, not %s",
                                  rd_kafka_event_name(rkev));

                terr = rd_kafka_CreateTopics_result_topics(res, &terr_cnt);

        } else if (evtype == RD_KAFKA_EVENT_DELETETOPICS_RESULT) {
                const rd_kafka_DeleteTopics_result_t *res;
                if (!(res = rd_kafka_event_DeleteTopics_result(rkev)))
                        TEST_FAIL("Expected a DeleteTopics result, not %s",
                                  rd_kafka_event_name(rkev));

                terr = rd_kafka_DeleteTopics_result_topics(res, &terr_cnt);

        } else if (evtype == RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT) {
                const rd_kafka_CreatePartitions_result_t *res;
                if (!(res = rd_kafka_event_CreatePartitions_result(rkev)))
                        TEST_FAIL("Expected a CreatePartitions result, not %s",
                                  rd_kafka_event_name(rkev));

                terr = rd_kafka_CreatePartitions_result_topics(res, &terr_cnt);

        } else if (evtype == RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT) {
                const rd_kafka_DescribeConfigs_result_t *res;

                if (!(res = rd_kafka_event_DescribeConfigs_result(rkev)))
                        TEST_FAIL("Expected a DescribeConfigs result, not %s",
                                  rd_kafka_event_name(rkev));

                cres =
                    rd_kafka_DescribeConfigs_result_resources(res, &cres_cnt);

        } else if (evtype == RD_KAFKA_EVENT_ALTERCONFIGS_RESULT) {
                const rd_kafka_AlterConfigs_result_t *res;

                if (!(res = rd_kafka_event_AlterConfigs_result(rkev)))
                        TEST_FAIL("Expected a AlterConfigs result, not %s",
                                  rd_kafka_event_name(rkev));

                cres = rd_kafka_AlterConfigs_result_resources(res, &cres_cnt);

        } else if (evtype == RD_KAFKA_EVENT_CREATEACLS_RESULT) {
                const rd_kafka_CreateAcls_result_t *res;

                if (!(res = rd_kafka_event_CreateAcls_result(rkev)))
                        TEST_FAIL("Expected a CreateAcls result, not %s",
                                  rd_kafka_event_name(rkev));

                aclres = rd_kafka_CreateAcls_result_acls(res, &aclres_cnt);

        } else if (evtype == RD_KAFKA_EVENT_DELETEGROUPS_RESULT) {
                const rd_kafka_DeleteGroups_result_t *res;
                if (!(res = rd_kafka_event_DeleteGroups_result(rkev)))
                        TEST_FAIL("Expected a DeleteGroups result, not %s",
                                  rd_kafka_event_name(rkev));

                gres = rd_kafka_DeleteGroups_result_groups(res, &gres_cnt);

        } else if (evtype == RD_KAFKA_EVENT_DELETERECORDS_RESULT) {
                const rd_kafka_DeleteRecords_result_t *res;
                if (!(res = rd_kafka_event_DeleteRecords_result(rkev)))
                        TEST_FAIL("Expected a DeleteRecords result, not %s",
                                  rd_kafka_event_name(rkev));

                offsets = rd_kafka_DeleteRecords_result_offsets(res);

        } else if (evtype == RD_KAFKA_EVENT_DELETECONSUMERGROUPOFFSETS_RESULT) {
                const rd_kafka_DeleteConsumerGroupOffsets_result_t *res;
                if (!(res = rd_kafka_event_DeleteConsumerGroupOffsets_result(
                          rkev)))
                        TEST_FAIL(
                            "Expected a DeleteConsumerGroupOffsets "
                            "result, not %s",
                            rd_kafka_event_name(rkev));

                gres = rd_kafka_DeleteConsumerGroupOffsets_result_groups(
                    rkev, &gres_cnt);

        } else {
                TEST_FAIL("Bad evtype: %d", evtype);
                RD_NOTREACHED();
        }

        /* Check topic errors */
        for (i = 0; i < terr_cnt; i++) {
                if (rd_kafka_topic_result_error(terr[i])) {
                        TEST_WARN("..Topics result: %s: error: %s\n",
                                  rd_kafka_topic_result_name(terr[i]),
                                  rd_kafka_topic_result_error_string(terr[i]));
                        if (!(errcnt++))
                                err = rd_kafka_topic_result_error(terr[i]);
                }
        }

        /* Check resource errors */
        for (i = 0; i < cres_cnt; i++) {
                if (rd_kafka_ConfigResource_error(cres[i])) {
                        TEST_WARN(
                            "ConfigResource result: %d,%s: error: %s\n",
                            rd_kafka_ConfigResource_type(cres[i]),
                            rd_kafka_ConfigResource_name(cres[i]),
                            rd_kafka_ConfigResource_error_string(cres[i]));
                        if (!(errcnt++))
                                err = rd_kafka_ConfigResource_error(cres[i]);
                }
        }

        /* Check ACL errors */
        for (i = 0; i < aclres_cnt; i++) {
                const rd_kafka_error_t *error =
                    rd_kafka_acl_result_error(aclres[i]);
                if (error) {
                        TEST_WARN("AclResult error: %s: %s\n",
                                  rd_kafka_error_name(error),
                                  rd_kafka_error_string(error));
                        if (!(errcnt++))
                                err = rd_kafka_error_code(error);
                }
        }

        /* Check group errors */
        for (i = 0; i < gres_cnt; i++) {
                const rd_kafka_topic_partition_list_t *parts;

                if (rd_kafka_group_result_error(gres[i])) {

                        TEST_WARN("%s result: %s: error: %s\n",
                                  rd_kafka_event_name(rkev),
                                  rd_kafka_group_result_name(gres[i]),
                                  rd_kafka_error_string(
                                      rd_kafka_group_result_error(gres[i])));
                        if (!(errcnt++))
                                err = rd_kafka_error_code(
                                    rd_kafka_group_result_error(gres[i]));
                }

                parts = rd_kafka_group_result_partitions(gres[i]);
                if (parts) {
                        int j;
                        for (j = 0; j < parts->cnt; i++) {
                                if (!parts->elems[j].err)
                                        continue;

                                TEST_WARN(
                                    "%s result: %s: "
                                    "%s [%" PRId32 "] error: %s\n",
                                    rd_kafka_event_name(rkev),
                                    rd_kafka_group_result_name(gres[i]),
                                    parts->elems[j].topic,
                                    parts->elems[j].partition,
                                    rd_kafka_err2str(parts->elems[j].err));
                                errcnt++;
                        }
                }
        }

        /* Check offset errors */
        for (i = 0; (offsets && i < (size_t)offsets->cnt); i++) {
                if (offsets->elems[i].err) {
                        TEST_WARN("DeleteRecords result: %s [%d]: error: %s\n",
                                  offsets->elems[i].topic,
                                  offsets->elems[i].partition,
                                  rd_kafka_err2str(offsets->elems[i].err));
                        if (!(errcnt++))
                                err = offsets->elems[i].err;
                }
        }

        if (!err && retevent)
                *retevent = rkev;
        else
                rd_kafka_event_destroy(rkev);

        return err;
}



/**
 * @brief Topic Admin API helpers
 *
 * @param useq Makes the call async and posts the response in this queue.
 *             If NULL this call will be synchronous and return the error
 *             result.
 *
 * @remark Fails the current test on failure.
 */

rd_kafka_resp_err_t test_CreateTopics_simple(rd_kafka_t *rk,
                                             rd_kafka_queue_t *useq,
                                             char **topics,
                                             size_t topic_cnt,
                                             int num_partitions,
                                             void *opaque) {
        rd_kafka_NewTopic_t **new_topics;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *q;
        size_t i;
        const int tmout = 30 * 1000;
        rd_kafka_resp_err_t err;

        new_topics = malloc(sizeof(*new_topics) * topic_cnt);

        for (i = 0; i < topic_cnt; i++) {
                char errstr[512];
                new_topics[i] = rd_kafka_NewTopic_new(
                    topics[i], num_partitions, 1, errstr, sizeof(errstr));
                TEST_ASSERT(new_topics[i],
                            "Failed to NewTopic(\"%s\", %d) #%" PRIusz ": %s",
                            topics[i], num_partitions, i, errstr);
        }

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_CREATETOPICS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                char errstr[512];

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, tmout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_request_timeout: %s", errstr);
                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, tmout - 5000, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_operation_timeout: %s", errstr);

                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        TEST_SAY("Creating %" PRIusz " topics\n", topic_cnt);

        rd_kafka_CreateTopics(rk, new_topics, topic_cnt, options, q);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_NewTopic_destroy_array(new_topics, topic_cnt);
        free(new_topics);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;


        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_CREATETOPICS_RESULT, NULL, tmout + 5000);

        rd_kafka_queue_destroy(q);

        if (err)
                TEST_FAIL("Failed to create %d topic(s): %s", (int)topic_cnt,
                          rd_kafka_err2str(err));

        return err;
}


rd_kafka_resp_err_t test_CreatePartitions_simple(rd_kafka_t *rk,
                                                 rd_kafka_queue_t *useq,
                                                 const char *topic,
                                                 size_t total_part_cnt,
                                                 void *opaque) {
        rd_kafka_NewPartitions_t *newp[1];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *q;
        const int tmout = 30 * 1000;
        rd_kafka_resp_err_t err;
        char errstr[512];

        newp[0] = rd_kafka_NewPartitions_new(topic, total_part_cnt, errstr,
                                             sizeof(errstr));
        TEST_ASSERT(newp[0], "Failed to NewPartitions(\"%s\", %" PRIusz "): %s",
                    topic, total_part_cnt, errstr);

        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_CREATEPARTITIONS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, tmout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_request_timeout: %s", errstr);
                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, tmout - 5000, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_operation_timeout: %s", errstr);

                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        TEST_SAY("Creating (up to) %" PRIusz " partitions for topic \"%s\"\n",
                 total_part_cnt, topic);

        rd_kafka_CreatePartitions(rk, newp, 1, options, q);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_NewPartitions_destroy(newp[0]);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;


        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT, NULL, tmout + 5000);

        rd_kafka_queue_destroy(q);

        if (err)
                TEST_FAIL("Failed to create partitions: %s",
                          rd_kafka_err2str(err));

        return err;
}


rd_kafka_resp_err_t test_DeleteTopics_simple(rd_kafka_t *rk,
                                             rd_kafka_queue_t *useq,
                                             char **topics,
                                             size_t topic_cnt,
                                             void *opaque) {
        rd_kafka_queue_t *q;
        rd_kafka_DeleteTopic_t **del_topics;
        rd_kafka_AdminOptions_t *options;
        size_t i;
        rd_kafka_resp_err_t err;
        const int tmout = 30 * 1000;

        del_topics = malloc(sizeof(*del_topics) * topic_cnt);

        for (i = 0; i < topic_cnt; i++) {
                del_topics[i] = rd_kafka_DeleteTopic_new(topics[i]);
                TEST_ASSERT(del_topics[i]);
        }

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETETOPICS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                char errstr[512];

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, tmout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_request_timeout: %s", errstr);
                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, tmout - 5000, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_operation_timeout: %s", errstr);

                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        TEST_SAY("Deleting %" PRIusz " topics\n", topic_cnt);

        rd_kafka_DeleteTopics(rk, del_topics, topic_cnt, options, useq);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_DeleteTopic_destroy_array(del_topics, topic_cnt);

        free(del_topics);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_DELETETOPICS_RESULT, NULL, tmout + 5000);

        rd_kafka_queue_destroy(q);

        if (err)
                TEST_FAIL("Failed to delete topics: %s", rd_kafka_err2str(err));

        return err;
}

rd_kafka_resp_err_t test_DeleteGroups_simple(rd_kafka_t *rk,
                                             rd_kafka_queue_t *useq,
                                             char **groups,
                                             size_t group_cnt,
                                             void *opaque) {
        rd_kafka_queue_t *q;
        rd_kafka_DeleteGroup_t **del_groups;
        rd_kafka_AdminOptions_t *options;
        size_t i;
        rd_kafka_resp_err_t err;
        const int tmout = 30 * 1000;

        del_groups = malloc(sizeof(*del_groups) * group_cnt);

        for (i = 0; i < group_cnt; i++) {
                del_groups[i] = rd_kafka_DeleteGroup_new(groups[i]);
                TEST_ASSERT(del_groups[i]);
        }

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETEGROUPS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                char errstr[512];

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, tmout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_request_timeout: %s", errstr);

                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        TEST_SAY("Deleting %" PRIusz " groups\n", group_cnt);

        rd_kafka_DeleteGroups(rk, del_groups, group_cnt, options, useq);

        rd_kafka_AdminOptions_destroy(options);

        rd_kafka_DeleteGroup_destroy_array(del_groups, group_cnt);
        free(del_groups);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_DELETEGROUPS_RESULT, NULL, tmout + 5000);

        rd_kafka_queue_destroy(q);

        rd_kafka_DeleteGroup_destroy_array(del_groups, group_cnt);

        if (err)
                TEST_FAIL("Failed to delete groups: %s", rd_kafka_err2str(err));

        return err;
}

rd_kafka_resp_err_t
test_DeleteRecords_simple(rd_kafka_t *rk,
                          rd_kafka_queue_t *useq,
                          const rd_kafka_topic_partition_list_t *offsets,
                          void *opaque) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_resp_err_t err;
        rd_kafka_DeleteRecords_t *del_records =
            rd_kafka_DeleteRecords_new(offsets);
        const int tmout = 30 * 1000;

        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETERECORDS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                char errstr[512];

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, tmout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_request_timeout: %s", errstr);
                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, tmout - 5000, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_operation_timeout: %s", errstr);

                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        TEST_SAY("Deleting offsets from %d partitions\n", offsets->cnt);

        rd_kafka_DeleteRecords(rk, &del_records, 1, options, q);

        rd_kafka_DeleteRecords_destroy(del_records);

        rd_kafka_AdminOptions_destroy(options);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_DELETERECORDS_RESULT, NULL, tmout + 5000);

        rd_kafka_queue_destroy(q);

        if (err)
                TEST_FAIL("Failed to delete records: %s",
                          rd_kafka_err2str(err));

        return err;
}

rd_kafka_resp_err_t test_DeleteConsumerGroupOffsets_simple(
    rd_kafka_t *rk,
    rd_kafka_queue_t *useq,
    const char *group_id,
    const rd_kafka_topic_partition_list_t *offsets,
    void *opaque) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_resp_err_t err;
        const int tmout = 30 * 1000;
        rd_kafka_DeleteConsumerGroupOffsets_t *cgoffsets;

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DELETECONSUMERGROUPOFFSETS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                char errstr[512];

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, tmout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_request_timeout: %s", errstr);
                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, tmout - 5000, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "set_operation_timeout: %s", errstr);

                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        if (offsets) {
                TEST_SAY(
                    "Deleting committed offsets for group %s and "
                    "%d partitions\n",
                    group_id, offsets->cnt);

                cgoffsets =
                    rd_kafka_DeleteConsumerGroupOffsets_new(group_id, offsets);
        } else {
                TEST_SAY("Provoking invalid DeleteConsumerGroupOffsets call\n");
                cgoffsets = NULL;
        }

        rd_kafka_DeleteConsumerGroupOffsets(rk, &cgoffsets, cgoffsets ? 1 : 0,
                                            options, useq);

        if (cgoffsets)
                rd_kafka_DeleteConsumerGroupOffsets_destroy(cgoffsets);

        rd_kafka_AdminOptions_destroy(options);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_DELETECONSUMERGROUPOFFSETS_RESULT, NULL,
            tmout + 5000);

        rd_kafka_queue_destroy(q);

        if (err)
                TEST_FAIL("Failed to delete committed offsets: %s",
                          rd_kafka_err2str(err));

        return err;
}

/**
 * @brief Delta Alter configuration for the given resource,
 *        overwriting/setting the configs provided in \p configs.
 *        Existing configuration remains intact.
 *
 * @param configs 'const char *name, const char *value' tuples
 * @param config_cnt is the number of tuples in \p configs
 */
rd_kafka_resp_err_t test_AlterConfigs_simple(rd_kafka_t *rk,
                                             rd_kafka_ResourceType_t restype,
                                             const char *resname,
                                             const char **configs,
                                             size_t config_cnt) {
        rd_kafka_queue_t *q;
        rd_kafka_ConfigResource_t *confres;
        rd_kafka_event_t *rkev;
        size_t i;
        rd_kafka_resp_err_t err;
        const rd_kafka_ConfigResource_t **results;
        size_t result_cnt;
        const rd_kafka_ConfigEntry_t **configents;
        size_t configent_cnt;


        q = rd_kafka_queue_new(rk);

        TEST_SAY("Getting configuration for %d %s\n", restype, resname);

        confres = rd_kafka_ConfigResource_new(restype, resname);
        rd_kafka_DescribeConfigs(rk, &confres, 1, NULL, q);

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT, &rkev, 15 * 1000);
        if (err) {
                rd_kafka_queue_destroy(q);
                rd_kafka_ConfigResource_destroy(confres);
                return err;
        }

        results = rd_kafka_DescribeConfigs_result_resources(
            rd_kafka_event_DescribeConfigs_result(rkev), &result_cnt);
        TEST_ASSERT(result_cnt == 1,
                    "expected 1 DescribeConfigs result, not %" PRIusz,
                    result_cnt);

        configents =
            rd_kafka_ConfigResource_configs(results[0], &configent_cnt);
        TEST_ASSERT(configent_cnt > 0,
                    "expected > 0 ConfigEntry:s, not %" PRIusz, configent_cnt);

        TEST_SAY("Altering configuration for %d %s\n", restype, resname);

        /* Apply all existing configuration entries to resource object that
         * will later be passed to AlterConfigs. */
        for (i = 0; i < configent_cnt; i++) {
                err = rd_kafka_ConfigResource_set_config(
                    confres, rd_kafka_ConfigEntry_name(configents[i]),
                    rd_kafka_ConfigEntry_value(configents[i]));
                TEST_ASSERT(!err,
                            "Failed to set read-back config %s=%s "
                            "on local resource object",
                            rd_kafka_ConfigEntry_name(configents[i]),
                            rd_kafka_ConfigEntry_value(configents[i]));
        }

        rd_kafka_event_destroy(rkev);

        /* Then apply the configuration to change. */
        for (i = 0; i < config_cnt; i += 2) {
                err = rd_kafka_ConfigResource_set_config(confres, configs[i],
                                                         configs[i + 1]);
                TEST_ASSERT(!err,
                            "Failed to set config %s=%s on "
                            "local resource object",
                            configs[i], configs[i + 1]);
        }

        rd_kafka_AlterConfigs(rk, &confres, 1, NULL, q);

        rd_kafka_ConfigResource_destroy(confres);

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_ALTERCONFIGS_RESULT, NULL, 15 * 1000);

        rd_kafka_queue_destroy(q);

        return err;
}

/**
 * @brief Topic Admin API helpers
 *
 * @param useq Makes the call async and posts the response in this queue.
 *             If NULL this call will be synchronous and return the error
 *             result.
 *
 * @remark Fails the current test on failure.
 */

rd_kafka_resp_err_t test_CreateAcls_simple(rd_kafka_t *rk,
                                           rd_kafka_queue_t *useq,
                                           rd_kafka_AclBinding_t **acls,
                                           size_t acl_cnt,
                                           void *opaque) {
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *q;
        rd_kafka_resp_err_t err;
        const int tmout = 30 * 1000;

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_CREATEACLS);
        rd_kafka_AdminOptions_set_opaque(options, opaque);

        if (!useq) {
                q = rd_kafka_queue_new(rk);
        } else {
                q = useq;
        }

        TEST_SAY("Creating %" PRIusz " acls\n", acl_cnt);

        rd_kafka_CreateAcls(rk, acls, acl_cnt, options, q);

        rd_kafka_AdminOptions_destroy(options);

        if (useq)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        err = test_wait_topic_admin_result(q, RD_KAFKA_EVENT_CREATEACLS_RESULT,
                                           NULL, tmout + 5000);

        rd_kafka_queue_destroy(q);

        if (err)
                TEST_FAIL("Failed to create %d acl(s): %s", (int)acl_cnt,
                          rd_kafka_err2str(err));

        return err;
}

static void test_free_string_array(char **strs, size_t cnt) {
        size_t i;
        for (i = 0; i < cnt; i++)
                free(strs[i]);
        free(strs);
}


/**
 * @return an array of all topics in the cluster matching our the
 *         rdkafka test prefix.
 */
static rd_kafka_resp_err_t
test_get_all_test_topics(rd_kafka_t *rk, char ***topicsp, size_t *topic_cntp) {
        size_t test_topic_prefix_len = strlen(test_topic_prefix);
        const rd_kafka_metadata_t *md;
        char **topics    = NULL;
        size_t topic_cnt = 0;
        int i;
        rd_kafka_resp_err_t err;

        *topic_cntp = 0;
        if (topicsp)
                *topicsp = NULL;

        /* Retrieve list of topics */
        err = rd_kafka_metadata(rk, 1 /*all topics*/, NULL, &md,
                                tmout_multip(10000));
        if (err) {
                TEST_WARN(
                    "%s: Failed to acquire metadata: %s: "
                    "not deleting any topics\n",
                    __FUNCTION__, rd_kafka_err2str(err));
                return err;
        }

        if (md->topic_cnt == 0) {
                TEST_WARN("%s: No topics in cluster\n", __FUNCTION__);
                rd_kafka_metadata_destroy(md);
                return RD_KAFKA_RESP_ERR_NO_ERROR;
        }

        if (topicsp)
                topics = malloc(sizeof(*topics) * md->topic_cnt);

        for (i = 0; i < md->topic_cnt; i++) {
                if (strlen(md->topics[i].topic) >= test_topic_prefix_len &&
                    !strncmp(md->topics[i].topic, test_topic_prefix,
                             test_topic_prefix_len)) {
                        if (topicsp)
                                topics[topic_cnt++] =
                                    rd_strdup(md->topics[i].topic);
                        else
                                topic_cnt++;
                }
        }

        if (topic_cnt == 0) {
                TEST_SAY(
                    "%s: No topics (out of %d) matching our "
                    "test prefix (%s)\n",
                    __FUNCTION__, md->topic_cnt, test_topic_prefix);
                rd_kafka_metadata_destroy(md);
                if (topics)
                        test_free_string_array(topics, topic_cnt);
                return RD_KAFKA_RESP_ERR_NO_ERROR;
        }

        rd_kafka_metadata_destroy(md);

        if (topicsp)
                *topicsp = topics;
        *topic_cntp = topic_cnt;

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief Delete all test topics using the Kafka Admin API.
 */
rd_kafka_resp_err_t test_delete_all_test_topics(int timeout_ms) {
        rd_kafka_t *rk;
        char **topics;
        size_t topic_cnt = 0;
        rd_kafka_resp_err_t err;
        int i;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_queue_t *q;
        char errstr[256];
        int64_t abs_timeout = test_clock() + ((int64_t)timeout_ms * 1000);

        rk = test_create_producer();

        err = test_get_all_test_topics(rk, &topics, &topic_cnt);
        if (err) {
                /* Error already reported by test_get_all_test_topics() */
                rd_kafka_destroy(rk);
                return err;
        }

        if (topic_cnt == 0) {
                rd_kafka_destroy(rk);
                return RD_KAFKA_RESP_ERR_NO_ERROR;
        }

        q = rd_kafka_queue_get_main(rk);

        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETETOPICS);
        if (rd_kafka_AdminOptions_set_operation_timeout(options, 2 * 60 * 1000,
                                                        errstr, sizeof(errstr)))
                TEST_SAY(_C_YEL
                         "Failed to set DeleteTopics timeout: %s: "
                         "ignoring\n",
                         errstr);

        TEST_SAY(_C_MAG
                 "====> Deleting all test topics with <===="
                 "a timeout of 2 minutes\n");

        test_DeleteTopics_simple(rk, q, topics, topic_cnt, options);

        rd_kafka_AdminOptions_destroy(options);

        while (1) {
                rd_kafka_event_t *rkev;
                const rd_kafka_DeleteTopics_result_t *res;

                rkev = rd_kafka_queue_poll(q, -1);

                res = rd_kafka_event_DeleteTopics_result(rkev);
                if (!res) {
                        TEST_SAY("%s: Ignoring event: %s: %s\n", __FUNCTION__,
                                 rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));
                        rd_kafka_event_destroy(rkev);
                        continue;
                }

                if (rd_kafka_event_error(rkev)) {
                        TEST_WARN("%s: DeleteTopics for %" PRIusz
                                  " topics "
                                  "failed: %s\n",
                                  __FUNCTION__, topic_cnt,
                                  rd_kafka_event_error_string(rkev));
                        err = rd_kafka_event_error(rkev);
                } else {
                        const rd_kafka_topic_result_t **terr;
                        size_t tcnt;
                        int okcnt = 0;

                        terr = rd_kafka_DeleteTopics_result_topics(res, &tcnt);

                        for (i = 0; i < (int)tcnt; i++) {
                                if (!rd_kafka_topic_result_error(terr[i])) {
                                        okcnt++;
                                        continue;
                                }

                                TEST_WARN("%s: Failed to delete topic %s: %s\n",
                                          __FUNCTION__,
                                          rd_kafka_topic_result_name(terr[i]),
                                          rd_kafka_topic_result_error_string(
                                              terr[i]));
                        }

                        TEST_SAY(
                            "%s: DeleteTopics "
                            "succeeded for %d/%" PRIusz " topics\n",
                            __FUNCTION__, okcnt, topic_cnt);
                        err = RD_KAFKA_RESP_ERR_NO_ERROR;
                }

                rd_kafka_event_destroy(rkev);
                break;
        }

        rd_kafka_queue_destroy(q);

        test_free_string_array(topics, topic_cnt);

        /* Wait for topics to be fully deleted */
        while (1) {
                err = test_get_all_test_topics(rk, NULL, &topic_cnt);

                if (!err && topic_cnt == 0)
                        break;

                if (abs_timeout < test_clock()) {
                        TEST_WARN(
                            "%s: Timed out waiting for "
                            "remaining %" PRIusz
                            " deleted topics "
                            "to disappear from cluster metadata\n",
                            __FUNCTION__, topic_cnt);
                        break;
                }

                TEST_SAY("Waiting for remaining %" PRIusz
                         " delete topics "
                         "to disappear from cluster metadata\n",
                         topic_cnt);

                rd_sleep(1);
        }

        rd_kafka_destroy(rk);

        return err;
}



void test_fail0(const char *file,
                int line,
                const char *function,
                int do_lock,
                int fail_now,
                const char *fmt,
                ...) {
        char buf[512];
        int is_thrd = 0;
        size_t of;
        va_list ap;
        char *t;
        char timestr[32];
        time_t tnow = time(NULL);

#ifdef __MINGW32__
        strftime(timestr, sizeof(timestr), "%a %b %d %H:%M:%S %Y",
                 localtime(&tnow));
#elif defined(_WIN32)
        ctime_s(timestr, sizeof(timestr), &tnow);
#else
        ctime_r(&tnow, timestr);
#endif
        t = strchr(timestr, '\n');
        if (t)
                *t = '\0';

        of = rd_snprintf(buf, sizeof(buf), "%s%s%s():%i: ", test_curr->subtest,
                         *test_curr->subtest ? ": " : "", function, line);
        rd_assert(of < sizeof(buf));

        va_start(ap, fmt);
        rd_vsnprintf(buf + of, sizeof(buf) - of, fmt, ap);
        va_end(ap);

        /* Remove trailing newline */
        if ((t = strchr(buf, '\n')) && !*(t + 1))
                *t = '\0';

        TEST_SAYL(0, "TEST FAILURE\n");
        fprintf(stderr,
                "\033[31m### Test \"%s%s%s%s\" failed at %s:%i:%s() at %s: "
                "###\n"
                "%s\n",
                test_curr->name, *test_curr->subtest ? " (" : "",
                test_curr->subtest, *test_curr->subtest ? ")" : "", file, line,
                function, timestr, buf + of);
        if (do_lock)
                TEST_LOCK();
        test_curr->state = TEST_FAILED;
        test_curr->failcnt += 1;
        test_curr->is_fatal_cb = NULL;

        if (!*test_curr->failstr) {
                strncpy(test_curr->failstr, buf, sizeof(test_curr->failstr));
                test_curr->failstr[sizeof(test_curr->failstr) - 1] = '\0';
        }
        if (fail_now && test_curr->mainfunc) {
                tests_running_cnt--;
                is_thrd = 1;
        }
        if (do_lock)
                TEST_UNLOCK();
        if (!fail_now)
                return;
        if (test_assert_on_fail || !is_thrd)
                assert(0);
        else
                thrd_exit(0);
}


/**
 * @brief Destroy a mock cluster and its underlying rd_kafka_t handle
 */
void test_mock_cluster_destroy(rd_kafka_mock_cluster_t *mcluster) {
        rd_kafka_t *rk = rd_kafka_mock_cluster_handle(mcluster);
        rd_kafka_mock_cluster_destroy(mcluster);
        rd_kafka_destroy(rk);
}



/**
 * @brief Create a standalone mock cluster that can be used by multiple
 *        rd_kafka_t instances.
 */
rd_kafka_mock_cluster_t *test_mock_cluster_new(int broker_cnt,
                                               const char **bootstraps) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_mock_cluster_t *mcluster;
        char errstr[256];

        test_conf_common_init(conf, 0);

        test_conf_set(conf, "client.id", "MOCK");

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "Failed to create mock cluster rd_kafka_t: %s", errstr);

        mcluster = rd_kafka_mock_cluster_new(rk, broker_cnt);
        TEST_ASSERT(mcluster, "Failed to acquire mock cluster");

        if (bootstraps)
                *bootstraps = rd_kafka_mock_cluster_bootstraps(mcluster);

        return mcluster;
}



/**
 * @name Sub-tests
 */


/**
 * @brief Start a sub-test. \p fmt is optional and allows additional
 *        sub-test info to be displayed, e.g., test parameters.
 *
 * @returns 0 if sub-test should not be run, else 1.
 */
int test_sub_start(const char *func,
                   int line,
                   int is_quick,
                   const char *fmt,
                   ...) {

        if (!is_quick && test_quick)
                return 0;

        if (fmt && *fmt) {
                va_list ap;
                char buf[256];

                va_start(ap, fmt);
                rd_vsnprintf(buf, sizeof(buf), fmt, ap);
                va_end(ap);

                rd_snprintf(test_curr->subtest, sizeof(test_curr->subtest),
                            "%s:%d: %s", func, line, buf);
        } else {
                rd_snprintf(test_curr->subtest, sizeof(test_curr->subtest),
                            "%s:%d", func, line);
        }

        if (subtests_to_run && !strstr(test_curr->subtest, subtests_to_run)) {
                *test_curr->subtest = '\0';
                return 0;
        }

        TIMING_START(&test_curr->subtest_duration, "SUBTEST");

        TEST_SAY(_C_MAG "[ %s ]\n", test_curr->subtest);

        return 1;
}


/**
 * @brief Reset the current subtest state.
 */
static void test_sub_reset(void) {
        *test_curr->subtest      = '\0';
        test_curr->is_fatal_cb   = NULL;
        test_curr->ignore_dr_err = rd_false;
        test_curr->exp_dr_err    = RD_KAFKA_RESP_ERR_NO_ERROR;
        /* Don't check msg status by default */
        test_curr->exp_dr_status = (rd_kafka_msg_status_t)-1;
        test_curr->dr_mv         = NULL;
}

/**
 * @brief Sub-test has passed.
 */
void test_sub_pass(void) {

        TEST_ASSERT(*test_curr->subtest);

        TEST_SAYL(1, _C_GRN "[ %s: PASS (%.02fs) ]\n", test_curr->subtest,
                  (float)(TIMING_DURATION(&test_curr->subtest_duration) /
                          1000000.0f));

        test_sub_reset();
}


/**
 * @brief Skip sub-test (must have been started with SUB_TEST*()).
 */
void test_sub_skip(const char *fmt, ...) {
        va_list ap;
        char buf[256];

        TEST_ASSERT(*test_curr->subtest);

        va_start(ap, fmt);
        rd_vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        TEST_SAYL(1, _C_YEL "[ %s: SKIP: %s ]\n", test_curr->subtest, buf);

        test_sub_reset();
}
