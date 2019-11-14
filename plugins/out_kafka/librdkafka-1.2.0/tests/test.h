/*
* librdkafka - Apache Kafka C library
*
* Copyright (c) 2012-2015, Magnus Edenhill
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
#ifndef _TEST_H_
#define _TEST_H_

#include "../src/rd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>

#include "rdkafka.h"
#include "tinycthread.h"
#include "rdlist.h"

#if WITH_SOCKEM
#include "sockem.h"
#endif

#include "testshared.h"
#ifdef _MSC_VER
#define sscanf(...) sscanf_s(__VA_ARGS__)
#endif

/**
 * Test output is controlled through "TEST_LEVEL=N" environemnt variable.
 * N < 2: TEST_SAY() is quiet.
 */
extern int test_level;

extern int test_seed;
extern char test_mode[64];
extern RD_TLS struct test *test_curr;
extern int test_assert_on_fail;
extern int tests_running_cnt;
extern double test_timeout_multiplier;
extern int  test_session_timeout_ms; /* Group session timeout */
extern int  test_flags;
extern int  test_neg_flags;
extern int  test_idempotent_producer;

extern mtx_t test_mtx;

#define TEST_LOCK()   mtx_lock(&test_mtx)
#define TEST_UNLOCK() mtx_unlock(&test_mtx)


typedef enum {
        TEST_NOT_STARTED,
        TEST_SKIPPED,
        TEST_RUNNING,
        TEST_PASSED,
        TEST_FAILED,
} test_state_t;

struct test {
        /**
         * Setup
         */
        const char *name;    /**< e.g. Same as filename minus extension */
        int (*mainfunc) (int argc, char **argv); /**< test's main func */
        const int flags;     /**< Test flags */
#define TEST_F_LOCAL   0x1   /**< Test is local, no broker requirement */
#define TEST_F_KNOWN_ISSUE 0x2 /**< Known issue, can fail without affecting
				*   total test run status. */
#define TEST_F_MANUAL      0x4 /**< Manual test, only started when specifically
                                *   stated */
#define TEST_F_SOCKEM      0x8 /**< Test requires socket emulation. */
	int minver;          /**< Limit tests to broker version range. */
	int maxver;

	const char *extra;   /**< Extra information to print in test_summary. */

	char **report_arr;   /**< Test-specific reporting, JSON array of objects. */
	int report_cnt;
	int report_size;

        rd_kafka_resp_err_t exp_dr_err; /* Expected error in test_dr_cb */
        rd_kafka_msg_status_t exp_dr_status; /**< Expected delivery status,
                                              *   or -1 for not checking. */
        int produce_sync;    /**< test_produce_sync() call in action */
        rd_kafka_resp_err_t produce_sync_err;  /**< DR error */

        /**
         * Runtime
         */
        thrd_t  thrd;
        int64_t start;
        int64_t duration;
        FILE   *stats_fp;
	int64_t timeout;
        test_state_t state;
        int     failcnt;     /**< Number of failures, useful with FAIL_LATER */
        char    failstr[512];/**< First test failure reason */

#if WITH_SOCKEM
        rd_list_t sockets;
        int (*connect_cb) (struct test *test, sockem_t *skm, const char *id);
#endif
        int (*is_fatal_cb) (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                            const char *reason);
};


#ifdef _MSC_VER
#define TEST_F_KNOWN_ISSUE_WIN32  TEST_F_KNOWN_ISSUE
#else
#define TEST_F_KNOWN_ISSUE_WIN32 0
#endif

#ifdef __APPLE__
#define TEST_F_KNOWN_ISSUE_OSX  TEST_F_KNOWN_ISSUE
#else
#define TEST_F_KNOWN_ISSUE_OSX  0
#endif

void test_fail0 (const char *file, int line, const char *function,
                 int do_lock, int fail_now, const char *fmt, ...);

#define TEST_FAIL0(file,line,do_lock,fail_now,...)   \
        test_fail0(__FILE__, __LINE__, __FUNCTION__, \
                   do_lock, fail_now, __VA_ARGS__)

/* Whine and abort test */
#define TEST_FAIL(...) TEST_FAIL0(__FILE__,__LINE__,1,1,__VA_ARGS__)

/* Whine right away, mark the test as failed, but continue the test. */
#define TEST_FAIL_LATER(...) TEST_FAIL0(__FILE__,__LINE__,1,0,__VA_ARGS__)

/* Whine right away, maybe mark the test as failed, but continue the test. */
#define TEST_FAIL_LATER0(LATER,...) TEST_FAIL0(__FILE__,__LINE__,1,!(LATER),__VA_ARGS__)

#define TEST_FAILCNT()  (test_curr->failcnt)

#define TEST_LATER_CHECK(...) do {                              \
        if (test_curr->state == TEST_FAILED)                    \
                TEST_FAIL("See previous errors. " __VA_ARGS__); \
        } while (0)

#define TEST_PERROR(call) do {						\
		if (!(call))						\
			TEST_FAIL(#call " failed: %s", rd_strerror(errno)); \
	} while (0)

#define TEST_WARN(...) do {                                              \
                fprintf(stderr, "\033[33m[%-28s/%7.3fs] WARN: ",	\
			test_curr->name,                                \
			test_curr->start ?                              \
			((float)(test_clock() -                         \
                                 test_curr->start)/1000000.0f) : 0);    \
		fprintf(stderr, __VA_ARGS__);				\
                fprintf(stderr, "\033[0m");                             \
	} while (0)

#define TEST_SAY0(...)  fprintf(stderr, __VA_ARGS__)
#define TEST_SAYL(LVL,...) do {						\
	if (test_level >= LVL) {                                        \
                fprintf(stderr, "\033[36m[%-28s/%7.3fs] ",		\
			test_curr->name,                                \
			test_curr->start ?                              \
			((float)(test_clock() -                         \
                                 test_curr->start)/1000000.0f) : 0);    \
		fprintf(stderr, __VA_ARGS__);				\
                fprintf(stderr, "\033[0m");                             \
        }                                                               \
	} while (0)
#define TEST_SAY(...) TEST_SAYL(2, __VA_ARGS__)

/**
 * Append JSON object (as string) to this tests' report array.
 */
#define TEST_REPORT(...) test_report_add(test_curr, __VA_ARGS__)


/* "..." is a failure reason in printf format, include as much info as needed */
#define TEST_ASSERT(expr,...) do {            \
        if (!(expr)) {                        \
                      TEST_FAIL("Test assertion failed: \"" # expr  "\": " \
                                __VA_ARGS__);                           \
                      }                                                 \
        } while (0)


/* "..." is a failure reason in printf format, include as much info as needed */
#define TEST_ASSERT_LATER(expr,...) do {                                \
                if (!(expr)) {                                          \
                        TEST_FAIL0(__FILE__, __LINE__, 1, 0,            \
                                   "Test assertion failed: \"" # expr  "\": " \
                                   __VA_ARGS__);                        \
                }                                                       \
        } while (0)

static RD_INLINE RD_UNUSED void rtrim (char *str) {
        size_t len = strlen(str);
        char *s;

        if (len == 0)
                return;

        s = str + len - 1;
        while (isspace((int)*s)) {
                *s = '\0';
                s--;
        }
}

/* Skip the current test. Argument is textual reason (printf format) */
#define TEST_SKIP(...) do {                                             \
                TEST_WARN("SKIPPING TEST: " __VA_ARGS__);               \
                TEST_LOCK();                                            \
                test_curr->state = TEST_SKIPPED;                        \
                if (!*test_curr->failstr) {                             \
                        rd_snprintf(test_curr->failstr,                 \
                                    sizeof(test_curr->failstr), __VA_ARGS__); \
                        rtrim(test_curr->failstr);                      \
                }                                                       \
                TEST_UNLOCK();                                          \
        } while (0)


void test_conf_init (rd_kafka_conf_t **conf, rd_kafka_topic_conf_t **topic_conf,
		     int timeout);







void test_msg_fmt (char *dest, size_t dest_size,
		   uint64_t testid, int32_t partition, int msgid);
void test_msg_parse0 (const char *func, int line,
		      uint64_t testid, rd_kafka_message_t *rkmessage,
		      int32_t exp_partition, int *msgidp);
#define test_msg_parse(testid,rkmessage,exp_partition,msgidp)	\
	test_msg_parse0(__FUNCTION__,__LINE__,\
			testid,rkmessage,exp_partition,msgidp)


static RD_INLINE int jitter (int low, int high) RD_UNUSED;
static RD_INLINE int jitter (int low, int high) {
	return (low + (rand() % ((high-low)+1)));
}



/******************************************************************************
 *
 * Helpers
 *
 ******************************************************************************/



/****************************************************************
 * Message verification services				*
 *								*
 *								*
 *								*
 ****************************************************************/


/**
 * A test_msgver_t is first fed with messages from any number of
 * topics and partitions, it is then checked for expected messages, such as:
 *   - all messages received, based on message payload information.
 *   - messages received in order
 *   - EOF
 */
typedef struct test_msgver_s {
	struct test_mv_p **p;  /* Partitions array */
	int p_cnt;             /* Partition count */
	int p_size;            /* p size */
	int msgcnt;            /* Total message count */
	uint64_t testid;       /* Only accept messages for this testid */

	struct test_msgver_s *fwd;  /* Also forward add_msg() to this mv */

	int log_cnt;           /* Current number of warning logs */
	int log_max;           /* Max warning logs before suppressing. */
	int log_suppr_cnt;     /* Number of suppressed log messages. */

        const char *msgid_hdr; /**< msgid string is in header by this name,
                                * rather than in the payload (default). */
} test_msgver_t;

/* Message */
struct test_mv_m {
        int64_t offset;    /* Message offset */
        int     msgid;     /* Message id */
        int64_t timestamp; /* Message timestamp */
};


/* Message vector */
struct test_mv_mvec {
	struct test_mv_m *m;
	int cnt;
	int size;  /* m[] size */
};

/* Partition */
struct test_mv_p {
	char *topic;
	int32_t partition;
	struct test_mv_mvec mvec;
	int64_t eof_offset;
};

/* Verification state */
struct test_mv_vs {
	int msg_base;
	int exp_cnt;

	/* used by verify_range */
	int msgid_min;
	int msgid_max;
        int64_t timestamp_min;
        int64_t timestamp_max;

	struct test_mv_mvec mvec;

        /* Correct msgver for comparison */
        test_msgver_t *corr;
} vs;


void test_msgver_init (test_msgver_t *mv, uint64_t testid);
void test_msgver_clear (test_msgver_t *mv);
int test_msgver_add_msg00 (const char *func, int line, test_msgver_t *mv,
                           uint64_t testid,
                           const char *topic, int32_t partition,
                           int64_t offset, int64_t timestamp,
                           rd_kafka_resp_err_t err, int msgnum);
int test_msgver_add_msg0 (const char *func, int line,
			  test_msgver_t *mv, rd_kafka_message_t *rkm);
#define test_msgver_add_msg(mv,rkm) \
	test_msgver_add_msg0(__FUNCTION__,__LINE__,mv,rkm)

/**
 * Flags to indicate what to verify.
 */
#define TEST_MSGVER_ORDER    0x1  /* Order */
#define TEST_MSGVER_DUP      0x2  /* Duplicates */
#define TEST_MSGVER_RANGE    0x4  /* Range of messages */

#define TEST_MSGVER_ALL      0xf  /* All verifiers */

#define TEST_MSGVER_BY_MSGID  0x10000 /* Verify by msgid (unique in testid) */
#define TEST_MSGVER_BY_OFFSET 0x20000 /* Verify by offset (unique in partition)*/
#define TEST_MSGVER_BY_TIMESTAMP 0x40000 /* Verify by timestamp range */

#define TEST_MSGVER_SUBSET 0x100000  /* verify_compare: allow correct mv to be
                                      * a subset of mv. */

/* Only test per partition, not across all messages received on all partitions.
 * This is useful when doing incremental verifications with multiple partitions
 * and the total number of messages has not been received yet.
 * Can't do range check here since messages may be spread out on multiple
 * partitions and we might just have read a few partitions. */
#define TEST_MSGVER_PER_PART ((TEST_MSGVER_ALL & ~TEST_MSGVER_RANGE) | \
			      TEST_MSGVER_BY_MSGID | TEST_MSGVER_BY_OFFSET)

/* Test on all messages across all partitions.
 * This can only be used to check with msgid, not offset since that
 * is partition local. */
#define TEST_MSGVER_ALL_PART (TEST_MSGVER_ALL | TEST_MSGVER_BY_MSGID)


int test_msgver_verify_part0 (const char *func, int line, const char *what,
			      test_msgver_t *mv, int flags,
			      const char *topic, int partition,
			      int msg_base, int exp_cnt);
#define test_msgver_verify_part(what,mv,flags,topic,partition,msg_base,exp_cnt) \
	test_msgver_verify_part0(__FUNCTION__,__LINE__,			\
				 what,mv,flags,topic,partition,msg_base,exp_cnt)

int test_msgver_verify0 (const char *func, int line, const char *what,
			 test_msgver_t *mv, int flags, struct test_mv_vs vs);
#define test_msgver_verify(what,mv,flags,msgbase,expcnt)		\
	test_msgver_verify0(__FUNCTION__,__LINE__,			\
			    what,mv,flags,                              \
                            (struct test_mv_vs){.msg_base = msgbase,   \
                                            .exp_cnt = expcnt})


void test_msgver_verify_compare0 (const char *func, int line,
                                  const char *what, test_msgver_t *mv,
                                  test_msgver_t *corr, int flags);
#define test_msgver_verify_compare(what,mv,corr,flags) \
        test_msgver_verify_compare0(__FUNCTION__,__LINE__, what, mv, corr, flags)

rd_kafka_t *test_create_handle (int mode, rd_kafka_conf_t *conf);

/**
 * Delivery reported callback.
 * Called for each message once to signal its delivery status.
 */
void test_dr_msg_cb (rd_kafka_t *rk,
                     const rd_kafka_message_t *rkmessage, void *opaque);

rd_kafka_t *test_create_producer (void);
rd_kafka_topic_t *test_create_producer_topic(rd_kafka_t *rk,
	const char *topic, ...);
void test_wait_delivery (rd_kafka_t *rk, int *msgcounterp);
void test_produce_msgs_nowait (rd_kafka_t *rk, rd_kafka_topic_t *rkt,
                               uint64_t testid, int32_t partition,
                               int msg_base, int cnt,
                               const char *payload, size_t size, int msgrate,
                               int *msgcounterp);
void test_produce_msgs (rd_kafka_t *rk, rd_kafka_topic_t *rkt,
                        uint64_t testid, int32_t partition,
                        int msg_base, int cnt,
			const char *payload, size_t size);
void test_produce_msgs_rate (rd_kafka_t *rk, rd_kafka_topic_t *rkt,
                             uint64_t testid, int32_t partition,
                             int msg_base, int cnt,
                             const char *payload, size_t size, int msgrate);
rd_kafka_resp_err_t test_produce_sync (rd_kafka_t *rk, rd_kafka_topic_t *rkt,
                                       uint64_t testid, int32_t partition);

rd_kafka_t *test_create_consumer (const char *group_id,
				  void (*rebalance_cb) (
					  rd_kafka_t *rk,
					  rd_kafka_resp_err_t err,
					  rd_kafka_topic_partition_list_t
					  *partitions,
					  void *opaque),
				  rd_kafka_conf_t *conf,
                                  rd_kafka_topic_conf_t *default_topic_conf);
rd_kafka_topic_t *test_create_consumer_topic (rd_kafka_t *rk,
                                              const char *topic);
rd_kafka_topic_t *test_create_topic_object (rd_kafka_t *rk,
					    const char *topic, ...);
void test_consumer_start (const char *what,
                          rd_kafka_topic_t *rkt, int32_t partition,
                          int64_t start_offset);
void test_consumer_stop (const char *what,
                         rd_kafka_topic_t *rkt, int32_t partition);
void test_consumer_seek (const char *what, rd_kafka_topic_t *rkt,
                         int32_t partition, int64_t offset);

#define TEST_NO_SEEK  -1
int64_t test_consume_msgs (const char *what, rd_kafka_topic_t *rkt,
                           uint64_t testid, int32_t partition, int64_t offset,
                           int exp_msg_base, int exp_cnt, int parse_fmt);


void test_verify_rkmessage0 (const char *func, int line,
                             rd_kafka_message_t *rkmessage, uint64_t testid,
                             int32_t partition, int msgnum);
#define test_verify_rkmessage(rkmessage,testid,partition,msgnum) \
        test_verify_rkmessage0(__FUNCTION__,__LINE__,\
                               rkmessage,testid,partition,msgnum)

void test_consumer_subscribe (rd_kafka_t *rk, const char *topic);

void
test_consume_msgs_easy_mv (const char *group_id, const char *topic,
                           int32_t partition,
                           uint64_t testid, int exp_eofcnt, int exp_msgcnt,
                           rd_kafka_topic_conf_t *tconf,
                           test_msgver_t *mv);
void
test_consume_msgs_easy (const char *group_id, const char *topic,
                        uint64_t testid, int exp_eofcnt, int exp_msgcnt,
                        rd_kafka_topic_conf_t *tconf);

void test_consumer_poll_no_msgs (const char *what, rd_kafka_t *rk,
				 uint64_t testid, int timeout_ms);
int test_consumer_poll_once (rd_kafka_t *rk, test_msgver_t *mv, int timeout_ms);
int test_consumer_poll (const char *what, rd_kafka_t *rk, uint64_t testid,
                        int exp_eof_cnt, int exp_msg_base, int exp_cnt,
			test_msgver_t *mv);

void test_consumer_assign (const char *what, rd_kafka_t *rk,
			   rd_kafka_topic_partition_list_t *parts);
void test_consumer_unassign (const char *what, rd_kafka_t *rk);

void test_consumer_close (rd_kafka_t *rk);

void test_flush (rd_kafka_t *rk, int timeout_ms);

void test_conf_set (rd_kafka_conf_t *conf, const char *name, const char *val);
char *test_conf_get (const rd_kafka_conf_t *conf, const char *name);
int test_conf_match (rd_kafka_conf_t *conf, const char *name, const char *val);
void test_topic_conf_set (rd_kafka_topic_conf_t *tconf,
                          const char *name, const char *val);
void test_any_conf_set (rd_kafka_conf_t *conf,
                        rd_kafka_topic_conf_t *tconf,
                        const char *name, const char *val);

void test_print_partition_list (const rd_kafka_topic_partition_list_t
				*partitions);

void test_kafka_topics (const char *fmt, ...);
void test_create_topic (rd_kafka_t *use_rk,
                        const char *topicname, int partition_cnt,
                        int replication_factor);
rd_kafka_resp_err_t test_auto_create_topic_rkt (rd_kafka_t *rk,
                                                rd_kafka_topic_t *rkt,
                                                int timeout_ms);
rd_kafka_resp_err_t test_auto_create_topic (rd_kafka_t *rk, const char *name,
                                            int timeout_ms);
int test_check_auto_create_topic (void);

void test_create_partitions (rd_kafka_t *use_rk,
                             const char *topicname, int new_partition_cnt);

int test_get_partition_count (rd_kafka_t *rk, const char *topicname,
                              int timeout_ms);

char *tsprintf (const char *fmt, ...) RD_FORMAT(printf, 1, 2);

void test_report_add (struct test *test, const char *fmt, ...);
int test_can_create_topics (int skip);

rd_kafka_event_t *test_wait_event (rd_kafka_queue_t *eventq,
				   rd_kafka_event_type_t event_type,
				   int timeout_ms);

void test_prepare_msg (uint64_t testid, int32_t partition, int msg_id,
                       char *val, size_t val_size,
                       char *key, size_t key_size);

#if WITH_SOCKEM
void test_socket_enable (rd_kafka_conf_t *conf);
void test_socket_close_all (struct test *test, int reinit);
int  test_socket_sockem_set_all (const char *key, int val);
void test_socket_sockem_set (int s, const char *key, int value);
#endif

void test_headers_dump (const char *what, int lvl,
                        const rd_kafka_headers_t *hdrs);

int32_t *test_get_broker_ids (rd_kafka_t *use_rk, size_t *cntp);

void test_wait_metadata_update (rd_kafka_t *rk,
                                rd_kafka_metadata_topic_t *topics,
                                size_t topic_cnt,
                                rd_kafka_metadata_topic_t *not_topics,
                                size_t not_topic_cnt,
                                int tmout);

rd_kafka_event_t *
test_wait_admin_result (rd_kafka_queue_t *q,
                        rd_kafka_event_type_t evtype,
                        int tmout);

rd_kafka_resp_err_t
test_wait_topic_admin_result (rd_kafka_queue_t *q,
                              rd_kafka_event_type_t evtype,
                              rd_kafka_event_t **retevent,
                              int tmout);

rd_kafka_resp_err_t
test_CreateTopics_simple (rd_kafka_t *rk,
                          rd_kafka_queue_t *useq,
                          char **topics, size_t topic_cnt,
                          int num_partitions,
                          void *opaque);
rd_kafka_resp_err_t
test_CreatePartitions_simple (rd_kafka_t *rk,
                              rd_kafka_queue_t *useq,
                              const char *topic,
                              size_t total_part_cnt,
                              void *opaque);

rd_kafka_resp_err_t
test_DeleteTopics_simple (rd_kafka_t *rk,
                          rd_kafka_queue_t *useq,
                          char **topics, size_t topic_cnt,
                          void *opaque);

rd_kafka_resp_err_t
test_AlterConfigs_simple (rd_kafka_t *rk,
                          rd_kafka_ResourceType_t restype,
                          const char *resname,
                          const char **configs, size_t config_cnt);

rd_kafka_resp_err_t test_delete_all_test_topics (int timeout_ms);

#endif /* _TEST_H_ */
