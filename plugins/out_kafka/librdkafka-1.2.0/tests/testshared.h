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
#ifndef _TESTSHARED_H_
#define _TESTSHARED_H_

/**
 * C variables and functions shared with C++ tests
 */

typedef struct rd_kafka_s rd_kafka_t;

/* ANSI color codes */
#define _C_CLR "\033[0m"
#define _C_RED "\033[31m"
#define _C_GRN "\033[32m"
#define _C_YEL "\033[33m"
#define _C_BLU "\033[34m"
#define _C_MAG "\033[35m"
#define _C_CYA "\033[36m"


/** @returns the \p msecs timeout multiplied by the test timeout multiplier */
extern int tmout_multip (int msecs);

/** @brief true if tests should run in quick-mode (faster, less data) */
extern int test_quick;

/** @brief Broker version to int */
#define TEST_BRKVER(A,B,C,D) \
        (((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
/** @brief return single version component from int */
#define TEST_BRKVER_X(V,I) \
        (((V) >> (24-((I)*8))) & 0xff)

extern int test_broker_version;
extern int test_on_ci;

const char *test_mk_topic_name (const char *suffix, int randomized);

void test_delete_topic (rd_kafka_t *use_rk, const char *topicname);

void test_create_topic (rd_kafka_t *use_rk, const char *topicname,
                        int partition_cnt, int replication_factor);

uint64_t
test_produce_msgs_easy_size (const char *topic, uint64_t testid,
                             int32_t partition, int msgcnt, size_t size);
#define test_produce_msgs_easy(topic,testid,partition,msgcnt) \
        test_produce_msgs_easy_size(topic,testid,partition,msgcnt,0)

void test_FAIL (const char *file, int line, int fail_now, const char *str);
void test_SAY (const char *file, int line, int level, const char *str);
void test_SKIP (const char *file, int line, const char *str);

void test_timeout_set (int timeout);
int test_set_special_conf (const char *name, const char *val, int *timeoutp);
const char *test_conf_get_path (void);
const char *test_getenv (const char *env, const char *def);

int test_needs_auth (void);

uint64_t test_id_generate (void);
char *test_str_id_generate (char *dest, size_t dest_size);
const char *test_str_id_generate_tmp (void);

void test_prepare_msg (uint64_t testid, int32_t partition, int msg_id,
                       char *val, size_t val_size,
                       char *key, size_t key_size);
/**
 * Parse a message token
 */
void test_msg_parse00 (const char *func, int line,
                       uint64_t testid, int32_t exp_partition, int *msgidp,
                       const char *topic, int32_t partition, int64_t offset,
                       const char *key, size_t key_size);


int test_check_builtin (const char *feature);

/**
 * @returns the current test's name (thread-local)
 */
extern const char *test_curr_name (void);

#ifndef _MSC_VER
#include <sys/time.h>
#ifndef RD_UNUSED
#define RD_UNUSED __attribute__((unused))
#endif

#else

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#ifndef RD_UNUSED
#define RD_UNUSED
#endif


/**
* A microsecond monotonic clock
*/
static RD_INLINE int64_t test_clock (void)
#ifndef _MSC_VER
__attribute__((unused))
#endif
;
static RD_INLINE int64_t test_clock (void) {
#ifdef __APPLE__
        /* No monotonic clock on Darwin */
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return ((int64_t)tv.tv_sec * 1000000LLU) + (int64_t)tv.tv_usec;
#elif _MSC_VER
        LARGE_INTEGER now;
        static RD_TLS LARGE_INTEGER freq;
        if (!freq.QuadPart)
                QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&now);
        return (now.QuadPart * 1000000) / freq.QuadPart;
#else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ((int64_t)ts.tv_sec * 1000000LLU) +
                ((int64_t)ts.tv_nsec / 1000LLU);
#endif
}


typedef struct test_timing_s {
        char name[64];
        int64_t ts_start;
        int64_t duration;
        int64_t ts_every; /* Last every */
} test_timing_t;

/**
 * @brief Start timing, Va-Argument is textual name (printf format)
 */
#define TIMING_RESTART(TIMING) do {                                     \
        (TIMING)->ts_start = test_clock();                              \
        (TIMING)->duration = 0;                                         \
        } while (0)

#define TIMING_START(TIMING,...) do {                                   \
        rd_snprintf((TIMING)->name, sizeof((TIMING)->name), __VA_ARGS__); \
        TIMING_RESTART(TIMING);                                         \
        (TIMING)->ts_every = (TIMING)->ts_start;                        \
        } while (0)

#define TIMING_STOPPED(TIMING) ((TIMING)->duration != 0)

#ifndef __cplusplus
#define TIMING_STOP(TIMING) do {                                \
        (TIMING)->duration = test_clock() - (TIMING)->ts_start; \
        TEST_SAY("%s: duration %.3fms\n",                               \
                 (TIMING)->name, (float)(TIMING)->duration / 1000.0f);  \
        } while (0)
#define TIMING_REPORT(TIMING) \
        TEST_SAY("%s: duration %.3fms\n",                               \
                 (TIMING)->name, (float)(TIMING)->duration / 1000.0f);  \

#else
#define TIMING_STOP(TIMING) do {                                        \
        char _str[128];                                                 \
        (TIMING)->duration = test_clock() - (TIMING)->ts_start;         \
        rd_snprintf(_str, sizeof(_str), "%s: duration %.3fms\n",        \
                    (TIMING)->name, (float)(TIMING)->duration / 1000.0f); \
        Test::Say(_str);                                                \
        } while (0)

#endif

#define TIMING_DURATION(TIMING) ((TIMING)->duration ? (TIMING)->duration : \
                                 (test_clock() - (TIMING)->ts_start))

#define TIMING_ASSERT0(TIMING,DO_FAIL_LATER,TMIN_MS,TMAX_MS) do {       \
        if (!TIMING_STOPPED(TIMING))                                    \
                TIMING_STOP(TIMING);                                    \
        int _dur_ms = (int)TIMING_DURATION(TIMING) / 1000;              \
        if (TMIN_MS <= _dur_ms && _dur_ms <= TMAX_MS)                   \
                break;                                                  \
        if (test_on_ci || strcmp(test_mode, "bare"))                    \
                TEST_WARN("%s: expected duration %d <= %d <= %d ms%s\n", \
                          (TIMING)->name, TMIN_MS, _dur_ms, TMAX_MS,    \
                          ": not FAILING test on CI");                  \
        else                                                            \
                TEST_FAIL_LATER0(DO_FAIL_LATER,                         \
                                 "%s: expected duration %d <= %d <= %d ms", \
                                 (TIMING)->name, TMIN_MS, _dur_ms, TMAX_MS); \
        } while (0)

#define TIMING_ASSERT(TIMING,TMIN_MS,TMAX_MS)           \
        TIMING_ASSERT0(TIMING,0,TMIN_MS,TMAX_MS)
#define TIMING_ASSERT_LATER(TIMING,TMIN_MS,TMAX_MS)     \
        TIMING_ASSERT0(TIMING,1,TMIN_MS,TMAX_MS)

/* Trigger something every US microseconds. */
static RD_UNUSED int TIMING_EVERY (test_timing_t *timing, int us) {
        int64_t now = test_clock();
        if (timing->ts_every + us <= now) {
                timing->ts_every = now;
                return 1;
        }
        return 0;
}


#ifndef _MSC_VER
#define rd_sleep(S) sleep(S)
#else
#define rd_sleep(S) Sleep((S)*1000)
#endif

/* Make sure __SANITIZE_ADDRESS__ (gcc) is defined if compiled with asan */
#if !defined(__SANITIZE_ADDRESS__) && defined(__has_feature)
 #if __has_feature(address_sanitizer)
 #define __SANITIZE_ADDRESS__ 1
 #endif
#endif


int test_run_java (const char *cls, const char **argv);
int test_waitpid (int pid);
#endif /* _TESTSHARED_H_ */
