/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2019 Magnus Edenhill
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


/**
 * @name Track test resource usage.
 */

#ifdef __APPLE__
#define _DARWIN_C_SOURCE  /* required for rusage.ru_maxrss, etc. */
#endif

#include "test.h"

#if HAVE_GETRUSAGE

#include <sys/time.h>
#include <sys/resource.h>
#include "rdfloat.h"


/**
 * @brief Call getrusage(2)
 */
static int test_getrusage (struct rusage *ru) {
        if (getrusage(RUSAGE_SELF, ru) == -1) {
                TEST_WARN("getrusage() failed: %s\n", rd_strerror(errno));
                return -1;
        }

        return 0;
}

/* Convert timeval to seconds */
#define _tv2s(TV) (double)((double)(TV).tv_sec +                \
                           ((double)(TV).tv_usec / 1000000.0))

/* Convert timeval to CPU usage percentage (5 = 5%, 130.3 = 130.3%) */
#define _tv2cpu(TV,DURATION) ((_tv2s(TV) / (DURATION)) * 100.0)


/**
 * @brief Calculate difference between \p end and \p start rusage.
 *
 * @returns the delta
 */
static struct rusage test_rusage_calc (const struct rusage *start,
                                       const struct rusage *end,
                                       double duration) {
        struct rusage delta = RD_ZERO_INIT;

        timersub(&end->ru_utime, &start->ru_utime, &delta.ru_utime);
        timersub(&end->ru_stime, &start->ru_stime, &delta.ru_stime);
        /* FIXME: maxrss doesn't really work when multiple tests are
         *        run in the same process since it only registers the
         *        maximum RSS, not the current one.
         *        Read this from /proc/<pid>/.. instead */
        delta.ru_maxrss = end->ru_maxrss - start->ru_maxrss;
        delta.ru_nvcsw  = end->ru_nvcsw  - start->ru_nvcsw;
        /* skip fields we're not interested in */

        TEST_SAY(_C_MAG "Test resource usage summary: "
                 "%.3fs (%.1f%%) User CPU time, "
                 "%.3fs (%.1f%%) Sys CPU time, "
                 "%.3fMB RSS memory increase, "
                 "%ld Voluntary context switches\n",
                 _tv2s(delta.ru_utime),
                 _tv2cpu(delta.ru_utime, duration),
                 _tv2s(delta.ru_stime),
                 _tv2cpu(delta.ru_stime, duration),
                 (double)delta.ru_maxrss / (1024.0*1024.0),
                 delta.ru_nvcsw);

        return delta;
}


/**
 * @brief Check that test ran within threshold levels
 */
static int test_rusage_check_thresholds (struct test *test,
                                         const struct rusage *ru,
                                         double duration) {
        static const struct rusage_thres defaults = {
                .ucpu  = 5.0,  /* min value, see below */
                .scpu  = 2.5,  /* min value, see below */
                .rss   = 10.0, /* 10 megs */
                .ctxsw = 100,  /* this is the default number of context switches
                                * per test second.
                                * note: when ctxsw is specified on a test
                                *       it should be specified as the total
                                *       number of context switches. */
        };
        /* CPU usage thresholds are too blunt for very quick tests.
         * Use a forgiving default CPU threshold for any test that
         * runs below a certain duration. */
        const double min_duration = 2.0; /* minimum test duration for
                                          * CPU thresholds to have effect. */
        const double lax_cpu = 1000.0;     /* 1000% CPU usage (e.g 10 cores
                                            * at full speed) allowed for any
                                            * test that finishes in under 2s */
        const struct rusage_thres *thres = &test->rusage_thres;
        double cpu, mb, uthres, uthres_orig, sthres, rssthres;
        int csthres;
        char reasons[3][128];
        int fails = 0;

        if (duration < min_duration)
                uthres = lax_cpu;
        else if (rd_dbl_zero((uthres = thres->ucpu)))
                uthres = defaults.ucpu;

        uthres_orig = uthres;
        uthres *= test_rusage_cpu_calibration;

        cpu  = _tv2cpu(ru->ru_utime, duration);
        if (cpu > uthres) {
                rd_snprintf(reasons[fails], sizeof(reasons[fails]),
                            "User CPU time (%.3fs) exceeded: %.1f%% > %.1f%%",
                            _tv2s(ru->ru_utime), cpu, uthres);
                TEST_WARN("%s\n", reasons[fails]);
                fails++;
        }

        /* Let the default Sys CPU be the maximum of the defaults.cpu
         * and 20% of the User CPU. */
        if (rd_dbl_zero((sthres = thres->scpu)))
                sthres = duration < min_duration ? lax_cpu :
                        RD_MAX(uthres_orig * 0.20, defaults.scpu);

        sthres *= test_rusage_cpu_calibration;

        cpu  = _tv2cpu(ru->ru_stime, duration);
        if (cpu > sthres) {
                rd_snprintf(reasons[fails], sizeof(reasons[fails]),
                            "Sys CPU time (%.3fs) exceeded: %.1f%% > %.1f%%",
                            _tv2s(ru->ru_stime), cpu, sthres);
                TEST_WARN("%s\n", reasons[fails]);
                fails++;
        }

        rssthres = thres->rss > 0.0 ? thres->rss : defaults.rss;
        if ((mb = (double)ru->ru_maxrss / (1024.0*1024.0)) > rssthres) {
                rd_snprintf(reasons[fails], sizeof(reasons[fails]),
                            "RSS memory exceeded: %.2fMB > %.2fMB",
                            mb, rssthres);
                TEST_WARN("%s\n", reasons[fails]);
                fails++;
        }


        if (!(csthres = thres->ctxsw))
                csthres = duration < min_duration ? defaults.ctxsw * 100 :
                        (int)(duration * (double)defaults.ctxsw);

        /* FIXME: not sure how to use this */
        if (0 && ru->ru_nvcsw > csthres) {
                TEST_WARN("Voluntary context switches exceeded: "
                          "%ld > %d\n",
                          ru->ru_nvcsw, csthres);
                fails++;
        }

        TEST_ASSERT(fails <= (int)RD_ARRAYSIZE(reasons),
                    "reasons[] array not big enough (needs %d slots)", fails);

        if (!fails || !test_rusage)
                return 0;

        TEST_FAIL("Test resource usage exceeds %d threshold(s): %s%s%s%s",
                  fails,
                  reasons[0],
                  fails > 1 ? ", " : "",
                  fails > 1 ? reasons[1] : "",
                  fails > 2 ? ", " : "",
                  fails > 2 ? reasons[2] : "");


        return -1;
}
#endif



void test_rusage_start (struct test *test) {
#if HAVE_GETRUSAGE
        /* Can't do per-test rusage checks when tests run in parallel. */
        if (test_concurrent_max > 1)
                return;

        if (test_getrusage(&test->rusage) == -1)
                return;
#endif
}


/**
 * @brief Stop test rusage and check if thresholds were exceeded.
 *        Call when test has finished.
 *
 * @returns -1 if thresholds were exceeded, else 0.
 */
 int test_rusage_stop (struct test *test, double duration) {
#if HAVE_GETRUSAGE
        struct rusage start, end;

        /* Can't do per-test rusage checks when tests run in parallel. */
        if (test_concurrent_max > 1)
                return 0;

        if (test_getrusage(&end) == -1)
                return 0;

        /* Let duration be at least 1ms to avoid
         * too-close-to-zero comparisons */
        if (duration < 0.001)
                duration = 0.001;

        start = test->rusage;
        test->rusage = test_rusage_calc(&start, &end, duration);

        return test_rusage_check_thresholds(test, &test->rusage, duration);
#else
        return 0;
#endif
}
