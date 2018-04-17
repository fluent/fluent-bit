/*
 * librd - Rapid Development C library
 *
 * Copyright (c) 2012, Magnus Edenhill
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

#ifndef _RDTIME_H_
#define _RDTIME_H_


#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv,ts) do {		\
    (ts)->tv_sec = (tv)->tv_sec;		\
    (ts)->tv_nsec = (tv)->tv_usec * 1000;	\
  } while (0)

#define TIMESPEC_TO_TIMEVAL(tv, ts) do {  \
    (tv)->tv_sec = (ts)->tv_sec;	  \
    (tv)->tv_usec = (ts)->tv_nsec / 1000; \
  } while (0)
#endif

#define TIMESPEC_TO_TS(ts) \
	(((rd_ts_t)(ts)->tv_sec * 1000000LLU) + ((ts)->tv_nsec / 1000))

#define TS_TO_TIMESPEC(ts,tsx) do {			\
	(ts)->tv_sec  = (tsx) / 1000000;		\
        (ts)->tv_nsec = ((tsx) % 1000000) * 1000;	\
	if ((ts)->tv_nsec >= 1000000000LLU) {		\
	   (ts)->tv_sec++;				\
	   (ts)->tv_nsec -= 1000000000LLU;		\
	}						\
       } while (0)

#define TIMESPEC_CLEAR(ts) ((ts)->tv_sec = (ts)->tv_nsec = 0LLU)


#define RD_POLL_INFINITE  -1
#define RD_POLL_NOWAIT     0


/**
 * @returns a monotonically increasing clock in microseconds.
 * @remark There is no monotonic clock on OSX, the system time
 *         is returned instead.
 */
static RD_INLINE rd_ts_t rd_clock (void) RD_UNUSED;
static RD_INLINE rd_ts_t rd_clock (void) {
#ifdef __APPLE__
	/* No monotonic clock on Darwin */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((rd_ts_t)tv.tv_sec * 1000000LLU) + (rd_ts_t)tv.tv_usec;
#elif defined(_MSC_VER)
	return (rd_ts_t)GetTickCount64() * 1000LLU;
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((rd_ts_t)ts.tv_sec * 1000000LLU) + 
		((rd_ts_t)ts.tv_nsec / 1000LLU);
#endif
}


/**
 * @returns UTC wallclock time as number of microseconds since
 *          beginning of the epoch.
 */
static RD_INLINE RD_UNUSED rd_ts_t rd_uclock (void) {
	struct timeval tv;
	rd_gettimeofday(&tv, NULL);
	return ((rd_ts_t)tv.tv_sec * 1000000LLU) + (rd_ts_t)tv.tv_usec;
}



/**
 * Thread-safe version of ctime() that strips the trailing newline.
 */
static RD_INLINE const char *rd_ctime (const time_t *t) RD_UNUSED;
static RD_INLINE const char *rd_ctime (const time_t *t) {
	static RD_TLS char ret[27];

#ifndef _MSC_VER
	ctime_r(t, ret);
#else
	ctime_s(ret, sizeof(ret), t);
#endif
	ret[25] = '\0';

	return ret;
}


/**
 * @brief Initialize an absolute timeout based on the provided \p timeout_ms
 *
 * To be used with rd_timeout_adjust().
 *
 * Honours RD_POLL_INFINITE, RD_POLL_NOWAIT.
 *
 * @returns the absolute timeout which should later be passed
 *          to rd_timeout_adjust().
 */
static RD_INLINE rd_ts_t rd_timeout_init (int timeout_ms) {
	if (timeout_ms == RD_POLL_INFINITE ||
	    timeout_ms == RD_POLL_NOWAIT)
		return timeout_ms;

	return rd_clock() + (timeout_ms * 1000);
}


/**
 * @returns the remaining timeout for timeout \p abs_timeout previously set
 *          up by rd_timeout_init()
 *
 * Honours RD_POLL_INFINITE, RD_POLL_NOWAIT.
 *
 * @remark Check explicitly for 0 (NOWAIT) to check if there is
 *         no remaining time to way. Any other value, even negative (INFINITE),
 *         means there is remaining time.
 *         rd_timeout_expired() can be used to check the return value
 *         in a bool fashion.
 */
static RD_INLINE int rd_timeout_remains (rd_ts_t abs_timeout) {
	int timeout_ms;

	if (abs_timeout == RD_POLL_INFINITE ||
	    abs_timeout == RD_POLL_NOWAIT)
		return (int)abs_timeout;

	timeout_ms = (int)((abs_timeout - rd_clock()) / 1000);
	if (timeout_ms <= 0)
		return RD_POLL_NOWAIT;
	else
		return timeout_ms;
}

/**
 * @brief Like rd_timeout_remains() but limits the maximum time to \p limit_ms
 */
static RD_INLINE int
rd_timeout_remains_limit (rd_ts_t abs_timeout, int limit_ms) {
	int timeout_ms = rd_timeout_remains(abs_timeout);

	if (timeout_ms == RD_POLL_INFINITE || timeout_ms > limit_ms)
		return limit_ms;
	else
		return timeout_ms;
}


/**
 * @returns 1 if the **relative** timeout as returned by rd_timeout_remains()
 *          has timed out / expired, else 0.
 */
static RD_INLINE int rd_timeout_expired (int timeout_ms) {
	return timeout_ms == RD_POLL_NOWAIT;
}

#endif /* _RDTIME_H_ */
