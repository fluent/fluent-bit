/*
 * Posix Threads library for Microsoft Windows
 *
 * Use at own risk, there is no implied warranty to this code.
 * It uses undocumented features of Microsoft Windows that can change
 * at any time in the future.
 *
 * (C) 2010 Lockless Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Lockless Inc. nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AN
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WIN_PTHREADS
#define WIN_PTHREADS

#define _WINSOCKAPI_
#include <windows.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif
#ifndef ENOTSUP
#define ENOTSUP   134
#endif

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 65535
#endif

#define PTHREAD_CANCEL_DISABLE 0
#define PTHREAD_CANCEL_ENABLE 0x01

#define PTHREAD_CANCEL_DEFERRED 0
#define PTHREAD_CANCEL_ASYNCHRONOUS 0x02

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 0x04

#define PTHREAD_EXPLICT_SCHED 0
#define PTHREAD_INHERIT_SCHED 0x08

#define PTHREAD_SCOPE_PROCESS 0
#define PTHREAD_SCOPE_SYSTEM 0x10

#define PTHREAD_DEFAULT_ATTR (PTHREAD_CANCEL_ENABLE)

#define PTHREAD_CANCELED ((void *) 0xDEADBEEF)

#define PTHREAD_ONCE_INIT 0
#define PTHREAD_MUTEX_INITIALIZER {(void*)-1,-1,0,0,0,0}
#define PTHREAD_RWLOCK_INITIALIZER {0}
#define PTHREAD_COND_INITIALIZER {0}
#define PTHREAD_BARRIER_INITIALIZER \
  {0,0,PTHREAD_MUTEX_INITIALIZER,PTHREAD_COND_INITIALIZER}
#define PTHREAD_SPINLOCK_INITIALIZER 0

#define PTHREAD_DESTRUCTOR_ITERATIONS 256
#define PTHREAD_KEYS_MAX (1<<20)

#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_ERRORCHECK 1
#define PTHREAD_MUTEX_RECURSIVE 2
#define PTHREAD_MUTEX_DEFAULT 3
#define PTHREAD_MUTEX_SHARED 4
#define PTHREAD_MUTEX_PRIVATE 0
#define PTHREAD_PRIO_NONE 0
#define PTHREAD_PRIO_INHERIT 8
#define PTHREAD_PRIO_PROTECT 16
#define PTHREAD_PRIO_MULT 32
#define PTHREAD_PROCESS_SHARED 0
#define PTHREAD_PROCESS_PRIVATE 1

#define PTHREAD_BARRIER_SERIAL_THREAD 1

/* Windows doesn't have this, so declare it ourselves. */
#if (_MSC_VER < 1900)
struct timespec
{
  /* long long in windows is the same as long in unix for 64bit */
  long long tv_sec;
  long long tv_nsec;
};
#else
#include <time.h>
#endif

struct _pthread_v;
typedef struct _pthread_v *pthread_t;

struct pthread_barrier_t
{
  int count;
  int total;
  CRITICAL_SECTION m;
  CONDITION_VARIABLE cv;
};

typedef struct pthread_barrier_t pthread_barrier_t;

struct pthread_attr_t
{
  unsigned p_state;
  void *stack;
  size_t s_size;
};

typedef struct pthread_attr_t pthread_attr_t;

typedef long pthread_once_t;
typedef unsigned pthread_mutexattr_t;
typedef SRWLOCK pthread_rwlock_t;
typedef CRITICAL_SECTION pthread_mutex_t;
typedef unsigned pthread_key_t;
typedef void *pthread_barrierattr_t;
typedef long pthread_spinlock_t;
typedef int pthread_condattr_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef int pthread_rwlockattr_t;

extern pthread_t pthread_self(void);

extern int pthread_once(pthread_once_t *o, void(*func)(void));

extern int pthread_mutex_lock(pthread_mutex_t *m);

extern int pthread_mutex_unlock(pthread_mutex_t *m);

extern int pthread_mutex_trylock(pthread_mutex_t *m);

extern int pthread_mutex_init(pthread_mutex_t *m, pthread_mutexattr_t *a);

extern int pthread_mutex_destroy(pthread_mutex_t *m);

#define pthread_mutex_getprioceiling(M, P) ENOTSUP
#define pthread_mutex_setprioceiling(M, P) ENOTSUP

extern int pthread_equal(pthread_t t1, pthread_t t2);

extern int pthread_rwlock_init(pthread_rwlock_t *l, pthread_rwlockattr_t *a);

extern int pthread_rwlock_destroy(pthread_rwlock_t *l);

extern int pthread_rwlock_rdlock(pthread_rwlock_t *l);

extern int pthread_rwlock_wrlock(pthread_rwlock_t *l);

extern int pthread_rwlock_unlock(pthread_rwlock_t *l);

extern int pthread_rwlock_tryrdlock(pthread_rwlock_t *l);

extern int pthread_rwlock_trywrlock(pthread_rwlock_t *l);

extern void pthread_tls_init(void);

extern int pthread_rwlock_timedrdlock(pthread_rwlock_t *l, const struct timespec *ts);

extern int pthread_rwlock_timedwrlock(pthread_rwlock_t *l, const struct timespec *ts);

extern int pthread_get_concurrency(int *val);

extern int pthread_set_concurrency(int val);

#define pthread_getschedparam(T, P, S) ENOTSUP
#define pthread_setschedparam(T, P, S) ENOTSUP
#define pthread_getcpuclockid(T, C) ENOTSUP

extern int pthread_exit(void *res);

extern void pthread_testcancel(void);

extern int pthread_cancel(pthread_t t);

extern int pthread_attr_init(pthread_attr_t *attr);

extern int pthread_attr_destroy(pthread_attr_t *attr);

extern int pthread_attr_setdetachstate(pthread_attr_t *a, int flag);

extern int pthread_attr_getdetachstate(pthread_attr_t *a, int *flag);

extern int pthread_attr_setinheritsched(pthread_attr_t *a, int flag);

extern int pthread_attr_getinheritsched(pthread_attr_t *a, int *flag);

extern int pthread_attr_setscope(pthread_attr_t *a, int flag);

extern int pthread_attr_getscope(pthread_attr_t *a, int *flag);

extern int pthread_attr_getstackaddr(pthread_attr_t *attr, void **stack);

extern int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stack);

extern int pthread_attr_getstacksize(pthread_attr_t *attr, size_t *size);

extern int pthread_attr_setstacksize(pthread_attr_t *attr, size_t size);

#define pthread_attr_getguardsize(A, S) ENOTSUP
#define pthread_attr_setgaurdsize(A, S) ENOTSUP
#define pthread_attr_getschedparam(A, S) ENOTSUP
#define pthread_attr_setschedparam(A, S) ENOTSUP
#define pthread_attr_getschedpolicy(A, S) ENOTSUP
#define pthread_attr_setschedpolicy(A, S) ENOTSUP

extern int pthread_setcancelstate(int state, int *oldstate);

extern int pthread_setcanceltype(int type, int *oldtype);

extern unsigned __stdcall pthread_create_wrapper(void *args);

extern int pthread_create(pthread_t *th, pthread_attr_t *attr, void *(*func)(void *), void *arg);

extern int pthread_join(pthread_t t, void **res);

extern int pthread_detach(pthread_t t);

extern int pthread_mutexattr_init(pthread_mutexattr_t *a);

extern int pthread_mutexattr_destroy(pthread_mutexattr_t *a);

extern int pthread_mutexattr_gettype(pthread_mutexattr_t *a, int *type);

extern int pthread_mutexattr_settype(pthread_mutexattr_t *a, int type);

extern int pthread_mutexattr_getpshared(pthread_mutexattr_t *a, int *type);

extern int pthread_mutexattr_setpshared(pthread_mutexattr_t * a, int type);

extern int pthread_mutexattr_getprotocol(pthread_mutexattr_t *a, int *type);

extern int pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int type);

extern int pthread_mutexattr_getprioceiling(pthread_mutexattr_t *a, int * prio);

extern int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *a, int prio);

extern int pthread_mutex_timedlock(pthread_mutex_t *m, struct timespec *ts);

extern int pthread_barrier_destroy(pthread_barrier_t *b);

extern int pthread_barrier_init(pthread_barrier_t *b, void *attr, int count);

extern int pthread_barrier_wait(pthread_barrier_t *b);

extern int pthread_barrierattr_init(void **attr);

extern int pthread_barrierattr_destroy(void **attr);

extern int pthread_barrierattr_setpshared(void **attr, int s);

extern int pthread_barrierattr_getpshared(void **attr, int *s);

extern int pthread_key_create(pthread_key_t *key, void(*dest)(void *));

extern int pthread_key_delete(pthread_key_t key);

extern void *pthread_getspecific(pthread_key_t key);

extern int pthread_setspecific(pthread_key_t key, const void *value);

extern int pthread_spin_init(pthread_spinlock_t *l, int pshared);

extern int pthread_spin_destroy(pthread_spinlock_t *l);

extern int pthread_spin_lock(pthread_spinlock_t *l);

extern int pthread_spin_trylock(pthread_spinlock_t *l);

extern int pthread_spin_unlock(pthread_spinlock_t *l);

extern int pthread_cond_init(pthread_cond_t *c, pthread_condattr_t *a);

extern int pthread_cond_signal(pthread_cond_t *c);

extern int pthread_cond_broadcast(pthread_cond_t *c);

extern int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m);

extern int pthread_cond_destroy(pthread_cond_t *c);

extern int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, struct timespec *t);

extern int pthread_condattr_destroy(pthread_condattr_t *a);

#define pthread_condattr_getclock(A, C) ENOTSUP
#define pthread_condattr_setclock(A, C) ENOTSUP

extern int pthread_condattr_init(pthread_condattr_t *a);

extern int pthread_condattr_getpshared(pthread_condattr_t *a, int *s);

extern int pthread_condattr_setpshared(pthread_condattr_t *a, int s);

extern int pthread_rwlockattr_destroy(pthread_rwlockattr_t *a);

extern int pthread_rwlockattr_init(pthread_rwlockattr_t *a);

extern int pthread_rwlockattr_getpshared(pthread_rwlockattr_t *a, int *s);

extern int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *a, int s);

/* No fork() in windows - so ignore this */
#define pthread_atfork(F1,F2,F3) 0

/* Windows has rudimentary signals support */
#define pthread_kill(T, S) 0
#define pthread_sigmask(H, S1, S2) 0

#ifdef __cplusplus
}
#endif

#endif /* WIN_PTHREADS */
