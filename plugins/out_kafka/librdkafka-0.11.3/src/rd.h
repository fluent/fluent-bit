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



#pragma once

#ifndef _MSC_VER
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* for strndup() */
#endif
#define __need_IOV_MAX
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* for timespec on solaris */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <limits.h>

#include "tinycthread.h"
#include "rdsysqueue.h"

#ifdef _MSC_VER
/* Visual Studio */
#include "win32_config.h"
#else
/* POSIX / UNIX based systems */
#include "../config.h" /* mklove output */
#endif

#ifdef _MSC_VER
/* Win32/Visual Studio */
#include "rdwin32.h"

#else
/* POSIX / UNIX based systems */
#include "rdposix.h"
#endif

#include "rdtypes.h"


/* Debug assert, only enabled with --enable-devel */
#if ENABLE_DEVEL == 1
#define rd_dassert(cond) rd_assert(cond)
#else
#define rd_dassert(cond)  do {} while (0)
#endif


/** Assert if reached */
#define RD_NOTREACHED() rd_kafka_assert(NULL, !*"/* NOTREACHED */ violated")



/**
* Allocator wrappers.
* We serve under the premise that if a (small) memory
* allocation fails all hope is lost and the application
* will fail anyway, so no need to handle it handsomely.
*/
static RD_INLINE RD_UNUSED void *rd_calloc(size_t num, size_t sz) {
	void *p = calloc(num, sz);
	rd_assert(p);
	return p;
}

static RD_INLINE RD_UNUSED void *rd_malloc(size_t sz) {
	void *p = malloc(sz);
	rd_assert(p);
	return p;
}

static RD_INLINE RD_UNUSED void *rd_realloc(void *ptr, size_t sz) {
	void *p = realloc(ptr, sz);
	rd_assert(p);
	return p;
}

static RD_INLINE RD_UNUSED void rd_free(void *ptr) {
	free(ptr);
}

static RD_INLINE RD_UNUSED char *rd_strdup(const char *s) {
#ifndef _MSC_VER
	char *n = strdup(s);
#else
	char *n = _strdup(s);
#endif
	rd_assert(n);
	return n;
}

static RD_INLINE RD_UNUSED char *rd_strndup(const char *s, size_t len) {
#if HAVE_STRNDUP
	char *n = strndup(s, len);
	rd_assert(n);
#else
	char *n = malloc(len + 1);
	rd_assert(n);
	memcpy(n, s, len);
	n[len] = '\0';
#endif
	return n;
}



/*
 * Portability
 */

#ifdef strndupa
#define rd_strndupa(DESTPTR,PTR,LEN)  (*(DESTPTR) = strndupa(PTR,LEN))
#else
#define rd_strndupa(DESTPTR,PTR,LEN) (*(DESTPTR) = rd_alloca(LEN+1), \
      memcpy(*(DESTPTR), (PTR), LEN), *((*(DESTPTR))+(LEN)) = 0)
#endif

#ifdef strdupa
#define rd_strdupa(DESTPTR,PTR)  (*(DESTPTR) = strdupa(PTR))
#else
#define rd_strdupa(DESTPTR,PTR)  rd_strndupa(DESTPTR,PTR,strlen(PTR))
#endif

#ifndef IOV_MAX
#ifdef __APPLE__
/* Some versions of MacOSX dont have IOV_MAX */
#define IOV_MAX 1024
#elif defined(_MSC_VER)
/* There is no IOV_MAX on MSVC but it is used internally in librdkafka */
#define IOV_MAX 1024
#else
#error "IOV_MAX not defined"
#endif
#endif


/* Round/align X upwards to STRIDE, which must be power of 2. */
#define RD_ROUNDUP(X,STRIDE) (((X) + ((STRIDE) - 1)) & ~(STRIDE-1))

#define RD_ARRAY_SIZE(A)          (sizeof((A)) / sizeof(*(A)))
#define RD_ARRAYSIZE(A)           RD_ARRAY_SIZE(A)
#define RD_SIZEOF(TYPE,MEMBER)    sizeof(((TYPE *)NULL)->MEMBER)
#define RD_OFFSETOF(TYPE,MEMBER)  ((size_t) &(((TYPE *)NULL)->MEMBER))

/**
 * Returns the 'I'th array element from static sized array 'A'
 * or NULL if 'I' is out of range.
 * var-args is an optional prefix to provide the correct return type.
 */
#define RD_ARRAY_ELEM(A,I,...)				\
	((unsigned int)(I) < RD_ARRAY_SIZE(A) ? __VA_ARGS__ (A)[(I)] : NULL)


#define RD_STRINGIFY(X)  # X



#define RD_MIN(a,b) ((a) < (b) ? (a) : (b))
#define RD_MAX(a,b) ((a) > (b) ? (a) : (b))


/**
 * Cap an integer (of any type) to reside within the defined limit.
 */
#define RD_INT_CAP(val,low,hi) \
	((val) < (low) ? low : ((val) > (hi) ? (hi) : (val)))



/**
 * Allocate 'size' bytes, copy 'src', return pointer to new memory.
 *
 * Use rd_free() to free the returned pointer.
*/
static RD_INLINE RD_UNUSED void *rd_memdup (const void *src, size_t size) {
	void *dst = rd_malloc(size);
	memcpy(dst, src, size);
	return dst;
}

/**
 * @brief Memset &OBJ to 0, does automatic sizeof(OBJ).
 */
#define RD_MEMZERO(OBJ) memset(&(OBJ), 0, sizeof(OBJ))


/**
 * Generic refcnt interface
 */
#ifndef _MSC_VER
/* Mutexes (critical sections) are slow, even when uncontended, on Windows */
#define RD_REFCNT_USE_LOCKS 1
#endif

#ifdef RD_REFCNT_USE_LOCKS
typedef struct rd_refcnt_t {
        mtx_t lock;
        int v;
} rd_refcnt_t;
#else
typedef rd_atomic32_t rd_refcnt_t;
#endif

#ifdef RD_REFCNT_USE_LOCKS
static RD_INLINE RD_UNUSED int rd_refcnt_init (rd_refcnt_t *R, int v) {
        int r;
        mtx_init(&R->lock, mtx_plain);
        mtx_lock(&R->lock);
        r = R->v = v;
        mtx_unlock(&R->lock);
        return r;
}
#else
#define rd_refcnt_init(R,v)  rd_atomic32_init(R, v)
#endif

#ifdef RD_REFCNT_USE_LOCKS
static RD_INLINE RD_UNUSED void rd_refcnt_destroy (rd_refcnt_t *R) {
        mtx_lock(&R->lock);
        rd_assert(R->v == 0);
        mtx_unlock(&R->lock);

        mtx_destroy(&R->lock);
}
#else
#define rd_refcnt_destroy(R) do { } while (0)
#endif


#ifdef RD_REFCNT_USE_LOCKS
static RD_INLINE RD_UNUSED int rd_refcnt_set (rd_refcnt_t *R, int v) {
        int r;
        mtx_lock(&R->lock);
        r = R->v = v;
        mtx_unlock(&R->lock);
        return r;
}
#else
#define rd_refcnt_set(R,v)  rd_atomic32_set(R, v)
#endif


#ifdef RD_REFCNT_USE_LOCKS
static RD_INLINE RD_UNUSED int rd_refcnt_add0 (rd_refcnt_t *R) {
        int r;
        mtx_lock(&R->lock);
        r = ++(R->v);
        mtx_unlock(&R->lock);
        return r;
}
#else
#define rd_refcnt_add0(R)  rd_atomic32_add(R, 1)
#endif

static RD_INLINE RD_UNUSED int rd_refcnt_sub0 (rd_refcnt_t *R) {
        int r;
#ifdef RD_REFCNT_USE_LOCKS
        mtx_lock(&R->lock);
        r = --(R->v);
        mtx_unlock(&R->lock);
#else
        r = rd_atomic32_sub(R, 1);
#endif
        if (r < 0)
                rd_assert(!*"refcnt sub-zero");
        return r;
}

#ifdef RD_REFCNT_USE_LOCKS
static RD_INLINE RD_UNUSED int rd_refcnt_get (rd_refcnt_t *R) {
        int r;
        mtx_lock(&R->lock);
        r = R->v;
        mtx_unlock(&R->lock);
        return r;
}
#else
#define rd_refcnt_get(R)   rd_atomic32_get(R)
#endif

/**
 * A wrapper for decreasing refcount and calling a destroy function
 * when refcnt reaches 0.
 */
#define rd_refcnt_destroywrapper(REFCNT,DESTROY_CALL) do {      \
                if (rd_refcnt_sub(REFCNT) > 0)                  \
                        break;                                  \
                DESTROY_CALL;                                   \
        } while (0)


#define rd_refcnt_destroywrapper2(REFCNT,WHAT,DESTROY_CALL) do {        \
                if (rd_refcnt_sub2(REFCNT,WHAT) > 0)                        \
                        break;                                  \
                DESTROY_CALL;                                   \
        } while (0)

#if ENABLE_REFCNT_DEBUG
#define rd_refcnt_add(R)                                                \
        (                                                               \
                printf("REFCNT DEBUG: %-35s %d +1: %16p: %s:%d\n",      \
                       #R, rd_refcnt_get(R), (R), __FUNCTION__,__LINE__), \
                rd_refcnt_add0(R)                                       \
                )

#define rd_refcnt_add2(R,WHAT)  do {                                        \
                printf("REFCNT DEBUG: %-35s %d +1: %16p: %16s: %s:%d\n",      \
                       #R, rd_refcnt_get(R), (R), WHAT, __FUNCTION__,__LINE__), \
                rd_refcnt_add0(R);                                      \
        } while (0)


#define rd_refcnt_sub2(R,WHAT) (                                            \
                printf("REFCNT DEBUG: %-35s %d -1: %16p: %16s: %s:%d\n",      \
                       #R, rd_refcnt_get(R), (R), WHAT, __FUNCTION__,__LINE__), \
                rd_refcnt_sub0(R) )

#define rd_refcnt_sub(R) (                                              \
                printf("REFCNT DEBUG: %-35s %d -1: %16p: %s:%d\n",      \
                       #R, rd_refcnt_get(R), (R), __FUNCTION__,__LINE__), \
                rd_refcnt_sub0(R) )

#else
#define rd_refcnt_add(R)  rd_refcnt_add0(R)
#define rd_refcnt_sub(R)  rd_refcnt_sub0(R)
#endif



#if !ENABLE_SHAREDPTR_DEBUG

/**
 * The non-debug version of shared_ptr is simply a reference counting interface
 * without any additional costs and no indirections.
 */

#define RD_SHARED_PTR_TYPE(STRUCT_NAME,WRAPPED_TYPE) WRAPPED_TYPE


#define rd_shared_ptr_get_src(FUNC,LINE,OBJ,REFCNT,SPTR_TYPE)	\
        (rd_refcnt_add(REFCNT), (OBJ))
#define rd_shared_ptr_get(OBJ,REFCNT,SPTR_TYPE)          \
        (rd_refcnt_add(REFCNT), (OBJ))

#define rd_shared_ptr_obj(SPTR) (SPTR)

#define rd_shared_ptr_put(SPTR,REF,DESTRUCTOR)                  \
                rd_refcnt_destroywrapper(REF,DESTRUCTOR)


#else

#define RD_SHARED_PTR_TYPE(STRUCT_NAME, WRAPPED_TYPE) \
        struct STRUCT_NAME {                          \
                LIST_ENTRY(rd_shptr0_s) link;         \
                WRAPPED_TYPE *obj;                     \
                rd_refcnt_t *ref;                     \
                const char *typename;                 \
                const char *func;                     \
                int line;                             \
        }



/* Common backing struct compatible with RD_SHARED_PTR_TYPE() types */
typedef RD_SHARED_PTR_TYPE(rd_shptr0_s, void) rd_shptr0_t;

LIST_HEAD(rd_shptr0_head, rd_shptr0_s);
extern struct rd_shptr0_head rd_shared_ptr_debug_list;
extern mtx_t rd_shared_ptr_debug_mtx;

static RD_INLINE RD_UNUSED RD_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
rd_shptr0_t *rd_shared_ptr_get0 (const char *func, int line,
                                 const char *typename,
                                 rd_refcnt_t *ref, void *obj) {
        rd_shptr0_t *sptr = rd_calloc(1, sizeof(*sptr));
        sptr->obj = obj;
        sptr->ref = ref;
        sptr->typename = typename;
        sptr->func = func;
        sptr->line = line;

        mtx_lock(&rd_shared_ptr_debug_mtx);
        LIST_INSERT_HEAD(&rd_shared_ptr_debug_list, sptr, link);
        mtx_unlock(&rd_shared_ptr_debug_mtx);
        return sptr;
}

#define rd_shared_ptr_get_src(FUNC,LINE,OBJ,REF,SPTR_TYPE)		\
        (rd_refcnt_add(REF),                                            \
         (SPTR_TYPE *)rd_shared_ptr_get0(FUNC,LINE, #SPTR_TYPE,REF,OBJ))
#define rd_shared_ptr_get(OBJ,REF,SPTR_TYPE)	\
	rd_shared_ptr_get_src(__FUNCTION__, __LINE__, OBJ, REF, SPTR_TYPE)



#define rd_shared_ptr_obj(SPTR) (SPTR)->obj

#define rd_shared_ptr_put(SPTR,REF,DESTRUCTOR) do {               \
                if (rd_refcnt_sub(REF) == 0)                      \
                        DESTRUCTOR;                               \
                mtx_lock(&rd_shared_ptr_debug_mtx);               \
                LIST_REMOVE(SPTR, link);                          \
                mtx_unlock(&rd_shared_ptr_debug_mtx);             \
                rd_free(SPTR);                                    \
        } while (0)

void rd_shared_ptrs_dump (void);
#endif


#define RD_IF_FREE(PTR,FUNC) do { if ((PTR)) FUNC(PTR); } while (0)


/**
 * @brief Utility types to hold memory,size tuple.
 */

typedef struct rd_chariov_s {
        char  *ptr;
        size_t size;
} rd_chariov_t;
