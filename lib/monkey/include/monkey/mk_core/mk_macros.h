/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_MACROS_H
#define MK_MACROS_H

#include <stdlib.h>
#include "mk_limits.h"

/* Boolean */
#define MK_FALSE 0
#define MK_TRUE  !MK_FALSE
#define MK_ERROR -1

/* Architecture */
#define INTSIZE sizeof(int)

/* Print macros */
#define MK_INFO     0x1000
#define MK_ERR      0X1001
#define MK_WARN     0x1002
#define MK_BUG      0x1003

#define mk_info(...)  mk_print(MK_INFO, __VA_ARGS__)
#define mk_err(...)   mk_print(MK_ERR, __VA_ARGS__)
#define mk_warn(...)  mk_print(MK_WARN, __VA_ARGS__)

/* ANSI Colors */
#ifndef _MSC_VER
#define ANSI_RESET    "\033[0m"
#define ANSI_BOLD     "\033[1m"
#define ANSI_CYAN     "\033[96m"
#define ANSI_MAGENTA  "\033[95m"
#define ANSI_RED      "\033[91m"
#define ANSI_YELLOW   "\033[93m"
#define ANSI_BLUE     "\033[94m"
#define ANSI_GREEN    "\033[92m"
#define ANSI_WHITE    "\033[97m"
#else
#define ANSI_RESET    ""
#define ANSI_BOLD     ""
#define ANSI_CYAN     ""
#define ANSI_MAGENTA  ""
#define ANSI_RED      ""
#define ANSI_YELLOW   ""
#define ANSI_BLUE     ""
#define ANSI_GREEN    ""
#define ANSI_WHITE    ""
#endif

#define ANSI_BOLD_CYAN     ANSI_BOLD ANSI_CYAN
#define ANSI_BOLD_MAGENTA  ANSI_BOLD ANSI_MAGENTA
#define ANSI_BOLD_RED      ANSI_BOLD ANSI_RED
#define ANSI_BOLD_YELLOW   ANSI_BOLD ANSI_YELLOW
#define ANSI_BOLD_BLUE     ANSI_BOLD ANSI_BLUE
#define ANSI_BOLD_GREEN    ANSI_BOLD ANSI_GREEN
#define ANSI_BOLD_WHITE    ANSI_BOLD ANSI_WHITE

/* Tags */
#define MK_BANNER_ENTRY    ANSI_BOLD "[" ANSI_GREEN "+" ANSI_RESET ANSI_BOLD "] " \
    ANSI_RESET

/* Transport type */
#define MK_TRANSPORT_HTTP  "http"
#define MK_TRANSPORT_HTTPS "https"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifdef __GNUC__ /* GCC supports this since 2.3. */
 #define PRINTF_WARNINGS(a,b) __attribute__ ((format (printf, a, b)))
#else
 #define PRINTF_WARNINGS(a,b)
#endif

#ifdef __GNUC__ /* GCC supports this since 2.7. */
 #define UNUSED_PARAM __attribute__ ((unused))
#else
 #define UNUSED_PARAM
#endif

/*
 * Validation macros
 * -----------------
 * Based on article http://lwn.net/Articles/13183/
 *
 * ---
 * ChangeSet 1.803, 2002/10/18 16:28:57-07:00, torvalds@home.transmeta.com
 *
 *	Make a polite version of BUG_ON() - WARN_ON() which doesn't
 *	kill the machine.
 *
 *	Damn I hate people who kill the machine for no good reason.
 * ---
 *
 */

#ifdef __GNUC__
  #define mk_unlikely(x) __builtin_expect((x),0)
  #define mk_likely(x) __builtin_expect((x),1)
  #define mk_prefetch(x, ...) __builtin_prefetch(x, __VA_ARGS__)
#else
  #define mk_unlikely(x)      (x)
  #define mk_likely(x)        (x)
  #define mk_prefetch(x, ...) (x, __VA_ARGS__)
#endif

#define mk_is_bool(x) ((x == MK_TRUE || x == MK_FALSE) ? 1 : 0)

#define mk_bug(condition) do {                                          \
        if (mk_unlikely((condition)!=0)) {                              \
            mk_print(MK_BUG, "Bug found in %s() at %s:%d",              \
                     __FUNCTION__, __FILE__, __LINE__);                 \
            abort();                                                    \
        }                                                               \
    } while(0)

#define mk_exception() do {                                             \
        mk_print(MK_WARN, "Exception found in %s() at %s:%d",           \
                 __FUNCTION__, __FILE__, __LINE__);                     \
    } while(0)

/*
 * Macros to calculate sub-net data using ip address and sub-net prefix. Macros
 * written by Zeus (@sxd).
 *
 * Zeus, why the hell you did not documented the macros data type ???.
 *
 *  addr = struct in_addr -> s_addr.
 *  pos  = numeric position for the octect (0, 1, 2..)
 *  net  = integer representing the short network mask (e.g: /24)
 */

#define MK_NET_IP_OCTECT(addr,pos) (addr >> (8 * pos) & 255)
#define MK_NET_NETMASK(addr,net) htonl((0xffffffff << (32 - net)))
#define MK_NET_BROADCAST(addr,net) (addr | ~MK_NET_NETMASK(addr,net))
#define MK_NET_NETWORK(addr,net) (addr & MK_NET_NETMASK(addr,net))
#define MK_NET_WILDCARD(addr,net) (MK_NET_BROADCAST(addr,net) ^ MK_NET_NETWORK(addr,net))
#define MK_NET_HOSTMIN(addr,net) net == 31 ? MK_NET_NETWORK(addr,net) : (MK_NET_NETWORK(addr,net) + 0x01000000)
#define MK_NET_HOSTMAX(addr,net) net == 31 ? MK_NET_BROADCAST(addr,net) : (MK_NET_BROADCAST(addr,net) - 0x01000000)

#ifdef __GNUC__
  #if __GNUC__ >= 4
    #define MK_EXPORT __attribute__ ((visibility ("default")))
  #else
    #define MK_EXPORT
  #endif
#elif defined(_WIN32)
  #define MK_EXPORT __declspec(dllexport)
#endif

#ifdef _WIN32
    #define MK_INLINE __forceinline
#else
    #define MK_INLINE inline __attribute__((always_inline))
#endif

/* Some old libc do not declare O_CLOEXEC */
#ifndef O_CLOEXEC
#define O_CLOEXEC      02000000 /* set close_on_exec */
#endif

/* Wrapper (mk_utils) libc error helpers */
#define mk_libc_error(c)    mk_utils_libc_error(c, __FILE__, __LINE__)
#define mk_libc_warn(c)     mk_utils_libc_warn(c, __FILE__, __LINE__)

#endif
