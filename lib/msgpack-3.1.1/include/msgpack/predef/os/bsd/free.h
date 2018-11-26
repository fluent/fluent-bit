/*
Copyright Rene Rivera 2012-2015
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_OS_BSD_FREE_H
#define MSGPACK_PREDEF_OS_BSD_FREE_H

#include <msgpack/predef/os/bsd.h>

/*`
[heading `MSGPACK_OS_BSD_FREE`]

[@http://en.wikipedia.org/wiki/Freebsd FreeBSD] operating system.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__FreeBSD__`] [__predef_detection__]]

    [[`__FreeBSD_version`] [V.R.P]]
    ]
 */

#define MSGPACK_OS_BSD_FREE MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if !defined(MSGPACK_PREDEF_DETAIL_OS_DETECTED) && ( \
    defined(__FreeBSD__) \
    )
#   ifndef MSGPACK_OS_BSD_AVAILABLE
#       define MSGPACK_OS_BSD MSGPACK_VERSION_NUMBER_AVAILABLE
#       define MSGPACK_OS_BSD_AVAILABLE
#   endif
#   undef MSGPACK_OS_BSD_FREE
#   include <sys/param.h>
#   if defined(__FreeBSD_version)
#       if __FreeBSD_version == 491000
#           define MSGPACK_OS_BSD_FREE \
                MSGPACK_VERSION_NUMBER(4, 10, 0)
#       elif __FreeBSD_version == 492000
#           define MSGPACK_OS_BSD_FREE \
                MSGPACK_VERSION_NUMBER(4, 11, 0)
#       elif __FreeBSD_version < 500000
#           define MSGPACK_OS_BSD_FREE \
                MSGPACK_PREDEF_MAKE_10_VRPPPP(__FreeBSD_version)
#       else
#           define MSGPACK_OS_BSD_FREE \
                MSGPACK_PREDEF_MAKE_10_VVRRPPP(__FreeBSD_version)
#       endif
#   else
#       define MSGPACK_OS_BSD_FREE MSGPACK_VERSION_NUMBER_AVAILABLE
#   endif
#endif

#if MSGPACK_OS_BSD_FREE
#   define MSGPACK_OS_BSD_FREE_AVAILABLE
#   include <msgpack/predef/detail/os_detected.h>
#endif

#define MSGPACK_OS_BSD_FREE_NAME "Free BSD"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_OS_BSD_FREE,MSGPACK_OS_BSD_FREE_NAME)
