/*
Copyright Rene Rivera 2008-2015
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_PLAT_MINGW32_H
#define MSGPACK_PREDEF_PLAT_MINGW32_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

/*`
[heading `MSGPACK_PLAT_MINGW32`]

[@http://www.mingw.org/ MinGW] platform.
Version number available as major, minor, and patch.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__MINGW32__`] [__predef_detection__]]

    [[`__MINGW32_VERSION_MAJOR`, `__MINGW32_VERSION_MINOR`] [V.R.0]]
    ]
 */

#define MSGPACK_PLAT_MINGW32 MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__MINGW32__)
#   include <_mingw.h>
#   if !defined(MSGPACK_PLAT_MINGW32_DETECTION) && (defined(__MINGW32_VERSION_MAJOR) && defined(__MINGW32_VERSION_MINOR))
#       define MSGPACK_PLAT_MINGW32_DETECTION \
            MSGPACK_VERSION_NUMBER(__MINGW32_VERSION_MAJOR,__MINGW32_VERSION_MINOR,0)
#   endif
#   if !defined(MSGPACK_PLAT_MINGW32_DETECTION)
#       define MSGPACK_PLAT_MINGW32_DETECTION MSGPACK_VERSION_NUMBER_AVAILABLE
#   endif
#endif

#ifdef MSGPACK_PLAT_MINGW32_DETECTION
#   define MSGPACK_PLAT_MINGW32_AVAILABLE
#   if defined(MSGPACK_PREDEF_DETAIL_PLAT_DETECTED)
#       define MSGPACK_PLAT_MINGW32_EMULATED MSGPACK_PLAT_MINGW32_DETECTION
#   else
#       undef MSGPACK_PLAT_MINGW32
#       define MSGPACK_PLAT_MINGW32 MSGPACK_PLAT_MINGW32_DETECTION
#   endif
#   include <msgpack/predef/detail/platform_detected.h>
#endif

#define MSGPACK_PLAT_MINGW32_NAME "MinGW"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_MINGW32,MSGPACK_PLAT_MINGW32_NAME)

#ifdef MSGPACK_PLAT_MINGW32_EMULATED
#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_MINGW32_EMULATED,MSGPACK_PLAT_MINGW32_NAME)
#endif
