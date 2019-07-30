/*
Copyright Rene Rivera 2008-2015
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_PLAT_MINGW64_H
#define MSGPACK_PREDEF_PLAT_MINGW64_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

/*`
[heading `MSGPACK_PLAT_MINGW64`]

[@https://mingw-w64.org/ MinGW-w64] platform.
Version number available as major, minor, and patch.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__MINGW64__`] [__predef_detection__]]

    [[`__MINGW64_VERSION_MAJOR`, `__MINGW64_VERSION_MINOR`] [V.R.0]]
    ]
 */

#define MSGPACK_PLAT_MINGW64 MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__MINGW64__)
#   include <_mingw.h>
#   if !defined(MSGPACK_PLAT_MINGW64_DETECTION) && (defined(__MINGW64_VERSION_MAJOR) && defined(__MINGW64_VERSION_MINOR))
#       define MSGPACK_PLAT_MINGW64_DETECTION \
            MSGPACK_VERSION_NUMBER(__MINGW64_VERSION_MAJOR,__MINGW64_VERSION_MINOR,0)
#   endif
#   if !defined(MSGPACK_PLAT_MINGW64_DETECTION)
#       define MSGPACK_PLAT_MINGW64_DETECTION MSGPACK_VERSION_NUMBER_AVAILABLE
#   endif
#endif

#ifdef MSGPACK_PLAT_MINGW64_DETECTION
#   define MSGPACK_PLAT_MINGW64_AVAILABLE
#   if defined(MSGPACK_PREDEF_DETAIL_PLAT_DETECTED)
#       define MSGPACK_PLAT_MINGW64_EMULATED MSGPACK_PLAT_MINGW64_DETECTION
#   else
#       undef MSGPACK_PLAT_MINGW64
#       define MSGPACK_PLAT_MINGW64 MSGPACK_PLAT_MINGW64_DETECTION
#   endif
#   include <msgpack/predef/detail/platform_detected.h>
#endif

#define MSGPACK_PLAT_MINGW64_NAME "MinGW-w64"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_MINGW64,MSGPACK_PLAT_MINGW64_NAME)

#ifdef MSGPACK_PLAT_MINGW64_EMULATED
#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_MINGW64_EMULATED,MSGPACK_PLAT_MINGW64_NAME)
#endif
