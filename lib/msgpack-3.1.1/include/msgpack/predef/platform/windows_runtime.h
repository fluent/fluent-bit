/*
Copyright (c) Microsoft Corporation 2014
Copyright Rene Rivera 2015
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_PLAT_WINDOWS_RUNTIME_H
#define MSGPACK_PREDEF_PLAT_WINDOWS_RUNTIME_H

#include <msgpack/predef/make.h>
#include <msgpack/predef/os/windows.h>
#include <msgpack/predef/platform/windows_phone.h>
#include <msgpack/predef/platform/windows_store.h>
#include <msgpack/predef/version_number.h>

/*`
[heading `MSGPACK_PLAT_WINDOWS_RUNTIME`]

Deprecated.

[@https://docs.microsoft.com/en-us/windows/uwp/get-started/universal-application-platform-guide UWP]
for Windows Phone or Store development.  This does not align to the existing development model for
UWP and is deprecated.  Use one of the other `MSGPACK_PLAT_WINDOWS_*`definitions instead.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`MSGPACK_PLAT_WINDOWS_PHONE`] [__predef_detection__]]
    [[`MSGPACK_PLAT_WINDOWS_STORE`] [__predef_detection__]]
    ]
 */

#define MSGPACK_PLAT_WINDOWS_RUNTIME MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if MSGPACK_OS_WINDOWS && \
    (MSGPACK_PLAT_WINDOWS_STORE || MSGPACK_PLAT_WINDOWS_PHONE)
#   undef MSGPACK_PLAT_WINDOWS_RUNTIME
#   define MSGPACK_PLAT_WINDOWS_RUNTIME MSGPACK_VERSION_NUMBER_AVAILABLE
#endif
 
#if MSGPACK_PLAT_WINDOWS_RUNTIME
#   define MSGPACK_PLAT_WINDOWS_RUNTIME_AVAILABLE
#   include <msgpack/predef/detail/platform_detected.h>
#endif

#define MSGPACK_PLAT_WINDOWS_RUNTIME_NAME "Windows Runtime"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_WINDOWS_RUNTIME,MSGPACK_PLAT_WINDOWS_RUNTIME_NAME)
