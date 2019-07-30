/*
Copyright James E. King III, 2017
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_PLAT_WINDOWS_SERVER_H
#define MSGPACK_PREDEF_PLAT_WINDOWS_SERVER_H

#include <msgpack/predef/make.h>
#include <msgpack/predef/os/windows.h>
#include <msgpack/predef/platform/windows_uwp.h>
#include <msgpack/predef/version_number.h>

/*`
[heading `MSGPACK_PLAT_WINDOWS_SERVER`]

[@https://docs.microsoft.com/en-us/windows/uwp/get-started/universal-application-platform-guide UWP]
for Windows Server development.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`WINAPI_FAMILY == WINAPI_FAMILY_SERVER`] [__predef_detection__]]
    ]
 */

#define MSGPACK_PLAT_WINDOWS_SERVER MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if MSGPACK_OS_WINDOWS && \
    defined(WINAPI_FAMILY_SERVER) && WINAPI_FAMILY == WINAPI_FAMILY_SERVER
#   undef MSGPACK_PLAT_WINDOWS_SERVER
#   define MSGPACK_PLAT_WINDOWS_SERVER MSGPACK_VERSION_NUMBER_AVAILABLE
#endif
 
#if MSGPACK_PLAT_WINDOWS_SERVER
#   define MSGPACK_PLAT_WINDOWS_SERVER_AVAILABLE
#   include <msgpack/predef/detail/platform_detected.h>
#endif

#define MSGPACK_PLAT_WINDOWS_SERVER_NAME "Windows Server"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_WINDOWS_SERVER,MSGPACK_PLAT_WINDOWS_SERVER_NAME)
