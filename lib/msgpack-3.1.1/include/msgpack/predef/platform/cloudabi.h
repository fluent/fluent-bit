/*
  Copyright 2017 James E. King, III
  Distributed under the Boost Software License, Version 1.0.
  (See accompanying file LICENSE_1_0.txt or copy at
    http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_PLAT_CLOUDABI_H
#define MSGPACK_PREDEF_PLAT_CLOUDABI_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

/*`
[heading `MSGPACK_PLAT_CLOUDABI`]

[@https://github.com/NuxiNL/cloudabi CloudABI] platform.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__CloudABI__`] [__predef_detection__]]
    ]
 */

#define MSGPACK_PLAT_CLOUDABI MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__CloudABI__)
#   undef MSGPACK_PLAT_CLOUDABI
#   define MSGPACK_PLAT_CLOUDABI MSGPACK_VERSION_NUMBER_AVAILABLE
#endif

#if MSGPACK_PLAT_CLOUDABI
#   define MSGPACK_PLAT_CLOUDABI_AVAILABLE
#   include <msgpack/predef/detail/platform_detected.h>
#endif

#define MSGPACK_PLAT_CLOUDABI_NAME "CloudABI"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_PLAT_CLOUDABI,MSGPACK_PLAT_CLOUDABI_NAME)
