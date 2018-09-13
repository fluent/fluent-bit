/*
 * Copyright (C) 2017 James E. King III
 *
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 *   http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef MSGPACK_PREDEF_LIBRARY_C_CLOUDABI_H
#define MSGPACK_PREDEF_LIBRARY_C_CLOUDABI_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

#include <msgpack/predef/library/c/_prefix.h>

#if defined(__CloudABI__)
#include <stddef.h>
#endif

/*`
[heading `MSGPACK_LIB_C_CLOUDABI`]

[@https://github.com/NuxiNL/cloudlibc cloudlibc] - CloudABI's standard C library.
Version number available as major, and minor.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__cloudlibc__`] [__predef_detection__]]

    [[`__cloudlibc_major__`, `__cloudlibc_minor__`] [V.R.0]]
    ]
 */

#define MSGPACK_LIB_C_CLOUDABI MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__cloudlibc__)
#   undef MSGPACK_LIB_C_CLOUDABI
#   define MSGPACK_LIB_C_CLOUDABI \
            MSGPACK_VERSION_NUMBER(__cloudlibc_major__,__cloudlibc_minor__,0)
#endif

#if MSGPACK_LIB_C_CLOUDABI
#   define MSGPACK_LIB_C_CLOUDABI_AVAILABLE
#endif

#define MSGPACK_LIB_C_CLOUDABI_NAME "cloudlibc"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_LIB_C_CLOUDABI,MSGPACK_LIB_C_CLOUDABI_NAME)
