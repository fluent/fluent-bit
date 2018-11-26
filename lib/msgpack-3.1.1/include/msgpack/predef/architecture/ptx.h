/*
Copyright Benjamin Worpitz 2018
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_ARCHITECTURE_PTX_H
#define MSGPACK_PREDEF_ARCHITECTURE_PTX_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

/*`
[heading `MSGPACK_ARCH_PTX`]

[@https://en.wikipedia.org/wiki/Parallel_Thread_Execution PTX] architecture.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__CUDA_ARCH__`] [__predef_detection__]]

    [[`__CUDA_ARCH__`] [V.R.0]]
    ]
 */

#define MSGPACK_ARCH_PTX MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__CUDA_ARCH__)
#   undef MSGPACK_ARCH_PTX
#   define MSGPACK_ARCH_PTX MSGPACK_PREDEF_MAKE_10_VR0(__CUDA_ARCH__)
#endif

#if MSGPACK_ARCH_PTX
#   define MSGPACK_ARCH_PTX_AVAILABLE
#endif

#define MSGPACK_ARCH_PTX_NAME "PTX"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_ARCH_PTX,MSGPACK_ARCH_PTX_NAME)
