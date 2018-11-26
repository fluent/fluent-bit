/*
Copyright Benjamin Worpitz 2018
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_LANGUAGE_CUDA_H
#define MSGPACK_PREDEF_LANGUAGE_CUDA_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

/*`
[heading `MSGPACK_LANG_CUDA`]

[@https://en.wikipedia.org/wiki/CUDA CUDA C/C++] language.
If available, the version is detected as VV.RR.P.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__CUDACC__`] [__predef_detection__]]
    [[`__CUDA__`] [__predef_detection__]]

    [[`CUDA_VERSION`] [VV.RR.P]]
    ]
 */

#define MSGPACK_LANG_CUDA MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__CUDACC__) || defined(__CUDA__)
#   undef MSGPACK_LANG_CUDA
#   include <cuda.h>
#   if defined(CUDA_VERSION)
#       define MSGPACK_LANG_CUDA MSGPACK_PREDEF_MAKE_10_VVRRP(CUDA_VERSION)
#   else
#       define MSGPACK_LANG_CUDA MSGPACK_VERSION_NUMBER_AVAILABLE
#   endif
#endif

#if MSGPACK_LANG_CUDA
#   define MSGPACK_LANG_CUDA_AVAILABLE
#endif

#define MSGPACK_LANG_CUDA_NAME "CUDA C/C++"


#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_LANG_CUDA,MSGPACK_LANG_CUDA_NAME)
