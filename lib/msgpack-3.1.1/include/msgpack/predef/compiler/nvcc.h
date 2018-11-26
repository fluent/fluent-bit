/*
Copyright Benjamin Worpitz 2018
Distributed under the Boost Software License, Version 1.0.
(See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef MSGPACK_PREDEF_COMPILER_NVCC_H
#define MSGPACK_PREDEF_COMPILER_NVCC_H

#include <msgpack/predef/version_number.h>
#include <msgpack/predef/make.h>

/*`
[heading `MSGPACK_COMP_NVCC`]

[@https://en.wikipedia.org/wiki/NVIDIA_CUDA_Compiler NVCC] compiler.
Version number available as major, minor, and patch beginning with version 7.5.

[table
    [[__predef_symbol__] [__predef_version__]]

    [[`__NVCC__`] [__predef_detection__]]

    [[`__CUDACC_VER_MAJOR__`, `__CUDACC_VER_MINOR__`, `__CUDACC_VER_BUILD__`] [V.R.P]]
    ]
 */

#define MSGPACK_COMP_NVCC MSGPACK_VERSION_NUMBER_NOT_AVAILABLE

#if defined(__NVCC__)
#   if !defined(__CUDACC_VER_MAJOR__) || !defined(__CUDACC_VER_MINOR__) || !defined(__CUDACC_VER_BUILD__)
#       define MSGPACK_COMP_NVCC_DETECTION MSGPACK_VERSION_NUMBER_AVAILABLE
#   else
#       define MSGPACK_COMP_NVCC_DETECTION MSGPACK_VERSION_NUMBER(__CUDACC_VER_MAJOR__, __CUDACC_VER_MINOR__, __CUDACC_VER_BUILD__)
#   endif
#endif

#ifdef MSGPACK_COMP_NVCC_DETECTION
#   if defined(MSGPACK_PREDEF_DETAIL_COMP_DETECTED)
#       define MSGPACK_COMP_NVCC_EMULATED MSGPACK_COMP_NVCC_DETECTION
#   else
#       undef MSGPACK_COMP_NVCC
#       define MSGPACK_COMP_NVCC MSGPACK_COMP_NVCC_DETECTION
#   endif
#   define MSGPACK_COMP_NVCC_AVAILABLE
#   include <msgpack/predef/detail/comp_detected.h>
#endif

#define MSGPACK_COMP_NVCC_NAME "NVCC"

#endif

#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_COMP_NVCC,MSGPACK_COMP_NVCC_NAME)

#ifdef MSGPACK_COMP_NVCC_EMULATED
#include <msgpack/predef/detail/test.h>
MSGPACK_PREDEF_DECLARE_TEST(MSGPACK_COMP_NVCC_EMULATED,MSGPACK_COMP_NVCC_NAME)
#endif
