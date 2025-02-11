// Copyright (C) 2014-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_BYTEORDER_HPP
#define VSOMEIP_V3_BYTEORDER_HPP

#define BYTEORDER_UNKNOWN 0
#define BYTEORDER_LITTLE_ENDIAN 1
#define BYTEORDER_BIG_ENDIAN 2

// Detect with GCC 4.6's macro
#  ifdef __BYTE_ORDER__
#    if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#      define COMPILE_TIME_ENDIAN BYTEORDER_LITTLE_ENDIAN
#    elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define COMPILE_TIME_ENDIAN BYTEORDER_BIG_ENDIAN
#    else
#      define COMPILE_TIME_ENDIAN BYTEORDER_UNKNOWN
#    endif // __BYTE_ORDER__
// Detect with GLIBC's endian.h
#  elif defined(__GLIBC__)
#    include <endian.h>
#    if (__BYTE_ORDER == __LITTLE_ENDIAN)
#      define COMPILE_TIME_ENDIAN BYTEORDER_LITTLE_ENDIAN
#    elif (__BYTE_ORDER == __BIG_ENDIAN)
#      define COMPILE_TIME_ENDIAN BYTEORDER_BIG_ENDIAN
#    else
#      define COMPILE_TIME_ENDIAN BYTEORDER_UNKNOWN
#   endif // __GLIBC__
// Detect with _LITTLE_ENDIAN and _BIG_ENDIAN macro
#  elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#    define COMPILE_TIME_ENDIAN BYTEORDER_LITTLE_ENDIAN
#  elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
#    define COMPILE_TIME_ENDIAN BYTEORDER_BIG_ENDIAN
// Detect with architecture macros
#  elif defined(__sparc) || defined(__sparc__) || defined(_POWER) || defined(__powerpc__) || defined(__ppc__) || defined(__hpux) || defined(__hppa) || defined(_MIPSEB) || defined(_POWER) || defined(__s390__)
#    define COMPILE_TIME_ENDIAN BYTEORDER_BIG_ENDIAN
#  elif defined(__i386__) || defined(__alpha__) || defined(__ia64) || defined(__ia64__) || defined(_M_IX86) || defined(_M_IA64) || defined(_M_ALPHA) || defined(__amd64) || defined(__amd64__) || defined(_M_AMD64) || defined(__x86_64) || defined(__x86_64__) || defined(_M_X64) || defined(__bfin__)
#    define COMPILE_TIME_ENDIAN BYTEORDER_LITTLE_ENDIAN
#  elif defined(_MSC_VER) && (defined(_M_ARM) || defined(_M_ARM64))
#    define COMPILE_TIME_ENDIAN BYTEORDER_LITTLE_ENDIAN
#  else
#    define COMPILE_TIME_ENDIAN BYTEORDER_UNKNOWN
#  endif


#endif // VSOMEIP_V3_BYTEORDER_HPP
