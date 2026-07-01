#!/bin/bash
#
# Checks for atomic ops:
#  compiler builtin (__sync_..) and portable libatomic's (__atomic_..)
# Will also provide abstraction by defining the prefix to use.
#
# Sets:
#  HAVE_ATOMICS
#  HAVE_ATOMICS_32
#  HAVE_ATOMICS_64
#  HAVE_ATOMICS_32_ATOMIC   __atomic interface
#  HAVE_ATOMICS_32_SYNC     __sync interface
#  HAVE_ATOMICS_64_ATOMIC   __atomic interface
#  HAVE_ATOMICS_64_SYNC     __sync interface
#  WITH_LIBATOMIC
#  LIBS
#
#  ATOMIC_OP(OP1,OP2,PTR,VAL)
#  ATOMIC_OP32(OP1,OP2,PTR,VAL)
#  ATOMIC_OP64(OP1,OP2,PTR,VAL)
#   where op* is 'add,sub,fetch'
#   e.g:  ATOMIC_OP32(add, fetch, &i, 10)
#         becomes __atomic_add_fetch(&i, 10, ..) or
#                 __sync_add_and_fetch(&i, 10)
#

function checks {


    # We prefer the newer __atomic stuff, but 64-bit atomics might
    # require linking with -latomic, so we need to perform these tests
    # in the proper order:
    #   __atomic 32
    #   __atomic 32 -latomic
    #   __sync 32
    #
    #   __atomic 64
    #   __atomic 64 -latomic
    #   __sync 64

    local _libs=
    local _a32="__atomic_ ## OP1 ## _ ## OP2(PTR, VAL, __ATOMIC_SEQ_CST)"
    local _a64="__atomic_ ## OP1 ## _ ## OP2(PTR, VAL, __ATOMIC_SEQ_CST)"

    # 32-bit:
    # Try fully builtin __atomic
    if ! mkl_compile_check __atomic_32 HAVE_ATOMICS_32 cont CC "" \
        "
#include <inttypes.h>
int32_t foo (int32_t i) {
  return __atomic_add_fetch(&i, 1, __ATOMIC_SEQ_CST);
}"
        then
        # Try __atomic with -latomic
        if mkl_compile_check --ldflags="-latomic" __atomic_32_lib HAVE_ATOMICS_32 \
            cont CC "" \
            "
#include <inttypes.h>
int32_t foo (int32_t i) {
  return __atomic_add_fetch(&i, 1, __ATOMIC_SEQ_CST);
}"
        then
            _libs="-latomic"
            mkl_allvar_set "__atomic_32_lib" "HAVE_ATOMICS_32_ATOMIC" "y"
        else
            # Try __sync interface
            if mkl_compile_check __sync_32 HAVE_ATOMICS_32 disable CC "" \
                "
#include <inttypes.h>
int32_t foo (int32_t i) {
  return __sync_add_and_fetch(&i, 1);
}"
                then
                _a32="__sync_ ## OP1 ## _and_ ## OP2(PTR, VAL)"
                mkl_allvar_set "__sync_32" "HAVE_ATOMICS_32_SYNC" "y"
            else
                _a32=""
            fi
        fi
    else
        mkl_allvar_set "__atomic_32" "HAVE_ATOMICS_32_ATOMIC" "y"
    fi


    if [[ ! -z $_a32 ]]; then
        mkl_define_set "atomic_32" "ATOMIC_OP32(OP1,OP2,PTR,VAL)" "code:$_a32"
    fi



    # 64-bit:
    # Try fully builtin __atomic
    if ! mkl_compile_check __atomic_64 HAVE_ATOMICS_64 cont CC "" \
        "
#include <inttypes.h>
int64_t foo (int64_t i) {
  return __atomic_add_fetch(&i, 1, __ATOMIC_SEQ_CST);
}"
        then
        # Try __atomic with -latomic
        if mkl_compile_check --ldflags="-latomic" __atomic_64_lib HAVE_ATOMICS_64 \
            cont CC "" \
            "
#include <inttypes.h>
int64_t foo (int64_t i) {
  return __atomic_add_fetch(&i, 1, __ATOMIC_SEQ_CST);
}"
        then
            _libs="-latomic"
            mkl_allvar_set "__atomic_64_lib" "HAVE_ATOMICS_64_ATOMIC" "y"
        else
            # Try __sync interface
            if mkl_compile_check __sync_64 HAVE_ATOMICS_64 disable CC "" \
                "
#include <inttypes.h>
int64_t foo (int64_t i) {
  return __sync_add_and_fetch(&i, 1);
}"
                then
                _a64="__sync_ ## OP1 ## _and_ ## OP2 (PTR, VAL)"
                mkl_allvar_set "__sync_64" "HAVE_ATOMICS_64_SYNC" "y"
            else
                _a64=""
            fi
        fi
    else
        mkl_allvar_set "__atomic_64" "HAVE_ATOMICS_64_ATOMIC" "y"
    fi


    if [[ ! -z $_a64 ]]; then
        mkl_define_set "atomic_64" "ATOMIC_OP64(OP1,OP2,PTR,VAL)" "code:$_a64"

        # Define generic ATOMIC() macro identical to 64-bit atomics"
        mkl_define_set "atomic_64" "ATOMIC_OP(OP1,OP2,PTR,VAL)" "code:$_a64"
    fi


    if [[ ! -z $_libs ]]; then
        mkl_mkvar_append LDFLAGS LDFLAGS "-Wl,--as-needed"
        mkl_mkvar_append LIBS LIBS "$_libs"
    fi

}
