#!/bin/bash
#
# Provides some known-good CFLAGS
# Sets:
#  CFLAGS
#  CXXFLAGS
#  CPPFLAGS


function checks {
    mkl_mkvar_append CPPFLAGS CPPFLAGS \
        "-Wall -Wsign-compare -Wfloat-equal -Wpointer-arith -Wcast-align"

    if [[ $MKL_WANT_WERROR = "y" ]]; then
        mkl_mkvar_append CPPFLAGS CPPFLAGS \
            "-Werror"
    fi
}
