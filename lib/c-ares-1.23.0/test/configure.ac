#############################################################
#
# Copyright (C) the Massachusetts Institute of Technology.
# Copyright (C) Daniel Stenberg
#
# Permission to use, copy, modify, and distribute this
# software and its documentation for any purpose and without
# fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright
# notice and this permission notice appear in supporting
# documentation, and that the name of M.I.T. not be used in
# advertising or publicity pertaining to distribution of the
# software without specific, written prior permission.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is"
# without express or implied warranty.
#
# SPDX-License-Identifier: MIT
#
#############################################################
AC_PREREQ(2.57)
AC_INIT([c-ares-test],[-],[-])
AC_CONFIG_SRCDIR([ares-test.cc])
AC_CONFIG_MACRO_DIR([../m4])

AM_INIT_AUTOMAKE([no-define])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AX_REQUIRE_DEFINED([AX_CXX_COMPILE_STDCXX_11])
AX_REQUIRE_DEFINED([AX_PTHREAD])

dnl Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])
LT_INIT
AC_SUBST(LIBTOOL_DEPS)
AX_PTHREAD([ CARES_THREADS=yes ], [ CARES_THREADS=no ])

if test "${CARES_THREADS}" = "yes" ; then
	LIBS="$PTHREAD_LIBS $LIBS"
	CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
	CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
	CC="$PTHREAD_CC"
	CXX="$PTHREAD_CXX"
fi

AX_CODE_COVERAGE
AX_CHECK_USER_NAMESPACE
AX_CHECK_UTS_NAMESPACE

AC_CHECK_HEADERS(netdb.h netinet/tcp.h)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
