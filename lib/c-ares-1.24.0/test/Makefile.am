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

ARES_BLD_DIR = $(top_builddir)/..
ARES_SRC_DIR = $(top_srcdir)/..

AUTOMAKE_OPTIONS = foreign subdir-objects nostdinc 1.9.6
ACLOCAL_AMFLAGS = -I ../m4 --install

CPPFLAGS += -I$(ARES_BLD_DIR)/include \
            -I$(ARES_BLD_DIR)/src/lib \
            -I$(ARES_SRC_DIR)/include \
            -I$(ARES_SRC_DIR)/src/lib \
            -I$(top_builddir)
CXXFLAGS += -Wall $(PTHREAD_CFLAGS)

# Makefile.inc provides the various *SOURCES and *HEADERS defines
include Makefile.inc

TESTS = arestest fuzzcheck.sh

noinst_PROGRAMS = arestest aresfuzz aresfuzzname dnsdump
EXTRA_DIST = fuzzcheck.sh CMakeLists.txt Makefile.m32 Makefile.msvc README.md buildconf $(srcdir)/fuzzinput/* $(srcdir)/fuzznames/*
arestest_SOURCES = $(TESTSOURCES) $(TESTHEADERS)

# Not interested in coverage of test code, but linking the test binary needs the coverage option
arestest_CXXFLAGS = $(GMOCK_CFLAGS)
arestest_LDADD = $(GMOCK_LIBS) $(ARES_BLD_DIR)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

include $(top_srcdir)/aminclude_static.am

aresfuzz_SOURCES = $(FUZZSOURCES)
aresfuzz_LDADD = $(ARES_BLD_DIR)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

aresfuzzname_SOURCES = $(FUZZNAMESOURCES)
aresfuzzname_LDADD = $(ARES_BLD_DIR)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

dnsdump_SOURCES = $(DUMPSOURCES)
dnsdump_LDADD = $(ARES_BLD_DIR)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

test: check
