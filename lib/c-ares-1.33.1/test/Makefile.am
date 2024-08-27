# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT
AUTOMAKE_OPTIONS = foreign subdir-objects nostdinc 1.9.6

AM_CPPFLAGS += -I$(top_builddir)/include \
               -I$(top_builddir)/src/lib \
               -I$(top_srcdir)/include   \
               -I$(top_srcdir)/src/lib   \
               -I$(top_srcdir)/test      \
               -I$(top_builddir)/test    \
               -I$(top_builddir) -DCARES_NO_DEPRECATED

AM_CXXFLAGS :=
AM_CXXFLAGS += $(PTHREAD_CFLAGS)
AM_CFLAGS   += $(PTHREAD_CFLAGS)

# Makefile.inc provides the various *SOURCES and *HEADERS defines
include Makefile.inc

TESTS = arestest fuzzcheck.sh

noinst_PROGRAMS = arestest aresfuzz aresfuzzname dnsdump ares_queryloop
EXTRA_DIST = fuzzcheck.sh CMakeLists.txt Makefile.m32 Makefile.msvc README.md $(srcdir)/fuzzinput/* $(srcdir)/fuzznames/*
arestest_SOURCES = $(TESTSOURCES) $(TESTHEADERS)

# Not interested in coverage of test code, but linking the test binary needs the coverage option
arestest_CXXFLAGS = $(AM_CXXFLAGS) $(GMOCK_CFLAGS)
arestest_LDADD = $(GMOCK_LIBS) $(top_builddir)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

aresfuzz_SOURCES = $(FUZZSOURCES)
aresfuzz_LDADD = $(top_builddir)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

aresfuzzname_SOURCES = $(FUZZNAMESOURCES)
aresfuzzname_LDADD = $(top_builddir)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

dnsdump_SOURCES = $(DUMPSOURCES)
dnsdump_LDADD = $(top_builddir)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

ares_queryloop_SOURCES = $(LOOPSOURCES)
ares_queryloop_LDADD = $(top_builddir)/src/lib/libcares.la $(PTHREAD_LIBS) $(CODE_COVERAGE_LIBS)

test: check
