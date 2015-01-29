
AM_CPPFLAGS   = -I$(top_srcdir)/src -I$(top_builddir)/src
AM_C_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src
AM_LDFLAGS = $(top_builddir)/src/libmsgpack.la -lgtest_main -lgtest -pthread

check_PROGRAMS = \
		zone \
		pack_unpack \
		pack_unpack_c \
		streaming \
		streaming_c \
		object \
		convert \
		buffer \
		cases \
		fixint \
		fixint_c \
		version \
		msgpackc_test \
		msgpack_test

TESTS = $(check_PROGRAMS)

zone_SOURCES = zone.cc

pack_unpack_SOURCES = pack_unpack.cc

pack_unpack_c_SOURCES = pack_unpack_c.cc

streaming_SOURCES = streaming.cc

streaming_c_SOURCES = streaming_c.cc

object_SOURCES = object.cc

convert_SOURCES = convert.cc

buffer_SOURCES = buffer.cc
buffer_LDADD = -lz

cases_SOURCES = cases.cc

fixint_SOURCES = fixint.cc

fixint_c_SOURCES = fixint_c.cc

version_SOURCES = version.cc

msgpackc_test_SOURCES = msgpackc_test.cpp

msgpack_test_SOURCES = msgpack_test.cpp

EXTRA_DIST = cases.mpac cases_compact.mpac

