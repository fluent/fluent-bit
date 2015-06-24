AM_CPPFLAGS   = -I$(top_srcdir)/include
AM_C_CPPFLAGS = -I$(top_srcdir)/include
AM_LDFLAGS = $(top_builddir)/src/libmsgpack.la -lgtest_main -lgtest -pthread

check_PROGRAMS = \
		zone \
		pack_unpack \
		pack_unpack_c \
		streaming \
		streaming_c \
		object \
		object_with_zone \
		convert \
		buffer \
		cases \
		fixint \
		fixint_c \
		version \
		msgpack_tuple \
		msgpack_c \
		msgpack_basic \
		msgpack_container \
		msgpack_stream \
		msgpack_vref \
		msgpack_cpp11 \
		reference_cpp11 \
		reference \
		limit \
		iterator_cpp11

TESTS = $(check_PROGRAMS)

zone_SOURCES = zone.cpp

pack_unpack_SOURCES = pack_unpack.cpp

pack_unpack_c_SOURCES = pack_unpack_c.cpp

streaming_SOURCES = streaming.cpp

streaming_c_SOURCES = streaming_c.cpp

object_SOURCES = object.cpp

object_with_zone_SOURCES = object_with_zone.cpp

convert_SOURCES = convert.cpp

buffer_SOURCES = buffer.cpp
buffer_LDADD = -lz

cases_SOURCES = cases.cpp

fixint_SOURCES = fixint.cpp

fixint_c_SOURCES = fixint_c.cpp

version_SOURCES = version.cpp

msgpack_tuple_SOURCES = msgpack_tuple.cpp

msgpack_c_SOURCES = msgpack_c.cpp

msgpack_basic_SOURCES = msgpack_basic.cpp

msgpack_container_SOURCES = msgpack_container.cpp

msgpack_stream_SOURCES = msgpack_stream.cpp

msgpack_vref_SOURCES = msgpack_vref.cpp

msgpack_cpp11_SOURCES = msgpack_cpp11.cpp

reference_SOURCES = reference.cpp

reference_cpp11_SOURCES = reference_cpp11.cpp

limit_SOURCES = limit.cpp

iterator_cpp11_SOURCES = iterator_cpp11.cpp

EXTRA_DIST = cases.mpac cases_compact.mpac
