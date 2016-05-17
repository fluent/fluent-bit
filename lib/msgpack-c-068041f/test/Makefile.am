AM_CPPFLAGS   = -I$(top_srcdir)/include -pthread
AM_C_CPPFLAGS = -I$(top_srcdir)/include -pthread
AM_LDFLAGS = $(top_builddir)/src/libmsgpackc.la -lgtest_main -lgtest -lpthread

check_PROGRAMS = \
		array_ref \
		buffer \
		cases \
		convert \
		fixint \
		fixint_c \
		json \
		limit \
		msgpack_basic \
		msgpack_c \
		msgpack_container \
		msgpack_stream \
		msgpack_tuple \
		msgpack_vref \
		object \
		object_with_zone \
		pack_unpack \
		pack_unpack_c \
		raw \
		reference \
		streaming \
		streaming_c \
		user_class \
		version \
		zone

check_PROGRAMS += \
		boost_fusion \
		boost_variant \
		boost_optional \
		boost_string_ref

check_PROGRAMS += \
		iterator_cpp11 \
		msgpack_cpp11 \
		reference_cpp11 \
		reference_wrapper_cpp11 \
		shared_ptr_cpp11 \
		unique_ptr_cpp11

check_PROGRAMS += \
		multi_file

TESTS = $(check_PROGRAMS)

array_ref_SOURCES = array_ref.cpp
buffer_SOURCES = buffer.cpp
cases_SOURCES = cases.cpp
convert_SOURCES = convert.cpp
fixint_SOURCES = fixint.cpp
fixint_c_SOURCES = fixint_c.cpp
json_SOURCES = json.cpp
limit_SOURCES = limit.cpp
msgpack_basic_SOURCES = msgpack_basic.cpp
msgpack_c_SOURCES = msgpack_c.cpp
msgpack_container_SOURCES = msgpack_container.cpp
msgpack_stream_SOURCES = msgpack_stream.cpp
msgpack_tuple_SOURCES = msgpack_tuple.cpp
msgpack_vref_SOURCES = msgpack_vref.cpp
object_SOURCES = object.cpp
object_with_zone_SOURCES = object_with_zone.cpp
pack_unpack_SOURCES = pack_unpack.cpp
pack_unpack_c_SOURCES = pack_unpack_c.cpp
raw_SOURCES = raw.cpp
reference_SOURCES = reference.cpp
streaming_SOURCES = streaming.cpp
streaming_c_SOURCES = streaming_c.cpp
user_class_SOURCES = user_class.cpp
version_SOURCES = version.cpp
zone_SOURCES = zone.cpp

iterator_cpp11_SOURCES = iterator_cpp11.cpp
msgpack_cpp11_SOURCES = msgpack_cpp11.cpp
reference_cpp11_SOURCES = reference_cpp11.cpp
reference_wrapper_cpp11_SOURCES = reference_wrapper_cpp11.cpp
shared_ptr_cpp11_SOURCES = shared_ptr_cpp11.cpp
unique_ptr_cpp11_SOURCES = unique_ptr_cpp11.cpp

boost_fusion_SOURCES = boost_fusion.cpp
boost_variant_SOURCES = boost_variant.cpp
boost_optional_SOURCES = boost_optional.cpp
boost_string_ref_SOURCES = boost_string_ref.cpp

multi_file_SOURCES = multi_file1.cpp multi_file2.cpp

buffer_LDADD = -lz

EXTRA_DIST = cases.mpac cases_compact.mpac test_allocator.hpp
