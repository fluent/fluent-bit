lib_LTLIBRARIES = libmsgpack.la

AM_CPPFLAGS = -I../include

libmsgpack_la_SOURCES = \
		unpack.c \
		objectc.c \
		version.c \
		vrefbuffer.c \
		zone.c

if ENABLE_GCC_CXX_ATOMIC
	CXXFLAGS="$CXXFLAGS -DENABLE_GCC_CXX_ATOMIC"
endif


# -version-info CURRENT:REVISION:AGE
libmsgpack_la_LDFLAGS = -version-info 4:0:0 -no-undefined


# backward compatibility
lib_LTLIBRARIES += libmsgpackc.la

libmsgpackc_la_SOURCES = \
		unpack.c \
		objectc.c \
		version.c \
		vrefbuffer.c \
		zone.c

libmsgpackc_la_LDFLAGS = -version-info 2:0:0 -no-undefined


nobase_include_HEADERS = \
		../include/msgpack/pack_define.h \
		../include/msgpack/pack_template.h \
		../include/msgpack/unpack_define.h \
		../include/msgpack/unpack_template.h \
		../include/msgpack/util.h \
		../include/msgpack/sysdep.h \
		../include/msgpack/gcc_atomic.h \
		../include/msgpack.h \
		../include/msgpack/sbuffer.h \
		../include/msgpack/version.h \
		../include/msgpack/version_master.h \
		../include/msgpack/vrefbuffer.h \
		../include/msgpack/zbuffer.h \
		../include/msgpack/fbuffer.h \
		../include/msgpack/pack.h \
		../include/msgpack/unpack.h \
		../include/msgpack/object.h \
		../include/msgpack/zone.h

if ENABLE_CXX
nobase_include_HEADERS += \
		../include/msgpack.hpp \
		../include/msgpack/adaptor/adaptor_base.hpp \
		../include/msgpack/adaptor/bool.hpp \
		../include/msgpack/adaptor/char_ptr.hpp \
		../include/msgpack/adaptor/check_container_size.hpp \
		../include/msgpack/adaptor/cpp11/array.hpp \
		../include/msgpack/adaptor/cpp11/array_char.hpp \
		../include/msgpack/adaptor/cpp11/forward_list.hpp \
		../include/msgpack/adaptor/cpp11/tuple.hpp \
		../include/msgpack/adaptor/cpp11/unordered_map.hpp \
		../include/msgpack/adaptor/cpp11/unordered_set.hpp \
		../include/msgpack/adaptor/define.hpp \
		../include/msgpack/adaptor/deque.hpp \
		../include/msgpack/adaptor/detail/cpp03_define.hpp \
		../include/msgpack/adaptor/detail/cpp03_msgpack_tuple.hpp \
		../include/msgpack/adaptor/detail/cpp11_define.hpp \
		../include/msgpack/adaptor/detail/cpp11_msgpack_tuple.hpp \
		../include/msgpack/adaptor/fixint.hpp \
		../include/msgpack/adaptor/float.hpp \
		../include/msgpack/adaptor/int.hpp \
		../include/msgpack/adaptor/list.hpp \
		../include/msgpack/adaptor/map.hpp \
		../include/msgpack/adaptor/msgpack_tuple.hpp \
		../include/msgpack/adaptor/nil.hpp \
		../include/msgpack/adaptor/pair.hpp \
		../include/msgpack/adaptor/raw.hpp \
		../include/msgpack/adaptor/set.hpp \
		../include/msgpack/adaptor/string.hpp \
		../include/msgpack/adaptor/tr1/unordered_map.hpp \
		../include/msgpack/adaptor/tr1/unordered_set.hpp \
		../include/msgpack/adaptor/vector.hpp \
		../include/msgpack/adaptor/vector_bool.hpp \
		../include/msgpack/adaptor/vector_char.hpp \
		../include/msgpack/cpp_config.hpp \
		../include/msgpack/detail/cpp03_zone.hpp \
		../include/msgpack/detail/cpp11_zone.hpp \
		../include/msgpack/fbuffer.hpp \
		../include/msgpack/iterator.hpp \
		../include/msgpack/object.hpp \
		../include/msgpack/object_fwd.hpp \
		../include/msgpack/pack.hpp \
		../include/msgpack/sbuffer.hpp \
		../include/msgpack/type.hpp \
		../include/msgpack/unpack.hpp \
		../include/msgpack/version.hpp \
		../include/msgpack/versioning.hpp \
		../include/msgpack/vrefbuffer.hpp \
		../include/msgpack/zbuffer.hpp \
		../include/msgpack/zone.hpp
endif

EXTRA_DIST = \
		../erb/cpp03_zone.hpp.erb \
		../erb/cpp03_define.hpp.erb \
		../erb/cpp03_msgpack_tuple.hpp.erb


doxygen_c:
	cat ../Doxyfile > Doxyfile_c
	echo "FILE_PATTERNS      = *.h" >> Doxyfile_c
	echo "OUTPUT_DIRECTORY   = doc_c" >> Doxyfile_c
	echo "INPUT              = ../include" >> Doxyfile_c
	echo "EXTRACT_ALL        = YES" >> Doxyfile_c
	echo "PROJECT_NAME       = \"MessagePack for C\"" >> Doxyfile_c
	doxygen Doxyfile_c

doxygen_cpp:
	cat ../Doxyfile > Doxyfile_cpp
	echo "FILE_PATTERNS      = *.hpp" >> Doxyfile_cpp
	echo "OUTPUT_DIRECTORY   = doc_cpp" >> Doxyfile_cpp
	echo "INPUT              = ../include" >> Doxyfile_cpp
	echo "EXTRACT_ALL        = YES" >> Doxyfile_cpp
	echo "PROJECT_NAME       = \"MessagePack for C++\"" >> Doxyfile_cpp
	doxygen Doxyfile_cpp

doxygen: doxygen_c doxygen_cpp
