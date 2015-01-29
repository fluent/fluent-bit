
lib_LTLIBRARIES = libmsgpack.la

libmsgpack_la_SOURCES = \
		unpack.c \
		objectc.c \
		version.c \
		vrefbuffer.c \
		zone.c

if ENABLE_CXX
libmsgpack_la_SOURCES += \
		object.cpp
endif

if ENABLE_GCC_CXX_ATOMIC
libmsgpack_la_SOURCES += \
		gcc_atomic.cpp
endif


# -version-info CURRENT:REVISION:AGE
libmsgpack_la_LDFLAGS = -version-info 3:0:0 -no-undefined


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
		msgpack/pack_define.h \
		msgpack/pack_template.h \
		msgpack/unpack_define.h \
		msgpack/unpack_template.h \
		msgpack/sysdep.h \
		msgpack.h \
		msgpack/sbuffer.h \
		msgpack/version.h \
		msgpack/vrefbuffer.h \
		msgpack/zbuffer.h \
		msgpack/fbuffer.h \
		msgpack/pack.h \
		msgpack/unpack.h \
		msgpack/object.h \
		msgpack/zone.h

if ENABLE_CXX
nobase_include_HEADERS += \
		msgpack.hpp \
		msgpack/sbuffer.hpp \
		msgpack/vrefbuffer.hpp \
		msgpack/zbuffer.hpp \
		msgpack/fbuffer.hpp \
		msgpack/pack.hpp \
		msgpack/unpack.hpp \
		msgpack/object.hpp \
		msgpack/zone.hpp \
		msgpack/type.hpp \
		msgpack/type/bool.hpp \
		msgpack/type/deque.hpp \
		msgpack/type/float.hpp \
		msgpack/type/fixint.hpp \
		msgpack/type/int.hpp \
		msgpack/type/list.hpp \
		msgpack/type/map.hpp \
		msgpack/type/nil.hpp \
		msgpack/type/pair.hpp \
		msgpack/type/raw.hpp \
		msgpack/type/set.hpp \
		msgpack/type/string.hpp \
		msgpack/type/vector.hpp \
		msgpack/type/tuple.hpp \
		msgpack/type/define.hpp \
		msgpack/type/tr1/unordered_map.hpp \
		msgpack/type/tr1/unordered_set.hpp
endif

EXTRA_DIST = \
		msgpack/version.h.in \
		msgpack/zone.hpp.erb \
		msgpack/type/define.hpp.erb \
		msgpack/type/tuple.hpp.erb


doxygen_c:
	cat ../Doxyfile > Doxyfile_c
	echo "FILE_PATTERNS      = *.h" >> Doxyfile_c
	echo "OUTPUT_DIRECTORY   = doc_c" >> Doxyfile_c
	echo "PROJECT_NAME       = \"MessagePack for C\"" >> Doxyfile_c
	doxygen Doxyfile_c

doxygen_cpp:
	cat ../Doxyfile > Doxyfile_cpp
	echo "FILE_PATTERNS      = *.hpp" >> Doxyfile_cpp
	echo "OUTPUT_DIRECTORY   = doc_cpp" >> Doxyfile_cpp
	echo "PROJECT_NAME       = \"MessagePack for C++\"" >> Doxyfile_cpp
	doxygen Doxyfile_cpp

doxygen: doxygen_c doxygen_cpp

