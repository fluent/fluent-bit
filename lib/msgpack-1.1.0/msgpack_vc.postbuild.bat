IF NOT EXIST include                  MKDIR include
IF NOT EXIST include\msgpack          MKDIR include\msgpack
IF NOT EXIST include\msgpack\type     MKDIR include\msgpack\type
IF NOT EXIST include\msgpack\type\tr1 MKDIR include\msgpack\type\tr1
copy src\msgpack\pack_define.h      include\msgpack\
copy src\msgpack\pack_template.h    include\msgpack\
copy src\msgpack\unpack_define.h    include\msgpack\
copy src\msgpack\unpack_template.h  include\msgpack\
copy src\msgpack\sysdep.h           include\msgpack\
copy src\msgpack.h                     include\
copy src\msgpack\sbuffer.h             include\msgpack\
copy src\msgpack\version.h             include\msgpack\
copy src\msgpack\vrefbuffer.h          include\msgpack\
copy src\msgpack\zbuffer.h             include\msgpack\
copy src\msgpack\fbuffer.h             include\msgpack\
copy src\msgpack\pack.h                include\msgpack\
copy src\msgpack\unpack.h              include\msgpack\
copy src\msgpack\object.h              include\msgpack\
copy src\msgpack\zone.h                include\msgpack\
copy src\msgpack.hpp                   include\
copy src\msgpack\sbuffer.hpp           include\msgpack\
copy src\msgpack\vrefbuffer.hpp        include\msgpack\
copy src\msgpack\zbuffer.hpp           include\msgpack\
copy src\msgpack\fbuffer.hpp           include\msgpack\
copy src\msgpack\pack.hpp              include\msgpack\
copy src\msgpack\unpack.hpp            include\msgpack\
copy src\msgpack\object.hpp            include\msgpack\
copy src\msgpack\zone.hpp              include\msgpack\
copy src\msgpack\type.hpp              include\msgpack\
copy src\msgpack\type\bool.hpp         include\msgpack\type\
copy src\msgpack\type\deque.hpp        include\msgpack\type\
copy src\msgpack\type\fixint.hpp       include\msgpack\type\
copy src\msgpack\type\float.hpp        include\msgpack\type\
copy src\msgpack\type\int.hpp          include\msgpack\type\
copy src\msgpack\type\list.hpp         include\msgpack\type\
copy src\msgpack\type\map.hpp          include\msgpack\type\
copy src\msgpack\type\nil.hpp          include\msgpack\type\
copy src\msgpack\type\pair.hpp         include\msgpack\type\
copy src\msgpack\type\raw.hpp          include\msgpack\type\
copy src\msgpack\type\set.hpp          include\msgpack\type\
copy src\msgpack\type\string.hpp       include\msgpack\type\
copy src\msgpack\type\vector.hpp       include\msgpack\type\
copy src\msgpack\type\tuple.hpp        include\msgpack\type\
copy src\msgpack\type\define.hpp       include\msgpack\type\
copy src\msgpack\type\tr1\unordered_map.hpp  include\msgpack\type\tr1\
copy src\msgpack\type\tr1\unordered_set.hpp  include\msgpack\type\tr1\

