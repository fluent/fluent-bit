2014-07-02 version 0.5.9:

  * Support std::tr1 unordered containers by default (#51, #63, #68, #69)
  * Remove some warnings (#56)
  * Fix segmentation fault after malloc failures (#58, #59)
  * Fix alloc/dealloc mismatch (#52, #61)
  * Fix sample codes (#60, #64)
  * Support implicit conversion from integer to float/double (#54)
  * Improve documents (#45, #75, #82, #83)
  * Support CMake (#20, #87)
  * Remove Ruby dependencies in bootstrap (#86, #87)
  * Add FILE* buffer (#40)
  * Other bug fixes and refactoring: #39, #73, #77, #79, #80, #81, #84, #90

2013-12-23 version 0.5.8:

  * Move to the new github repository msgpack/msgpack-c
  * Support the new deserialization specification
  * fixes the problem of unpack helpers for array and map with 32bit compilers (#37, #38)
  * Other bug fixes and refactoring: #46, #41, #36, #35, #33, #32, #30, #29, #28, #27, #26, #25, #8, #3
  * Update of documents: #23, #18, #17

2011-08-08 version 0.5.7:

  * fixes compile error problem with llvm-gcc and Mac OS X Lion

2011-04-24 version 0.5.6:

  * #42 fixes double-free problem on msgpack_unpacker_release_zone

2011-02-24 version 0.5.5:

  * eliminates dependency of winsock2.h header
  * fixes msgpack_vc.postbuild.bat file
  * fixes some implicit cast warnings

2010-08-29 version 0.5.4:

  * includes msgpack_vc2008.vcproj file in source package
  * fixes type::fix_int types

2010-08-27 version 0.5.3:

  * adds type::fix_{u,}int{8,16,32,64} types
  * adds msgpack_pack_fix_{u,}int{8,16,32,64} functions
  * adds packer<Stream>::pack_fix_{u,}int{8,16,32,64} functions
  * fixes include paths

2010-07-14 version 0.5.2:

  * type::raw::str(), operator==, operator!=, operator< and operator> are now const
  * generates version.h using AC_OUTPUT macro in ./configure

2010-07-06 version 0.5.1:

  * Add msgpack_vrefbuffer_new and msgpack_vrefbuffer_free
  * Add msgpack_sbuffer_new and msgpack_sbuffer_free
  * Add msgpack_unpacker_next and msgpack_unpack_next
  * msgpack::unpack returns void
  * Add MSGPACK_VERSION{,_MAJOR,_MINOR} macros to check header version
  * Add msgpack_version{,_major,_minor} functions to check library version
  * ./configure supports --disable-cxx option not to build C++ API

2010-04-29 version 0.5.0:

  * msgpack_object_type is changed. MSGPACK_OBJECT_NIL is now 0x00.
  * New safe streaming deserializer API.
  * Add object::object(const T&) and object::operator=(const T&)
  * Add operator==(object, const T&)
  * MSGPACK_DEFINE macro defines msgpack_object(object* obj, zone* z)
  * C++ programs doesn't need to link "msgpackc" library.

