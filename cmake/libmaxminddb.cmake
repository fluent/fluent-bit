# This file provides 'libmaxminddb' target for both UNIX and Windows.
#
# To enalbe libmaxminddb, include this file:
#
#    include(cmake/libmaxminddb.cmake)

add_library(libmaxminddb STATIC IMPORTED GLOBAL)

# Global Settings
set(LIBMAXMINDDB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lib/libmaxminddb-1.3.2)
set(LIBMAXMINDDB_DEST ${CMAKE_CURRENT_BINARY_DIR})

# libmaxminddb (UNIX)
ExternalProject_Add(maxminddb
  BUILD_IN_SOURCE TRUE
  EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR ${LIBMAXMINDDB_SRC}
  CONFIGURE_COMMAND ./configure
  BUILD_COMMAND $(MAKE)
  INSTALL_COMMAND cp src/.libs/libmaxminddb.a "${LIBMAXMINDDB_DEST}/lib/libmaxminddb.a")

if(MSVC)
  add_dependencies(libmaxminddb maxminddb)
  set(LIBMAXMINDDB_STATIC_LIB "${LIBMAXMINDDB_DEST}/lib/libmaxminddb.lib")
else()
  add_dependencies(libmaxminddb maxminddb)
  set(LIBMAXMINDDB_STATIC_LIB "${LIBMAXMINDDB_DEST}/lib/libmaxminddb.a")
endif()

set_target_properties(libmaxminddb PROPERTIES IMPORTED_LOCATION "${LIBMAXMINDDB_STATIC_LIB}")
include_directories("${LIBMAXMINDDB_DEST}/include/")
