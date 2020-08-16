# This file provides 'libjansson' target for both UNIX and Windows.
#
# To enable Jansson, include this file and link the build target:
#
#    include(cmake/jansson.cmake)
#    target_link_libraries(fluent-bit libjansson)

add_library(libjansson STATIC IMPORTED GLOBAL)
#add_library(libjansson-so SHARED IMPORTED GLOBAL)

# Global Settings
set(JANSSON_SRC "${PROJECT_SOURCE_DIR}/lib/jansson-2.13.1")
set(JANSSON_DEST "${CMAKE_CURRENT_BINARY_DIR}")

if(CMAKE_SIZEOF_VOID_P MATCHES 8)
  set(JANSSON_ARCH "x64")
else()
  set(JANSSON_ARCH "x86")
endif()

# Jansson (UNIX)
# =============
if(FLB_SMALL)
ExternalProject_Add(jansson
  BUILD_IN_SOURCE TRUE
  EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR ${JANSSON_SRC}
  INSTALL_DIR ${JANSSON_DEST}
  #CONFIGURE_COMMAND ./configure ${AUTOCONF_HOST_OPT} --with-pic --disable-shared --enable-static --prefix=${JANSSON_DEST}
  CONFIGURE_COMMAND ./configure ${AUTOCONF_HOST_OPT} --with-pic --enable-static --prefix=${JANSSON_DEST})
  #CFLAGS=-std=gnu99\ -Wall\ -pipe\ -Os\ -g0\ -s\ -fno-stack-protector\ -fomit-frame-pointer\ -DNDEBUG\ -U_FORTIFY_SOURCE
  #BUILD_COMMAND $(MAKE)
  #INSTALL_COMMAND $(MAKE) DESTDIR= install)
else()
ExternalProject_Add(jansson
  BUILD_IN_SOURCE TRUE
  EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR ${JANSSON_SRC}
  INSTALL_DIR ${JANSSON_DEST}
  #CONFIGURE_COMMAND ./configure ${AUTOCONF_HOST_OPT} --with-pic --disable-shared --enable-static --prefix=${JANSSON_DEST}
  CONFIGURE_COMMAND ./configure ${AUTOCONF_HOST_OPT} --with-pic --enable-static --prefix=${JANSSON_DEST})
  #CFLAGS=-std=gnu99\ -Wall\ -pipe\ -g3\ -O3\ -funroll-loops
  #BUILD_COMMAND $(MAKE)
  #INSTALL_COMMAND $(MAKE) DESTDIR= install)
endif()

# Jansson (Windows)
# ================
if(MSVC)
  ExternalProject_Add(jansson-windows
    BUILD_IN_SOURCE TRUE
    EXCLUDE_FROM_ALL TRUE
    SOURCE_DIR ${JANSSON_SRC}
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E copy win32/Makefile win32/config.h ${JANSSON_SRC}
    BUILD_COMMAND nmake ARCH=${JANSSON_ARCH}
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy build_${JANSSON_ARCH}/jansson_s.lib ${JANSSON_DEST}/lib/libjansson.lib
            COMMAND ${CMAKE_COMMAND} -E copy jansson.h ${JANSSON_DEST}/include/)
endif()

# Hook the buld definition to 'libjansson' target
if(MSVC)
  add_dependencies(libjansson jansson-windows)
  set(JANSSON_STATIC_LIB "${JANSSON_DEST}/lib/libjansson.lib")

  # We need this line in order to link libjansson.lib statically.
  # Read jansson/README for details.
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DJANSSON_EXTERN=extern")
else()
  add_dependencies(libjansson jansson)
  set(JANSSON_STATIC_LIB "${JANSSON_DEST}/lib/libjansson.a")
  #set(JANSSON_STATIC_LIBSO "${JANSSON_DEST}/lib/libjansson.so")
endif()

set_target_properties(libjansson PROPERTIES IMPORTED_LOCATION ${JANSSON_STATIC_LIB})
#set_target_properties(libjansson-so PROPERTIES IMPORTED_LOCATION ${JANSSON_STATIC_LIBSO})
include_directories("${JANSSON_DEST}/include/")


ExternalProject_Get_Property(jansson install_dir)
