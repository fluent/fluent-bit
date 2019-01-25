# This file provides 'libonigmo' target for both UNIX and Windows.
#
# To enable Onigmo, include this file and link the build target:
#
#    include(cmake/onigmo.cmake)
#    target_link_libraries(fluent-bit libonigmo)

add_library(libonigmo STATIC IMPORTED GLOBAL)

# Global Settings
set(ONIGMO_SRC "${CMAKE_CURRENT_SOURCE_DIR}/lib/onigmo")
set(ONIGMO_DEST "${CMAKE_CURRENT_BINARY_DIR}")

if(CMAKE_SIZEOF_VOID_P MATCHES 8)
  set(ONIGMO_ARCH "x64")
else()
  set(ONIGMO_ARCH "x86")
endif()

# Onigmo (UNIX)
# =============
ExternalProject_Add(onigmo
  BUILD_IN_SOURCE TRUE
  EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR ${ONIGMO_SRC}
  INSTALL_DIR ${ONIGMO_DEST}
  CONFIGURE_COMMAND ./configure ${AUTOCONF_HOST_OPT} --with-pic --disable-shared --enable-static --prefix=${ONIGMO_DEST}
  CFLAGS=-std=gnu99\ -Wall\ -pipe\ -g3\ -O3\ -funroll-loops
  BUILD_COMMAND $(MAKE)
  INSTALL_COMMAND $(MAKE) install)

# Onigmo (Windows)
# ================
ExternalProject_Add(onigmo-windows
  BUILD_IN_SOURCE TRUE
  EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR ${ONIGMO_SRC}
  CONFIGURE_COMMAND cmake -E copy win32/Makefile win32/config.h ${ONIGMO_SRC}
  BUILD_COMMAND nmake ARCH=${ONIGMO_ARCH}
  INSTALL_COMMAND cmake -E copy build_${ONIGMO_ARCH}/onigmo_s.lib ${ONIGMO_DEST}/lib/libonigmo.lib
          COMMAND cmake -E copy onigmo.h ${ONIGMO_DEST}/include/)

# Hook the buld definition to 'libonigmo' target
if(MSVC)
  add_dependencies(libonigmo onigmo-windows)
  set(ONIGMO_STATIC_LIB "${ONIGMO_DEST}/lib/libonigmo.lib")

  # We need this line in order to link libonigmo.lib statically.
  # Read onigmo/README for details.
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DONIG_EXTERN=extern")
else()
  add_dependencies(libonigmo onigmo)
  set(ONIGMO_STATIC_LIB "${ONIGMO_DEST}/lib/libonigmo.a")
endif()

set_target_properties(libonigmo PROPERTIES IMPORTED_LOCATION ${ONIGMO_STATIC_LIB})
include_directories("${ONIGMO_DEST}/include/")
