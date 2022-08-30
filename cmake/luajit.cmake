# This file provides 'libluajit' target for both UNIX and Windows.
#
# To enable LuaJIT, include this file and link the build target:
#
#    include(cmake/luajit.cmake)
#    target_link_libraries(fluent-bit libluajit)

add_library(libluajit STATIC IMPORTED GLOBAL)

# Global Settings
set(LUAJIT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${FLB_PATH_LIB_LUAJIT})
set(LUAJIT_DEST ${CMAKE_CURRENT_BINARY_DIR})

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(CFLAGS "${CFLAGS} -isysroot ${CMAKE_OSX_SYSROOT} -fno-stack-check")

  if(DEFINED ENV{MACOSX_DEPLOYMENT_TARGET})
    # Refer MACOSX_DEPLOYMENT_TARGET if available.
    set(DEPLOYMENT_TARGET "MACOSX_DEPLOYMENT_TARGET=$ENV{MACOSX_DEPLOYMENT_TARGET}")
  else()
    # Calculate MACOSX_DEPLOYMENT_TARGET from sw_vers command result.
    execute_process(COMMAND sw_vers -productVersion OUTPUT_VARIABLE MACOSX_DEPLOYMENT_TARGET)
    string(REGEX REPLACE "\n$" "" MACOSX_DEPLOYMENT_TARGET ${MACOSX_DEPLOYMENT_TARGET})
    string(REPLACE "." ";" DEPLOYMENT_VERSION_LIST ${MACOSX_DEPLOYMENT_TARGET})
    list(GET DEPLOYMENT_VERSION_LIST 0 MACOSX_DEPLOYMENT_TARGET_MAJOR)
    list(GET DEPLOYMENT_VERSION_LIST 1 MACOSX_DEPLOYMENT_TARGET_MINOR)
    set(DEPLOYMENT_TARGET "MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET_MAJOR}.${MACOSX_DEPLOYMENT_TARGET_MINOR}")
  endif()
else()
  set(DEPLOYMENT_TARGET "")
endif()

# luajit (UNIX)
# =============

ExternalProject_Add(luajit
  BUILD_IN_SOURCE TRUE
  EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR ${LUAJIT_SRC}
  CONFIGURE_COMMAND ./configure
  BUILD_COMMAND $(MAKE) CC=${CMAKE_C_COMPILER} ${DEPLOYMENT_TARGET} CFLAGS=${CFLAGS} LDFLAGS="-L${CMAKE_OSX_SYSROOT}/usr/lib" BUILDMODE=static "XCFLAGS=-fPIC"
  INSTALL_COMMAND cp src/libluajit.a "${LUAJIT_DEST}/lib/libluajit.a")

# luajit (Windows)
# ================
if (MSVC)
  ExternalProject_Add(luajit-windows
    BUILD_IN_SOURCE TRUE
    EXCLUDE_FROM_ALL TRUE
    SOURCE_DIR ${LUAJIT_SRC}/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ./msvcbuild.bat static
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy lua51.lib "${LUAJIT_DEST}/lib/libluajit.lib")
endif()

# Hook the buld definition to 'libluajit' target
if(MSVC)
  add_dependencies(libluajit luajit-windows)
  set(LUAJIT_STATIC_LIB "${LUAJIT_DEST}/lib/libluajit.lib")
else()
  add_dependencies(libluajit luajit)
  set(LUAJIT_STATIC_LIB "${LUAJIT_DEST}/lib/libluajit.a")
endif()

set_target_properties(libluajit PROPERTIES IMPORTED_LOCATION "${LUAJIT_STATIC_LIB}")
include_directories("${LUAJIT_DEST}/include/")
