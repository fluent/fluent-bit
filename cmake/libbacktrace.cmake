# libbacktrace.cmake
# Build configuration for libbacktrace library
# Supports: Windows (MSVC), Linux, macOS, and other Unix-like systems

set(LIBBACKTRACE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${FLB_PATH_LIB_LIBBACKTRACE})
set(LIBBACKTRACE_FOUND FALSE)

# Try to find system libbacktrace first (if enabled)
if(FLB_PREFER_SYSTEM_LIB_BACKTRACE)
  find_path(LIBBACKTRACE_INCLUDE_DIRS NAMES backtrace.h)
  find_library(LIBBACKTRACE_LIBRARIES NAMES backtrace)

  if(LIBBACKTRACE_INCLUDE_DIRS AND LIBBACKTRACE_LIBRARIES)
    message(STATUS "libbacktrace: using system library (${LIBBACKTRACE_LIBRARIES})")
    include_directories(${LIBBACKTRACE_INCLUDE_DIRS})
    link_directories(${LIBBACKTRACE_LIBRARY_DIRS})
    set(LIBBACKTRACE_FOUND TRUE)
    FLB_DEFINITION(FLB_HAVE_LIBBACKTRACE)
  endif()
endif()

# Build libbacktrace if system library not found
if(NOT LIBBACKTRACE_FOUND)
  if(MSVC)
    # ============================================================
    # Windows/MSVC: Build directly with CMake
    # ============================================================
    # autoconf/configure doesn't work with MSVC, so we build directly
    message(STATUS "libbacktrace: building directly with CMake for Windows/MSVC")

    # Core source files (always needed)
    set(LIBBACKTRACE_CORE_SOURCES
      ${LIBBACKTRACE_SOURCE_DIR}/atomic.c
      ${LIBBACKTRACE_SOURCE_DIR}/dwarf.c
      ${LIBBACKTRACE_SOURCE_DIR}/fileline.c
      ${LIBBACKTRACE_SOURCE_DIR}/posix.c
      ${LIBBACKTRACE_SOURCE_DIR}/print.c
      ${LIBBACKTRACE_SOURCE_DIR}/sort.c
      ${LIBBACKTRACE_SOURCE_DIR}/state.c
    )

    # Platform-specific source files for Windows
    # - Backtrace implementation: backtrace.c (uses C++ unwind API)
    # - Format: pecoff.c (for PE/COFF format on Windows)
    # - View: read.c (file reading, not mmap for Windows)
    # - Alloc: alloc.c (standard alloc, not mmap for Windows)
    set(LIBBACKTRACE_PLATFORM_SOURCES
      ${LIBBACKTRACE_SOURCE_DIR}/backtrace.c
      ${LIBBACKTRACE_SOURCE_DIR}/pecoff.c
      ${LIBBACKTRACE_SOURCE_DIR}/read.c
      ${LIBBACKTRACE_SOURCE_DIR}/alloc.c
    )

    set(LIBBACKTRACE_SOURCES
      ${LIBBACKTRACE_CORE_SOURCES}
      ${LIBBACKTRACE_PLATFORM_SOURCES}
    )

    # Build libbacktrace as a static library
    add_library(libbacktrace STATIC ${LIBBACKTRACE_SOURCES})
    target_include_directories(libbacktrace PUBLIC
      ${LIBBACKTRACE_SOURCE_DIR}
    )

    # Windows-specific compile definitions
    # These match what configure would set for Windows
    target_compile_definitions(libbacktrace PRIVATE
      HAVE_WINDOWS_H=1
      HAVE_DECL__PGMPTR=1
      HAVE_STDLIB_H=1
      HAVE_STRING_H=1
      HAVE_STDINT_H=1
      STDC_HEADERS=1
      BACKTRACE_ELF_SIZE=0
      BACKTRACE_XCOFF_SIZE=0
      PACKAGE_NAME="libbacktrace"
      PACKAGE_VERSION="1.0"
    )

    # Set output name to match expected name
    set_target_properties(libbacktrace PROPERTIES
      OUTPUT_NAME "backtrace"
    )

    set(LIBBACKTRACE_LIBRARIES "libbacktrace")
    set(LIBBACKTRACE_FOUND TRUE)
    FLB_DEFINITION(FLB_HAVE_LIBBACKTRACE)

  else()
    # ============================================================
    # Unix-like systems (Linux, macOS, BSD, etc.): Use autoconf
    # ============================================================
    message(STATUS "libbacktrace: building with autoconf/configure")

    # Handle macOS SDK path for C compiler
    if(CMAKE_OSX_SYSROOT)
      # From macOS Mojave, /usr/include does not store C SDK headers.
      # For libbacktrace building on macOS, we have to tell C headers where they are located.
      set(DEPS_C_COMPILER "${CMAKE_C_COMPILER} -isysroot ${CMAKE_OSX_SYSROOT}")
    else()
      set(DEPS_C_COMPILER "${CMAKE_C_COMPILER}")
    endif()

    # Set up build paths
    set(FLB_LIBBACKTRACE_PATH "${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/lib/libbacktrace.a")

    # Build using ExternalProject with autoconf/configure
    ExternalProject_Add(backtrace
      SOURCE_DIR ${LIBBACKTRACE_SOURCE_DIR}
      CONFIGURE_COMMAND ${LIBBACKTRACE_SOURCE_DIR}/configure
                        ${AUTOCONF_HOST_OPT}
                        --prefix=<INSTALL_DIR>
                        --enable-shared=no
                        --enable-static=yes
      BUILD_COMMAND ${EXTERNAL_BUILD_TOOL}
      BUILD_BYPRODUCTS ${FLB_LIBBACKTRACE_PATH}
      INSTALL_COMMAND ${EXTERNAL_BUILD_TOOL} DESTDIR= install
    )

    # Create imported target for the built library
    add_library(libbacktrace STATIC IMPORTED GLOBAL)
    set_target_properties(libbacktrace PROPERTIES
      IMPORTED_LOCATION ${FLB_LIBBACKTRACE_PATH}
    )
    add_dependencies(libbacktrace backtrace)

    # Include directories
    include_directories("${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/include/")

    set(LIBBACKTRACE_LIBRARIES "libbacktrace")
    set(LIBBACKTRACE_FOUND TRUE)
    FLB_DEFINITION(FLB_HAVE_LIBBACKTRACE)
  endif()
endif()

# Summary
if(LIBBACKTRACE_FOUND)
  message(STATUS "libbacktrace: enabled (${LIBBACKTRACE_LIBRARIES})")
else()
  message(WARNING "libbacktrace: not available - stacktrace support will be disabled")
endif()
