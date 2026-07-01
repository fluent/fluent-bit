cmake_minimum_required(VERSION 3.20)
project(onigmo C)

# Onigmo Version
set(ONIGMO_VERSION_MAJOR  6)
set(ONIGMO_VERSION_MINOR  2)
set(ONIGMO_VERSION_PATCH  0)
set(ONIGMO_VERSION_STR "${ONIGMO_VERSION_MAJOR}.${ONIGMO_VERSION_MINOR}.${ONIGMO_VERSION_PATCH}")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(ONIGMO_SYSTEM_WINDOWS On)
  add_definitions(-DONIGMO_SYSTEM_WINDOWS)
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(ONIGMO_SYSTEM_MACOS On)
  add_definitions(-DONIGMO_SYSTEM_MACOS)
endif()

# Define macro to identify Linux system
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(ONIGMO_SYSTEM_LINUX On)
  add_definitions(-DONIGMO_SYSTEM_LINUX)
endif()

# Update CFLAGS
if (MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)

  # Use custom CFLAGS for MSVC
  #
  #   /Zi ...... Generate pdb files.
  #   /MT ...... Static link C runtimes.
  #   /wd4711 .. C4711 (function selected for inline expansion)
  #   /wd4100 .. C4100 (unreferenced formal parameter)
  #   /wd5045 .. C5045 (Spectre mitigation)
  #
  set(CMAKE_C_FLAGS "/DWIN32 /D_WINDOWS /DNDEBUG /O2 /Zi /wd4100 /wd4711 /wd5045")
  set(CMAKE_EXE_LINKER_FLAGS "/Debug /INCREMENTAL:NO")
  set(CMAKE_BUILD_TYPE None)

  # We need this line in order to link libonigmo.lib statically.
  # Read onigmo/README for details.
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEXPORT -DHAVE_CONFIG_H")
  # Use add_compile_options() to set /MT since Visual Studio
  # Generator does not notice /MT in CMAKE_C_FLAGS.
  add_compile_options(/MT)
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FLB_FILENAME__=__FILE__")

include(GNUInstallDirs)
include(ExternalProject)
include(CheckTypeSize)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCSourceCompiles)

# Output paths
set(ONIGMO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

set(ONIGMO_OUT_NAME "onigmo")
set(ONIGMO_PACKAGE_STRING "${ONIGMO_OUT_NAME} ${ONIGMO_VERSION_STR}")

# For config.h
set(PACKAGE_NAME ${ONIGMO_OUT_NAME})
set(PACKAGE_TARNAME ${ONIGMO_OUT_NAME})
set(PACKAGE_VERSION ${ONIGMO_VERSION_STR})
set(PACKAGE_STRING ${ONIGMO_PACKAGE_STRING})
set(PACKAGE_BUGREPORT "")
set(PACKAGE_URL "")

# Build Options
option(USE_COMBINATION_EXPLOSION_CHECK "Enable combination explosion check"    No)
option(USE_CRNL_AS_LINE_TERMINATOR     "Enable CR+NL as line terminator"       No)
option(ONIGMO_SHARED_LIB               "Enable to build shared library"       Yes)
option(ONIGMO_CTESTS                   "Enable testing with ctest"            Yes)
option(ONIGMO_CTESTS_SAMPLE            "Enable testing with ctest on sample"  Yes)
option(ONIGMO_PYTHON_TESTS             "Enable testing with python tests"     Yes)
option(ONIGMO_MACOS_DEFAULTS           "Build with predefined macOS settings" Yes)

if(USE_COMBINATION_EXPLOSION_CHECK)
  add_definitions(-DUSE_COMBINATION_EXPLOSION_CHECK=1)
endif()

if(USE_CRNL_AS_LINE_TERMINATOR)
  add_definitions(-DUSE_CRNL_AS_LINE_TERMINATOR=1)
endif()

# Search python executables
if(ONIGMO_SYSTEM_WINDOWS)
  # On Windows, we need to prioritize for Python for Windows installer installed python.
  find_program(PYTHON_EXECUTABLE "python" "python3" "python2")
else()
  find_program(PYTHON_EXECUTABLE "python3" "python" "python2")
endif()
message(STATUS "Using python executable is: ${PYTHON_EXECUTABLE}")

# Tweak build targets for macOS
if(ONIGMO_SYSTEM_MACOS)
  include(cmake/macos-setup.cmake)
endif()

check_type_size(int SIZEOF_INT)
check_type_size(short SIZEOF_SHORT)
check_type_size(long SIZEOF_LONG)
check_type_size(void* SIZEOF_VOIDP)
check_type_size("long long" SIZEOF_LONG_LONG)
check_type_size("size_t" SIZEOF_SIZE_T)

# AC_HEADERS_STDC
check_c_source_compiles("
  #include <stdlib.h>
  #include <stdarg.h>
  #include <string.h>
  #include <float.h>
  int main() {
     return 0;
  }" STDC_HEADERS)
if(STDC_HEADERS)
  add_definitions(-DSTDC_HEADERS=1)
endif()

check_include_file(dlfcn.h HAVE_DLFCN_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(memory.h HAVE_MEMORY_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(stdlib.h HAVE_STDLIB_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)

check_c_source_compiles("
  #include <sys/types.h>
  #include <sys/time.h>
  #include <time.h>
  int main() {
     struct tm *tm;
     return 0;
  }" TIME_WITH_SYS_TIME)
if(TIME_WITH_SYS_TIME)
  add_definitions(-DTIME_WITH_SYS_TIME=1)
endif()

check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/times.h HAVE_SYS_TIMES_H)
check_include_file(unistd.h HAVE_UNISTD_H)

check_symbol_exists(alloca alloca.h HAVE_ALLOCA_H)
check_symbol_exists(memcmp string.h HAVE_MEMCMP)


# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(ONIGMO_INSTALL_BINDIR "bin")
  set(ONIGMO_INSTALL_LIBDIR "lib")
  set(ONIGMO_INSTALL_CONFDIR "conf")
  set(ONIGMO_INSTALL_DATADIR "share")
  set(ONIGMO_INSTALL_INCLUDEDIR "include")
else()
  set(ONIGMO_INSTALL_BINDIR ${CMAKE_INSTALL_FULL_BINDIR})
  set(ONIGMO_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
  set(ONIGMO_INSTALL_CONFDIR "${CMAKE_INSTALL_SYSCONFDIR}/${ONIGMO_OUT_NAME}/")
  set(ONIGMO_INSTALL_DATADIR "${CMAKE_INSTALL_PREFIX}/share")
  set(ONIGMO_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

configure_file(${ONIGMO_ROOT}/config.h.cmake ${ONIGMO_ROOT}/config.h)
configure_file(${ONIGMO_ROOT}/onigmo.pc.cmake ${ONIGMO_ROOT}/onigmo.pc @ONLY)

include_directories(${ONIGMO_ROOT}
  ${ONIGMO_ROOT}/enc/unicode/
  ${ONIGMO_ROOT}/enc/
  )

# Source
set(src
  ${src}
  regerror.c
  regparse.c
  regext.c
  regcomp.c
  regexec.c
  reggnu.c
  regenc.c
  regsyntax.c
  regtrav.c
  regversion.c
  st.c
  regposix.c
  regposerr.c
  enc/unicode.c
  enc/ascii.c
  enc/utf_8.c
  enc/utf_16be.c
  enc/utf_16le.c
  enc/utf_32be.c
  enc/utf_32le.c
  enc/euc_jp.c
  enc/shift_jis.c
  enc/windows_31j.c
  enc/jis/props.kwd
  enc/iso_8859.h
  enc/iso_8859_1.c
  enc/iso_8859_2.c
  enc/iso_8859_3.c
  enc/iso_8859_4.c
  enc/iso_8859_5.c
  enc/iso_8859_6.c
  enc/iso_8859_7.c
  enc/iso_8859_8.c
  enc/iso_8859_9.c
  enc/iso_8859_10.c
  enc/iso_8859_11.c
  enc/iso_8859_13.c
  enc/iso_8859_14.c
  enc/iso_8859_15.c
  enc/iso_8859_16.c
  enc/euc_tw.c
  enc/euc_kr.c
  enc/big5.c
  enc/gb18030.c
  enc/koi8_r.c
  enc/koi8_u.c
  enc/windows_1250.c
  enc/windows_1251.c
  enc/windows_1252.c
  enc/windows_1253.c
  enc/windows_1254.c
  enc/windows_1257.c
  )

# Static Library
add_library(onigmo-static STATIC ${src})

# Shared Library
if(ONIGMO_SHARED_LIB)
  add_library(onigmo-shared SHARED ${src})
  set_target_properties(onigmo-shared
    PROPERTIES OUTPUT_NAME onigmo
    WINDOWS_EXPORT_ALL_SYMBOLS ON)

  if (MSVC)
    set_target_properties(onigmo-shared
      PROPERTIES PDB_NAME onigmo.dll)
    target_link_options(onigmo-shared
      PUBLIC /pdb:$<TARGET_PDB_FILE:onigmo-shared>
      PRIVATE /LTCG)
  endif()

  # Library install routines
  install(TARGETS onigmo-shared
    LIBRARY DESTINATION ${ONIGMO_INSTALL_LIBDIR}
    COMPONENT library
    RUNTIME DESTINATION ${ONIGMO_INSTALL_BINDIR})
endif()

# Test Source

if(ONIGMO_CTESTS)
  enable_testing()
  if(ONIGMO_SYSTEM_WINDOWS)
    add_executable(testc win32/testc.c)
    target_compile_options(testc PUBLIC -DONIG_EXTERN=extern)
  else()
    add_executable(testc testc.c)
  endif()
  add_test(NAME testc COMMAND testc)
  target_link_libraries(testc onigmo-static)

  if(ONIGMO_SYSTEM_WINDOWS)
    add_executable(testp win32/testc.c)
  else()
    add_executable(testp testc.c)
  endif()
  target_compile_options(testp PUBLIC -DPOSIX_TEST)
  add_test(NAME testp COMMAND testp)
  target_link_libraries(testp onigmo-static)

  add_executable(testu testu.c)
  add_test(NAME testu COMMAND testu)
  target_link_libraries(testu onigmo-static)

  add_executable(test_enc_utf8 test_enc_utf8.c)
  add_test(NAME test_enc_utf8 COMMAND test_enc_utf8)
  target_link_libraries(test_enc_utf8 onigmo-static)
endif()

if(ONIGMO_CTESTS_SAMPLE)
  enable_testing()
  macro(SAMPLE_TEST_ADD name)
    add_executable(${name} sample/${name}.c)
    add_test(NAME ${name} COMMAND ${name})
    target_link_libraries(${name} onigmo-static)
  endmacro()
  SAMPLE_TEST_ADD(encode)
  SAMPLE_TEST_ADD(listcap)
  SAMPLE_TEST_ADD(names)
  SAMPLE_TEST_ADD(posix)
  SAMPLE_TEST_ADD(simple)
  SAMPLE_TEST_ADD(sql)
  SAMPLE_TEST_ADD(syntax)
  SAMPLE_TEST_ADD(scan)
  SAMPLE_TEST_ADD(crnl)
endif()

if(PYTHON_EXECUTABLE AND ONIGMO_PYTHON_TESTS AND ONIGMO_SHARED_LIB)
  enable_testing()
  set(TEST_WORK_DIR "")
  if (ONIGMO_SYSTEM_LINUX)
    set(TEST_LIBRARY_PATH_ENV "LD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/lib")
  elseif(ONIGMO_SYSTEM_MACOS)
    set(TEST_LIBRARY_PATH_ENV "DYLD_LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/lib")
  elseif(ONIGMO_SYSTEM_WINDOWS)
    set(TEST_WORK_DIR ${CMAKE_CURRENT_BINARY_DIR}/bin)
  endif()
  macro(PYTHON_TEST_ADD name encoding)
    add_test(NAME ${name} COMMAND ${PYTHON_EXECUTABLE} ${ONIGMO_ROOT}/testpy.py ${encoding}
      WORKING_DIRECTORY ${TEST_WORK_DIR})
    set_property(TEST ${name} PROPERTY ENVIRONMENT ${TEST_LIBRARY_PATH_ENV})
  endmacro()
  PYTHON_TEST_ADD(python-euc-jp  EUC-JP)
  PYTHON_TEST_ADD(python-sjis    SJIS)
  PYTHON_TEST_ADD(python-utf8    UTF-8)
  PYTHON_TEST_ADD(python-utf16le UTF-16LE)
  PYTHON_TEST_ADD(python-utf16be UTF-16BE)
  PYTHON_TEST_ADD(python-utf32le UTF-32LE)
  PYTHON_TEST_ADD(python-utf32be UTF-32BE)
endif()
