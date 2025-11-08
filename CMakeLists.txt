cmake_minimum_required(VERSION 3.12)
project(fluent-bit C)

# CMP0069 ensures that LTO is enabled for all compilers
cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

# Fluent Bit Version
set(FLB_VERSION_MAJOR  4)
set(FLB_VERSION_MINOR  2)
set(FLB_VERSION_PATCH  0)
set(FLB_VERSION_STR "${FLB_VERSION_MAJOR}.${FLB_VERSION_MINOR}.${FLB_VERSION_PATCH}")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(FLB_SYSTEM_WINDOWS On)
  add_definitions(-DFLB_SYSTEM_WINDOWS)
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(FLB_SYSTEM_MACOS On)
  add_definitions(-DFLB_SYSTEM_MACOS)
endif()

# Define macro to identify Linux system
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(FLB_SYSTEM_LINUX On)
  add_definitions(-DFLB_SYSTEM_LINUX)
  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
    set(FLB_LINUX_ON_AARCH64 On)
    add_definitions(-DFLB_LINUX_ON_AARCH64)
  endif()

  find_program(CAT_EXEC cat)
  if (CAT_EXEC)
    set(RELEASE_FILE "/etc/system-release")
    if (EXISTS ${RELEASE_FILE})
      execute_process(COMMAND ${CAT_EXEC} ${RELEASE_FILE}
        OUTPUT_VARIABLE CAT_SYSTEM_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      message(STATUS "##### cat /etc/system-release -- OK")

      if (CAT_SYSTEM_RELEASE STREQUAL "Amazon Linux release 2 (Karoo)")
        set(FLB_AMAZON_LINUX2 On)
        add_definitions(-DFLB_AMAZON_LINUX2)
      endif()
    endif()
  endif()
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
  # Restore /OPT:REF after setting /Debug, enable /OPT:ICF for 64-bit
  # builds per Microsoft recommended best practices.
  set(CMAKE_C_FLAGS "/DWIN32 /D_WINDOWS /DNDEBUG /O2 /Zi /wd4100 /wd4711 /wd5045")
  set(CMAKE_EXE_LINKER_FLAGS "/DEBUG /OPT:REF /INCREMENTAL:NO")
  set(CMAKE_SHARED_LINKER_FLAGS "/DEBUG /OPT:REF /INCREMENTAL:NO")
  set(CMAKE_BUILD_TYPE None)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /OPT:ICF")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /OPT:ICF")
  endif()

  # Use add_compile_options() to set /MT since Visual Studio
  # Generator does not notice /MT in CMAKE_C_FLAGS.
  add_compile_options(/MT)
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  # The following flags are to enhance security, but it may impact performance,
  # we disable them by default.
  if (FLB_WASM_STACK_PROTECT)
    if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
      set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftrapv -D_FORTIFY_SOURCE=2")
    endif ()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong --param ssp-buffer-size=4")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack,-z,relro,-z,now")
  endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FLB_FILENAME__=__FILE__")

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "armv7l")
  set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -latomic")
  set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -latomic")
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  set(FLB_SYSTEM_FREEBSD On)
  add_definitions(-DFLB_SYSTEM_FREEBSD)
  set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -lutil")
  set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -lutil")
endif()

# *BSD is not supported platform for wasm-micro-runtime except for FreeBSD.
# Now, we should be disabled for these platforms.
if(NOT FLB_SYSTEM_FREEBSD AND ${CMAKE_SYSTEM_NAME} MATCHES "BSD")
  message(STATUS "This platform is not supported for WASM feature so disabled.")
  set(FLB_WASM OFF)
elseif(FLB_SYSTEM_FREEBSD)
  message(STATUS "Some of FreeBSD environment do not work with hardware boundary check so disabled.")
  set(WAMR_DISABLE_STACK_HW_BOUND_CHECK 1)
endif()

INCLUDE(TestBigEndian)
include(GNUInstallDirs)
include(ExternalProject)
include(cmake/FindJournald.cmake)
include(cmake/FindMonkey.cmake)
include(cmake/macros.cmake)
include(cmake/platform_feature_checks.cmake)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

# Check for CXX support
include(CheckLanguage)
check_language(CXX)

# Enable CXX features if CXX is available
if (NOT DEFINED FLB_USE_SIMDUTF)
  if(CMAKE_CXX_COMPILER)
    message(STATUS "CXX compiler found, enable simdutf.")
    set(FLB_USE_SIMDUTF Yes)
  else()
    message(STATUS "CXX compiler not found, disable simdutf.")
    set(FLB_USE_SIMDUTF No)
  endif()
endif()

# Output paths
set(FLB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

# Build Options
option(FLB_ALL                 "Enable all features"                         No)
option(FLB_DEBUG               "Build with debug mode (-g)"                 Yes)
option(FLB_RELEASE             "Build with release mode (-O2 -g -DNDEBUG)"   No)
set(FLB_IPO "ReleaseOnly" CACHE STRING "Build with interprocedural optimization")
set_property(CACHE FLB_IPO PROPERTY STRINGS "On;Off;ReleaseOnly")
option(FLB_SMALL               "Optimise for small size"       No)
set(FLB_SECURITY "ReleaseOnly" CACHE STRING "Build with security optimizations")
set_property(CACHE FLB_SECURITY PROPERTY STRINGS "On;Off;ReleaseOnly")
option(FLB_COVERAGE            "Build with code-coverage"      No)
option(FLB_COMPILER_STRICT_POINTER_TYPES "Build with -Werror=incompatible-pointer-types" No)
option(FLB_JEMALLOC            "Build with Jemalloc support"   No)
option(FLB_REGEX               "Build with Regex support"     Yes)
option(FLB_UTF8_ENCODER        "Build with UTF8 encoding support" Yes)
option(FLB_UNICODE_ENCODER     "Build with Unicode (UTF-16LE, UTF-16BE) encoding support" ${FLB_USE_SIMDUTF})
option(FLB_PARSER              "Build with Parser support"    Yes)
option(FLB_TLS                 "Build with SSL/TLS support"   Yes)
option(FLB_BINARY              "Build executable binary"      Yes)
option(FLB_EXAMPLES            "Build examples"               Yes)
option(FLB_SHARED_LIB          "Build shared library"         Yes)
option(FLB_VALGRIND            "Enable Valgrind support"       No)
option(FLB_TRACE               "Enable trace mode"             No)
option(FLB_CHUNK_TRACE         "Enable chunk traces"          Yes)
option(FLB_TESTS_RUNTIME       "Enable runtime tests"          No)
option(FLB_TESTS_INTERNAL      "Enable internal tests"         No)
option(FLB_TESTS_INTERNAL_FUZZ "Enable internal fuzz tests"    No)
option(FLB_TESTS_OSSFUZZ       "Enable OSS-Fuzz build"         No)
option(FLB_MTRACE              "Enable mtrace support"         No)
option(FLB_POSIX_TLS           "Force POSIX thread storage"    No)
option(FLB_INOTIFY             "Enable inotify support"       Yes)
option(FLB_SQLDB               "Enable SQL embedded DB"       Yes)
option(FLB_HTTP_SERVER         "Enable HTTP Server"           Yes)
option(FLB_BACKTRACE           "Enable stacktrace support"    Yes)
option(FLB_LUAJIT              "Enable Lua Scripting support" Yes)
option(FLB_RECORD_ACCESSOR     "Enable record accessor"       Yes)
option(FLB_SIGNV4              "Enable AWS Signv4 support"    Yes)
option(FLB_AWS                 "Enable AWS support"           Yes)
option(FLB_STATIC_CONF         "Build binary using static configuration")
option(FLB_STREAM_PROCESSOR    "Enable Stream Processor"                    Yes)
option(FLB_SIMD                "Enable SIMD support"                         No)
option(FLB_CORO_STACK_SIZE     "Set coroutine stack size")
option(FLB_AVRO_ENCODER        "Build with Avro encoding support"            No)
option(FLB_AWS_ERROR_REPORTER  "Build with aws error reporting support"      No)
option(FLB_ARROW               "Build with Apache Arrow support"             No)
option(FLB_WINDOWS_DEFAULTS    "Build with predefined Windows settings"     Yes)
option(FLB_WASM                "Build with WASM runtime support"            Yes)
option(FLB_WAMRC               "Build with WASM AOT compiler executable"    No)
option(FLB_WASM_STACK_PROTECT  "Build with WASM runtime with strong stack protector flags" No)
option(FLB_ENFORCE_ALIGNMENT   "Enable limited platform specific aligned memory access" No)
option(FLB_KAFKA               "Enable Kafka support"         Yes)
option(FLB_ZIG                 "Enable zig integration"       Yes)

# Native Metrics Support (cmetrics)
option(FLB_METRICS             "Enable metrics support"       Yes)

# Native Profiules Support (cprofiles)
option(FLB_PROFILES            "Enable profiles support"      Yes)

# Proxy Plugins
option(FLB_PROXY_GO            "Enable Go plugins support"    Yes)

# Built-in Custom Plugins
option(FLB_CUSTOM_CALYPTIA     "Enable Calyptia Support"      Yes)

# Config formats
option(FLB_CONFIG_YAML         "Enable YAML config format"    Yes)

option(FLB_BENCHMARKS          "Enable benchmarks"             No)


# List of plugins available and defaults for each option
include(cmake/plugins_options.cmake)


# Event loop backend (advanced users only)
# ----------------------------------------
# The following options are for advanced users only, they are used to enable
# specific event loop backends. By default, the build system will try to
# detect the best backend for the current Operating System. If you want to
# force a specific backend, you can use ONE of the following options.
#
# Note that these options will enable the proper option for Monkey library.
option(FLB_EVENT_LOOP_EPOLL     "Enable epoll(2) event loop backend"  No)
option(FLB_EVENT_LOOP_POLL      "Enable poll(2) event loop backend"   No)
option(FLB_EVENT_LOOP_KQUEUE    "Enable kqueue(2) event loop backend" No)
option(FLB_EVENT_LOOP_SELECT    "Enable select(2) event loop backend" No)
option(FLB_EVENT_LOOP_LIBEVENT  "Enable libevent event loop backend"  No)

# SIMD support
if(FLB_SIMD)
  FLB_DEFINITION(FLB_HAVE_SIMD)
endif()

if(DEFINED FLB_NIGHTLY_BUILD AND NOT "${FLB_NIGHTLY_BUILD}" STREQUAL "")
  FLB_DEFINITION_VAL(FLB_NIGHTLY_BUILD ${FLB_NIGHTLY_BUILD})
endif()

if(FLB_IN_STORAGE_BACKLOG)
  FLB_DEFINITION(FLB_HAVE_IN_STORAGE_BACKLOG)
endif()

# Debug callbacks
option(FLB_HTTP_CLIENT_DEBUG  "Enable HTTP Client debug callbacks"   No)

# Run ldconfig on package post-install
option(FLB_RUN_LDCONFIG "Enable execution of ldconfig after installation" No)

# Prefer system libraries if available
option(FLB_PREFER_SYSTEM_LIBS             "Prefer system libraries"                   No)
option(FLB_PREFER_SYSTEM_LIB_BACKTRACE    "Prefer the libbacktrace system library"    ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_CARES        "Prefer the libcares system library"        ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_JEMALLOC     "Prefer the libjemalloc system library"     ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_KAFKA        "Prefer the libkafka system library"        ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_LUAJIT       "Prefer the libluajit system library"       ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_MSGPACK      "Prefer the libmsgpack system library"      ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_NGHTTP2      "Prefer the libnghttp2 system library"      ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_SQLITE       "Prefer the libsqlite3 system library"      ${FLB_PREFER_SYSTEM_LIBS})
option(FLB_PREFER_SYSTEM_LIB_ZSTD         "Prefer the libzstd system library"         ${FLB_PREFER_SYSTEM_LIBS})

# Enable all features
if(FLB_ALL)
  # Global
  set(FLB_DEBUG           1)
  set(FLB_TLS             1)

  # Input plugins
  set(FLB_IN_CPU          1)
  set(FLB_IN_MEM          1)
  set(FLB_IN_KMSG         1)
  set(FLB_IN_MQTT         1)
  set(FLB_IN_SERIAL       1)
  set(FLB_IN_STDIN        1)
  set(FLB_IN_HEAD         1)
  set(FLB_IN_PROC         1)
  set(FLB_IN_DISK         1)
  set(FLB_IN_DUMMY        1)
  set(FLB_IN_DUMMY_THREAD 1)
  set(FLB_IN_NETIF        1)
  set(FLB_IN_NGINX_STATUS 1)
  set(FLB_IN_EXEC         1)
  set(FLB_IN_UNIX_SOCKET  1)

  # Output plugins
  set(FLB_OUT_ES          1)
  set(FLB_OUT_FORWARD     1)
  set(FLB_OUT_GELF        1)
  set(FLB_OUT_HTTP        1)
  set(FLB_OUT_NATS        1)
  set(FLB_OUT_NULL        1)
  set(FLB_OUT_PLOT        1)
  set(FLB_OUT_FILE        1)
  set(FLB_OUT_RETRY       1)
  set(FLB_OUT_TD          1)
  set(FLB_OUT_STDOUT      1)
  set(FLB_OUT_S3          1)
  set(FLB_OUT_SYSLOG      1)
  set(FLB_OUT_LIB         1)
  set(FLB_OUT_FLOWCOUNTER 1)
  set(FLB_OUT_WEBSOCKET   1)
endif()

if(FLB_DEV)
  FLB_DEFINITION(FLB_HAVE_DEV)

  set(FLB_DEBUG             On)
  set(FLB_TRACE             On)
  set(FLB_OUT_ZIG_DEMO      On)
  set(FLB_CHUNK_TRACE       On)
  set(FLB_METRICS           On)
  set(FLB_PROFILES          On)
  set(FLB_IN_EVENT_TEST     On)
  set(FLB_HTTP_SERVER       On)
  set(FLB_HTTP_CLIENT_DEBUG On)
  set(FLB_TESTS_INTERNAL    On)
  set(FLB_BENCHMARKS        On)
endif()

if(FLB_TRACE)
  add_definitions(-DFLB_TRACE=1)
endif()

if(FLB_CHUNK_TRACE)
  FLB_DEFINITION(FLB_HAVE_CHUNK_TRACE)
endif()

# SSL/TLS: add encryption support
if(FLB_OUT_TD)
  set(FLB_TLS ON)
endif()

if(FLB_HTTP_CLIENT_DEBUG)
  FLB_DEFINITION(FLB_HAVE_HTTP_CLIENT_DEBUG)
endif()

if (FLB_TESTS_OSSFUZZ)
  FLB_DEFINITION(FLB_HAVE_TESTS_OSSFUZZ)
endif()

if (FLB_WASM)
  # For Linking libedit adjustments on LLVM 15.
  include(cmake/FindLibEdit.cmake)
endif()

# Set Fluent Bit dependency libraries path
include(cmake/libraries.cmake)

# Export headers provided by libraries/dependencies
include(cmake/headers.cmake)

# Tweak build targets for Windows
if(FLB_SYSTEM_WINDOWS)
  include(cmake/windows-setup.cmake)
endif()

# Tweak build targets for macOS
if (FLB_SYSTEM_MACOS)
  # build tweaks
  include(cmake/macos-setup.cmake)
endif()

# Build for SystemZ - s390x arch
if (FLB_SYSTEM_LINUX)
  include(cmake/s390x.cmake)
endif ()

# Build for Linux - riscv64 arch
if (FLB_SYSTEM_LINUX)
  include(cmake/riscv64.cmake)
endif ()

# Enable signed char support on Linux AARCH64 if specified
if (FLB_LINUX_ON_AARCH64)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsigned-char")
  message(STATUS "Enabling signed char")
endif()

# Extract Git commit information for debug output.
# Note that this is only set when cmake is run, the intent here is to use in CI for verification of releases so is acceptable.
# For a better solution see https://jonathanhamberg.com/post/cmake-embedding-git-hash/ but this is simple and easy.
find_package(Git)
# If we do not have Git or this is not a Git repo or another error this just is ignored and we have no output at runtime.
execute_process(COMMAND
  "${GIT_EXECUTABLE}" -c log.showSignature=false log -1 --format=%H
  WORKING_DIRECTORY "${FLB_ROOT}"
  OUTPUT_VARIABLE FLB_GIT_HASH
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "Git hash: ${FLB_GIT_HASH}")

# Optional features like Stream Processor and Record Accessor needs Flex
# and Bison to generate it parsers.
find_package(FLEX 2)
find_package(BISON 3)

if(FLEX_FOUND AND BISON_FOUND)
  set(FLB_FLEX_BISON  1)
endif()

find_program(ZIG_PATH zig)

# Enable zig only when the appropriate toolchain is available
if (FLB_ZIG)
  set(FLB_ZIG Off)

  if (ZIG_PATH)
    execute_process(
        COMMAND ${ZIG_PATH} version
        OUTPUT_VARIABLE COMMAND_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # This is not great, improvements would be appreciated
    if (COMMAND_OUTPUT STREQUAL "0.14.0")
      FLB_DEFINITION(FLB_HAVE_ZIG)
      set(FLB_ZIG On)
    endif()
  endif()
endif()

if(FLB_SMALL)
  if(CMAKE_COMPILER_IS_GNUCC)
    set(strip_flag  " -s ")
  else()
    set(strip_flag  "")
  endif()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -g0 ${strip_flag} -fno-stack-protector -fomit-frame-pointer -DNDEBUG -U_FORTIFY_SOURCE")
endif()

# simdutf
if(FLB_UNICODE_ENCODER)
  if (NOT FLB_USE_SIMDUTF)
    message(STATUS "FLB_USE_SIMDUTF is disabled. Disabling FLB_UNICODE_ENCODER support.")
    set(FLB_UNICODE_ENCODER OFF)
  endif()
endif()

if(FLB_COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")
  if (FLB_UNICODE_ENCODER)
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")
  endif()
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if(FLB_COMPILER_STRICT_POINTER_TYPES)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-Werror=incompatible-pointer-types)
  endif()
  # Currently, AppleClang has more struct rules when using -Werror=incompatible-pointer-types.
  # We still permit to discarding const qualifiers warnings.
  if(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
    add_compile_options(-Wno-incompatible-pointer-types-discards-qualifiers)
  endif()
endif()

# Enable Debug symbols if specified
if(MSVC)
  set(CMAKE_BUILD_TYPE None)  # Avoid flag conflicts (See CMakeList.txt:L18)
elseif(FLB_RELEASE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
elseif(FLB_DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if(FLB_IPO STREQUAL "On" OR (FLB_IPO STREQUAL "ReleaseOnly" AND FLB_RELEASE))
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported)
  # IPO in GCC versions smaller v8 is broken
  if(ipo_supported AND NOT (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8))
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(Warning "IPO is not supported on this platform")
  endif()
endif()

# Memory alignment enforcement
if(FLB_ENFORCE_ALIGNMENT)
  FLB_DEFINITION(FLB_ENFORCE_ALIGNMENT)
endif()

# Harden release binary against security vulnerabilities
if(FLB_SECURITY STREQUAL "On" OR (FLB_SECURITY STREQUAL "ReleaseOnly" AND FLB_RELEASE))
  if (NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,relro,-z,now")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack")
    if(NOT FLB_SMALL)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector")
      # Fortify requires optimization
      if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=1")
      endif()
    endif()
  endif()
endif()

if(FLB_PARSER)
  FLB_DEFINITION(FLB_HAVE_PARSER)
  message(STATUS "Enabling FLB_REGEX since FLB_PARSER requires")
  set(FLB_REGEX On)
endif()

# Is sanitize_address defined ?
if(SANITIZE_ADDRESS)
  FLB_DEFINITION(FLB_HAVE_SANITIZE_ADDRESS)
endif()

# Record Accessor
if(FLB_RECORD_ACCESSOR)
  if(NOT FLB_FLEX_BISON)
    message(FATAL_ERROR
      "Record Accessor feature requires Flex and Bison in your system.\n"
      "This is a build time dependency, you can either install the "
      "dependencies or disable the feature setting the CMake option "
      "-DFLB_RECORD_ACCESSOR=Off ."
      )
  endif()
  FLB_DEFINITION(FLB_HAVE_RECORD_ACCESSOR)
endif()

# Stream Processor
if(FLB_STREAM_PROCESSOR)
  if(NOT FLB_FLEX_BISON)
    message(FATAL_ERROR
      "Stream Processor feature requires Flex and Bison in your system.\n"
      "This is a build time dependency, you can either install the "
      "dependencies or disable the feature setting the CMake option "
      "-DFLB_STREAM_PROCESSOR=Off ."
      )
  endif()

  # Enable Stream Processor internal helper plugin
  set(FLB_IN_STREAM_PROCESSOR On)
  FLB_DEFINITION(FLB_HAVE_STREAM_PROCESSOR)
endif()

# mk_core is aware about jemalloc usage, we need to disable this as
# fluent-bit do not use it.
set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")

# Headers: required headers by bundled libraries, this act as a helper for
# CFL, Ctraces, CMetrics, CProfiles and fluent-otel-proto
#
# Note: any check_c_source_compiles() cmake function might require this to
# work.
#
set(CMAKE_REQUIRED_INCLUDES
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CFL}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_FLUENT_OTEL}/include/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_FLUENT_OTEL}/proto_c/
  )

# CFL
add_subdirectory(${FLB_PATH_LIB_CFL} EXCLUDE_FROM_ALL)

# fluent-otel-proto
FLB_OPTION(FLUENT_PROTO_METRICS ON)
FLB_OPTION(FLUENT_PROTO_PROFILES ON)
add_subdirectory(${FLB_PATH_LIB_FLUENT_OTEL} EXCLUDE_FROM_ALL)

# MsgPack options
if(FLB_PREFER_SYSTEM_LIB_MSGPACK)
  find_package(PkgConfig)
  # Try msgpack first (Ubuntu/Debian), then msgpack-c (Arch Linux)
  pkg_check_modules(MSGPACK msgpack>=4.0.0)
  if(NOT MSGPACK_FOUND)
    pkg_check_modules(MSGPACK msgpack-c>=4.0.0)
  endif()
endif()
if(MSGPACK_FOUND)
  include_directories(${MSGPACK_INCLUDE_DIRS})
  link_directories(${MSGPACK_LIBRARY_DIRS})
else()
  include(cmake/msgpack.cmake)
endif()

# MPack
add_definitions(-DMPACK_EXTENSIONS=1)
add_subdirectory(${FLB_PATH_LIB_MPACK} EXCLUDE_FROM_ALL)

# Miniz (zip)
add_subdirectory(${FLB_PATH_LIB_MINIZ} EXCLUDE_FROM_ALL)

# Zstd (zstd)
if(FLB_PREFER_SYSTEM_LIB_ZSTD)
  find_package(PkgConfig)
  pkg_check_modules(LIBZSTD libzstd>=1.4.8)
endif()
if(LIBZSTD_FOUND)
  include_directories(${LIBZSTD_INCLUDE_DIRS})
  link_directories(${LIBZSTD_LIBRARY_DIRS})
else()
  include(cmake/zstd.cmake)
endif()

# ring buffer library
add_subdirectory(${FLB_PATH_LIB_RING_BUFFER} EXCLUDE_FROM_ALL)

# yyson
add_subdirectory(${FLB_PATH_LIB_YYJSON} EXCLUDE_FROM_ALL)

# Avro
if(FLB_AVRO_ENCODER)
  # jansson
  option(JANSSON_BUILD_DOCS         OFF)
  option(JANSSON_EXAMPLES           OFF)
  option(JANSSON_WITHOUT_TESTS       ON)
  option(JANSSON_BUILD_SHARED_LIBS  OFF)
  add_subdirectory(${FLB_PATH_LIB_JANSSON})

  #avro
  add_subdirectory(${FLB_PATH_LIB_AVRO} EXCLUDE_FROM_ALL)
endif()

# tutf8e
if(FLB_UTF8_ENCODER)
  add_subdirectory(${FLB_PATH_LIB_TUTF8E} EXCLUDE_FROM_ALL)
endif()

# simdutf
if(FLB_UNICODE_ENCODER AND FLB_USE_SIMDUTF)
  if (NOT FLB_USE_SIMDUTF)
    message(FATAL_ERROR "FLB_UNICODE_ENCODER requires FLB_USE_SIMDUTF")
  endif()
  enable_language(CXX)
  set (CMAKE_CXX_STANDARD 11)
  add_subdirectory(${FLB_PATH_LIB_SIMDUTF} EXCLUDE_FROM_ALL)
  FLB_DEFINITION(FLB_HAVE_UNICODE_ENCODER)
endif()

# snappy
add_subdirectory(${FLB_PATH_LIB_SNAPPY} EXCLUDE_FROM_ALL)

# CMetrics
add_subdirectory(${FLB_PATH_LIB_CMETRICS} EXCLUDE_FROM_ALL)

# CTraces
add_subdirectory(${FLB_PATH_LIB_CTRACES} EXCLUDE_FROM_ALL)

# CProfiles
add_subdirectory(${FLB_PATH_LIB_CPROFILES} EXCLUDE_FROM_ALL)

# Nghttp2 options
if(FLB_PREFER_SYSTEM_LIB_NGHTTP2)
  find_package(PkgConfig)
  pkg_check_modules(NGHTTP2 libnghttp2>=1.0.0)
endif()
if(NGHTTP2_FOUND)
  include_directories(${NGHTTP2_INCLUDE_DIRS})
  link_directories(${NGHTTP2_LIBRARY_DIRS})
else()
  include(cmake/nghttp2.cmake)
endif()

# C-Ares (DNS library)
if(FLB_PREFER_SYSTEM_LIB_CARES)
  find_package(PkgConfig)
  pkg_check_modules(LIBCARES libcares>=1.18.0)
endif()
if(LIBCARES_FOUND)
  include_directories(${LIBCARES_INCLUDE_DIRS})
  link_directories(${LIBCARES_LIBRARY_DIRS})
else()
  include(cmake/cares.cmake)
endif()

# Chunk I/O
FLB_OPTION(CIO_LIB_STATIC  ON)
FLB_OPTION(CIO_LIB_SHARED  OFF)
add_subdirectory(${FLB_PATH_LIB_CHUNKIO} EXCLUDE_FROM_ALL)

# Lib: build the core libraries used by Fluent-Bit
FLB_DEFINITION(JSMN_PARENT_LINKS)
FLB_DEFINITION(JSMN_STRICT)
add_subdirectory(${FLB_PATH_LIB_JSMN})
# Runtime Tests (filter_kubernetes) requires HTTP Server
if(FLB_TESTS_RUNTIME)
  FLB_OPTION(FLB_HTTP_SERVER  ON)
endif()

# Monkey Core Library
macro(MK_SET_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
MK_SET_OPTION(MK_SYSTEM_MALLOC    ON)
MK_SET_OPTION(MK_DEBUG            ON)

# Monkey backend event loop
if (FLB_EVENT_LOOP_EPOLL)
  MK_SET_OPTION(MK_EVENT_LOOP_EPOLL ON)
  FLB_DEFINITION(FLB_EVENT_LOOP_EPOLL)
  message(STATUS "FLB Event loop backend > epoll(2)")
elseif (FLB_EVENT_LOOP_POLL)
  MK_SET_OPTION(MK_EVENT_LOOP_POLL ON)
  FLB_DEFINITION(FLB_EVENT_LOOP_POLL)
  message(STATUS "FLB Event loop backend > poll(2)")
elseif (FLB_EVENT_LOOP_KQUEUE)
  MK_SET_OPTION(MK_EVENT_LOOP_KQUEUE ON)
  FLB_DEFINITION(FLB_EVENT_LOOP_KQUEUE)
  message(STATUS "FLB Event loop backend > kqueue(2)")
elseif (FLB_EVENT_LOOP_SELECT)
  MK_SET_OPTION(MK_EVENT_LOOP_SELECT ON)
  FLB_DEFINITION(FLB_EVENT_LOOP_SELECT)
  message(STATUS "FLB Event loop backend > select(2)")
elseif (FLB_EVENT_LOOP_LIBEVENT)
  MK_SET_OPTION(MK_EVENT_LOOP_LIBEVENT ON)
  FLB_DEFINITION(FLB_EVENT_LOOP_LIBEVENT)
  message(STATUS "FLB Event loop backend > libevent")
else()
  FLB_DEFINITION(FLB_EVENT_LOOP_AUTO_DISCOVERY)
  message(STATUS "FLB Event loop backend > auto discovery (Monkey library)")
endif()

# Build Monkey HTTP Server
if(FLB_HTTP_SERVER)
  add_subdirectory(${FLB_PATH_LIB_MONKEY} EXCLUDE_FROM_ALL)
else()
  add_subdirectory(${FLB_PATH_LIB_MONKEY}/mk_core EXCLUDE_FROM_ALL)
endif()

if(FLB_TLS)
  FLB_DEFINITION(FLB_HAVE_TLS)

  option(ENABLE_TESTING  OFF)
  option(ENABLE_PROGRAMS OFF)
  option(INSTALL_MBEDTLS_HEADERS OFF)

  # Link OpenSSL statically on Windows.
  if (FLB_SYSTEM_WINDOWS)
    set(OPENSSL_USE_STATIC_LIBS ON)
    set(OPENSSL_MSVC_STATIC_RT  ON)
  endif()

  # find OpenSSL (our preferred choice now)
  find_package(OpenSSL)
  if(OPENSSL_FOUND)
    FLB_DEFINITION(FLB_HAVE_OPENSSL)
  endif()

  if (FLB_SYSTEM_WINDOWS AND NOT(OPENSSL_FOUND))
    # win32 builds w/o openssl will fail later so we might as well catch it
    # early instead.
    MESSAGE(FATAL_ERROR "OpenSSL required on Windows, see DEVELOPER_GUIDE.md")
  endif()
endif()

# Metrics
if(FLB_METRICS)
  FLB_DEFINITION(FLB_HAVE_METRICS)
endif()

# Profiles
if(FLB_PROFILES)
  FLB_DEFINITION(FLB_HAVE_PROFILES)
endif()

# WASM
if(FLB_WASM)
  if (FLB_SYSTEM_LINUX)
    check_c_source_compiles("
       #include <stdatomic.h>
       int main() {
          _Atomic int a;
          return 0;
       }" FLB_HAVE_STDATOMIC_H)
    include(CheckIncludeFiles)
    check_include_files(stdatomic.h FLB_HAVE_STDATOMIC_H)
    if (FLB_HAVE_STDATOMIC_H)
      enable_language (ASM)
      FLB_DEFINITION(FLB_HAVE_WASM)
    else ()
      message(STATUS "This platform does not provide stdatomic.h that is needed for the FLB_WASM feature so disabled.")
      set(FLB_WASM OFF)
    endif ()
  else ()
    enable_language (ASM)
    FLB_DEFINITION(FLB_HAVE_WASM)
  endif ()
endif()

# Kafka support (library in general)
if(FLB_KAFKA)
  if(FLB_IN_KAFKA OR FLB_OUT_KAFKA)
    if(FLB_PREFER_SYSTEM_LIB_KAFKA)
      find_package(PkgConfig)
      pkg_check_modules(KAFKA rdkafka>=2.3.0)
    endif()
    if(KAFKA_FOUND)
      include_directories(${KAFKA_INCLUDE_DIRS})
      link_directories(${KAFKA_LIBRARY_DIRS})
    else()
      include(cmake/kafka.cmake)
    endif()
  endif()
endif()

# AWS MSK IAM detection (must come after Kafka section)
if(FLB_AWS AND FLB_KAFKA)
  # Check if Kafka SASL support was detected
  if(DEFINED FLB_SASL_ENABLED AND FLB_SASL_ENABLED)
    set(FLB_HAVE_AWS_MSK_IAM ON)  # Set CMake variable
    FLB_DEFINITION(FLB_HAVE_AWS_MSK_IAM)  # Set preprocessor definition
    message(STATUS "AWS MSK IAM authentication: ENABLED")
  else()
    message(STATUS "AWS MSK IAM authentication: DISABLED (requires Kafka with libsasl2)")
  endif()
else()
  if(FLB_AWS AND NOT FLB_KAFKA)
    message(STATUS "AWS MSK IAM authentication: DISABLED (requires FLB_KAFKA=ON)")
  endif()
endif()

# AWS
if (FLB_AWS)
  FLB_DEFINITION(FLB_HAVE_AWS)

  # Support for credential_process in the AWS config file is currently Linux-only.
  # The current implementation might work for other Unix systems, but would require
  # further testing to confirm.
  # Spawning a sub-process in Windows is very different and will require its own
  # implementation.
  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FLB_OPTION(FLB_HAVE_AWS_CREDENTIAL_PROCESS ON)
    FLB_DEFINITION(FLB_HAVE_AWS_CREDENTIAL_PROCESS)
  else()
    FLB_OPTION(FLB_HAVE_AWS_CREDENTIAL_PROCESS OFF)
  endif()
endif()

if (FLB_AWS_ERROR_REPORTER)
  FLB_DEFINITION(FLB_HAVE_AWS_ERROR_REPORTER)
endif()

# Signv4
if (FLB_SIGNV4)
  FLB_DEFINITION(FLB_HAVE_SIGNV4)
endif()

if(FLB_SQLDB)
  if(FLB_PREFER_SYSTEM_LIB_SQLITE)
    find_package(PkgConfig)
    pkg_check_modules(SQLITE sqlite3>=3.0.0)
  endif()
  if(SQLITE_FOUND)
    include_directories(${SQLITE_INCLUDE_DIRS})
    link_directories(${SQLITE_LIBRARY_DIRS})
  else()
    include(cmake/sqlite.cmake)
  endif()
  FLB_DEFINITION(FLB_HAVE_SQLDB)
endif()

if(FLB_TRACE)
  FLB_DEFINITION(FLB_HAVE_TRACE)
endif()

# Disable colors and any other control characters in the output
if (FLB_LOG_NO_CONTROL_CHARS)
  FLB_DEFINITION(FLB_LOG_NO_CONTROL_CHARS)
endif()

if(FLB_HTTP_SERVER)
  FLB_OPTION(FLB_METRICS ON)
  FLB_DEFINITION(FLB_HAVE_METRICS)
  FLB_DEFINITION(FLB_HAVE_HTTP_SERVER)
endif()

if(NOT TARGET co)
  add_subdirectory(${FLB_PATH_LIB_CO})
endif()

if(NOT TARGET rbtree)
  add_subdirectory(${FLB_PATH_LIB_RBTREE})
endif()

# Systemd Journald support
if(JOURNALD_FOUND)
  FLB_DEFINITION(FLB_HAVE_SYSTEMD)

  check_c_source_compiles("
    #include <systemd/sd-bus.h>
    int main() {
       return 0;
    }" FLB_HAVE_SYSTEMD_SDBUS)

  if(FLB_HAVE_SYSTEMD_SDBUS)
    FLB_DEFINITION(FLB_HAVE_SYSTEMD_SDBUS)
  endif()
else()
  FLB_OPTION(FLB_IN_SYSTEMD OFF)
endif()

# Valgrind support
check_c_source_compiles("
  #include <valgrind/valgrind.h>
  int main() {
     return 0;
  }" FLB_HAVE_VALGRIND)

if(FLB_VALGRIND OR FLB_HAVE_VALGRIND)
  FLB_DEFINITION(FLB_HAVE_VALGRIND)
endif()

# fork(2) support
check_c_source_compiles("
  #include <unistd.h>
  int main() {
     fork();
     return 0;
  }" FLB_HAVE_FORK)

if(FLB_HAVE_FORK)
  FLB_DEFINITION(FLB_HAVE_FORK)
endif()

# mtrace support
if(FLB_MTRACE)
  check_c_source_compiles("
    #include <mcheck.h>
    int main() {
       return 0;
    }" FLB_HAVE_MTRACE)

  if(FLB_HAVE_MTRACE AND FLB_DEBUG)
    FLB_DEFINITION(FLB_HAVE_MTRACE)
  endif()
endif()

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" FLB_HAVE_TIMESPEC_GET)
if(FLB_HAVE_TIMESPEC_GET)
  FLB_DEFINITION(FLB_HAVE_TIMESPEC_GET)
endif()

# gmtoff support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     tm.tm_gmtoff = 0;
     return 0;
  }" FLB_HAVE_GMTOFF)
if(FLB_HAVE_GMTOFF)
  FLB_DEFINITION(FLB_HAVE_GMTOFF)
endif()

# tm_zone support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     tm.tm_zone = \"GMT\";
     return 0;
  }" FLB_HAVE_TIME_ZONE)
if(FLB_HAVE_TIME_ZONE)
  FLB_DEFINITION(FLB_HAVE_TIME_ZONE)
endif()

# clock_get_time() support for macOS.
check_c_source_compiles("
  #include <mach/clock.h>
  #include <mach/mach.h>
  int main() {
      clock_serv_t cclock;
      mach_timespec_t mts;
      host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
      clock_get_time(cclock, &mts);
      return mach_port_deallocate(mach_task_self(), cclock);
  }" FLB_HAVE_CLOCK_GET_TIME)
if(FLB_HAVE_CLOCK_GET_TIME)
  FLB_DEFINITION(FLB_HAVE_CLOCK_GET_TIME)
endif()

# unix socket support
check_c_source_compiles("
  #include <unistd.h>
  #include <sys/un.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  int main() {
      int sock;
      sock = socket(AF_UNIX, SOCK_STREAM, 0);
      close(sock);
      return 0;
  }" FLB_HAVE_UNIX_SOCKET)
if(FLB_HAVE_UNIX_SOCKET)
  FLB_DEFINITION(FLB_HAVE_UNIX_SOCKET)
endif()

# byte order detection
test_big_endian(BIG_ENDIAN_SYSTEM_DETECTED)

if (BIG_ENDIAN_SYSTEM_DETECTED)
    FLB_DEFINITION(FLB_HAVE_BIG_ENDIAN_SYSTEM)
else()
    FLB_DEFINITION(FLB_HAVE_LITTLE_ENDIAN_SYSTEM)
endif ()

# Configuration file YAML format support
if(FLB_CONFIG_YAML)
  find_package(PkgConfig)
  # libyaml's corresponding pkg-config file is yaml-0.1.pc.
  # We should search it first.
  pkg_check_modules(LIBYAML QUIET yaml-0.1)

  if (LIBYAML_FOUND)
    # For if(FLB_HAVE_LIBYAML) clause on CMakeList.txt.
    set(FLB_HAVE_LIBYAML 1)
    FLB_DEFINITION(FLB_HAVE_LIBYAML)
    # For non-standard libyaml installation paths such as homebrew bottled libyaml.
    include_directories(${LIBYAML_INCLUDEDIR})
    link_directories(${LIBYAML_LIBRARY_DIRS})
  else()
    if (FLB_LIBYAML_DIR)
      set(LIBYAML_LIBRARY_DIRS "${FLB_LIBYAML_DIR}/lib")
      set(LIBYAML_INCLUDEDIR "${FLB_LIBYAML_DIR}/include")
      message(STATUS "specified libyaml dir: ${FLB_LIBYAML_DIR}")
      if (MSVC)
        FLB_DEFINITION(YAML_DECLARE_STATIC)
      endif ()
      set(FLB_HAVE_LIBYAML 1)
      FLB_DEFINITION(FLB_HAVE_LIBYAML)
      include_directories(${LIBYAML_INCLUDEDIR})
      link_directories(${LIBYAML_LIBRARY_DIRS})
    else ()
      # Requires libyaml support
      check_c_source_compiles("
      #include <yaml.h>
      int main() {
        yaml_parser_t parser;
        return 0;
      }" FLB_HAVE_LIBYAML)

      if(NOT FLB_HAVE_LIBYAML)
        message(FATAL_ERROR
          "YAML development dependencies required for YAML configuration format handling.\n"
          "This is a build time dependency, you can either install the "
          "dependencies or disable the feature setting the CMake option "
          "-DFLB_CONFIG_YAML=Off ."
        )
      endif()
    endif ()

    FLB_DEFINITION(FLB_HAVE_LIBYAML)
  endif()
endif()

# check attribute alloc_size
check_c_source_compiles("
#include <stdlib.h>
__attribute__ ((alloc_size(1, 2))) static void* f(size_t a, size_t b) {
    return calloc(a, b);
}
int main() {
    f(1, 2);
    return 0;
}
" FLB_HAVE_ATTRIBUTE_ALLOC_SIZE)
if(FLB_HAVE_ATTRIBUTE_ALLOC_SIZE)
  FLB_DEFINITION(FLB_HAVE_ATTRIBUTE_ALLOC_SIZE)
endif()

# parameters for flb_msgpack_raw_to_json_sds buffer strategy
if (NOT DEFINED FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE)
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE 2.0)
else()
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE ${FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE})
endif()

if (NOT DEFINED FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE)
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE 0.10)
else()
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE ${FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE})
endif()

if (FLB_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

# Build tools/xxd-c
add_subdirectory(tools/xxd-c)

# Static configuration generator (using xxd-c)
if(FLB_STATIC_CONF)
  FLB_DEFINITION(FLB_HAVE_STATIC_CONF)
  add_subdirectory(gen_static_conf)
endif()

# Special definition to set the coroutine stack size
if(FLB_CORO_STACK_SIZE)
  add_definitions(-DFLB_CORO_STACK_SIZE=${FLB_CORO_STACK_SIZE})
  set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef FLB_CORO_STACK_SIZE\n#define FLB_CORO_STACK_SIZE ${FLB_CORO_STACK_SIZE}\n#endif\n")
else()

endif()

set(FLB_PROG_NAME "Fluent Bit")
set(FLB_OUT_NAME "fluent-bit")

if(FLB_PROXY_GO)
  FLB_DEFINITION(FLB_HAVE_PROXY_GO)
endif()

if("${GNU_HOST}" STREQUAL "")
    set(AUTOCONF_HOST_OPT "")
else()
    set(AUTOCONF_HOST_OPT "--host=${GNU_HOST}")
endif()

if(CMAKE_GENERATOR MATCHES "Ninja" AND NOT FLB_SYSTEM_WINDOWS)
  set(EXTERNAL_BUILD_TOOL "make")
else()
  set(EXTERNAL_BUILD_TOOL "$(MAKE)")
endif()

# Memory Allocator
# ================
if(FLB_JEMALLOC AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  if(FLB_PREFER_SYSTEM_LIB_JEMALLOC)
    find_package(PkgConfig)
    pkg_check_modules(JEMALLOC jemalloc>=5.0.0)
  endif()
  if(JEMALLOC_FOUND)
    include_directories(${JEMALLOC_INCLUDE_DIRS})
    link_directories(${JEMALLOC_LIBRARY_DIRS})
  else()
    FLB_DEFINITION(JEMALLOC_MANGLE)

    # Add support for options like page size, if empty we default it
    if(NOT DEFINED FLB_JEMALLOC_OPTIONS OR "${FLB_JEMALLOC_OPTIONS}" STREQUAL "")
      set(FLB_JEMALLOC_OPTIONS "--with-lg-quantum=3")
    endif()
    # Split into a list so CMake handles it correctly when passing to configure command
    separate_arguments(FLB_JEMALLOC_OPTIONS_LIST UNIX_COMMAND ${FLB_JEMALLOC_OPTIONS})
    message(STATUS "jemalloc configure: ${FLB_JEMALLOC_OPTIONS_LIST}")

    # Link to Jemalloc as an external dependency
    set(FLB_LIBJEMALLOC_PATH "${CMAKE_CURRENT_BINARY_DIR}/lib/libjemalloc_pic.a")
    ExternalProject_Add(jemalloc
      SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/jemalloc-5.3.0
      CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/jemalloc-5.3.0/configure ${AUTOCONF_HOST_OPT} "${FLB_JEMALLOC_OPTIONS_LIST}" --prefix=<INSTALL_DIR>
      CFLAGS=-std=gnu99\ -Wall\ -pipe\ -g3\ -O3\ -funroll-loops
      BUILD_COMMAND ${EXTERNAL_BUILD_TOOL}
      BUILD_BYPRODUCTS ${FLB_LIBJEMALLOC_PATH}
      INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/
      INSTALL_COMMAND ${EXTERNAL_BUILD_TOOL} install_lib_static install_include)
    add_library(libjemalloc STATIC IMPORTED GLOBAL)
    set_target_properties(libjemalloc PROPERTIES IMPORTED_LOCATION ${FLB_LIBJEMALLOC_PATH})
    add_dependencies(libjemalloc jemalloc)
    include_directories("${CMAKE_BINARY_DIR}/include/")
    set(JEMALLOC_LIBRARIES "libjemalloc")
  endif()
  FLB_DEFINITION(FLB_HAVE_JEMALLOC)
else()
  FLB_OPTION(FLB_JEMALLOC OFF)
endif()

# LibBacktrace (friendly stacktrace support)
# =========================================
if(FLB_BACKTRACE)
  if(FLB_PREFER_SYSTEM_LIB_BACKTRACE)
    find_path(LIBBACKTRACE_INCLUDE_DIRS NAMES backtrace.h)
    find_library(LIBBACKTRACE_LIBRARIES NAMES backtrace)
  endif()
  if(LIBBACKTRACE_INCLUDE_DIRS AND LIBBACKTRACE_LIBRARIES)
    message(STATUS "libbacktrace found (${LIBBACKTRACE_LIBRARIES})")
    include_directories(${LIBBACKTRACE_INCLUDE_DIRS})
    link_directories(${LIBBACKTRACE_LIBRARY_DIRS})
  else()
    message(STATUS "libbacktrace not found, building ourselves")
    if (CMAKE_OSX_SYSROOT)
      # From macOS Mojave, /usr/include does not store C SDK headers.
      # For libbacktrace building on macOS, we have to tell C headers where they are located.
      set(DEPS_C_COMPILER "${CMAKE_C_COMPILER} -isysroot ${CMAKE_OSX_SYSROOT}")
    else()
      set(DEPS_C_COMPILER "${CMAKE_C_COMPILER}")
    endif()
    set(FLB_LIBBACKTRACE_PATH "${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/lib/libbacktrace.a")
    ExternalProject_Add(backtrace
      SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbacktrace-8602fda/
      CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbacktrace-8602fda/configure ${AUTOCONF_HOST_OPT} --prefix=<INSTALL_DIR> --enable-shared=no --enable-static=yes
      BUILD_COMMAND ${EXTERNAL_BUILD_TOOL}
      BUILD_BYPRODUCTS ${FLB_LIBBACKTRACE_PATH}
      INSTALL_COMMAND ${EXTERNAL_BUILD_TOOL} DESTDIR= install
      )
    add_library(libbacktrace STATIC IMPORTED GLOBAL)
    set_target_properties(libbacktrace PROPERTIES IMPORTED_LOCATION ${FLB_LIBBACKTRACE_PATH})
    add_dependencies(libbacktrace backtrace)
    include_directories("${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/include/")
    set(LIBBACKTRACE_LIBRARIES "libbacktrace")
  endif()
  FLB_DEFINITION(FLB_HAVE_LIBBACKTRACE)
endif()

# Onigmo (Regex Engine) options
# =====================
if(FLB_REGEX)
  option(ONIGMO_SHARED_LIB    OFF)
  option(ONIGMO_CTESTS        OFF)
  option(ONIGMO_CTESTS_SAMPLE OFF)
  option(ONIGMO_PYTHON_TESTS  OFF)
  FLB_DEFINITION(FLB_HAVE_REGEX)

  if (FLB_SYSTEM_WINDOWS)
    # We need this line in order to link libonigmo.lib statically.
    # Read onigmo/README for details.
    FLB_DEFINITION_VAL(ONIG_EXTERN "extern")
  endif()
  add_subdirectory(${FLB_PATH_LIB_ONIGMO} EXCLUDE_FROM_ALL)
  target_include_directories(onigmo-static INTERFACE ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_ONIGMO})
endif()

# tutf8e (UTF8 Encoding)
# =====================
if(FLB_UTF8_ENCODER)
  FLB_DEFINITION(FLB_HAVE_UTF8_ENCODER)
endif()

# avro-c (Avro Encoding)
# =====================
if(FLB_AVRO_ENCODER)
  FLB_DEFINITION(FLB_HAVE_AVRO_ENCODER)
endif()

# LuaJIT (Scripting Support)
# ==========================
if(FLB_LUAJIT)
  if(FLB_PREFER_SYSTEM_LIB_LUAJIT)
    find_package(PkgConfig)
    pkg_check_modules(LUAJIT luajit>=2.1.0)
  endif()
  if(LUAJIT_FOUND)
    include_directories(${LUAJIT_INCLUDE_DIRS})
    link_directories(${LUAJIT_LIBRARY_DIRS})
  else()
    include(cmake/luajit.cmake)
  endif()
  FLB_DEFINITION(FLB_HAVE_LUAJIT)
endif()

# PostgreSQL
# ==========
find_package(PostgreSQL)
if(FLB_OUT_PGSQL AND (NOT PostgreSQL_FOUND))
   FLB_OPTION(FLB_OUT_PGSQL OFF)
endif()

# Arrow GLib
# ==========
find_package(PkgConfig)
pkg_check_modules(ARROW_GLIB QUIET arrow-glib)
if(FLB_ARROW AND ARROW_GLIB_FOUND)
  FLB_DEFINITION(FLB_HAVE_ARROW)
else()
  set(FLB_ARROW OFF)
endif()

# Additional prerequisites for Apache Parquet
pkg_check_modules(ARROW_GLIB_PARQUET QUIET parquet-glib)
if(FLB_ARROW AND ARROW_GLIB_PARQUET_FOUND)
  FLB_DEFINITION(FLB_HAVE_ARROW_PARQUET)
else()
  message(STATUS "Arrow GLib Parquet not found. Disabling parquet compression")
endif()

# EBPF Support
# ============
if (FLB_IN_EBPF)
  find_package(PkgConfig)

  # Check for Clang compiler
  find_program(CLANG_EXECUTABLE clang)

  if (CLANG_EXECUTABLE)
    message(STATUS "Clang found: ${CLANG_EXECUTABLE}")
    # Get Clang version
    execute_process(
            COMMAND ${CLANG_EXECUTABLE} --version
            OUTPUT_VARIABLE CLANG_VERSION_OUTPUT
            ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (CLANG_VERSION_OUTPUT MATCHES "clang version ([0-9]+)\\.([0-9]+)\\.([0-9]+)")
      set(CLANG_VERSION_MAJOR "${CMAKE_MATCH_1}")
      set(CLANG_VERSION_MINOR "${CMAKE_MATCH_2}")
      set(CLANG_VERSION_PATCH "${CMAKE_MATCH_3}")

      message(STATUS "Detected Clang version: ${CLANG_VERSION_MAJOR}.${CLANG_VERSION_MINOR}.${CLANG_VERSION_PATCH}")
      # Check if Clang version is at least 3.7.0
      if (CLANG_VERSION_MAJOR LESS 3 AND CLANG_VERSION_MINOR LESS 7)
        message(FATAL_ERROR "Clang version must be at least 3.7.0, but found ${CLANG_VERSION_MAJOR}.${CLANG_VERSION_MINOR}.${CLANG_VERSION_PATCH}")
      endif()
    endif()
  else()
    message(FATAL_ERROR "Clang not found! Please install Clang version >= 3.7.0!")
  endif()

  # Check for libbpf with pkg-config
  pkg_check_modules(LIBBPF libbpf>=0.5.0)

  if (LIBBPF_FOUND)
    message(STATUS "libbpf found: ${LIBBPF_LIBRARIES}")
    include_directories(${LIBBPF_INCLUDE_DIRS})
    list(APPEND EXTRA_LIBS ${LIBBPF_LIBRARIES})
  else()
    # Manually find the library if pkg-config fails
    find_library(LIBBPF_LIBRARY NAMES bpf REQUIRED)
    if (LIBBPF_LIBRARY)
      message(STATUS "Found libbpf: ${LIBBPF_LIBRARY}")
      list(APPEND EXTRA_LIBS ${LIBBPF_LIBRARY})
    else()
      if (FLB_SYSTEM_LINUX)
        message(FATAL_ERROR "libbpf is required on Linux. Please install libbpf or ensure it is in your library path.")
      else()
        message(STATUS "libbpf is not found. Disabling eBPF support.")
        set(FLB_IN_EBPF OFF)
      endif()
    endif()
  endif()

endif()

# AMQP
# ==========
find_package(rabbitmq-c)
if(FLB_IN_AMQP AND (NOT rabbitmq-c_FOUND))
   FLB_OPTION(FLB_IN_AMQP OFF)
endif()

# Pthread Local Storage
# =====================
# By default we expect the compiler already support thread local storage
# through __thread type, otherwise Fluent Bit fallback to the old POSIX
# pthread mode (pthread_key_t), or it can be forced setting FLB_POSIX_TLS
# for testing/compatibility purposes.
if(NOT FLB_POSIX_TLS)
  check_c_source_compiles("
   __thread int a;
   int main() {
       __tls_get_addr(0);
       return 0;
   }" FLB_HAVE_C_TLS)
  if(FLB_HAVE_C_TLS)
    FLB_DEFINITION(FLB_HAVE_C_TLS)
  endif()
endif()

# accept(4)
check_c_source_compiles("
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <sys/socket.h>
    int main() {
        accept4(0, NULL, NULL, 0);
        return 0;
    }" FLB_HAVE_ACCEPT4)
if(FLB_HAVE_ACCEPT4)
  FLB_DEFINITION(FLB_HAVE_ACCEPT4)
endif()

# inotify_init(2)
if(FLB_INOTIFY)
  check_c_source_compiles("
    #include <sys/inotify.h>
    int main() {
        return inotify_init1(0);
    }" FLB_HAVE_INOTIFY)
  if(FLB_HAVE_INOTIFY)
    FLB_DEFINITION(FLB_HAVE_INOTIFY)
  endif()
endif()

include(CheckSymbolExists)

# Check for getentropy(3)
check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
if(HAVE_GETENTROPY)
  FLB_DEFINITION(FLB_HAVE_GETENTROPY)
endif()

# getentropy(3) is in sys/random.h on mac
check_symbol_exists(getentropy "sys/random.h" HAVE_GETENTROPY_SYS_RANDOM)
if(HAVE_GETENTROPY_SYS_RANDOM)
  FLB_DEFINITION(FLB_HAVE_GETENTROPY_SYS_RANDOM)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/tls/flb_tls_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/tls/flb_tls_info.h"
  )

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(FLB_INSTALL_BINDIR "bin")
  set(FLB_INSTALL_LIBDIR "lib")
  set(FLB_INSTALL_CONFDIR "conf")
  set(FLB_INSTALL_INCLUDEDIR "include")
else()
  set(FLB_INSTALL_BINDIR ${CMAKE_INSTALL_FULL_BINDIR})
  set(FLB_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${FLB_OUT_NAME}")
  set(FLB_INSTALL_CONFDIR "${CMAKE_INSTALL_SYSCONFDIR}/${FLB_OUT_NAME}/")
  set(FLB_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(include)
add_subdirectory(plugins)
add_subdirectory(src)

if(NOT FLB_SHARED_LIB)
  set(FLB_EXAMPLES OFF)
endif()

if(FLB_EXAMPLES)
  add_subdirectory(examples)
endif()

if(FLB_TESTS_RUNTIME)
  enable_testing()
  add_subdirectory(tests/runtime/)
  add_subdirectory(tests/runtime_shell/)
endif()

if(FLB_TESTS_INTERNAL)
  enable_testing()
  add_subdirectory(tests/internal/)
endif()

# Installer Generation (Cpack)
# ============================

set(CPACK_PACKAGE_VERSION ${FLB_VERSION_STR})
set(CPACK_PACKAGE_NAME "fluent-bit")

set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo.silva@chronosphere.io>")
set(CPACK_PACKAGE_VENDOR "Chronosphere Inc.")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

if(FLB_SYSTEM_WINDOWS)
  set(CPACK_GENERATOR "NSIS" "ZIP" "WIX")

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|AARCH64)")
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-winarm64")
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win64")
  else()
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32")
  endif()
endif()

# Enable components
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_productbuild_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL ${CPACK_COMPONENTS_ALL} binary library headers headers-extra)
set(CPACK_COMPONENTS_GROUPING "ONE_PER_GROUP")

set(CPACK_COMPONENT_BINARY_GROUP "RUNTIME")
set(CPACK_COMPONENT_LIBRARY_GROUP "RUNTIME")

# Debian package setup and name sanitizer
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

find_program(DPKG_PROGRAM dpkg DOC "dpkg program of Debian-based systems")
if(DPKG_PROGRAM)
  execute_process(
    COMMAND ${DPKG_PROGRAM} --print-architecture
    OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

  set(CPACK_DEBIAN_HEADERS_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-headers.deb")
  set(CPACK_DEBIAN_HEADERS_EXTRA_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-headers-extra.deb")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
  set(CPACK_DEBIAN_RUNTIME_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONTROL_EXTRA
    ${PROJECT_SOURCE_DIR}/cpack/debian/conffiles
    )

  if(FLB_RUN_LDCONFIG)
    set(LDCONFIG_DIR ${FLB_INSTALL_LIBDIR})
    file(WRITE ${PROJECT_BINARY_DIR}/scripts/postinst "
mkdir -p /etc/ld.so.conf.d
echo \"${LDCONFIG_DIR}\" > /etc/ld.so.conf.d/libfluent-bit.conf
ldconfig
    ")
    file(WRITE ${PROJECT_BINARY_DIR}/scripts/prerm "
rm -f -- /etc/ld.so.conf.d/libfluent-bit.conf
ldconfig
    ")
    set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONTROL_EXTRA "${PROJECT_BINARY_DIR}/scripts/postinst;${PROJECT_BINARY_DIR}/scripts/prerm")
  endif(FLB_RUN_LDCONFIG)

endif()

# RPM Generation information
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE})
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/cpack/description")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Fast data collector for Linux")
set(CPACK_RPM_SPEC_MORE_DEFINE "%define ignore \#")
set(CPACK_RPM_RUNTIME_USER_FILELIST
  "%config(noreplace) /etc/${FLB_OUT_NAME}/${FLB_OUT_NAME}.conf"
  "%config(noreplace) /etc/${FLB_OUT_NAME}/parsers.conf"
  "%config(noreplace) /etc/${FLB_OUT_NAME}/plugins.conf"
  "%ignore /lib"
  "%ignore /lib/systemd"
  "%ignore /lib/systemd/system"
  "%ignore /lib64"
  "%ignore /lib64/pkgconfig"
  "%ignore /usr/local"
  "%ignore /usr/local/bin"
  "%ignore /opt"
  "%ignore /etc")

set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
set(CPACK_RPM_HEADERS_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}-headers.rpm")
set(CPACK_RPM_HEADERS_EXTRA_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}-headers-extra.rpm")
set(CPACK_RPM_RUNTIME_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}.rpm")

# CPack: DEB
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# CPack: Windows System
if(CPACK_GENERATOR MATCHES "NSIS")
  set(CPACK_MONOLITHIC_INSTALL 1)
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "fluent-bit")
endif()

# CPack: Windows System w/ WiX
if(CPACK_GENERATOR MATCHES "WIX")
  set(CPACK_WIX_UPGRADE_GUID cb6825fd-37e6-4596-a55d-6d490d4fe178)
  configure_file(LICENSE "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt")
  configure_file(${CMAKE_SOURCE_DIR}/cpack/wix/WIX.template.in.cmakein
    ${CMAKE_CURRENT_BINARY_DIR}/WIX.template.in)
  # Specify LICENSE file that has .txt extension
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt")
  set(CPACK_WIX_TEMPLATE ${CMAKE_CURRENT_BINARY_DIR}/WIX.template.in)
  set(CPACK_WIX_LIGHT_EXTENSIONS "WixUtilExtension")
endif()

if(FLB_SYSTEM_MACOS)
  # Determine the platform suffix
  execute_process(
    COMMAND uname -m
    RESULT_VARIABLE UNAME_M_RESULT
    OUTPUT_VARIABLE UNAME_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "arm64")
    set(FLUENT_BIT_PKG ${CMAKE_CURRENT_BINARY_DIR}/fluent-bit-${FLB_VERSION_STR}-apple)
  elseif(UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "x86_64")
    set(FLUENT_BIT_PKG ${CMAKE_CURRENT_BINARY_DIR}/fluent-bit-${FLB_VERSION_STR}-intel)
  else()
    set(FLUENT_BIT_PKG ${CMAKE_CURRENT_BINARY_DIR}/fluent-bit-${FLB_VERSION_STR}-${UNAME_ARCH})
  endif()

  if (CPACK_GENERATOR MATCHES "productbuild")
    set(CPACK_SET_DESTDIR "ON")
    configure_file(cpack/macos/welcome.txt.cmakein ${CMAKE_CURRENT_BINARY_DIR}/welcome.txt)
    configure_file(cpack/macos/fluent-bit.plist.cmakein ${CMAKE_CURRENT_BINARY_DIR}/${FLB_OUT_NAME}.plist)
    configure_file(LICENSE ${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt)
    find_program(CONVERTER textutil)
    if (NOT CONVERTER)
      message(FATAL_ERROR "textutil not found.")
    endif()
    if (CONVERTER)
      execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_SOURCE_DIR}/README.md" -output "${CMAKE_BINARY_DIR}/README.html")
    endif()
    set(CPACK_PACKAGE_FILE_NAME "${FLUENT_BIT_PKG}")
    set(CPACK_RESOURCE_FILE_WELCOME ${CMAKE_CURRENT_BINARY_DIR}/welcome.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_BINARY_DIR}/README.html)
    set(CPACK_PRODUCTBUILD_IDENTIFIER "io.fluentbit.${FLB_OUT_NAME}")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${FLB_OUT_NAME}.plist
      COMPONENT binary
      DESTINATION /Library/LaunchDaemons)
  endif()
endif()

include(CPack)
