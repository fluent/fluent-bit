string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (FLB_SYSTEM_WINDOWS)
  enable_language(ASM_MASM)
endif()
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

set (CMAKE_C_STANDARD 99)

if (FLB_SYSTEM_WINDOWS)
  add_definitions(-DCOMPILING_WASM_RUNTIME_API=1)
endif ()

# WAMR features switch

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]",
# "MIPS", "XTENSA", "RISCV64[sub]", "RISCV32[sub]"
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
    set (WAMR_BUILD_TARGET "AARCH64")
  # For raspbian/buster: armv6l-unknown-linux-gnueabihf
  elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^(armv6.*|armv7.*)")
    set (WAMR_BUILD_TARGET "ARM")
  elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
    set (WAMR_BUILD_TARGET "RISCV64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  else ()
    message(SEND_ERROR "Unsupported build target platform!")
  endif ()
endif ()

string(TOUPPER ${WAMR_BUILD_TARGET} WAMR_BUILD_TARGET)

# Add definitions for the build target
if (WAMR_BUILD_TARGET STREQUAL "X86_64")
  add_definitions(-DBUILD_TARGET_X86_64)
elseif (WAMR_BUILD_TARGET STREQUAL "AMD_64")
  add_definitions(-DBUILD_TARGET_AMD_64)
elseif (WAMR_BUILD_TARGET STREQUAL "X86_32")
  add_definitions(-DBUILD_TARGET_X86_32)
elseif (WAMR_BUILD_TARGET MATCHES "AARCH64.*")
  add_definitions(-DBUILD_TARGET_AARCH64)
  add_definitions(-DBUILD_TARGET="${WAMR_BUILD_TARGET}")
elseif (WAMR_BUILD_TARGET MATCHES "ARM.*")
  add_definitions(-DBUILD_TARGET_ARM)
  add_definitions(-DBUILD_TARGET="${WAMR_BUILD_TARGET}")
elseif (WAMR_BUILD_TARGET STREQUAL "MIPS")
  add_definitions(-DBUILD_TARGET_MIPS)
elseif (WAMR_BUILD_TARGET STREQUAL "XTENSA")
  add_definitions(-DBUILD_TARGET_XTENSA)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV64" OR WAMR_BUILD_TARGET STREQUAL "RISCV64_LP64D")
  add_definitions(-DBUILD_TARGET_RISCV64_LP64D)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV64_LP64")
  add_definitions(-DBUILD_TARGET_RISCV64_LP64)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV32" OR WAMR_BUILD_TARGET STREQUAL "RISCV32_ILP32D")
  add_definitions(-DBUILD_TARGET_RISCV32_ILP32D)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV32_ILP32")
  add_definitions(-DBUILD_TARGET_RISCV32_ILP32)
elseif (WAMR_BUILD_TARGET STREQUAL "ARC")
  add_definitions(-DBUILD_TARGET_ARC)
else ()
  message (FATAL_ERROR "-- Build target isn't set")
endif ()

message ("-- Build as target ${WAMR_BUILD_TARGET}")

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif ()

set (WAMR_BUILD_MINI_LOADER 0)
set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_FAST_INTERP 1)
if (NOT DEFINED WAMR_DISABLE_AOT_LOADING)
  set (WAMR_BUILD_AOT 1)
endif ()
set (WAMR_BUILD_JIT 0)
set (WAMR_BUILD_LIBC_BUILTIN 1)
if (MSVC)
  # Currently, LIBC_UVWASI build is disabled.
  # FIXME: Need to investigate how to build libuv and uvwasi without fetching repos.
  set (WAMR_BUILD_LIBC_UVWASI 0)
else ()
  set (WAMR_BUILD_LIBC_WASI 1)
endif ()
if (NOT MSVC)
  set (WAMR_BUILD_LIB_PTHREAD 1)
endif ()
set (WAMR_BUILD_REF_TYPES 1)

if (NOT MSVC)
  # linker flags
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -fPIE")
  if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
  endif ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wformat -Wformat-security")
  if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
    if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
      check_c_compiler_flag(-mindirect-branch-register FLB_WASM_INDIRECT_BRANCH_REGISTER_SUPPORTED)
      if (FLB_WASM_INDIRECT_BRANCH_REGISTER_SUPPORTED)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
      endif ()
    endif ()
  endif ()
endif ()

set (WAMR_BUILD_SIMD 0)
set (WAMR_ROOT_DIR ../../${FLB_PATH_LIB_WASM_MICRO_RUNTIME})

# build out vmlib-static
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib-static STATIC ${WAMR_RUNTIME_LIB_SOURCE})

# Application related
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

# platform common sources
include (${WAMR_ROOT_DIR}/core/shared/platform/common/libc-util/platform_common_libc_util.cmake)

set(src
  flb_wasm.c
  ${UNCOMMON_SHARED_SOURCE}) # link wasm-micro-runtime's uncommon object symbols (for bh_read_file_to_buffer)

add_library(flb-wasm-static STATIC ${src})

if (FLB_JEMALLOC AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND (NOT JEMALLOC_FOUND))
  set(${JEMALLOC_LIBS} libjemalloc)
  add_dependencies(flb-wasm-static libjemalloc)
  include_directories("${CMAKE_BINARY_DIR}/include/")
endif ()

if (WAMR_BUILD_LIBC_UVWASI)
  target_link_libraries(flb-wasm-static vmlib-static ${UV_A_LIBS})
else ()
  target_link_libraries(flb-wasm-static vmlib-static ${JEMALLOC_LIBRARIES})
endif()
