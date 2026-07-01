string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
enable_language (CXX)

if (FLB_SYSTEM_WINDOWS)
  enable_language(ASM_MASM)
endif()
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

set (CMAKE_CXX_STANDARD 14)

if (FLB_SYSTEM_WINDOWS)
  add_definitions(-DCOMPILING_WASM_RUNTIME_API=1)
endif ()

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# WAMR features switch

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]",
# "MIPS", "XTENSA", "RISCV64[sub]", "RISCV32[sub]"
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
    set (WAMR_BUILD_TARGET "AARCH64")
    add_definitions(-DBUILD_TARGET="${WAMR_BUILD_TARGET}")
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
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV64" OR WAMR_BUILD_TARGET STREQUAL "RISCV64_LP64D")
  add_definitions(-DBUILD_TARGET_RISCV64_LP64D)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV64_LP64")
  add_definitions(-DBUILD_TARGET_RISCV64_LP64)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV32" OR WAMR_BUILD_TARGET STREQUAL "RISCV32_ILP32D")
  add_definitions(-DBUILD_TARGET_RISCV32_ILP32D)
elseif (WAMR_BUILD_TARGET STREQUAL "RISCV32_ILP32")
  add_definitions(-DBUILD_TARGET_RISCV32_ILP32)
else ()
  message (FATAL_ERROR "-- Build target isn't set")
endif ()

message ("-- Build as target ${WAMR_BUILD_TARGET}")

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif ()

add_definitions(-DWASM_ENABLE_INTERP=1)
add_definitions(-DWASM_ENABLE_WAMR_COMPILER=1)
add_definitions(-DWASM_ENABLE_BULK_MEMORY=1)
add_definitions(-DWASM_DISABLE_HW_BOUND_CHECK=1)
add_definitions(-DWASM_ENABLE_SHARED_MEMORY=1)
add_definitions(-DWASM_ENABLE_THREAD_MGR=1)
add_definitions(-DWASM_ENABLE_TAIL_CALL=1)
add_definitions(-DWASM_ENABLE_SIMD=1)
add_definitions(-DWASM_ENABLE_REF_TYPES=1)
add_definitions(-DWASM_ENABLE_CUSTOM_NAME_SECTION=1)
add_definitions(-DWASM_ENABLE_AOT_STACK_FRAME=1)
add_definitions(-DWASM_ENABLE_DUMP_CALL_STACK=1)
add_definitions(-DWASM_ENABLE_PERF_PROFILING=1)
add_definitions(-DWASM_ENABLE_LOAD_CUSTOM_SECTION=1)
add_definitions(-DWASM_ENABLE_LIB_WASI_THREADS=1)
add_definitions(-DWASM_ENABLE_MODULE_INST_CONTEXT=1)
add_definitions(-DWASM_ENABLE_MEMORY64=1)
add_definitions(-DWASM_ENABLE_EXTENDED_CONST_EXPR=1)

if (WAMR_BUILD_LLVM_LEGACY_PM EQUAL 1)
  add_definitions(-DWASM_ENABLE_LLVM_LEGACY_PM=1)
endif()

if (DEFINED WAMR_BUILD_AOT_FUNC_PREFIX)
  add_definitions(-DAOT_FUNC_PREFIX="${WAMR_BUILD_AOT_FUNC_PREFIX}")
endif ()

if (NOT MSVC)
  # linker flags
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -fPIE")
  if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
  endif ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wformat -Wformat-security")
  if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
    if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
      check_c_compiler_flag(-mindirect-branch-register FLB_WAMRC_INDIRECT_BRANCH_REGISTER_SUPPORTED)
      if (FLB_WAMRC_INDIRECT_BRANCH_REGISTER_SUPPORTE)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
      endif ()
    endif ()
  endif ()
endif ()

# Searching homebrewed LLVM automatically on macOS.
if(FLB_SYSTEM_MACOS AND NOT DEFINED ENV{LLVM_DIR})
  execute_process(
    COMMAND brew --prefix llvm
    RESULT_VARIABLE HOMEBREW_LLVM
    OUTPUT_VARIABLE HOMEBREW_LLVM_PREFIX
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (HOMEBREW_LLVM EQUAL 0 AND EXISTS "${HOMEBREW_LLVM_PREFIX}")
    message(STATUS "Using llvm keg installed by Homebrew at ${HOMEBREW_LLVM_PREFIX}")
    set(ENV{LLVM_DIR} "${HOMEBREW_LLVM_PREFIX}")
  endif()
endif()

# Enable LLVM
set (WAMR_BUILD_WITH_SYSTEM_LLVM 1)
if (NOT WAMR_BUILD_WITH_SYSTEM_LLVM)
  set (LLVM_SRC_ROOT "${PROJECT_SOURCE_DIR}/../core/deps/llvm")
  if (WAMR_BUILD_PLATFORM STREQUAL "windows")
    if (NOT EXISTS "${LLVM_SRC_ROOT}/win32build")
      message (FATAL_ERROR "Cannot find LLVM dir: ${LLVM_SRC_ROOT}/win32build")
    endif ()
    set (CMAKE_PREFIX_PATH "${LLVM_SRC_ROOT}/win32build;${CMAKE_PREFIX_PATH}")
  else()
    if (NOT EXISTS "${LLVM_SRC_ROOT}/build")
      message (FATAL_ERROR "Cannot find LLVM dir: ${LLVM_SRC_ROOT}/build")
    endif ()
    set (CMAKE_PREFIX_PATH "${LLVM_SRC_ROOT}/build;${CMAKE_PREFIX_PATH}")
  endif ()
endif ()

if(LLVM_ENABLE_CURL STREQUAL FORCE_ON)
  find_package(CURL REQUIRED)
else()
  find_package(CURL)
endif()

find_package(LLVM CONFIG)
if (LLVM_FOUND)
  if (LLVM_PACKAGE_VERSION VERSION_LESS 13.0)
    message(STATUS "Outdated LLVM ${LLVM_PACKAGE_VERSION} is found. WAMRC won't be built.")
    set(LLVM_FOUND 0)
  endif()
else()
  message(STATUS "LLVM is not found. WAMRC won't be built.")
endif()
if (LLVM_FOUND)
  include_directories(${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})

  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

  set (WAMR_ROOT_DIR ../../${FLB_PATH_LIB_WASM_MICRO_RUNTIME})
  set (SHARED_DIR ${WAMR_ROOT_DIR}/core/shared)
  set (IWASM_DIR ${WAMR_ROOT_DIR}/core/iwasm)
  set (APP_FRAMEWORK_DIR ${WAMER_ROOT_DIR}/core/app-framework)

  include_directories (${SHARED_DIR}/include
    ${IWASM_DIR}/include)

  enable_language (ASM)

  if (NOT MINGW AND NOT MSVC)
    set(WAMR_BUILD_LIBC_WASI 1)
  else()
    set(WAMR_BUILD_LIBC_UVWASI 1)
  endif()

  include (${SHARED_DIR}/platform/${WAMR_BUILD_PLATFORM}/shared_platform.cmake)
  include (${SHARED_DIR}/mem-alloc/mem_alloc.cmake)
  include (${SHARED_DIR}/utils/shared_utils.cmake)
  include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)
  include (${WAMR_ROOT_DIR}/core/shared/platform/common/libc-util/platform_common_libc_util.cmake)
  include (${IWASM_DIR}/libraries/thread-mgr/thread_mgr.cmake)
  include (${IWASM_DIR}/libraries/libc-builtin/libc_builtin.cmake)
  if (NOT MINGW)
    if (NOT MSVC)
      include (${IWASM_DIR}/libraries/libc-wasi/libc_wasi.cmake)
    else()
      include (${IWASM_DIR}/libraries/libc-uvwasi/libc_uvwasi.cmake)
    endif()
  endif()
  include (${IWASM_DIR}/libraries/lib-pthread/lib_pthread.cmake)
  include (${IWASM_DIR}/libraries/lib-wasi-threads/lib_wasi_threads.cmake)
  include (${IWASM_DIR}/common/iwasm_common.cmake)
  include (${IWASM_DIR}/interpreter/iwasm_interp.cmake)
  include (${IWASM_DIR}/aot/iwasm_aot.cmake)
  include (${IWASM_DIR}/compilation/iwasm_compl.cmake)

  add_library (vmlib-wamrc-static STATIC
    ${PLATFORM_SHARED_SOURCE}
    ${MEM_ALLOC_SHARED_SOURCE}
    ${UTILS_SHARED_SOURCE}
    ${UNCOMMON_SHARED_SOURCE}
    ${THREAD_MGR_SOURCE}
    ${LIBC_BUILTIN_SOURCE}
    ${LIBC_WASI_SOURCE}
    ${LIB_PTHREAD_SOURCE}
    ${LIB_WASI_THREADS_SOURCE}
    ${IWASM_COMMON_SOURCE}
    ${IWASM_INTERP_SOURCE}
    ${IWASM_AOT_SOURCE})
  add_library (aotclib-static STATIC ${IWASM_COMPL_SOURCE})
  add_executable (flb-wamrc-bin ${WAMR_ROOT_DIR}/wamr-compiler/main.c)

  if (NOT MSVC)
    target_link_libraries (flb-wamrc-bin aotclib-static vmlib-wamrc-static LLVMDemangle ${LLVM_AVAILABLE_LIBS} ${lib_ubsan}
      -lm -lpthread ${lib_lldb} ${UV_A_LIBS})
    if (MINGW)
      target_link_libraries (flb-wamrc-bin -lssp -lWs2_32)
    else()
      target_link_libraries (flb-wamrc-bin -ldl)
    endif()
  else()
    target_link_libraries (flb-wamrc-bin aotclib-static vmlib-wamrc-static  ${lib_lldb} ${LLVM_AVAILABLE_LIBS} ${lib_ubsan}
      ${UV_A_LIBS})
  endif()

  set_target_properties(flb-wamrc-bin
    PROPERTIES
    OUTPUT_NAME flb-wamrc
    ENABLE_EXPORTS ON)
  install(TARGETS flb-wamrc-bin RUNTIME DESTINATION ${FLB_INSTALL_BINDIR} COMPONENT binary)

  # Include PDB file (if available)
  if (MSVC)
    target_link_options(flb-wamrc-bin
      PUBLIC /pdb:$<TARGET_PDB_FILE:flb-wamrc-bin>)
    install(FILES $<TARGET_PDB_FILE:flb-wamrc-bin>
      DESTINATION "${FLB_INSTALL_BINDIR}")
  endif()
endif ()