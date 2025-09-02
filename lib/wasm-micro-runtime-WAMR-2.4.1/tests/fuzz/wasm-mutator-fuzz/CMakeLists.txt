# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(wamr_fuzzing LANGUAGES ASM C CXX)

include(CMakePrintHelpers)

# Ensure Clang is used as the compiler
if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang"
    OR NOT CMAKE_ASM_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR "Please use Clang as the C compiler for libFuzzer compatibility.")
endif()

#
# Global settings
#
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)

# Reset default linker flags
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Check if the compiler supports the sanitizer flags
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-fsanitize=address"   HAS_ADDRESS_SANITIZER)
check_cxx_compiler_flag("-fsanitize=memory"    HAS_MEMORY_SANITIZER)
check_cxx_compiler_flag("-fsanitize=undefined" HAS_UNDEFINED_SANITIZER)

# Determine WAMR_BUILD_TARGET based on system properties
if(NOT DEFINED WAMR_BUILD_TARGET)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
    set(WAMR_BUILD_TARGET "AARCH64")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
    set(WAMR_BUILD_TARGET "RISCV64")
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WAMR_BUILD_TARGET "X86_64")
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(WAMR_BUILD_TARGET "X86_32")
  else()
    message(SEND_ERROR "Unsupported build target platform!")
  endif()
endif()

if(APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif()

# Disable hardware bound check and enable AOT validator
set(WAMR_DISABLE_HW_BOUND_CHECK 1)
set(WAMR_BUILD_AOT_VALIDATOR 1)

set(REPO_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)
message(STATUS "REPO_ROOT_DIR: ${REPO_ROOT_DIR}")

# Use LLVM_DIR from command line if defined
# LLVM_DIR should be something like /path/to/llvm/build/lib/cmake/llvm
if(DEFINED LLVM_DIR)
  set(LLVM_DIR $ENV{LLVM_DIR})
else()
  set(LLVM_SRC_ROOT ${REPO_ROOT_DIR}/core/deps/llvm)
  set(LLVM_BUILD_ROOT ${LLVM_SRC_ROOT}/build)
  set(LLVM_DIR ${LLVM_BUILD_ROOT}/lib/cmake/llvm)
endif()

# if LLVM_DIR is an existing directory, use it
if(NOT EXISTS ${LLVM_DIR})
  message(FATAL_ERROR "LLVM_DIR not found: ${LLVM_DIR}")
endif()

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

list(
  APPEND
  REQUIRED_LLVM_LIBS
    LLVMDemangle
    LLVMSupport
    LLVMTableGen
    LLVMTableGenGlobalISel
    LLVMCore
    LLVMFuzzerCLI
    LLVMFuzzMutate
    LLVMFileCheck
    LLVMInterfaceStub
    LLVMIRReader
    LLVMCodeGen
    LLVMSelectionDAG
    LLVMAsmPrinter
    LLVMMIRParser
    LLVMGlobalISel
    LLVMBinaryFormat
    LLVMBitReader
    LLVMBitWriter
    LLVMBitstreamReader
    LLVMDWARFLinker
    LLVMExtensions
    LLVMFrontendOpenACC
    LLVMFrontendOpenMP
    LLVMTransformUtils
    LLVMInstrumentation
    LLVMAggressiveInstCombine
    LLVMInstCombine
    LLVMScalarOpts
    LLVMipo
    LLVMVectorize
    LLVMObjCARCOpts
    LLVMCoroutines
    LLVMCFGuard
    LLVMLinker
    LLVMAnalysis
    LLVMLTO
    LLVMMC
    LLVMMCParser
    LLVMMCDisassembler
    LLVMMCA
    LLVMObjCopy
    LLVMObject
    LLVMObjectYAML
    LLVMOption
    LLVMRemarks
    LLVMDebuginfod
    LLVMDebugInfoDWARF
    LLVMDebugInfoGSYM
    LLVMDebugInfoMSF
    LLVMDebugInfoCodeView
    LLVMDebugInfoPDB
    LLVMSymbolize
    LLVMDWP
    LLVMExecutionEngine
    LLVMInterpreter
    LLVMJITLink
    LLVMMCJIT
    LLVMOrcJIT
    LLVMOrcShared
    LLVMOrcTargetProcess
    LLVMRuntimeDyld
    LLVMTarget
    LLVMX86CodeGen
    LLVMX86AsmParser
    LLVMX86Disassembler
    LLVMX86TargetMCA
    LLVMX86Desc
    LLVMX86Info
    LLVMAsmParser
    LLVMLineEditor
    LLVMProfileData
    LLVMCoverage
    LLVMPasses
    LLVMTextAPI
    LLVMDlltoolDriver
    LLVMLibDriver
    LLVMXRay
    LLVMWindowsDriver
    LLVMWindowsManifest
)

set(SHARED_DIR ${REPO_ROOT_DIR}/core/shared)
set(IWASM_DIR ${REPO_ROOT_DIR}/core/iwasm)

# Global setting
add_compile_options(-Wno-unused-command-line-argument)

# Enable fuzzer
add_definitions(-DWASM_ENABLE_FUZZ_TEST=1)
# '-fsanitize=vptr' not allowed with '-fno-rtti
# But, LLVM by default, disables the use of `rtti` in the compiler
add_compile_options(-fsanitize=fuzzer -fno-sanitize=vptr)
add_link_options(-fsanitize=fuzzer -fno-sanitize=vptr)

# Enable sanitizers if not in oss-fuzz environment
set(CFLAGS_ENV $ENV{CFLAGS})
string(FIND "${CFLAGS_ENV}" "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" FUZZ_POS)
if (FUZZ_POS GREATER -1)
  set(IN_OSS_FUZZ 1)
else()
  set(IN_OSS_FUZZ 0)
endif()

add_subdirectory(aot-compiler)
add_subdirectory(wasm-mutator)
