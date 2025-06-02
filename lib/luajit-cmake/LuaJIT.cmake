cmake_minimum_required(VERSION 3.5)

project(luajit C)
set(can_use_assembler TRUE)
enable_language(ASM)

if(NOT LUAJIT_DIR)
  message(FATAL_ERROR "Must set LUAJIT_DIR to build luajit with CMake")
endif()

set(LJ_DIR ${LUAJIT_DIR}/src)

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_LIST_DIR}/Modules"
)

if (NOT WIN32)
  include(GNUInstallDirs)
endif ()

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.10" CACHE STRING "Minimum version of macOS/iOS)")
set(LUAJIT_BUILD_EXE ON CACHE BOOL "Enable luajit exe build")
set(LUAJIT_BUILD_ALAMG OFF CACHE BOOL "Enable alamg build mode")
set(LUAJIT_DISABLE_GC64 OFF CACHE BOOL "Disable GC64 mode for x64")
set(LUA_MULTILIB "lib" CACHE PATH "The name of lib directory.")
set(LUAJIT_DISABLE_FFI OFF CACHE BOOL "Permanently disable the FFI extension")
set(LUAJIT_DISABLE_JIT OFF CACHE BOOL "Disable the JIT compiler")
set(LUAJIT_NO_UNWIND OFF CACHE BOOL "Disable the UNWIND")
set(LUAJIT_ENABLE_LUA52COMPAT ON CACHE BOOL "Enable LuaJIT2.1 compat with Lua5.2")
set(LUAJIT_NUMMODE 0 CACHE STRING
"Specify the number mode to use. Possible values:
  0 - Default mode
  1 - Single number mode
  2 - Dual number mode
")

message(STATUS "${CMAKE_CROSSCOMPILING} ${CMAKE_HOST_SYSTEM_NAME}")
message(STATUS "${CMAKE_SIZEOF_VOID_P} ${CMAKE_SYSTEM_NAME}")
if(CMAKE_CROSSCOMPILING)
  if(${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES 64)
    set(HOST_64 TRUE)
  else()
    set(HOST_64 FALSE)
  endif()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TARGET_64 TRUE)
  else()
    set(TARGET_64 FALSE)
  endif()
  message(STATUS "HOST_64 is ${HOST_64}")
  message(STATUS "TARGET_64 is ${TARGET_64}")

  if(HOST_64)
    if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL Darwin)
      if(NOT TARGET_64)
        if(TARGET_SYS)
          set(TARGET_SYS "-DTARGET_SYS=${TARGET_SYS}")
        endif()
        set(USE_64BITS OFF)
        set(WINE true)
        set(HOST_WINE wine)
        set(TOOLCHAIN "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_LIST_DIR}/Utils/windows.toolchain.cmake")
      endif()
    elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL ${CMAKE_SYSTEM_NAME})
      if(TARGET_64)
        set(TOOLCHAIN "-UCMAKE_TOOLCHAIN_FILE")
        if(DEFINED ENV{CMAKE_TOOLCHAIN_FILE})
          message(STATUS "Check CMAKE_TOOLCHAIN_FILE in environment variable, found")
          unset(ENV{CMAKE_TOOLCHAIN_FILE})
          message(WARNING "unset Environment Variables CMAKE_TOOLCHAIN_FILE")
        else()
          message(STATUS "Check CMAKE_TOOLCHAIN_FILE in environment variable, not found")
        endif()
          endif()
        else()
      message(WARNING "build ${CMAKE_SYSTEM_NAME} for on ${CMAKE_HOST_SYSTEM_NAME}")
    endif()
  else()
    set(TOOLCHAIN "-UCMAKE_TOOLCHAIN_FILE")
    if(DEFINED ENV{CMAKE_TOOLCHAIN_FILE})
      message(STATUS "Check CMAKE_TOOLCHAIN_FILE in environment variable, found")
      unset(ENV{CMAKE_TOOLCHAIN_FILE})
      message(WARNING "unset Environment Variables CMAKE_TOOLCHAIN_FILE")
    else()
      message(STATUS "Check CMAKE_TOOLCHAIN_FILE in environment variable, not found")
    endif()
  endif()
endif()

include(CheckTypeSize)
include(TestBigEndian)
test_big_endian(LJ_BIG_ENDIAN)

include(${CMAKE_CURRENT_LIST_DIR}/Modules/DetectArchitecture.cmake)
detect_architecture(LJ_DETECTED_ARCH)

include(${CMAKE_CURRENT_LIST_DIR}/Modules/DetectFPUApi.cmake)
detect_fpu_mode(LJ_DETECTED_FPU_MODE)
detect_fpu_abi(LJ_DETECTED_FPU_ABI)

if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
  find_library(LIBM_LIBRARIES NAMES m)
  find_library(LIBDL_LIBRARIES NAMES dl)
endif()

if(LUA_TARGET_SHARED)
  add_definitions(-fPIC)
endif()

set(TARGET_ARCH "")
set(DASM_FLAGS "")

set(LJ_TARGET_ARCH "")
if("${LJ_DETECTED_ARCH}" STREQUAL "x86")
  set(LJ_TARGET_ARCH "x86")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "x86_64")
  set(LJ_TARGET_ARCH "x64")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "AArch64")
  set(LJ_TARGET_ARCH "arm64")
  if(LJ_BIG_ENDIAN)
    set(TARGET_ARCH -D__AARCH64EB__=1)
  endif()
elseif("${LJ_DETECTED_ARCH}" STREQUAL "ARM")
  set(LJ_TARGET_ARCH "arm")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "Mips64")
  set(LJ_TARGET_ARCH "mips64")
  if(NOT LJ_BIG_ENDIAN)
    set(TARGET_ARCH -D__MIPSEL__=1)
  endif()
elseif("${LJ_DETECTED_ARCH}" STREQUAL "Loongarch64")
  set(LJ_TARGET_ARCH "loongarch64")
  set(TARGET_ARCH -DLJ_ARCH_ENDIAN=LUAJIT_LE)
elseif("${LJ_DETECTED_ARCH}" STREQUAL "Mips")
  set(LJ_TARGET_ARCH "mips")
  if(NOT LJ_BIG_ENDIAN)
    set(TARGET_ARCH -D__MIPSEL__=1)
  endif()
elseif("${LJ_DETECTED_ARCH}" STREQUAL "PowerPC")
  if(LJ_64)
    set(LJ_TARGET_ARCH "ppc64")
  else()
    set(LJ_TARGET_ARCH "ppc")
  endif()
  if(LJ_BIG_ENDIAN)
    set(TARGET_ARCH -DLJ_ARCH_ENDIAN=LUAJIT_BE)
  else()
    set(TARGET_ARCH -DLJ_ARCH_ENDIAN=LUAJIT_LE)
  endif()
else()
  message(FATAL_ERROR "Unsupported target architecture: '${LJ_DETECTED_ARCH}'")
endif()

if("${LJ_DETECTED_FPU_MODE}" STREQUAL "Hard")
  set(LJ_HAS_FPU 1)
  set(DASM_FLAGS ${DASM_FLAGS} -D FPU)
  set(TARGET_ARCH ${TARGET_ARCH} -DLJ_ARCH_HASFPU=1)
else()
  set(LJ_HAS_FPU 0)
  set(TARGET_ARCH ${TARGET_ARCH} -DLJ_ARCH_HASFPU=0)
endif()

if("${LJ_DETECTED_FPU_ABI}" STREQUAL "Hard")
  set(LJ_ABI_SOFTFP 0)
  set(DASM_FLAGS ${DASM_FLAGS} -D HFABI)
  set(TARGET_ARCH ${TARGET_ARCH} -DLJ_ABI_SOFTFP=0)
else()
  set(LJ_ABI_SOFTFP 1)
  set(TARGET_ARCH ${TARGET_ARCH} -DLJ_ABI_SOFTFP=1)
endif()

set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_TARGET=LUAJIT_ARCH_${LJ_TARGET_ARCH})

if(WIN32 OR MINGW)
  set(DASM_FLAGS ${DASM_FLAGS} -D WIN)
endif()

set(ARM64_CROSS_MSVC 0)
if (MSVC)
  if ("${LJ_DETECTED_ARCH}" STREQUAL "AArch64" AND
  "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL ARM64)
    set(ARM64_CROSS_MSVC 1)
    message(STATUS "Compiling for ARM64 with MSVC: ${ARM64_CROSS_MSVC}")
  endif()
endif()

include(${CMAKE_CURRENT_LIST_DIR}/Modules/FindUnwind.cmake)
if (NOT unwind_FOUND)
  if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
    set(LUAJIT_NO_UNWIND OFF)
  else()
    set(LUAJIT_NO_UNWIND ON)
  endif()
  if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL mips64 OR
     "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL aarch64 OR
     "${CMAKE_SYSTEM_NAME}" STREQUAL Windows)
    if(NOT IOS)
      set(LUAJIT_NO_UNWIND IGNORE)
    endif()
  endif()
endif()

message(STATUS "#### CMAKE_SYSTEM_NAME is ${CMAKE_SYSTEM_NAME}")
message(STATUS "#### CMAKE_SYSTEM_PROCESSOR is ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "#### TARGET_ARCH is ${TARGET_ARCH}")
message(STATUS "#### unwind_FOUND is ${unwind_FOUND}")
message(STATUS "#### HAVE_UNWIND_H is ${HAVE_UNWIND_H}")
message(STATUS "#### HAVE_UNWIND_LIB is ${HAVE_UNWIND_LIB}")
message(STATUS "#### UNWIND_LIBRARY is ${UNWIND_LIBRARY}")

message(STATUS "#### LUAJIT_NO_UNWIND is ${LUAJIT_NO_UNWIND}")

set(LJ_DEFINITIONS "")
if(${LUAJIT_NO_UNWIND} STREQUAL ON)
  # LUAJIT_NO_UNWIND is ON
  set(DASM_FLAGS ${DASM_FLAGS} -D NO_UNWIND)
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_NO_UNWIND)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_NO_UNWIND)
elseif(${LUAJIT_NO_UNWIND} STREQUAL OFF)
  # LUAJIT_NO_UNWIND is OFF
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_UNWIND_EXTERNAL)
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_UNWIND_EXTERNAL)
endif()

if(ANDROID)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLJ_NO_SYSTEM=1)
endif()

if(IOS)
  set(LUAJIT_DISABLE_JIT ON)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLJ_NO_SYSTEM=1)
endif()

set(LJ_ENABLE_LARGEFILE 1)
if(ANDROID AND (CMAKE_SYSTEM_VERSION LESS 21))
  set(LJ_ENABLE_LARGEFILE 0)
elseif(WIN32 OR MINGW)
  set(LJ_ENABLE_LARGEFILE 0)
endif()

if(LJ_ENABLE_LARGEFILE)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS}
      -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE)
endif()

set(LJ_FFI 1)
if(LUAJIT_DISABLE_FFI)
  set(LJ_FFI 0)
endif()

set(LJ_JIT 1)
if(LUAJIT_DISABLE_JIT)
  set(LJ_JIT 0)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(LJ_64 1)
endif()

set(LJ_GC64 ${LJ_64})

if(LJ_64 AND LUAJIT_DISABLE_GC64 AND ("${LJ_TARGET_ARCH}" STREQUAL "x64"))
  set(LJ_GC64 0)
endif()

set(LJ_FR2 ${LJ_GC64})

set(LJ_NUMMODE_SINGLE 0) # Single-number mode only.
set(LJ_NUMMODE_SINGLE_DUAL 1) # Default to single-number mode.
set(LJ_NUMMODE_DUAL 2) # Dual-number mode only.
set(LJ_NUMMODE_DUAL_SINGLE 3) # Default to dual-number mode.

set(LJ_ARCH_NUMMODE ${LJ_NUMMODE_DUAL})
if(LJ_HAS_FPU)
  set(LJ_ARCH_NUMMODE ${LJ_NUMMODE_DUAL_SINGLE})
endif()

if(("${LJ_TARGET_ARCH}" STREQUAL "x86") OR
    ("${LJ_TARGET_ARCH}" STREQUAL "x64"))
  set(LJ_ARCH_NUMMODE ${LJ_NUMMODE_SINGLE_DUAL})
endif()

if(("${LJ_TARGET_ARCH}" STREQUAL "arm") OR
    ("${LJ_TARGET_ARCH}" STREQUAL "arm64") OR
    ("${LJ_TARGET_ARCH}" STREQUAL "mips") OR
    ("${LJ_TARGET_ARCH}" STREQUAL "mips64"))
  set(LJ_ARCH_NUMMODE ${LJ_NUMMODE_DUAL})
endif()

# Enable or disable the dual-number mode for the VM.
if(((LJ_ARCH_NUMMODE EQUAL LJ_NUMMODE_SINGLE) AND (LUAJIT_NUMMODE EQUAL 2)) OR
    ((LJ_ARCH_NUMMODE EQUAL LJ_NUMMODE_DUAL) AND (LUAJIT_NUMMODE EQUAL 1)))
  message(FATAL_ERROR "No support for this number mode on this architecture")
endif()
if(
    (LJ_ARCH_NUMMODE EQUAL LJ_NUMMODE_DUAL) OR
    ( (LJ_ARCH_NUMMODE EQUAL LJ_NUMMODE_DUAL_SINGLE) AND NOT
      (LUAJIT_NUMMODE EQUAL 1) ) OR
    ( (LJ_ARCH_NUMMODE EQUAL LJ_NUMMODE_SINGLE_DUAL) AND
      (LUAJIT_NUMMODE EQUAL 2) )
  )
  set(LJ_DUALNUM 1)
else()
  set(LJ_DUALNUM 0)
endif()

set(BUILDVM_ARCH_H ${CMAKE_CURRENT_BINARY_DIR}/buildvm_arch.h)
set(DASM_PATH ${LUAJIT_DIR}/dynasm/dynasm.lua)

if(NOT LJ_BIG_ENDIAN)
  set(DASM_FLAGS ${DASM_FLAGS} -D ENDIAN_LE)
else()
  set(DASM_FLAGS ${DASM_FLAGS} -D ENDIAN_BE)
endif()

if(LJ_64)
  set(DASM_FLAGS ${DASM_FLAGS} -D P64)
endif()

if(LJ_FFI)
  set(DASM_FLAGS ${DASM_FLAGS} -D FFI)
endif()

if(LJ_JIT)
  set(DASM_FLAGS ${DASM_FLAGS} -D JIT)
endif()

if(LJ_DUALNUM)
  set(DASM_FLAGS ${DASM_FLAGS} -D DUALNUM)
endif()

set(DASM_ARCH ${LJ_TARGET_ARCH})

if("${LJ_TARGET_ARCH}" STREQUAL "x64")
  if(NOT LJ_FR2)
    set(DASM_ARCH "x86")
  endif()
endif()

set(DASM_FLAGS ${DASM_FLAGS} -D VER=)

set(TARGET_OS_FLAGS "")
if(${CMAKE_SYSTEM_NAME} STREQUAL Android)
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_LINUX -DTARGET_OS_IPHONE=0)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Windows)
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_WINDOWS -DTARGET_OS_IPHONE=0)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_OSX -DTARGET_OS_IPHONE=0)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_LINUX -DTARGET_OS_IPHONE=0)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Haiku)
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_POSIX -DTARGET_OS_IPHONE=0)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "(Open|Free|Net)BSD")
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_BSD -DTARGET_OS_IPHONE=0)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL iOS)
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_OSX -DTARGET_OS_IPHONE=1)
else()
  set(TARGET_OS_FLAGS ${TARGET_OS_FLAGS} -DLUAJIT_OS=LUAJIT_OS_OTHER -DTARGET_OS_IPHONE=0)
endif()

if(LUAJIT_DISABLE_GC64)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_DISABLE_GC64)
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_DISABLE_GC64)
endif()

set(TARGET_ARCH ${TARGET_ARCH} ${TARGET_OS_FLAGS})
set(LJ_DEFINITIONS ${LJ_DEFINITIONS} ${TARGET_OS_FLAGS})

if(LUAJIT_DISABLE_FFI)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_DISABLE_FFI)
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_DISABLE_FFI)
endif()
if(LUAJIT_DISABLE_JIT)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_DISABLE_JIT)
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_DISABLE_JIT)
endif()

if(("${LUAJIT_NUMMODE}" STREQUAL "1") OR
    ("${LUAJIT_NUMMODE}" STREQUAL "2"))
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_NUMMODE=${LUAJIT_NUMMODE})
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_NUMMODE=${LUAJIT_NUMMODE})
endif()

if(LUAJIT_ENABLE_GDBJIT)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_ENABLE_GDBJIT)
  set(TARGET_ARCH ${TARGET_ARCH} -DLUAJIT_ENABLE_GDBJIT)
endif()

set(VM_DASC_PATH ${LJ_DIR}/vm_${DASM_ARCH}.dasc)

# Build the minilua for host platform
if((NOT CMAKE_CROSSCOMPILING) OR ARM64_CROSS_MSVC)
  add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/host/minilua)
  set(MINILUA_PATH $<TARGET_FILE:minilua>)
else()
  make_directory(${CMAKE_CURRENT_BINARY_DIR}/minilua)
  if (HOST_WINE)
    set(MINILUA_PATH ${CMAKE_CURRENT_BINARY_DIR}/minilua/minilua.exe)
  else()
    set(MINILUA_PATH ${CMAKE_CURRENT_BINARY_DIR}/minilua/minilua)
  endif()

  add_custom_command(OUTPUT ${MINILUA_PATH}
    COMMAND ${CMAKE_COMMAND} ${TOOLCHAIN} ${TARGET_SYS} -DLUAJIT_DIR=${LUAJIT_DIR}
            -DCMAKE_SIZEOF_VOID_P=${CMAKE_SIZEOF_VOID_P}
            ${CMAKE_CURRENT_LIST_DIR}/host/minilua
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/minilua
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/minilua)

  add_custom_target(minilua ALL
    DEPENDS ${MINILUA_PATH}
  )
endif()

# Generate luajit.h
set(GIT_FORMAT %ct)
if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  set(GIT_FORMAT %%ct)
endif()

execute_process(
  COMMAND git --version
  RESULT_VARIABLE GIT_EXISTENCE
  OUTPUT_VARIABLE GIT_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND git rev-parse --is-inside-work-tree
  RESULT_VARIABLE GIT_IN_REPOSITORY
  OUTPUT_VARIABLE GIT_IS_IN_REPOSITORY
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

if ((GIT_EXISTENCE EQUAL 0) AND (GIT_IN_REPOSITORY EQUAL 0))
  message(STATUS "Using Git: ${GIT_VERSION}")
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/luajit_relver.txt
    COMMAND git -c log.showSignature=false show -s --format=${GIT_FORMAT} > ${CMAKE_CURRENT_BINARY_DIR}/luajit_relver.txt
    WORKING_DIRECTORY ${LUAJIT_DIR}
  )
else()
  string(TIMESTAMP current_epoch "%s")
  message(STATUS "Using current epoch: ${current_epoch}")
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/luajit_relver.txt
    COMMAND echo "${current_epoch}" > ${CMAKE_CURRENT_BINARY_DIR}/luajit_relver.txt
    WORKING_DIRECTORY ${LUAJIT_DIR}
   )
endif()

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/luajit.h
  COMMAND ${HOST_WINE} ${MINILUA_PATH} ${LUAJIT_DIR}/src/host/genversion.lua
  ARGS ${LUAJIT_DIR}/src/luajit_rolling.h
       ${CMAKE_CURRENT_BINARY_DIR}/luajit_relver.txt
       ${CMAKE_CURRENT_BINARY_DIR}/luajit.h
  DEPENDS ${LUAJIT_DIR}/src/luajit_rolling.h
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/luajit_relver.txt
)

# Generate buildvm_arch.h
add_custom_command(OUTPUT ${BUILDVM_ARCH_H}
  COMMAND ${HOST_WINE} ${MINILUA_PATH} ${DASM_PATH} ${DASM_FLAGS}
          -o ${BUILDVM_ARCH_H} ${VM_DASC_PATH}
  DEPENDS minilua ${DASM_PATH} ${CMAKE_CURRENT_BINARY_DIR}/luajit.h)
add_custom_target(buildvm_arch_h ALL
  DEPENDS ${BUILDVM_ARCH_H}
)

# Build the buildvm for host platform
set(BUILDVM_COMPILER_FLAGS "${TARGET_ARCH}")

set(BUILDVM_COMPILER_FLAGS_PATH
  "${CMAKE_CURRENT_BINARY_DIR}/buildvm_flags.config")
file(WRITE ${BUILDVM_COMPILER_FLAGS_PATH} "${BUILDVM_COMPILER_FLAGS}")

set(BUILDVM_EXE buildvm)
if(HOST_WINE)
  set(BUILDVM_EXE buildvm.exe)
endif()

if((NOT CMAKE_CROSSCOMPILING) OR ARM64_CROSS_MSVC)
  add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/host/buildvm)
  set(BUILDVM_PATH $<TARGET_FILE:buildvm>)
  add_dependencies(buildvm buildvm_arch_h)
else()
  set(BUILDVM_PATH ${CMAKE_CURRENT_BINARY_DIR}/buildvm/${BUILDVM_EXE})

  make_directory(${CMAKE_CURRENT_BINARY_DIR}/buildvm)

  add_custom_command(OUTPUT ${BUILDVM_PATH}
    COMMAND ${CMAKE_COMMAND} ${TOOLCHAIN} ${TARGET_SYS}
            ${CMAKE_CURRENT_LIST_DIR}/host/buildvm
            -DCMAKE_SIZEOF_VOID_P=${CMAKE_SIZEOF_VOID_P}
            -DLUAJIT_DIR=${LUAJIT_DIR}
            -DEXTRA_COMPILER_FLAGS_FILE=${BUILDVM_COMPILER_FLAGS_PATH}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}/buildvm
    DEPENDS ${CMAKE_CURRENT_LIST_DIR}/host/buildvm/CMakeLists.txt
    DEPENDS buildvm_arch_h
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/buildvm)

  add_custom_target(buildvm ALL
    DEPENDS ${BUILDVM_PATH}
  )
endif()

set(LJVM_MODE elfasm)
if(APPLE)
  set(LJVM_MODE machasm)
elseif(WIN32 OR MINGW)
  set(LJVM_MODE peobj)
endif()

set(LJ_VM_NAME lj_vm.S)
if("${LJVM_MODE}" STREQUAL "peobj")
  set(LJ_VM_NAME lj_vm.obj)
endif()
if(IOS)
  set_source_files_properties(${LJ_VM_NAME} PROPERTIES
    COMPILE_FLAGS "-arch ${ARCHS} -isysroot ${CMAKE_OSX_SYSROOT} ${BITCODE}")
endif()


set(LJ_VM_S_PATH ${CMAKE_CURRENT_BINARY_DIR}/${LJ_VM_NAME})
add_custom_command(OUTPUT ${LJ_VM_S_PATH}
  COMMAND ${HOST_WINE} ${BUILDVM_PATH} -m ${LJVM_MODE} -o ${LJ_VM_S_PATH}
  DEPENDS buildvm
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)

if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET AND NOT(CMAKE_CROSSCOMPILING))
  set_source_files_properties(${LJ_VM_NAME} PROPERTIES
    COMPILE_FLAGS -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
endif()

make_directory(${CMAKE_CURRENT_BINARY_DIR}/jit)
set(LJ_LIBDEF_PATH ${CMAKE_CURRENT_BINARY_DIR}/lj_libdef.h)
set(LJ_RECDEF_PATH ${CMAKE_CURRENT_BINARY_DIR}/lj_recdef.h)
set(LJ_FFDEF_PATH ${CMAKE_CURRENT_BINARY_DIR}/lj_ffdef.h)
set(LJ_BCDEF_PATH ${CMAKE_CURRENT_BINARY_DIR}/lj_bcdef.h)
set(LJ_VMDEF_PATH ${CMAKE_CURRENT_BINARY_DIR}/jit/vmdef.lua)

set(LJ_LIB_SOURCES
  ${LJ_DIR}/lib_base.c ${LJ_DIR}/lib_math.c ${LJ_DIR}/lib_bit.c
  ${LJ_DIR}/lib_string.c ${LJ_DIR}/lib_table.c ${LJ_DIR}/lib_io.c
  ${LJ_DIR}/lib_os.c ${LJ_DIR}/lib_package.c ${LJ_DIR}/lib_debug.c
  ${LJ_DIR}/lib_jit.c ${LJ_DIR}/lib_ffi.c ${LJ_DIR}/lib_buffer.c)
add_custom_command(
  OUTPUT ${LJ_LIBDEF_PATH} ${LJ_VMDEF_PATH} ${LJ_RECDEF_PATH} ${LJ_FFDEF_PATH}
  OUTPUT ${LJ_BCDEF_PATH}
  COMMAND ${HOST_WINE}
    ${BUILDVM_PATH} -m libdef -o ${LJ_LIBDEF_PATH} ${LJ_LIB_SOURCES}
  COMMAND ${HOST_WINE}
    ${BUILDVM_PATH} -m recdef -o ${LJ_RECDEF_PATH} ${LJ_LIB_SOURCES}
  COMMAND ${HOST_WINE}
    ${BUILDVM_PATH} -m ffdef -o ${LJ_FFDEF_PATH} ${LJ_LIB_SOURCES}
  COMMAND ${HOST_WINE}
    ${BUILDVM_PATH} -m bcdef -o ${LJ_BCDEF_PATH} ${LJ_LIB_SOURCES}
  COMMAND ${HOST_WINE}
    ${BUILDVM_PATH} -m vmdef -o ${LJ_VMDEF_PATH} ${LJ_LIB_SOURCES}
  DEPENDS buildvm ${LJ_LIB_SOURCE}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)

add_custom_target(lj_gen_headers ALL
  DEPENDS ${LJ_LIBDEF_PATH} ${LJ_RECDEF_PATH} ${LJ_VMDEF_PATH}
  DEPENDS ${LJ_FFDEF_PATH} ${LJ_BCDEF_PATH}
)

set(LJ_FOLDDEF_PATH ${CMAKE_CURRENT_BINARY_DIR}/lj_folddef.h)

set(LJ_FOLDDEF_SOURCE ${LJ_DIR}/lj_opt_fold.c)
add_custom_command(
  OUTPUT ${LJ_FOLDDEF_PATH}
  COMMAND ${HOST_WINE}
    ${BUILDVM_PATH} -m folddef -o ${LJ_FOLDDEF_PATH} ${LJ_FOLDDEF_SOURCE}
  DEPENDS ${BUILDVM_PATH}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)

add_custom_target(lj_gen_folddef ALL
  DEPENDS ${LJ_FOLDDEF_PATH}
)

file(GLOB_RECURSE SRC_LJCORE    "${LJ_DIR}/lj_*.c")
file(GLOB_RECURSE SRC_LIBCORE   "${LJ_DIR}/lib_*.c")

if(LUAJIT_BUILD_ALAMG)
  set(luajit_sources ${LJ_DIR}/ljamalg.c ${LJ_VM_NAME})
else()
  set(luajit_sources ${SRC_LIBCORE} ${SRC_LJCORE} ${LJ_VM_NAME})
endif()

# Build the luajit static library
add_library(libluajit ${luajit_sources})
if(MSVC)
  set_target_properties(libluajit PROPERTIES OUTPUT_NAME libluajit)
else()
  set_target_properties(libluajit PROPERTIES OUTPUT_NAME luajit)
endif()
add_dependencies(libluajit
  buildvm_arch_h
  buildvm
  lj_gen_headers
  lj_gen_folddef)
target_include_directories(libluajit PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(libluajit PUBLIC
  ${LJ_DIR})
if(BUILD_SHARED_LIBS)
  if(WIN32)
    set(LJ_DEFINITIONS ${LJ_DEFINITIONS}
      -DLUA_BUILD_AS_DLL -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS)
  endif()
endif()

if(LIBM_LIBRARIES)
  target_link_libraries(libluajit ${LIBM_LIBRARIES})
endif()

if(LIBDL_LIBRARIES)
  target_link_libraries(libluajit ${LIBDL_LIBRARIES})
endif()

if(LUAJIT_ENABLE_LUA52COMPAT)
  set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUAJIT_ENABLE_LUA52COMPAT)
endif()

set(LJ_DEFINITIONS ${LJ_DEFINITIONS} -DLUA_MULTILIB="${LUA_MULTILIB}")
target_compile_definitions(libluajit PRIVATE ${LJ_DEFINITIONS})
if(IOS)
    set_xcode_property(libluajit IPHONEOS_DEPLOYMENT_TARGET "9.0" "all")
endif()

if("${LJ_TARGET_ARCH}" STREQUAL "x86")
  if(CMAKE_COMPILER_IS_CLANGXX OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(libluajit PRIVATE
      -march=i686 -msse -msse2 -mfpmath=sse)
  endif()
  if(MSVC)
    target_compile_options(libluajit PRIVATE "/arch:SSE2")
  endif()
endif()

set(LJ_COMPILE_OPTIONS -U_FORTIFY_SOURCE)
if(NO_STACK_PROTECTOR_FLAG)
  set(LJ_COMPILE_OPTIONS ${LJ_COMPILE_OPTIONS} -fno-stack-protector)
endif()
if(IOS AND ("${LJ_TARGET_ARCH}" STREQUAL "arm64"))
  set(LJ_COMPILE_OPTIONS ${LJ_COMPILE_OPTIONS} -fno-omit-frame-pointer)
endif()

target_compile_options(libluajit PRIVATE ${LJ_COMPILE_OPTIONS})
if(MSVC)
  target_compile_options(libluajit PRIVATE "/D_CRT_STDIO_INLINE=__declspec(dllexport)__inline")
endif()

if("${LJ_DETECTED_ARCH}" STREQUAL "Loongarch64")
  set(LJ_TARGET_ARCH "loongarch64")
  target_compile_options(libluajit PRIVATE "-fwrapv")
endif()

set(luajit_headers
  ${LJ_DIR}/lauxlib.h
  ${LJ_DIR}/lua.h
  ${LJ_DIR}/luaconf.h
  ${LJ_DIR}/lualib.h
  ${CMAKE_CURRENT_BINARY_DIR}/luajit.h)
install(FILES ${luajit_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/luajit)
install(TARGETS libluajit
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Build the luajit binary
if (LUAJIT_BUILD_EXE)
  add_executable(luajit ${LJ_DIR}/luajit.c)
  target_link_libraries(luajit libluajit)
  target_include_directories(luajit PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LJ_DIR}
  )
  if(APPLE AND ${CMAKE_C_COMPILER_ID} STREQUAL "zig")
    target_link_libraries(luajit c pthread)
    set_target_properties(luajit PROPERTIES
      LINK_FLAGS "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
  endif()
  if(WIN32)
    target_compile_definitions(libluajit PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
  if(HAVE_UNWIND_LIB AND (NOT LUAJIT_NO_UNWIND STREQUAL ON))
    target_link_libraries(luajit ${UNWIND_LIBRARY})
  endif()

  target_compile_definitions(luajit PRIVATE ${LJ_DEFINITIONS})
  file(COPY ${LJ_DIR}/jit DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

  install(TARGETS luajit DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

add_library(luajit-header INTERFACE)
target_include_directories(luajit-header INTERFACE ${LJ_DIR})

add_library(luajit::lib ALIAS libluajit)
add_library(luajit::header ALIAS luajit-header)
add_executable(luajit::lua ALIAS luajit)
