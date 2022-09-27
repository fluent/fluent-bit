cmake_minimum_required(VERSION 3.0)

project(buildvm C)

set(EXTRA_COMPILER_FLAGS_FILE ""
  CACHE PATH "Location of a file to specify extra compiler flags.")
set(EXTRA_COMPILER_FLAGS "")
if(EXISTS ${EXTRA_COMPILER_FLAGS_FILE})
  file(READ ${EXTRA_COMPILER_FLAGS_FILE} EXTRA_COMPILER_FLAGS)
else()
  set(EXTRA_COMPILER_FLAGS ${BUILDVM_COMPILER_FLAGS})
endif()

include(CheckTypeSize)
if("${EXTRA_COMPILER_FLAGS}" MATCHES "LUAJIT_ARCH_.*64")
  set(TARGET_SIZE_OF_P 8)
else()
  set(TARGET_SIZE_OF_P 4)
endif()

set(CXX_ARCH_FLAGS "")
if(NOT (CMAKE_SIZEOF_VOID_P EQUAL ${TARGET_SIZE_OF_P}))
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(CXX_ARCH_FLAGS "-m32")
    else()
      set(CXX_ARCH_FLAGS "-m64")
    endif()
endif()

find_library(LIBM_LIBRARIES NAMES m)

add_executable(buildvm
  ${LUAJIT_DIR}/src/host/buildvm.c
  ${LUAJIT_DIR}/src/host/buildvm_asm.c
  ${LUAJIT_DIR}/src/host/buildvm_fold.c
  ${LUAJIT_DIR}/src/host/buildvm_lib.c
  ${LUAJIT_DIR}/src/host/buildvm_peobj.c)

target_compile_options(buildvm PRIVATE
  ${EXTRA_COMPILER_FLAGS} ${CXX_ARCH_FLAGS})
target_link_libraries(buildvm PRIVATE ${CXX_ARCH_FLAGS})
if(LIBM)
  target_link_libraries(buildvm PRIVATE ${LIBM_LIBRARIES})
endif()

target_include_directories(buildvm PRIVATE
  ${LUAJIT_DIR}/src
  ${LUAJIT_DIR}/src/host
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/..
  ${CMAKE_CURRENT_BINARY_DIR}/../../..
  ${CMAKE_CURRENT_BINARY_DIR})
