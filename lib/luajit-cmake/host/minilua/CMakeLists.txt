cmake_minimum_required(VERSION 3.5)

project(minilua C)

if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
  find_library(LIBM_LIBRARIES NAMES m)
endif()

add_executable(minilua ${LUAJIT_DIR}/src/host/minilua.c)
if(LIBM_LIBRARIES)
  target_link_libraries(minilua ${LIBM_LIBRARIES})
endif()
if(TARGET_ARCH)
  string (REPLACE ";" " " STARGET_ARCH "${TARGET_ARCH}")
  set_target_properties(minilua PROPERTIES
    COMPILE_FLAGS "${STARGET_ARCH}")
endif()
