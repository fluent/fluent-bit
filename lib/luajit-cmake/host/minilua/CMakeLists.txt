cmake_minimum_required(VERSION 3.0)

project(minilua C)

find_library(LIBM_LIBRARIES NAMES m)

add_executable(minilua ${LUAJIT_DIR}/src/host/minilua.c)
if(LIBM_LIBRARIES)
  target_link_libraries(minilua ${LIBM_LIBRARIES})
endif()
if(TARGET_ARCH)
  string (REPLACE ";" " " STARGET_ARCH "${TARGET_ARCH}")
  set_target_properties(minilua PROPERTIES
    COMPILE_FLAGS "${STARGET_ARCH}")
endif()
