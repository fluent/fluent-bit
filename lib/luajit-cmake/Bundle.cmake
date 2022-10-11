# Modfied from luajit.cmake Added LUA_ADD_EXECUTABLE Ryan Phillips <ryan at
# trolocsis.com> This CMakeLists.txt has been first taken from LuaDist Copyright
# (C) 2007-2011 LuaDist. Created by Peter Drahoš Redistribution and use of this
# file is allowed according to the terms of the MIT license. Debugged and (now
# seriously) modIFied by Ronan Collobert, for Torch7

if(NOT DEFINED BUNDLE_CMD)
  set(BUNDLE_CMD luajit CACHE STRING "Use lua to do lua file bundle")
endif()
if(NOT DEFINED BUNDLE_CMD_ARGS)
  set(BUNDLE_CMD_ARGS "" CACHE STRING "Bundle args for cross compile")
endif()
if(NOT DEFINED BUNDLE_USE_LUA2C)
  set(BUNDLE_USE_LUA2C OFF CACHE BOOL "Use bin2c.lua do lua file bundle")
endif()

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
 message(STATUS "BIG_ENDIAN")
else()
 message(STATUS "LITTLE_ENDIAN")
endif()

if(BUNDLE_USE_LUA2C)
  file(COPY ${CMAKE_CURRENT_LIST_DIR}/lua2c.lua DESTINATION ${LUA_TARGET_PATH})
endif()

macro(LUA_add_custom_commands luajit_target)
  set(target_srcs "")
  foreach(file ${ARGN})
    if(${file} MATCHES ".*\\.lua$")
      if(NOT IS_ABSOLUTE ${file})
        set(file "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
      endif()
      set(source_file ${file})
      string(LENGTH ${CMAKE_SOURCE_DIR} _luajit_source_dir_length)
      string(LENGTH ${file} _luajit_file_length)
      math(EXPR _begin "${_luajit_source_dir_length} + 1")
      math(EXPR _stripped_file_length
            "${_luajit_file_length} - ${_luajit_source_dir_length} - 1")
      string(SUBSTRING  ${file}
                        ${_begin}
                        ${_stripped_file_length}
                        stripped_file)

      set(
        generated_file
        "${CMAKE_BINARY_DIR}/luacode_tmp/${stripped_file}_${luajit_target}_generated.c"
        )

      add_custom_command(
        OUTPUT ${generated_file}
        MAIN_DEPENDENCY ${source_file}
        DEPENDS ${LUA_TARGET}
        COMMAND ${BUNDLE_CMD} ARGS
          ${BUNDLE_CMD_ARGS} lua2c.lua ${source_file} ${generated_file}
        COMMENT "${BUNDLE_CMD} ${BUNDLE_CMD_ARGS} lua2c.lua ${source_file} ${generated_file}"
        WORKING_DIRECTORY ${LUA_TARGET_PATH})

      get_filename_component(basedir ${generated_file} PATH)
      file(MAKE_DIRECTORY ${basedir})

      set(target_srcs ${target_srcs} ${generated_file})
      set_source_files_properties(${generated_file}
                                  properties
                                  generated
                                  true  # to say that "it is OK that the obj-
                                        # files do not exist before build time"
                                  )
    else()
      set(target_srcs ${target_srcs} ${file})
    endif()
  endforeach()
endmacro()

if(NOT LJ_TARGET_ARCH)
include(${CMAKE_CURRENT_LIST_DIR}/Modules/DetectArchitecture.cmake)
detect_architecture(LJ_DETECTED_ARCH)
if("${LJ_DETECTED_ARCH}" STREQUAL "x86")
  set(LJ_TARGET_ARCH "x86")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "x86_64")
  set(LJ_TARGET_ARCH "x64")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "AArch64")
  set(LJ_TARGET_ARCH "arm64")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "ARM")
  set(LJ_TARGET_ARCH "arm")
elseif("${LJ_DETECTED_ARCH}" STREQUAL "Mips64")
  if(IS_BIG_ENDIAN)
    set(LJ_TARGET_ARCH "mips64")
  else()
    set(LJ_TARGET_ARCH "mips64el")
  endif()
elseif("${LJ_DETECTED_ARCH}" STREQUAL "Mips")
  if(IS_BIG_ENDIAN)
    set(LJ_TARGET_ARCH "mips")
  else()
    set(LJ_TARGET_ARCH "mipsel")
  endif()
elseif("${LJ_DETECTED_ARCH}" STREQUAL "PowerPC")
  if(LJ_64)
    set(LJ_TARGET_ARCH "ppc64")
  else()
    set(LJ_TARGET_ARCH "ppc")
  endif()
else()
  message(FATAL_ERROR "Unsupported target architecture: '${LJ_DETECTED_ARCH}'")
endif()
endif()

macro(LUAJIT_add_custom_commands luajit_target)
  set(target_srcs "")

  if(WIN32)
    set(LJDUMP_OPT -b -g -a ${LJ_TARGET_ARCH} -o windows)
  elseif(APPLE)
    set(LJDUMP_OPT -b -g -a ${LJ_TARGET_ARCH} -o osx)
  elseif(ANDROID OR ${CMAKE_SYSTEM_NAME} STREQUAL Linux)
    set(LJDUMP_OPT -b -g -a ${LJ_TARGET_ARCH} -o linux)
  else()
    set(LJDUMP_OPT -b -g -a ${LJ_TARGET_ARCH})
  endif()

  foreach(file ${ARGN})
    if(${file} MATCHES ".*\\.lua$")
      if(NOT IS_ABSOLUTE ${file})
        set(file "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
      endif()
      set(source_file ${file})
      string(LENGTH ${CMAKE_SOURCE_DIR} _luajit_source_dir_length)
      string(LENGTH ${file} _luajit_file_length)
      math(EXPR _begin "${_luajit_source_dir_length} + 1")
      math(EXPR _stripped_file_length
            "${_luajit_file_length} - ${_luajit_source_dir_length} - 1")
      string(SUBSTRING ${file}
                        ${_begin}
                        ${_stripped_file_length}
                        stripped_file)

      set(
        generated_file
        "${CMAKE_CURRENT_BINARY_DIR}/jitted_tmp/${stripped_file}_${luajit_target}_generated${CMAKE_C_OUTPUT_EXTENSION}"
        )
      string(REPLACE ";" " " LJDUMP_OPT_STR "${LJDUMP_OPT}")

      add_custom_command(
        OUTPUT ${generated_file}
        MAIN_DEPENDENCY ${source_file}
        DEPENDS ${LUA_TARGET}
        COMMAND ${BUNDLE_CMD} ARGS
          ${BUNDLE_CMD_ARGS}
          ${LJDUMP_OPT} ${source_file} ${generated_file}
        COMMENT "${BUNDLE_CMD} ${BUNDLE_CMD_ARGS} ${LJDUMP_OPT_STR} ${source_file} ${generated_file}"
        WORKING_DIRECTORY ${LUA_TARGET_PATH})
      get_filename_component(basedir ${generated_file} PATH)
      file(MAKE_DIRECTORY ${basedir})

      set(target_srcs ${target_srcs} ${generated_file})
      set_source_files_properties(${generated_file}
                                  properties
                                  external_object
                                  true # this is an object file
                                  generated
                                  true  # to say that "it is OK that the obj-
                                        # files do not exist before build time"
                                  )
    else()
      set(target_srcs ${target_srcs} ${file})
    endif()
  endforeach()
endmacro()

if(BUNDLE_USE_LUA2C)

  macro(LUA_ADD_CUSTOM luajit_target)
    lua_add_custom_commands(${luajit_target} ${ARGN})
  endmacro()

  macro(LUA_ADD_EXECUTABLE luajit_target)
    lua_add_custom_commands(${luajit_target} ${ARGN})
    add_executable(${luajit_target} ${target_srcs})
  endmacro()

else()

  macro(LUA_ADD_CUSTOM luajit_target)
    luajit_add_custom_commands(${luajit_target} ${ARGN})
  endmacro()

  macro(LUA_ADD_EXECUTABLE luajit_target)
    luajit_add_custom_commands(${luajit_target} ${ARGN})
    add_executable(${luajit_target} ${target_srcs})
  endmacro()

endif()
