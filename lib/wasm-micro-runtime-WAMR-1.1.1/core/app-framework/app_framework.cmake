# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception


add_definitions (-DWASM_ENABLE_APP_FRAMEWORK=1)

set (APP_FRAMEWORK_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

if ( NOT DEFINED APP_FRAMEWORK_INCLUDE_TYPE )
    LIST (APPEND WASM_APP_LIB_SOURCE_ALL ${CMAKE_CURRENT_LIST_DIR}/app_ext_lib_export.c)
endif()

# app-native-shared and base are required
include (${APP_FRAMEWORK_ROOT_DIR}/app-native-shared/native_interface.cmake)
LIST (APPEND WASM_APP_SOURCE_ALL ${NATIVE_INTERFACE_SOURCE})

MACRO(SUBDIRLIST result curdir)
    FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
    SET(dirlist "")
    FOREACH(child ${children})
        IF(IS_DIRECTORY ${curdir}/${child})
        LIST(APPEND dirlist ${child})
        ENDIF()
    ENDFOREACH()
    SET(${result} ${dirlist})
ENDMACRO()

function (add_module_native arg)
    message ("Add native module ${ARGV0}")
    include (${APP_FRAMEWORK_ROOT_DIR}/${ARGV0}/native/wasm_lib.cmake)

    file (GLOB header
        ${APP_FRAMEWORK_ROOT_DIR}/${ARGV0}/native/*.h
        ${APP_FRAMEWORK_ROOT_DIR}/${ARGV0}/native/*.inl
    )

    LIST (APPEND WASM_APP_LIBS_DIR ${APP_FRAMEWORK_ROOT_DIR}/${ARGV0}/native)
    set (WASM_APP_LIBS_DIR ${WASM_APP_LIBS_DIR} PARENT_SCOPE)

    LIST (APPEND RUNTIME_LIB_HEADER_LIST ${header})
    set (RUNTIME_LIB_HEADER_LIST ${RUNTIME_LIB_HEADER_LIST} PARENT_SCOPE)

    LIST (APPEND WASM_APP_LIB_SOURCE_ALL ${WASM_APP_LIB_CURRENT_SOURCE})
    set (WASM_APP_LIB_SOURCE_ALL ${WASM_APP_LIB_SOURCE_ALL} PARENT_SCOPE)
endfunction ()

function (add_module_app arg)
    message ("Add app module ${ARGV0}")
    include (${APP_FRAMEWORK_ROOT_DIR}/${ARGV0}/app/wasm_app.cmake)

    LIST (APPEND WASM_APP_WA_INC_DIR_LIST "${APP_FRAMEWORK_ROOT_DIR}/${ARGV0}/app/wa-inc")
    set (WASM_APP_WA_INC_DIR_LIST ${WASM_APP_WA_INC_DIR_LIST} PARENT_SCOPE)

    LIST (APPEND WASM_APP_NAME ${ARGV0})
    set (WASM_APP_NAME ${WASM_APP_NAME} PARENT_SCOPE)

    LIST (APPEND WASM_APP_SOURCE_ALL ${WASM_APP_CURRENT_SOURCE})
    set (WASM_APP_SOURCE_ALL ${WASM_APP_SOURCE_ALL} PARENT_SCOPE)
endfunction ()

if ("${WAMR_BUILD_APP_LIST}" STREQUAL "WAMR_APP_BUILD_ALL")
    # add all modules under this folder
    SUBDIRLIST(SUBDIRS ${APP_FRAMEWORK_ROOT_DIR})

    FOREACH(subdir ${SUBDIRS})
        if ("${subdir}" STREQUAL "app-native-shared")
            continue()
        endif ()
        if ("${subdir}" STREQUAL "template")
            continue()
        endif ()

        if ( NOT DEFINED APP_FRAMEWORK_INCLUDE_TYPE )
            add_module_native (${subdir})
        else ()
            add_module_app (${subdir})
        endif ()
    ENDFOREACH()

else ()
    # add each module in the list
    FOREACH (dir IN LISTS WAMR_BUILD_APP_LIST)
        string(REPLACE "WAMR_APP_BUILD_" "" dir ${dir})
        string(TOLOWER ${dir} dir)

        if ( NOT DEFINED APP_FRAMEWORK_INCLUDE_TYPE )
            add_module_native (${dir})
        else ()
            add_module_app (${dir})
        endif ()
    ENDFOREACH (dir)

endif()
