cmake_minimum_required(VERSION 3.5)
project(lua-ffi C)

set(CMAKE_MACOSX_RPATH 1)
if(NOT DEFINED BUILD_SHARED_LUA_FFI)
option(BUILD_SHARED_LUA_FFI "Shared or Static lua-ffi" ON)
endif()

if(DEFINED ENV{LIBFFI_DIR})
    set(LIBFFI_DIR $ENV{LIBFFI_DIR})
endif()

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

if(LIBFFI_DIR)
    enable_language(ASM)
    set(BUILD_SHARED_LUA_FFI OFF)

    file(GLOB FFI_C_SOURCES "${LIBFFI_DIR}/src/*.c")
    list(REMOVE_ITEM FFI_C_SOURCES "${LIBFFI_DIR}/src/dlmalloc.c")
    list(REMOVE_ITEM FFI_C_SOURCES "${LIBFFI_DIR}/src/java_raw_api.c")

    # config variables for ffi.h.in
    set(VERSION 3.4.4)

    set(KNOWN_PROCESSORS x86 x86_64 amd64 arm arm64 i386 i686 armv7l armv7-a mips mips64 mips64el aarch64 loongarch64)

    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" lower_system_processor)

    if(NOT lower_system_processor IN_LIST KNOWN_PROCESSORS)
        message(FATAL_ERROR "Unknown processor: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    set(FFI_ARCH OFF)
    set(INC_ARCH OFF)

    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        if(lower_system_processor STREQUAL "arm")
            set(TARGET ARM_WIN32)
            set(FFI_ARCH arm)
        elseif(lower_system_processor STREQUAL "arm64")
            set(TARGET ARM_WIN64)
            set(FFI_ARCH aarch64)
        elseif(lower_system_processor STREQUAL "x86")
            set(TARGET X86_WIN32)
            set(FFI_ARCH x86)
        elseif(lower_system_processor STREQUAL "x86_64")
            set(TARGET X86_WIN64)
            set(FFI_ARCH x86)
        else()
            message(FATAL_ERROR "Not support ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
        if(lower_system_processor MATCHES "arm64:aarch64")
            set(TARGET ARM64)
            set(FFI_ARCH aarch64)
        elseif(lower_system_processor STREQUAL "x86_64")
            set(FFI_ARCH x86)
        elseif(lower_system_processor MATCHES "mips64")
            set(TARGET mips64)
            set(FFI_ARCH mips64)
            set(INC_ARCH mips)
        elseif(lower_system_processor STREQUAL "loongarch64")
            set(TARGET LOONGARCH64)
            set(FFI_ARCH loongarch64)
        else()
            message(FATAL_ERROR "Not support ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
        if(lower_system_processor MATCHES "arm64|aarch64")
            set(TARGET ARM64)
            set(FFI_ARCH aarch64)
        elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
            set(TARGET X86_64)
            set(FFI_ARCH x86)
        elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
            set(TARGET X86_DARWIN)
            set(FFI_ARCH x86)
        else()
            message(FATAL_ERROR "Not support ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
        endif()
    else()
        message(FATAL_ERROR "Not support ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}, Please consult ${CMAKE_CURRENT_SOURCE_DIR}/configure.ac and add your platform to this CMake file.")
    endif()

    if(NOT INC_ARCH)
        set(INC_ARCH ${FFI_ARCH})
    endif()

    file(GLOB FFI_ARCH_C_SOURCES "${LIBFFI_DIR}/src/${FFI_ARCH}/*.c")
    file(GLOB FFI_ARCH_S_SOURCES "${LIBFFI_DIR}/src/${FFI_ARCH}/*.S")

    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    list(REMOVE_ITEM FFI_ARCH_S_SOURCES "${LIBFFI_DIR}/src/${FFI_ARCH}/sysv_intel.S")
        if(NOT lower_system_processor STREQUAL "x86_64")
            list(REMOVE_ITEM FFI_ARCH_S_SOURCES "${LIBFFI_DIR}/src/${FFI_ARCH}/win64_intel.S")
        endif()
    else()
    list(REMOVE_ITEM FFI_ARCH_S_SOURCES "${LIBFFI_DIR}/src/${FFI_ARCH}/sysv_intel.S")
    list(REMOVE_ITEM FFI_ARCH_S_SOURCES "${LIBFFI_DIR}/src/${FFI_ARCH}/win64_intel.S")
    endif()

    if("${TARGET}" MATCHES "X86_64|LOONGARCH64|ARM64|mips64")
        set(HAVE_LONG_DOUBLE 1)
    else()
        set(HAVE_LONG_DOUBLE 0)
    endif()
    set(FFI_EXEC_TRAMPOLINE_TABLE 0)

    # mimic layout of original buildsystem
    configure_file(${LIBFFI_DIR}/include/ffi.h.in ${CMAKE_BINARY_DIR}/include/ffi.h)

    set(FFI_INCLUDE_DIRS
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/ffi
        ${LIBFFI_DIR}/src/${INC_ARCH}
        ${LIBFFI_DIR}/include)
    set(FFI_SOURCES ${FFI_C_SOURCES} ${FFI_ARCH_C_SOURCES} ${FFI_ARCH_S_SOURCES})
    set(FFI_INCLUDE_DIR ${LIBFFI_DIR}/include ${CMAKE_CURRENT_BINARY_DIR})
else()
    include(GNUInstallDirs)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules (FFI REQUIRED libffi)

    find_package(Threads REQUIRED)
endif()


if(BUILD_SHARED_LUA_FFI)
    set(LUA_FFI_LIBTYPE MODULE)
    if(WIN32)
        add_definitions(-DLUA_BUILD_AS_DLL)
    endif()
else()
    set(LUA_FFI_LIBTYPE STATIC)
endif()

add_library(luaffi ${LUA_FFI_LIBTYPE} ${FFI_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/../thirdparty/ffi/ffi.c
)

if(LIBFFI_DIR)
    set_target_properties(luaffi PROPERTIES
        DEFINITIONS FFI_BUILDING
        COMPILE_FLAGS "-std=c11"
        INCLUDE_DIRECTORIES "${FFI_INCLUDE_DIRS}"
        )
endif()

target_include_directories(luaffi PUBLIC
    ${FFI_INCLUDE_DIR}
    ${LUA_INCLUDE_DIR}
    ${LUA_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../thirdparty/compat-5.3
)

if(BUILD_SHARED_LUA_FFI)
    target_link_libraries(luaffi PUBLIC
        ${FFI_LIBRARIES}
        Threads::Threads
    )

    if(WIN32)
        target_link_libraries(luaffi PUBLIC ${LUA_LIBRARIES})
    endif()

    if(APPLE)
        target_link_options(luaffi PUBLIC -bundle -undefined dynamic_lookup)
    endif()

    set_target_properties(luaffi PROPERTIES
        PREFIX ""
        OUTPUT_NAME "ffi"
    )

    install(TARGETS luaffi
        LIBRARY DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}
    )
else()
    get_directory_property(hasParent PARENT_DIRECTORY)
    if(hasParent)
        set(LUA_FFI_LIBS luaffi ${FFI_LIBRARIES} PARENT_SCOPE)
    else()
        set(LUA_FFI_LIBS luaffi ${FFI_LIBRARIES})
    endif()
endif()
