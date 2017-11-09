################################################################################

# Build Flags used for win32 platform

################################################################################
# Compile flags

# Common compile flags
SET(SHARED_COMPILE_FLAGS                "/D _WIN64 /D WIN64 /D _WINDOWS /D _CRT_SECURE_NO_WARNINGS /nologo /GF /Oi /fp:fast /bigobj /errorReport:prompt /WX- /MP /EHsc")
if(${VS} EQUAL 2015)
    # temporary
    SET(SHARED_COMPILE_FLAGS            "${SHARED_COMPILE_FLAGS}")
endif()

SET(SHARED_COMPILE_FLAGS_DEBUG          "/D NDEBUG /MT /Od /Ob0 /Zi /GS /RTC1")
SET(SHARED_COMPILE_FLAGS_RELEASE        "/D NDEBUG /MT /O2 /Ob0 /Zi /GS-")
SET(SHARED_COMPILE_FLAGS_PROFILE        "/D NDEBUG /MT /O2 /Ob0 /Zi /GS-")
SET(SHARED_COMPILE_FLAGS_RETAIL         "/D NDEBUG /MT /O2 /Ob0 /GS-")

set (CMAKE_CXX_FLAGS                    "${SHARED_COMPILE_FLAGS}")
set (CMAKE_CXX_FLAGS_DEBUG              "${SHARED_COMPILE_FLAGS_DEBUG}")
set (CMAKE_CXX_FLAGS_RELEASE            "${SHARED_COMPILE_FLAGS_RELEASE}")
set (CMAKE_CXX_FLAGS_PROFILE            "${SHARED_COMPILE_FLAGS_PROFILE}")
set (CMAKE_CXX_FLAGS_RETAIL             "${SHARED_COMPILE_FLAGS_RETAIL}")

set (CMAKE_C_FLAGS                      "${SHARED_COMPILE_FLAGS}")
set (CMAKE_C_FLAGS_DEBUG                "${SHARED_COMPILE_FLAGS_DEBUG}")
set (CMAKE_C_FLAGS_RELEASE              "${SHARED_COMPILE_FLAGS_RELEASE}")
set (CMAKE_C_FLAGS_PROFILE              "${SHARED_COMPILE_FLAGS_PROFILE}")
set (CMAKE_C_FLAGS_RETAIL               "${SHARED_COMPILE_FLAGS_RETAIL}")

################################################################################
# Linker flags

set(STORM_LINKER_FLAGS                  "/MACHINE:X64 /IGNORE:4221")
set(STORM_LINKER_FLAGS_DEBUG            "")
set(STORM_LINKER_FLAGS_RELEASE          "")
set(STORM_LINKER_FLAGS_PROFILE          "")
set(STORM_LINKER_FLAGS_RETAIL           "")

set(CMAKE_SHARED_LINKER_FLAGS           "${STORM_LINKER_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG     "${STORM_LINKER_FLAGS_DEBUG} /DEBUG")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE   "${STORM_LINKER_FLAGS_RELEASE} /DEBUG")
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE   "${STORM_LINKER_FLAGS_PROFILE} /DEBUG")
set(CMAKE_SHARED_LINKER_FLAGS_RETAIL    "${STORM_LINKER_FLAGS_RETAIL} /MAP /MAPINFO:EXPORTS")

set(CMAKE_STATIC_LINKER_FLAGS           "${STORM_LINKER_FLAGS}")
set(CMAKE_STATIC_LINKER_FLAGS_DEBUG     "${STORM_LINKER_FLAGS_DEBUG}")
set(CMAKE_STATIC_LINKER_FLAGS_RELEASE   "${STORM_LINKER_FLAGS_RELEASE}")
set(CMAKE_STATIC_LINKER_FLAGS_PROFILE   "${STORM_LINKER_FLAGS_PROFILE}")
set(CMAKE_STATIC_LINKER_FLAGS_RETAIL    "${STORM_LINKER_FLAGS_RETAIL}")

set(CMAKE_EXE_LINKER_FLAGS              "${STORM_LINKER_FLAGS} /INCREMENTAL:NO")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG        "${STORM_LINKER_FLAGS_DEBUG} /DEBUG")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE      "${STORM_LINKER_FLAGS_RELEASE} /DEBUG")
set(CMAKE_EXE_LINKER_FLAGS_PROFILE      "${STORM_LINKER_FLAGS_PROFILE} /DEBUG")
set(CMAKE_EXE_LINKER_FLAGS_RETAIL       "${STORM_LINKER_FLAGS_RETAIL} /MAP /MAPINFO:EXPORTS")

################################################################################
# Storm specific build flags

# configure win32 API for Windows 7+ compatibility
set(WINVER "0x0601" CACHE STRING "Win32 API Target version (see http://msdn.microsoft.com/en-us/library/aa383745%28v=VS.85%29.aspx)")
add_definitions("/DWINVER=${WINVER}" "/D_WIN32_WINNT=${WINVER}")

if(NOT USE_RTTI)
    SET(CMAKE_CXX_FLAGS                 "${CMAKE_CXX_FLAGS} /GR-")
endif()

################################################################################
