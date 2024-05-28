# - Try to find cunit
# Once done this will define
#  CUNIT_FOUND        - System has cunit
#  CUNIT_INCLUDE_DIRS - The cunit include directories
#  CUNIT_LIBRARIES    - The libraries needed to use cunit

find_package(PkgConfig QUIET)
pkg_check_modules(PC_CUNIT QUIET cunit)

find_path(CUNIT_INCLUDE_DIR
  NAMES CUnit/CUnit.h
  HINTS ${PC_CUNIT_INCLUDE_DIRS}
)
find_library(CUNIT_LIBRARY
  NAMES cunit
  HINTS ${PC_CUNIT_LIBRARY_DIRS}
)

if(CUNIT_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+CU_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${CUNIT_INCLUDE_DIR}/CUnit/CUnit.h"
    CUNIT_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1"
    CUNIT_VERSION "${CUNIT_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CUNIT_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(CUnit REQUIRED_VARS
                                  CUNIT_LIBRARY CUNIT_INCLUDE_DIR
                                  VERSION_VAR CUNIT_VERSION)

if(CUNIT_FOUND)
  set(CUNIT_LIBRARIES     ${CUNIT_LIBRARY})
  set(CUNIT_INCLUDE_DIRS  ${CUNIT_INCLUDE_DIR})
endif()

mark_as_advanced(CUNIT_INCLUDE_DIR CUNIT_LIBRARY)
