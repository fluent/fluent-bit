# - Try to find Journald library.
# Once done this will define
#
#  JOURNALD_FOUND - system has Journald
#  JOURNALD_INCLUDE_DIR - the Journald include directory
#  JOURNALD_LIBRARIES - Link these to use Journald
#  JOURNALD_DEFINITIONS - Compiler switches required for using Journald
#  SYSTEMD_UNITDIR - The systemd units' directory
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

# Copyright (c) 2015 David Edmundson
#

# use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
find_package(PkgConfig)
pkg_check_modules(PC_JOURNALD QUIET systemd)
pkg_get_variable(PC_SYSTEMD_UNITDIR systemd "systemdsystemunitdir")

set(SYSTEMD_UNITDIR ${PC_SYSTEMD_UNITDIR})
set(JOURNALD_FOUND ${PC_JOURNALD_FOUND})
set(JOURNALD_DEFINITIONS ${PC_JOURNALD_CFLAGS_OTHER})

find_path(JOURNALD_INCLUDE_DIR NAMES systemd/sd-journal.h
  PATHS
  ${PC_JOURNALD_INCLUDEDIR}
  ${PC_JOURNALD_INCLUDE_DIRS}
)

find_library(JOURNALD_LIBRARY NAMES systemd
  PATHS
  ${PC_JOURNALD_LIBDIR}
  ${PC_JOURNALD_LIBRARY_DIRS}
)

set(JOURNALD_LIBRARIES ${JOURNALD_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Journald DEFAULT_MSG JOURNALD_LIBRARY JOURNALD_INCLUDE_DIR)

include(FeatureSummary)
set_package_properties(Journald PROPERTIES URL https://github.com/systemd
  DESCRIPTION "Systemd logging daemon")

# show the JOURNALD_INCLUDE_DIR and JOURNALD_LIBRARY variables only in the advanced view
mark_as_advanced(JOURNALD_INCLUDE_DIR JOURNALD_LIBRARY)
