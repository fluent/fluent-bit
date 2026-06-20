# Try to find Monkey HTTP Server core/library
# ===========================================
#
#   http://monkey-project.com
#
# Definitions:
#
#  - MONKEY_FOUND      : source code found
#  - MONKEY_INCLUDE_DIR: root include directory

unset(MONKEY_INCLUDE_DIR CACHE)
find_path(MONKEY_INCLUDE_DIR
  NAMES monkey/mk_core.h monkey/mk_lib.h
  PATHS ${PROJECT_SOURCE_DIR}/lib/monkey/include
  CMAKE_FIND_ROOT_PATH_BOTH
  )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Monkey DEFAULT_MSG MONKEY_INCLUDE_DIR)
include(FeatureSummary)
