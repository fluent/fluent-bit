# Custom build settings for macOS
#
# pytest are not supported on macOS yet. This file tweaks
# the build flags so that we can execute tests for onigmo on it.

if(ONIGMO_MACOS_DEFAULTS)
  message(STATUS "Overriding setttings with macos-setup.cmake")
  set(ONIGMO_PYTHON_TESTS No)
endif()
