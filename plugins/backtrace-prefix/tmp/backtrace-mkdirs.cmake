# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/Users/adheipsingh/parseable/fluent-bit/lib/libbacktrace-8602fda")
  file(MAKE_DIRECTORY "/Users/adheipsingh/parseable/fluent-bit/lib/libbacktrace-8602fda")
endif()
file(MAKE_DIRECTORY
  "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/src/backtrace-build"
  "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix"
  "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/tmp"
  "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/src/backtrace-stamp"
  "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/src"
  "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/src/backtrace-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/src/backtrace-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/adheipsingh/parseable/fluent-bit/plugins/backtrace-prefix/src/backtrace-stamp${cfgdir}") # cfgdir has leading slash
endif()
