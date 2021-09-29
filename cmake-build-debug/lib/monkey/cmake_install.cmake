# Install script for directory: /home/shikugawa/dev/fluent-bit/lib/monkey

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/man/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/deps/rbtree/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/deps/regex/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/deps/flb_libco/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/mk_core/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/plugins/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/mk_server/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/mk_bin/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/conf/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/htdocs/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/include/cmake_install.cmake")
  include("/home/shikugawa/dev/fluent-bit/cmake-build-debug/lib/monkey/api/cmake_install.cmake")

endif()

