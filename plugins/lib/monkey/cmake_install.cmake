# Install script for directory: /Users/adheipsingh/parseable/fluent-bit/lib/monkey

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

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Library/Developer/CommandLineTools/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/man/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/deps/rbtree/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/deps/regex/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/deps/flb_libco/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/mk_core/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/plugins/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/mk_server/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/mk_bin/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/conf/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/htdocs/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/include/cmake_install.cmake")
  include("/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/api/cmake_install.cmake")

endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/adheipsingh/parseable/fluent-bit/plugins/lib/monkey/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
