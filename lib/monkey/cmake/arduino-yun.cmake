# Arduino YUN toolchain helper file
include(CMakeForceCompiler)

if(NOT YUN_ROOT)
  set(YUN_ROOT /home/edsiper/coding/ArduinoYun-x86_64-OpenWRT-mips-linux-toolchain)
endif()

set(YUN_TC ${YUN_ROOT}/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR mips)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_C_COMPILER   ${YUN_TC}/bin/mips-openwrt-linux-uclibc-gcc)

# where is the target environment
set(CMAKE_FIND_ROOT_PATH ${YUN_ROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
