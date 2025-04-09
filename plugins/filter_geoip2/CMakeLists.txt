# libmaxminddb

# The subdirectory 'libmaxminddb' was imported from the following repo.
# (The minimum set of files required to compile geoip2.c were imported)
#
# https://github.com/maxmind/libmaxminddb
#
# We keep the exact version in the file 'libmaxminddb/VERSION',
# Please update the content when you upgrade libmaxminddb.
#
option(BUILD_TESTING "" OFF)
set(CMAKE_C_FLAGS "-std=gnu99 ${CMAKE_C_FLAGS}")
add_subdirectory(libmaxminddb-1.12.2 EXCLUDE_FROM_ALL)
include_directories(libmaxminddb/include/)

set(src
  geoip2.c)

FLB_PLUGIN(filter_geoip2 "${src}" "maxminddb")
