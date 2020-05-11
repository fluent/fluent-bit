# libmaxminddb
include(libmaxminddb.cmake)

# libmaxminddb headers
include_directories(${LIBMAXMINDDB_DEST}/include/)

set(src
  geoip2.c)

FLB_PLUGIN(filter_geoip2 "${src}" "libmaxminddb")
