set(src
  logrotate.c)

find_package(ZLIB REQUIRED)
FLB_PLUGIN(out_logrotate "${src}" "${ZLIB_LIBRARIES}")
