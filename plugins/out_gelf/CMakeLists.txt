set(src
  gelf.c
  )

FLB_PLUGIN(out_gelf "${src}" ${ZLIB_LIBRARIES})

