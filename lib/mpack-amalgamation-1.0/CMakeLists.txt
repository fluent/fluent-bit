set(src
  src/mpack/mpack.c
  )

add_definitions(-DMPACK_EXTENSIONS=1)
add_library(mpack-static STATIC ${src})
