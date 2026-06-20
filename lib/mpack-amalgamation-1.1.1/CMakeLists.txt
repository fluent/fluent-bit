set(src
  src/mpack/mpack.c
  )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
add_definitions(-DMPACK_EXTENSIONS=1)
add_library(mpack-static STATIC ${src})
