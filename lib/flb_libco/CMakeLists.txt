set(src
  libco.c
  )

add_definitions(-DLIBCO_MP)
add_library(co STATIC ${src})
