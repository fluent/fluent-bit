set(src
  jsmn.c
)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC")
add_library(jsmn STATIC ${src})
