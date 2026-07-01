set(src
  jsmn.c
)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -DJSMN_PARENT_LINKS -DJSMN_STRICT")
add_library(jsmn STATIC ${src})
