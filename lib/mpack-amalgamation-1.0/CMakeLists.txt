set(src
  src/mpack/mpack.c
  )

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
endif()

add_definitions(-DMPACK_EXTENSIONS=1)
add_library(mpack-static STATIC ${src})
