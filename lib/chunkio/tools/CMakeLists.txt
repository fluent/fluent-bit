set(src
  cio.c)

add_executable(cio ${src})
target_link_libraries(cio chunkio-static)
