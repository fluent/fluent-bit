set(src
  cio.c)

add_executable(cio ${src})

if (CIO_LIB_SHARED)
  target_link_libraries(cio chunkio-shared)
elseif (CIO_LIB_STATIC)
  target_link_libraries(cio chunkio-static)
endif()