set(src
  miniz.c
  )

add_definitions("-DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -DMINIZ_NO_TIME")
add_library(miniz STATIC ${src})
target_link_libraries(miniz ${CMAKE_DL_LIBS})
