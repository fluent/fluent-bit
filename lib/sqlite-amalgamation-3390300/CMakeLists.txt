set(src
  sqlite3.c
  )

add_library(sqlite3 STATIC ${src})
target_link_libraries(sqlite3 ${CMAKE_DL_LIBS})
