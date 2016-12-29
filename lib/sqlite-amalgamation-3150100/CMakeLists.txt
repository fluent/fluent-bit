set(src
  sqlite3.c
  )

add_library(sqlite3 STATIC ${src})

if(NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
  target_link_libraries(sqlite3 dl)
endif()
