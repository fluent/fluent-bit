set(src
  pgsql.c
  pgsql_connections.c
  )

FLB_PLUGIN(out_pgsql "${src}" "")

if (FLB_SYSTEM_WINDOWS)
  if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
    set(PG_INCLUDE "C:/Program Files/PostgreSQL/9.6/include")
    set(PG_LIB "C:/Program Files/PostgreSQL/9.6/lib")
  else()
    set(PG_INCLUDE "C:/Program Files (x86)/PostgreSQL/9.6/include")
    set(PG_LIB "C:/Program Files (x86)/PostgreSQL/9.6/lib")
  endif()
  message(STATUS "PG_INCLUDE is ${PG_INCLUDE}, PG_LIB is ${PG_LIB}")
  target_include_directories(flb-plugin-out_pgsql PRIVATE ${PG_INCLUDE})
  target_link_directories(flb-plugin-out_pgsql PRIVATE ${PG_LIB})
  target_link_libraries(flb-plugin-out_pgsql ${PG_LIB}/libpq.lib)
else()
  target_include_directories(flb-plugin-out_pgsql PRIVATE ${PostgreSQL_INCLUDE_DIRS})
  target_link_libraries(flb-plugin-out_pgsql -lpq)
endif()