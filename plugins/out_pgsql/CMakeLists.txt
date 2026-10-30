set(src
  pgsql.c
  pgsql_connections.c
  pgsql_libpq.c
  )

FLB_PLUGIN(out_pgsql "${src}" "")
target_include_directories(flb-plugin-out_pgsql PRIVATE ${PostgreSQL_INCLUDE_DIRS})
target_link_libraries(flb-plugin-out_pgsql ${CMAKE_DL_LIBS})
