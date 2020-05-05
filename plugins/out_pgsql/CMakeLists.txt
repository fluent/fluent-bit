set(src
  pgsql.c
  )

FLB_PLUGIN(out_pgsql "${src}" "")
target_include_directories(flb-plugin-out_pgsql PRIVATE ${PostgreSQL_INCLUDE_DIRS})
target_link_libraries(flb-plugin-out_pgsql -lpq)
