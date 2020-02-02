set(src
  pgsql.c
  )

FLB_PLUGIN(out_pgsql "${src}" "")
target_link_libraries(flb-plugin-out_pgsql -lpq)
