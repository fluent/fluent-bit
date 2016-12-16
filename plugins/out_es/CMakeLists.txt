set(src
  es_bulk.c
  es.c)

FLB_PLUGIN(out_es "${src}" "mk_core")
target_link_libraries(flb-plugin-out_es "cJSON")

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  target_link_libraries(flb-plugin-out_es "m")
endif()
