set(src lua_metrics_exporter.c)

if(MSVC)
  FLB_PLUGIN(in_lua_metrics_exporter "${src}" "")
else()
  FLB_PLUGIN(in_lua_metrics_exporter "${src}" "m")
endif()
