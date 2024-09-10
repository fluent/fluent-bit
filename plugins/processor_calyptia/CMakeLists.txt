set(LUA_HELPERS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/processor_helpers.lua)
set(LUA_HELPERS_DST ${CMAKE_CURRENT_BINARY_DIR}/calyptia_processor_helpers.c)

add_custom_command(
  OUTPUT  ${LUA_HELPERS_DST}
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/generate_lua_helpers.cmake ${LUA_HELPERS_SRC} ${LUA_HELPERS_DST}
  DEPENDS generate_lua_helpers.cmake ${LUA_HELPERS_SRC}
  )

set(src
  calyptia.c
  calyptia_logs.c
  calyptia_logs_from_lua.c
  calyptia_logs_to_lua.c
  calyptia_metrics.c
  calyptia_metrics_from_lua.c
  calyptia_metrics_to_lua.c
  calyptia_traces.c
  calyptia_traces_to_lua.c
  calyptia_traces_from_lua.c
  cfl_to_lua.c
  lua_to_cfl.c
  ${LUA_HELPERS_DST})

if(MSVC)
  FLB_PLUGIN(processor_calyptia "${src}" "")
else()
  FLB_PLUGIN(processor_calyptia "${src}" "m")
endif()
