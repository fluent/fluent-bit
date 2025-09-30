set(src
  lua_config.c
  lua.c)

if(MSVC)
  FLB_PLUGIN(filter_lua "${src}" "")
else()
  FLB_PLUGIN(filter_lua "${src}" "m")
endif()

