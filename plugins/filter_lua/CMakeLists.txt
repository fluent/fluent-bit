set(src
  lua_config.c
  lua.c)

FLB_PLUGIN(filter_lua "${src}" "m")
