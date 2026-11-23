cmake_minimum_required(VERSION 3.12)
project(flb_portable_lua C)

if(NOT EXISTS "${LUA_SOURCE_DIR}/src/lapi.c")
  message(FATAL_ERROR "LUA_SOURCE_DIR must contain the pinned Lua source release")
endif()
file(GLOB lua_sources "${LUA_SOURCE_DIR}/src/*.c")
list(REMOVE_ITEM lua_sources "${LUA_SOURCE_DIR}/src/lua.c" "${LUA_SOURCE_DIR}/src/luac.c")
add_library(flb-lua STATIC ${lua_sources})
target_include_directories(flb-lua PUBLIC "${LUA_SOURCE_DIR}/src")
install(TARGETS flb-lua ARCHIVE DESTINATION lib)
install(FILES "${LUA_SOURCE_DIR}/src/lua.h" "${LUA_SOURCE_DIR}/src/luaconf.h"
  "${LUA_SOURCE_DIR}/src/lauxlib.h" "${LUA_SOURCE_DIR}/src/lualib.h" DESTINATION include)
