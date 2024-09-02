#ifndef CALYPTIA_TRACES_FROM_LUA_H
#define CALYPTIA_TRACES_FROM_LUA_H

#include <lua.h>
#include <ctraces/ctraces.h>

int calyptia_traces_from_lua(lua_State *L, struct ctrace *ctx);

#endif
