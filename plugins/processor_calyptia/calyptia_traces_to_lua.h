#ifndef CALYPTIA_TRACES_TO_LUA_H
#define CALYPTIA_TRACES_TO_LUA_H

#include <lua.h>
#include <ctraces/ctraces.h>

int calyptia_traces_to_lua(lua_State *L, struct ctrace *ctx);

#endif
