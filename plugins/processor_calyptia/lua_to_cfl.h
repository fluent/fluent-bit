#ifndef FLB_CALYPTIA_PROCESSOR_LUA_TO_CFL_H
#define FLB_CALYPTIA_PROCESSOR_LUA_TO_CFL_H

#include <stdbool.h>
#include <lua.h>
#include <cfl/cfl.h>

cfl_sds_t lua_to_sds(lua_State *L);
double lua_to_double(lua_State *L, int index);
uint64_t lua_to_uint(lua_State *L);
long lua_to_int(lua_State *L);
struct cfl_variant *lua_string_to_variant(lua_State *L, int index);
bool lua_isinteger(lua_State *L, int index);
struct cfl_array *lua_array_to_variant(lua_State *L, int array_len);
struct cfl_kvlist *lua_map_to_variant(lua_State *L);
struct cfl_variant *lua_to_variant(lua_State *L, int index);

#endif
