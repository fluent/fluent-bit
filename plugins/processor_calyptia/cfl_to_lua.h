#ifndef FLB_CALYPTIA_PROCESSOR_CFL_TO_LUA_H
#define FLB_CALYPTIA_PROCESSOR_CFL_TO_LUA_H

#include <lua.h>
#include <cfl/cfl.h>

void push_variant(lua_State *L, struct cfl_variant *variant);
void push_string(lua_State *L, const char *str, size_t size);
void push_array(lua_State *L, struct cfl_array *array);
void push_kvlist(lua_State *L, struct cfl_kvlist *kvlist);
void push_timestamp_as_table(lua_State *L, uint64_t timestamp);
void push_timestamp_as_string(lua_State *L, uint64_t timestamp);
void push_variant(lua_State *L, struct cfl_variant *variant);

#endif
