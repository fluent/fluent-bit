#ifndef FLB_CALYPTIA_METRICS_TO_LUA_H
#define FLB_CALYPTIA_METRICS_TO_LUA_H

#include <lua.h>
#include <fluent-bit/flb_processor_plugin.h>

int calyptia_logs_to_lua(lua_State *L, struct flb_mp_chunk_cobj *chunk_cobj);

#endif
