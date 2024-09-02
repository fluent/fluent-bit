#ifndef FLB_CALYPTIA_METRICS_FROM_LUA
#define FLB_CALYPTIA_METRICS_FROM_LUA

#include <lua.h>
#include <fluent-bit/flb_processor_plugin.h>

int calyptia_logs_from_lua(struct flb_processor_instance *ins, lua_State *L, struct flb_mp_chunk_cobj *chunk_cobj);

#endif
