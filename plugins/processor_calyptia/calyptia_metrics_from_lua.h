#ifndef FLB_CALYPTIA_METRICS_FROM_LUA
#define FLB_CALYPTIA_METRICS_FROM_LUA

#include <lua.h>
#include <cmetrics/cmetrics.h>
#include <fluent-bit/flb_processor_plugin.h>

int calyptia_metrics_from_lua(struct flb_processor_instance *ins, lua_State *L, struct cmt *cmt);

#endif
