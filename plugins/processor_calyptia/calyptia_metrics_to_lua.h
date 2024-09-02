#ifndef FLB_CALYPTIA_METRICS_TO_LUA_H
#define FLB_CALYPTIA_METRICS_TO_LUA_H

#include <lua.h>
#include <cmetrics/cmetrics.h>


int calyptia_metrics_to_lua(lua_State *L, struct cmt *cmt);

#endif
