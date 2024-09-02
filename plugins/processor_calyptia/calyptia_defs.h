#ifndef FLB_CALYPTIA_DEFS_H
#define FLB_CALYPTIA_DEFS_H

#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_processor_plugin.h>

extern char calyptia_processor_lua_helpers[];

#define LUA_LOGS_HELPER_KEY (calyptia_processor_lua_helpers + 1)
#define LUA_METRICS_HELPER_KEY (calyptia_processor_lua_helpers + 2)
#define LUA_TRACES_HELPER_KEY (calyptia_processor_lua_helpers + 3)

struct calyptia_context {
    flb_sds_t code;                     /* lua script source code */
    flb_sds_t script;                   /* lua script path */
    flb_sds_t call;                     /* lua callback to process the event */
    struct flb_luajit *lua;             /* state context   */
    struct flb_processor_instance *ins; /* processor instance */
    bool disable_warnings;              /* disable warnings from lua helpers */
    struct cfl_variant *opts;           /* arbitrary object passed to lua script */
};


#endif
