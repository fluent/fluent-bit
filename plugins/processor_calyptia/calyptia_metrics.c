#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_luajit.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_untyped.h>
#include <fluent-bit/flb_processor_plugin.h>

#include "calyptia_metrics_to_lua.h"
#include "calyptia_metrics_from_lua.h"
#include "calyptia_defs.h"

int calyptia_process_metrics(struct flb_processor_instance *ins,
                             struct cmt *metrics_context,
                             struct cmt **out_context, const char *tag,
                             int tag_len)
{
    struct calyptia_context *ctx;
    int ret;
    int l_code;

    ret = FLB_PROCESSOR_SUCCESS;
    ctx = ins->context;
    /* push the lua helper */
    lua_pushlightuserdata(ctx->lua->state, LUA_METRICS_HELPER_KEY);
    lua_gettable(ctx->lua->state, LUA_REGISTRYINDEX);
    /* push the lua callback */
    lua_getglobal(ctx->lua->state, ctx->call);
    /* push the tag */
    lua_pushlstring(ctx->lua->state, tag, tag_len);

    if (calyptia_metrics_to_lua(ctx->lua->state, metrics_context)) {
        flb_plg_error(ctx->ins, "Failed to encode metrics");
        return FLB_PROCESSOR_FAILURE;
    }

    ret = lua_pcall(ctx->lua->state, 3, 3, 0);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error code %d: %s", ret,
                      lua_tostring(ctx->lua->state, -1));
        lua_pop(ctx->lua->state, 1);
        return FLB_PROCESSOR_FAILURE;
    }

    /* index -2 is the "ingest" object, for which handling will only be
     * implemented in the future */
    l_code = (int) lua_tointeger(ctx->lua->state, -3);
    if (l_code == -1) {
        *out_context = cmt_create();
    } else if (l_code == 0) {
        /* don't touch the metrics */
        *out_context = metrics_context;
    } else if (l_code != 1) {
        flb_plg_error(ctx->ins, "invalid return code %d", l_code);
        ret = FLB_PROCESSOR_FAILURE;
    } else {
        struct cmt *new_metrics = cmt_create();
        if (calyptia_metrics_from_lua(ins, ctx->lua->state, new_metrics)) {
            cmt_destroy(new_metrics);
            flb_plg_error(ctx->ins, "Failed to decode metrics from lua");
            ret = FLB_PROCESSOR_FAILURE;
        } else {
            *out_context = new_metrics;
        }
    }

    /* clear lua stack */
    lua_settop(ctx->lua->state, 0);
    return ret;
}
