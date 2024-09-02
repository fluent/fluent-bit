#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_luajit.h>

#include "calyptia_defs.h"
#include "calyptia_traces.h"
#include "calyptia_traces_to_lua.h"
#include "calyptia_traces_from_lua.h"

static void drop_traces(struct ctrace *ctx)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct ctrace_resource_span *resource_span;

    cfl_list_foreach_safe(head, tmp, &ctx->resource_spans)
    {
        resource_span
            = cfl_list_entry(head, struct ctrace_resource_span, _head);
        ctr_resource_span_destroy(resource_span);
    }
    cfl_list_init(&ctx->resource_spans);
    cfl_list_init(&ctx->span_list);
}

int calyptia_process_traces(struct flb_processor_instance *ins,
                            struct ctrace *traces_context, const char *tag,
                            int tag_len)
{
    struct calyptia_context *ctx;
    int ret;
    int l_code;

    ret = FLB_PROCESSOR_SUCCESS;
    ctx = ins->context;

    /* push the lua helper */
    lua_pushlightuserdata(ctx->lua->state, LUA_TRACES_HELPER_KEY);
    lua_gettable(ctx->lua->state, LUA_REGISTRYINDEX);
    /* push the lua callback */
    lua_getglobal(ctx->lua->state, ctx->call);
    /* push the tag */
    lua_pushlstring(ctx->lua->state, tag, tag_len);
    if (calyptia_traces_to_lua(ctx->lua->state, traces_context) != 0) {
        flb_plg_error(ctx->ins, "Failed to encode traces");
        ret = FLB_PROCESSOR_FAILURE;
        goto cleanup;
    }

    ret = lua_pcall(ctx->lua->state, 3, 3, 0);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error code %d: %s", ret,
                      lua_tostring(ctx->lua->state, -1));
        lua_pop(ctx->lua->state, 1);
        ret = FLB_PROCESSOR_FAILURE;
    }

    /* index -2 is the "ingest" object, for which handling will only be
     * implemented in the future */
    l_code = (int) lua_tointeger(ctx->lua->state, -3);
    if (l_code == -1) {
        drop_traces(traces_context);
    } else if (l_code == 0) {
        /* don't touch the traces */
        goto cleanup;
    } else {
        assert(l_code == 1);
        drop_traces(traces_context);

        if (calyptia_traces_from_lua(ctx->lua->state, traces_context)) {
            flb_plg_error(ctx->ins, "Failed to decode traces from lua");
            ret = FLB_PROCESSOR_FAILURE;
        }
    }

cleanup:
    /* clear lua stack */
    lua_settop(ctx->lua->state, 0);
    return ret;
}
