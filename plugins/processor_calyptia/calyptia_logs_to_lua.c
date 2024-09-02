
#include <lua.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_untyped.h>

#include "calyptia_logs_to_lua.h"
#include "cfl_to_lua.h"

int calyptia_logs_to_lua(lua_State *L, struct flb_mp_chunk_cobj *chunk_cobj)
{
    double ts;
    struct flb_mp_chunk_record *record;

    /* top-level table */
    lua_createtable(L, chunk_cobj->total_records, 0);
    /* one array for records */
    lua_createtable(L, chunk_cobj->total_records, 0);
    /* one array for metadata */
    lua_createtable(L, chunk_cobj->total_records, 0);
    /* one array for timestamps */
    lua_createtable(L, chunk_cobj->total_records, 0);

    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
      push_variant(L, record->cobj_record->variant);
      lua_rawseti(L, -4, lua_objlen(L, -4) + 1);

      push_variant(L, record->cobj_metadata->variant);
      lua_rawseti(L, -3, lua_objlen(L, -3) + 1);

      ts = flb_time_to_double(&record->event.timestamp);
      lua_pushnumber(L, ts);
      lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    }

    lua_setfield(L, -4, "timestamps");
    lua_setfield(L, -3, "metadata");
    lua_setfield(L, -2, "logs");

    return 0;
}
