#include "sp_cb_functions.h"

#ifndef FLB_TEST_SP_WINDOW
#define FLB_TEST_SP_WINDOW

/* Tests for test_window */
struct task_check window_checks[] = {
    {
        0, FLB_SP_WINDOW_TUMBLING, 5, 0,
        "window_5_seconds",
        "SELECT SUM(id), AVG(id) FROM STREAM:FLB WINDOW TUMBLING (5 SECOND) " \
        "WHERE word3 IS NOT NULL;",
        cb_window_5_second
    },
    {
        1, FLB_SP_WINDOW_TUMBLING, 1, 0,
        "select_aggr_window_tumbling",
        "SELECT MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB WINDOW TUMBLING (1 SECOND);",
        cb_select_aggr,
    },
    {
        2, FLB_SP_WINDOW_TUMBLING, 1, 0,
        "select_aggr_window_tumbling_groupby",
        "SELECT bool, MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB WINDOW TUMBLING (1 SECOND) WHERE word3 IS NOT NULL " \
        "GROUP BY bool;",
        cb_select_groupby,
    },
    {
        3, FLB_SP_WINDOW_HOPPING, 5, 2,
        "hopping_window_5_seconds",
        "SELECT SUM(id), AVG(id) FROM STREAM:FLB WINDOW HOPPING (5 SECOND, " \
        "ADVANCE BY 2 SECOND) WHERE word3 IS NOT NULL;",
        cb_hopping_window_5_second
    },
    {    /* FORECAST */
        4, FLB_SP_WINDOW_TUMBLING, 1, 0,
        "timeseries_forecast_window_tumbling",
        "SELECT AVG(usage), TIMESERIES_FORECAST(usage, 20) FROM " \
        "STREAM:FLB WINDOW TUMBLING (5 SECOND);",
        cb_forecast_tumbling_window
    },
    {
        5, FLB_SP_WINDOW_HOPPING, 5, 2,
        "timeseries_forecast_window_hopping",
        "SELECT AVG(usage), TIMESERIES_FORECAST(usage, 20) FROM " \
        "STREAM:FLB WINDOW HOPPING (5 SECOND, ADVANCE BY 2 SECOND);",
        cb_forecast_hopping_window
    },
};

#endif
