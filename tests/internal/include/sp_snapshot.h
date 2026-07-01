#include "sp_cb_functions.h"

#ifndef FLB_TEST_SP_SNAPSHOT
#define FLB_TEST_SP_SNAPSHOT

/* Tests for 'test_snapshot' */
struct task_check snapshot_checks[][2] = {
    {
        {   // Snapshot
            0, 0, 0, 0,
            "snapshot_create",
            "SELECT * FROM STREAM:FLB LIMIT 5;",
            cb_snapshot_create
        },
        {   // Flush
            1, 0, 0, 0,
            "snapshot_purge",
            "SELECT * FROM STREAM:FLB;",
            cb_snapshot_purge
        },
    },
    {
        {  // Snapshot
            2, 0, 5, 0,
            "snapshot_create",
            "SELECT * FROM STREAM:FLB;",
            cb_snapshot_create
        },
        {  // Flush
            3, 0, 0, 0,
            "snapshot_purge",
            "SELECT * FROM STREAM:FLB;",
            cb_snapshot_purge_time
        },
    },
};

#endif
