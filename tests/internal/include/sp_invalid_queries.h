#ifndef FLB_TEST_INVALID_QUERIES
#define FLB_TEST_INVALID_QUERIES

/* Tests to check if syntactically invalid queries return error */
char *invalid_query_checks[] = {
    "SELECT id, MIN(id) FROM STREAM:FLB;",
    "SELECT *, COUNT(id) FROM STREAM:FLB;",
    "SELECT * FROM TAG:FLB WHERE bool = NULL ;",
    "SELECT * FROM TAG:FLB WHERE @record.some_random_func() ;",
    "SELECT id, MIN(id) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;",
    "SELECT *, COUNT(id) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;",
    "SELECT *, COUNT(bool) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;",
    "SELECT *, bool, COUNT(bool) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;"
};

#endif
