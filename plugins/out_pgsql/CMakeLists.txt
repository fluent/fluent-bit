if(WIN32)
    set(src
    pgsql.c
    pgsql_connections.c
    pgsql_loadlib.c
    )
else()
    set(src
    pgsql.c
    pgsql_connections.c
    )
endif()

FLB_PLUGIN(out_pgsql "${src}" "")

if(NOT WIN32)
    target_include_directories(flb-plugin-out_pgsql PRIVATE ${PostgreSQL_INCLUDE_DIRS})
    target_link_libraries(flb-plugin-out_pgsql -lpq)
endif()
