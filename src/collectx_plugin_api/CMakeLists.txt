set(src collectx_plugin_api.c)

find_package (Threads)
# add_executable(collectx_plugin_test ${src})
# target_link_libraries(collectx_plugin_test fluent-bit-shared)
# target_link_libraries(collectx_plugin_test ${CMAKE_THREAD_LIBS_INIT})

add_library(collectx_plugin_api SHARED ${src})
target_link_libraries(collectx_plugin_api fluent-bit-shared)
target_link_libraries(collectx_plugin_api ${CMAKE_THREAD_LIBS_INIT})
set_target_properties(collectx_plugin_api PROPERTIES INSTALL_RPATH "/opt/mellanox/collectx/lib:$ORIGIN")

install(TARGETS collectx_plugin_api LIBRARY DESTINATION ${FLB_INSTALL_LIBDIR})
