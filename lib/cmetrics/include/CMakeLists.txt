# Install headers conditionally based on Prometheus text decoder availability
file(GLOB cmetricsHeaders "cmetrics/*.h")

if(CMT_BUILD_PROMETHEUS_TEXT_DECODER)
    # Install all headers when Prometheus text decoder is enabled
    install(FILES ${cmetricsHeaders}
        DESTINATION ${CMT_INSTALL_INCLUDEDIR}/cmetrics
        COMPONENT headers
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
else()
    # Install headers except Prometheus text decoder header when disabled
    # (remote write decoder header is always installed)
    foreach(header ${cmetricsHeaders})
        get_filename_component(header_name ${header} NAME)
        if(NOT header_name STREQUAL "cmt_decode_prometheus.h")
            install(FILES ${header}
                DESTINATION ${CMT_INSTALL_INCLUDEDIR}/cmetrics
                COMPONENT headers
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
        endif()
    endforeach()
endif()

file(GLOB promHeaders "prometheus_remote_write/*.h")
install(FILES ${promHeaders}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/prometheus_remote_write
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
