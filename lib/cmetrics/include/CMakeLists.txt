file(GLOB cmetricsHeaders "cmetrics/*.h")
install(FILES ${cmetricsHeaders}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/cmetrics
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

file(GLOB promHeaders "prometheus_remote_write/*.h")
install(FILES ${promHeaders}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/prometheus_remote_write
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
