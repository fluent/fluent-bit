file(GLOB headers "cmetrics/*.h")
install(FILES ${headers}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/cmetrics
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
