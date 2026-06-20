file(GLOB ctracesHeaders "ctraces/*.h")
install(FILES ${ctracesHeaders}
    DESTINATION ${CTR_INSTALL_INCLUDEDIR}/ctraces
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
