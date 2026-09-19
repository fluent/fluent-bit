file(GLOB cprofilesHeaders "cprofiles/*.h")
install(FILES ${cprofilesHeaders}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/cprofiles
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
