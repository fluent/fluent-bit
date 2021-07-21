file(GLOB headers "monkey/mk_core/*.h")
install(FILES ${headers}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/monkey/mk_core
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

file(GLOB headers "monkey/mk_core/external/*.h")
install(FILES ${headers}
    DESTINATION ${CMT_INSTALL_INCLUDEDIR}/monkey/mk_core/external
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
