file(GLOB cprofilesHeaders "cprofiles/*.h")
install(FILES ${cprofilesHeaders}
    DESTINATION ${CPROF_INSTALL_INCLUDEDIR}/cprofiles
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/cprofiles/cprof_info.h"
    "${CMAKE_CURRENT_BINARY_DIR}/cprofiles/cprof_version.h"
    DESTINATION ${CPROF_INSTALL_INCLUDEDIR}/cprofiles
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
