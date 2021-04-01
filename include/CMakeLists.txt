# Install fluent-bit headers
install(FILES "fluent-bit.h"
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

file(GLOB headers "fluent-bit/*.h")
install(FILES ${headers}
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}/fluent-bit
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

file(GLOB headers "fluent-bit/tls/*.h")
install(FILES ${headers}
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}/fluent-bit/tls/
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)