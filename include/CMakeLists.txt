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

file(GLOB headers "fluent-bit/wasm/*.h")
install(FILES ${headers}
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}/fluent-bit/wasm/
    COMPONENT headers
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(FILES "../lib/monkey/include/monkey/mk_core.h"
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}/monkey/
    COMPONENT headers-extra
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

file(GLOB headers "../lib/monkey/include/monkey/mk_core/*.h")
    install(FILES ${headers}
    COMPONENT headers-extra
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}/monkey/mk_core/
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)


file(GLOB headers "../lib/flb_libco/*.h")
    install(FILES ${headers}
    COMPONENT headers-extra
    DESTINATION ${FLB_INSTALL_INCLUDEDIR}/
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
