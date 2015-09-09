# Install fluent-bit headers

install(FILES "fluent-bit.h"
        DESTINATION include/
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

file(GLOB headers "fluent-bit/*.h")
install(FILES ${headers}
        DESTINATION include/fluent-bit
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
