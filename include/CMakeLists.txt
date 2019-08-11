# Install fluent-bit headers

if(NOT WITHOUT_HEADERS)
  install(FILES "fluent-bit.h"
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

  file(GLOB headers "fluent-bit/*.h")
  install(FILES ${headers}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/fluent-bit
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
