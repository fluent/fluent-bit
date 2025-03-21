# MK_CORE
if(NOT WITHOUT_HEADERS)
  install(FILES "mk_core.h"
    DESTINATION include/
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

  file(GLOB headers "mk_core/*.h")
  install(FILES ${headers}
    DESTINATION include/mk_core
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
