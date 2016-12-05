if(NOT MK_LOCAL)
  install(DIRECTORY
      ${CMAKE_CURRENT_SOURCE_DIR}/monkey/
    DESTINATION
      ${MK_PATH_HEADERS})
endif()

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
