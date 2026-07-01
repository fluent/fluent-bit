set(src
  ../sha1.c
  ../base64.c
  mk_passwd.c
  )

include_directories(../)
add_definitions(-D_FORCE_SYSMALLOC)
add_executable(mk_passwd ${src})

if(BUILD_LOCAL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/")
else()
  install(TARGETS mk_passwd RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_SBINDIR})
endif()
