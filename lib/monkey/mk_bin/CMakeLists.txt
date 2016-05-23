set(src
  monkey.c
  mk_signals.c
  )

add_executable(monkey-bin ${src})
target_link_libraries(monkey-bin monkey-core-static)
set_target_properties(monkey-bin PROPERTIES OUTPUT_NAME monkey)

if(MK_BUILD_LOCAL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "../${CMAKE_CURRENT_BINARY_DIR}/")
else()
  install(TARGETS monkey-bin RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_SBINDIR})
  configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/systemd.in"
    "${PROJECT_SOURCE_DIR}/monkey.service"
    )
  if(SYSTEMD_DIR)
    install(FILES ${PROJECT_SOURCE_DIR}/monkey.service DESTINATION ${SYSTEMD_DIR})
  endif()
endif()
