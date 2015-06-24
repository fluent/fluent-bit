# Generate conf/monkey.conf
configure_file(
  "${PROJECT_SOURCE_DIR}/conf/monkey.conf.in"
  "${PROJECT_BINARY_DIR}/conf/monkey.conf"
  )

# Generate (copy) conf/monkey.mime
configure_file(
  "${PROJECT_SOURCE_DIR}/conf/monkey.mime.in"
  "${PROJECT_BINARY_DIR}/conf/monkey.mime"
  )

# Generate conf/sites/default
configure_file(
  "${PROJECT_SOURCE_DIR}/conf/sites/default.in"
  "${PROJECT_BINARY_DIR}/conf/sites/default"
  )

if(NOT BUILD_LOCAL)
  install(FILES
      ${PROJECT_BINARY_DIR}/conf/monkey.conf
      ${PROJECT_BINARY_DIR}/conf/monkey.mime
      ${PROJECT_BINARY_DIR}/conf/plugins.load
    DESTINATION
      ${MK_PATH_CONF})
  install(FILES
      ${PROJECT_BINARY_DIR}/conf/sites/default
    DESTINATION
      ${MK_PATH_CONF}/sites/)
endif()
