set(conf_dir "${MK_PATH_CONF}/plugins/logger/")

install(DIRECTORY DESTINATION ${conf_dir})
configure_file(
  "${PROJECT_SOURCE_DIR}/plugins/logger/conf/logger.conf.in"
  "${PROJECT_BINARY_DIR}/conf/plugins/logger/logger.conf"
  )

if(NOT BUILD_LOCAL)
  install(FILES ${PROJECT_BINARY_DIR}/conf/plugins/logger/logger.conf DESTINATION ${conf_dir})
endif()
