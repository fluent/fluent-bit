set(conf_dir "${MK_PATH_CONF}/plugins/mandril/")

install(DIRECTORY DESTINATION ${conf_dir})

if(BUILD_LOCAL)
  file(COPY mandril.conf DESTINATION ${conf_dir})
else()
  install(FILES mandril.conf DESTINATION ${conf_dir})
endif()
