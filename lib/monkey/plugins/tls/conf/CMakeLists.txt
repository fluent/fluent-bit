set(conf_dir "${MK_PATH_CONF}/plugins/tls/")

install(DIRECTORY DESTINATION ${conf_dir})

if(BUILD_LOCAL)
  file(COPY tls.conf DESTINATION ${conf_dir})
else()
  install(FILES tls.conf DESTINATION ${conf_dir})
endif()
