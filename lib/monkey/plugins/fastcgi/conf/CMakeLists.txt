set(conf_dir "${MK_PATH_CONF}/plugins/fastcgi/")

install(DIRECTORY DESTINATION ${conf_dir})

if(BUILD_LOCAL)
  file(COPY fastcgi.conf DESTINATION ${conf_dir})
else()
  install(FILES fastcgi.conf DESTINATION ${conf_dir})
endif()
