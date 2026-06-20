set(conf_dir "${MK_PATH_CONF}/plugins/cheetah/")

install(DIRECTORY DESTINATION ${conf_dir})

if(BUILD_LOCAL)
  file(COPY cheetah.conf DESTINATION ${conf_dir})
else()
  install(FILES cheetah.conf DESTINATION ${conf_dir})
endif()
