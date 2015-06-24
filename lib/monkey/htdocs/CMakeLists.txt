if(NOT BUILD_LOCAL)
  set(SRC ${PROJECT_SOURCE_DIR}/htdocs)
  install(FILES
      ${SRC}/favicon.ico
      ${SRC}/404.html
      ${SRC}/index.html
    DESTINATION
      ${MK_PATH_WWW})
  install(FILES
      ${SRC}/css/bootstrap.min.css
    DESTINATION
      ${MK_PATH_WWW}/css/)
  install(FILES
      ${SRC}/imgs/info_pic.jpg
      ${SRC}/imgs/monkey_logo.png
    DESTINATION
      ${MK_PATH_WWW}/imgs/)
endif()
