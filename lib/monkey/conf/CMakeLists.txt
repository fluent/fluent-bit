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
