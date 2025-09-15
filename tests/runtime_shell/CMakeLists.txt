configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime_shell.env.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime_shell.env"
  )

set(UNIT_TESTS_SH
  custom_calyptia.sh
  in_dummy_expect.sh
  in_tail_expect.sh
  in_http_tls_expect.sh
  in_syslog_tcp_tls_expect.sh
  in_syslog_tcp_plaintext_expect.sh
  in_syslog_udp_plaintext_expect.sh
  in_syslog_uds_dgram_plaintext_expect.sh
  in_syslog_uds_stream_plaintext_expect.sh
  processor_conditional.sh
  processor_invalid.sh
  )

# Prepare list of unit tests
foreach(script ${UNIT_TESTS_SH})
  add_test(NAME ${script}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/${script}
    )

  set_tests_properties(${script} PROPERTIES ENVIRONMENT
    "FLB_ROOT=${PROJECT_SOURCE_DIR};\
FLB_RUNTIME_SHELL_PATH=${CMAKE_CURRENT_SOURCE_DIR};\
FLB_RUNTIME_SHELL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/conf;\
FLB_BIN=${CMAKE_BINARY_DIR}/bin/fluent-bit"
    )
endforeach()
