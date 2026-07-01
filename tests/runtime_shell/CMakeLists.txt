set(RUNTIME_SHELL_ENVIRONMENT
  "FLB_ROOT=${PROJECT_SOURCE_DIR};\
FLB_RUNTIME_SHELL_PATH=${CMAKE_CURRENT_SOURCE_DIR};\
FLB_RUNTIME_SHELL_CONF=${CMAKE_CURRENT_SOURCE_DIR}/conf;\
FLB_BIN=${CMAKE_BINARY_DIR}/bin/fluent-bit${CMAKE_EXECUTABLE_SUFFIX};\
FLB_BUILD=${CMAKE_BINARY_DIR}"
  )

if(WIN32)
  find_program(POWERSHELL_EXECUTABLE NAMES pwsh powershell)

  if(POWERSHELL_EXECUTABLE)
    set(UNIT_TESTS_PS
      in_dummy_expect.ps1
      in_tail_expect.ps1
      in_syslog_tcp_plaintext_expect.ps1
      in_syslog_udp_plaintext_expect.ps1
      )

    if(FLB_TLS)
      list(APPEND UNIT_TESTS_PS
        in_http_tls_expect.ps1
        in_syslog_tcp_tls_expect.ps1
        )
    else()
      message(STATUS "Skipping TLS runtime_shell tests on Windows: TLS is disabled")
    endif()

    if(FLB_CUSTOM_CALYPTIA)
      list(APPEND UNIT_TESTS_PS custom_calyptia.ps1)
    endif()

    if(FLB_HAVE_LIBYAML)
      list(APPEND UNIT_TESTS_PS
        dry_run_invalid_property.ps1
        processor_conditional.ps1
        processor_invalid.ps1
        )
    else()
      message(STATUS
        "Skipping YAML runtime_shell tests on Windows: libyaml is unavailable")
    endif()

    message(STATUS
      "Skipping Unix-domain-socket runtime_shell tests on Windows")

    foreach(script ${UNIT_TESTS_PS})
      add_test(NAME ${script}
        COMMAND ${POWERSHELL_EXECUTABLE}
          -NoLogo
          -NoProfile
          -NonInteractive
          -ExecutionPolicy Bypass
          -File ${CMAKE_CURRENT_SOURCE_DIR}/${script}
        )

      set_tests_properties(${script} PROPERTIES
        ENVIRONMENT "${RUNTIME_SHELL_ENVIRONMENT}"
        LABELS "runtime_shell"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endforeach()
  else()
    message(STATUS
      "Skipping runtime_shell tests on Windows: PowerShell was not found")
  endif()
else()
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime_shell.env.in"
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime_shell.env"
    )

  set(UNIT_TESTS_SH
    custom_calyptia.sh
    dry_run_invalid_property.sh
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

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(riscv64)")
      message(STATUS
        "We don't test Golang plugins on RISC-V 64bit platform for now")
    else()
      list(APPEND UNIT_TESTS_SH proxy_logs_expect.sh)
    endif()
  endif()

  foreach(script ${UNIT_TESTS_SH})
    add_test(NAME ${script}
      COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/${script}
      )

    set_tests_properties(${script} PROPERTIES
      ENVIRONMENT "${RUNTIME_SHELL_ENVIRONMENT}"
      LABELS "runtime_shell"
      )
  endforeach()
endif()
