execute_process(
  COMMAND brew --prefix
  RESULT_VARIABLE HOMEBREW
  OUTPUT_VARIABLE HOMEBREW_PREFIX
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wundef-prefix=TARGET_OS_ ")

if (HOMEBREW EQUAL 0 AND EXISTS "${HOMEBREW_PREFIX}")
  message(STATUS "Found Homebrew at ${HOMEBREW_PREFIX}")
  include(cmake/homebrew.cmake)
endif()

if(FLB_MACOS_DEFAULTS)
  message(STATUS "Overriding setttings with macos-setup.cmake")
  
  # INPUT plugins
  # =============
  set(FLB_IN_SNMP                No)
endif()

# Create rootcert on macOS
set(MACOS_ROOT_CERT ${CMAKE_CURRENT_BINARY_DIR}/certs/rootcert.pem)
execute_process(
  COMMAND security find-certificate -a -p /Library/Keychains/System.keychain
  RESULT_VARIABLE SECURITY_SYSTEM_RESULT
  OUTPUT_VARIABLE SECURITY_SYSTEM_CERTS
  ) # Don't strip trailing a white space and newline in the end of exported certificate.
file(WRITE ${MACOS_ROOT_CERT} ${SECURITY_SYSTEM_CERTS})

execute_process(
  COMMAND security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain
  RESULT_VARIABLE SECURITY_ROOT_RESULT
  OUTPUT_VARIABLE SECURITY_ROOT_CERTS
  ) # Don't strip trailing a white space and newline in the end of exported certificate.
file(APPEND ${MACOS_ROOT_CERT} ${SECURITY_ROOT_CERTS})

install(FILES ${MACOS_ROOT_CERT} COMPONENT binary DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/certs)
