# Search homebrewed keg-only versions of Bison and Flex on macOS.
execute_process(
  COMMAND brew --prefix bison
  RESULT_VARIABLE HOMEBREW_BISON
  OUTPUT_VARIABLE HOMEBREW_BISON_PREFIX
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )
if (HOMEBREW_BISON EQUAL 0 AND EXISTS "${HOMEBREW_BISON_PREFIX}")
  message(STATUS "Using bison keg installed by Homebrew at ${HOMEBREW_BISON_PREFIX}")
  set(BISON_EXECUTABLE "${HOMEBREW_BISON_PREFIX}/bin/bison")
endif()

execute_process(
  COMMAND brew --prefix flex
  RESULT_VARIABLE HOMEBREW_FLEX
  OUTPUT_VARIABLE HOMEBREW_FLEX_PREFIX
  OUTPUT_STRIP_TRAILING_WHITESPACE
  )
if (HOMEBREW_FLEX EQUAL 0 AND EXISTS "${HOMEBREW_FLEX_PREFIX}")
  message(STATUS "Using flex keg installed by Homebrew at ${HOMEBREW_FLEX_PREFIX}")
  set(FLEX_EXECUTABLE "${HOMEBREW_FLEX_PREFIX}/bin/flex")
endif()

if (OPENSSL_ROOT_DIR)
  message(STATUS "Using openssl specified by cmake option: ${OPENSSL_ROOT_DIR}")
else()
  # Also, searching homebrewed OpenSSL automatically.
  execute_process(
    COMMAND brew --prefix openssl
    RESULT_VARIABLE HOMEBREW_OPENSSL
    OUTPUT_VARIABLE HOMEBREW_OPENSSL_PREFIX
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (HOMEBREW_OPENSSL EQUAL 0 AND EXISTS "${HOMEBREW_OPENSSL_PREFIX}")
    message(STATUS "Using openssl keg installed by Homebrew at ${HOMEBREW_OPENSSL_PREFIX}")
    set(OPENSSL_ROOT_DIR "${HOMEBREW_OPENSSL_PREFIX}")
  endif()
endif()
