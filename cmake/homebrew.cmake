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
