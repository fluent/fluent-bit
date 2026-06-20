# AWS unit tests
set(UNIT_TESTS_FILES
  placeholder.c
  )

# Prepare list of unit tests
prepare_unit_tests(flb-it-aws_ "${UNIT_TESTS_FILES}")
