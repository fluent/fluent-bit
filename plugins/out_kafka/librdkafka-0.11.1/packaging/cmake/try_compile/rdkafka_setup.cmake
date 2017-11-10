try_compile(
    HAVE_REGEX
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/regex_test.c"
)

try_compile(
    HAVE_STRNDUP
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/strndup_test.c"
)

# Atomic 32 tests {
set(LINK_ATOMIC NO)
set(HAVE_ATOMICS_32 NO)
set(HAVE_ATOMICS_32_SYNC NO)

try_compile(
    _atomics_32
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/atomic_32_test.c"
)

if(_atomics_32)
  set(HAVE_ATOMICS_32 YES)
else()
  try_compile(
      _atomics_32_lib
      "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
      "${TRYCOMPILE_SRC_DIR}/atomic_32_test.c"
      LINK_LIBRARIES "-latomic"
  )
  if(_atomics_32_lib)
    set(HAVE_ATOMICS_32 YES)
    set(LINK_ATOMIC YES)
  else()
    try_compile(
        HAVE_ATOMICS_32_SYNC
        "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
        "${TRYCOMPILE_SRC_DIR}/sync_32_test.c"
    )
  endif()
endif()
# }

# Atomic 64 tests {
set(HAVE_ATOMICS_64 NO)
set(HAVE_ATOMICS_64_SYNC NO)

try_compile(
    _atomics_64
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/atomic_64_test.c"
)

if(_atomics_64)
  set(HAVE_ATOMICS_64 YES)
else()
  try_compile(
      _atomics_64_lib
      "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
      "${TRYCOMPILE_SRC_DIR}/atomic_64_test.c"
      LINK_LIBRARIES "-latomic"
  )
  if(_atomics_64_lib)
    set(HAVE_ATOMICS_64 YES)
    set(LINK_ATOMIC YES)
  else()
    try_compile(
        HAVE_ATOMICS_64_SYNC
        "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
        "${TRYCOMPILE_SRC_DIR}/sync_64_test.c"
    )
  endif()
endif()
# }
