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

try_compile(
    HAVE_RAND_R
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/rand_r_test.c"
)

try_compile(
    HAVE_PTHREAD_SETNAME_GNU
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/pthread_setname_gnu_test.c"
    COMPILE_DEFINITIONS "-D_GNU_SOURCE"
    LINK_LIBRARIES "-lpthread"
)

try_compile(
    HAVE_PTHREAD_SETNAME_DARWIN
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/pthread_setname_darwin_test.c"
    COMPILE_DEFINITIONS "-D_DARWIN_C_SOURCE"
    LINK_LIBRARIES "-lpthread"
)

try_compile(
    HAVE_PTHREAD_SETNAME_FREEBSD
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/pthread_setname_freebsd_test.c"
    LINK_LIBRARIES "-lpthread"
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

# C11 threads
try_compile(
    WITH_C11THREADS
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/c11threads_test.c"
    LINK_LIBRARIES "-pthread"
)
# }

# CRC32C {
try_compile(
    WITH_CRC32C_HW
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/crc32c_hw_test.c"
)
# }
