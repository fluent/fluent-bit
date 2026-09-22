cmake_minimum_required(VERSION 3.12)
project(flb_libco C)
option(LIBCO_TESTS "Build coroutine tests" OFF)
option(LIBCO_TESTS_ASAN "Test ASan diagnostics (requires -fsanitize=address)" OFF)
option(LIBCO_TESTS_PORTABLE "Also test portable backends on native platforms" ON)

set(src
  libco.c
  )

include(CheckSymbolExists)

# Check for posix_memalign so that Apple Silicon can be supported
check_symbol_exists(posix_memalign "stdlib.h" HAVE_POSIX_MEMALIGN_IN_STDLIB)

IF(HAVE_POSIX_MEMALIGN_IN_STDLIB)
  # We need HAVE_POSIX_MEMALIGN for the ifdefs to use posix_memalign
  # We defined HAVE_POSIX_MEMALIGN_IN_STDLIB in order to avoid including in malloc.h
  add_definitions(-DHAVE_POSIX_MEMALIGN_IN_STDLIB -DHAVE_POSIX_MEMALIGN)
  MESSAGE("Found posix_memalign in stdlib.h -DHAVE_POSIX_MEMALIGN_IN_STDLIB -DHAVE_POSIX_MEMALIGN")
ENDIF(HAVE_POSIX_MEMALIGN_IN_STDLIB)

# Check for posix_memalign so that FreeBSD can be supported
check_symbol_exists(posix_memalign "malloc_np.h" HAVE_POSIX_MEMALIGN_IN_PTHREAD_NP)

IF(HAVE_POSIX_MEMALIGN_IN_PTHREAD_NP)
  # We need HAVE_POSIX_MEMALIGN for the ifdefs to use posix_memalign
  # We defined DHAVE_POSIX_MEMALIGN_IN_PTHREAD_NP in order to include malloc_np.h
  add_definitions(-DHAVE_POSIX_MEMALIGN_IN_PTHREAD_NP -DHAVE_POSIX_MEMALIGN)
  MESSAGE("Found posix_memalign in malloc_np.h -DHAVE_POSIX_MEMALIGN_IN_PTHREAD_NP -DHAVE_POSIX_MEMALIGN")
ENDIF(HAVE_POSIX_MEMALIGN_IN_PTHREAD_NP)

add_definitions(-DLIBCO_MP)
add_library(co STATIC ${src})

if(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  # The validated backend uses pthread TLS and shared memory. Consumers need
  # matching compile/link flags even when the library's tests are disabled.
  target_compile_options(co PUBLIC -pthread)
  target_link_libraries(co INTERFACE -pthread "-sASYNCIFY=1")
endif()

if(LIBCO_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  enable_testing()
  add_executable(co-wasm-test tests/emscripten.c)
  target_include_directories(co-wasm-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(co-wasm-test co)
  set_target_properties(co-wasm-test PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=4 -sSTACK_SIZE=262144")
  add_test(NAME co-wasm-test COMMAND co-wasm-test)
  set_tests_properties(co-wasm-test PROPERTIES TIMEOUT 30)
  add_executable(co-wasm-worker-reuse tests/worker_reuse.c)
  target_include_directories(co-wasm-worker-reuse PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(co-wasm-worker-reuse co)
  set_target_properties(co-wasm-worker-reuse PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=2 -sSTACK_SIZE=262144")
  add_test(NAME co-wasm-worker-reuse COMMAND co-wasm-worker-reuse)
  set_tests_properties(co-wasm-worker-reuse PROPERTIES TIMEOUT 30)
  if(CMAKE_CROSSCOMPILING_EMULATOR)
    add_test(NAME co-wasm-consumer
      COMMAND ${CMAKE_COMMAND}
        "-DCONSUMER_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/tests/consumer"
        "-DCONSUMER_BINARY=${CMAKE_CURRENT_BINARY_DIR}/consumer-test"
        "-DTEST_TOOLCHAIN=${CMAKE_TOOLCHAIN_FILE}"
        "-DTEST_GENERATOR=${CMAKE_GENERATOR}"
        "-DTEST_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
        "-DTEST_C_FLAGS=${CMAKE_C_FLAGS}"
        "-DTEST_LINK_FLAGS=${CMAKE_EXE_LINKER_FLAGS}"
        "-DTEST_EMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR}"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_consumer.cmake)
    set_tests_properties(co-wasm-consumer PROPERTIES TIMEOUT 120)
    set(fault_modes limits)
    if(LIBCO_TESTS_ASAN)
      target_compile_definitions(co-wasm-test PRIVATE LIBCO_TESTS_ASAN)
      list(APPEND fault_modes heap stack)
    endif()
    foreach(fault IN LISTS fault_modes)
      add_test(NAME co-wasm-fault-${fault}
        COMMAND ${CMAKE_COMMAND}
          "-DTEST_EMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR}"
          "-DTEST_PROGRAM=$<TARGET_FILE:co-wasm-test>"
          "-DFAULT=${fault}"
          -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_fault.cmake)
      set_tests_properties(co-wasm-fault-${fault} PROPERTIES TIMEOUT 40)
    endforeach()
  endif()
endif()

if(LIBCO_TESTS AND NOT CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  enable_testing()
  if(NOT WIN32)
    find_package(Threads REQUIRED)
  endif()
  function(libco_runtime_test name library)
    add_executable(${name} tests/runtime.c)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${name} ${library})
    if(NOT WIN32)
      target_link_libraries(${name} Threads::Threads)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 60)
  endfunction()
  libco_runtime_test(co-runtime co)
  if(LIBCO_TESTS_PORTABLE)
    if(WIN32)
      set(portable_backends fiber)
    elseif(UNIX AND NOT APPLE)
      set(portable_backends sjlj ucontext)
    else()
      set(portable_backends "")
    endif()
    foreach(backend IN LISTS portable_backends)
      add_library(co-test-${backend} STATIC ${backend}.c)
      if(backend STREQUAL "sjlj" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        # glibc's fortified longjmp rejects intentional alternate-stack jumps.
        target_compile_options(co-test-${backend} PRIVATE -U_FORTIFY_SOURCE)
      endif()
      libco_runtime_test(co-runtime-${backend} co-test-${backend})
    endforeach()
  endif()
endif()

if(LIBCO_TESTS AND CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv64")
  enable_testing()
  add_executable(co-riscv64-stack tests/riscv64_stack.c)
  target_include_directories(co-riscv64-stack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(co-riscv64-stack co)
  add_test(NAME co-riscv64-stack COMMAND co-riscv64-stack)
  set_tests_properties(co-riscv64-stack PROPERTIES TIMEOUT 60)
endif()
