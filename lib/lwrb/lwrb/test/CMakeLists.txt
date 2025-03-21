cmake_minimum_required(VERSION 3.0)
project(lwrb-testing)

set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/../../third_party)
set(UNITY_DIR ${THIRD_PARTY_DIR}/Unity)
set(LWRB_DIR ${CMAKE_SOURCE_DIR}/../src)

set(CMAKE_MODULE_PATH "${THIRD_PARTY_DIR}/sanitizers-cmake/cmake;${THIRD_PARTY_DIR}/cmake-modules" ${CMAKE_MODULE_PATH})

if(WITH_COVERAGE)
    find_program(LLVMCOV_PATH llvm-cov)
    if("${CMAKE_CXX_COMPILER_ID}" MATCHES "(Apple)?[Cc]lang")
        if(LLVMCOV_PATH)
            set(GCOV_PATH "${CMAKE_CURRENT_SOURCE_DIR}/llvm-cov.sh")
        endif(LLVMCOV_PATH)
    endif()
    include(CodeCoverage)
    append_coverage_compiler_flags()
endif(WITH_COVERAGE)

find_package(Sanitizers)

enable_testing()

add_executable(lwrb_test test.c ${LWRB_DIR}/lwrb/lwrb.c ${UNITY_DIR}/src/unity.c)
target_include_directories(lwrb_test PRIVATE ${LWRB_DIR}/include ${UNITY_DIR}/src)

add_sanitizers(lwrb_test)

add_test(lwrb_test_suite lwrb_test)

if(WITH_COVERAGE)
    setup_target_for_coverage_lcov(
        NAME coverage
        EXECUTABLE ctest
        EXCLUDE "${CMAKE_SOURCE_DIR}/*" "${THIRD_PARTY_DIR}/*")
endif(WITH_COVERAGE)
