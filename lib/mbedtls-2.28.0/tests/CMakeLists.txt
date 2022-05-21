set(libs
    ${mbedtls_target}
)

# Set the project root directory if it's not already defined, as may happen if
# the tests folder is included directly by a parent project, without including
# the top level CMakeLists.txt.
if(NOT DEFINED MBEDTLS_DIR)
    set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR})
endif()

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

if(NOT MBEDTLS_PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Cannot build test suites without Python 3")
endif()

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
add_definitions("-D_POSIX_C_SOURCE=200809L")

# Test suites caught by SKIP_TEST_SUITES are built but not executed.
# "foo" as a skip pattern skips "test_suite_foo" and "test_suite_foo.bar"
# but not "test_suite_foobar".
string(REGEX REPLACE "[ ,;]" "|" SKIP_TEST_SUITES_REGEX "${SKIP_TEST_SUITES}")
string(REPLACE "." "\\." SKIP_TEST_SUITES_REGEX "${SKIP_TEST_SUITES_REGEX}")
set(SKIP_TEST_SUITES_REGEX "^(${SKIP_TEST_SUITES_REGEX})(\$|\\.)")

function(add_test_suite suite_name)
    if(ARGV1)
        set(data_name ${ARGV1})
    else()
        set(data_name ${suite_name})
    endif()

    add_custom_command(
        OUTPUT test_suite_${data_name}.c
        COMMAND ${MBEDTLS_PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_test_code.py -f ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${suite_name}.function -d ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${data_name}.data -t ${CMAKE_CURRENT_SOURCE_DIR}/suites/main_test.function -p ${CMAKE_CURRENT_SOURCE_DIR}/suites/host_test.function -s ${CMAKE_CURRENT_SOURCE_DIR}/suites --helpers-file ${CMAKE_CURRENT_SOURCE_DIR}/suites/helpers.function -o .
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_test_code.py ${mbedtls_target} ${CMAKE_CURRENT_SOURCE_DIR}/suites/helpers.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/main_test.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/host_test.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${suite_name}.function ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${data_name}.data
    )

    add_executable(test_suite_${data_name} test_suite_${data_name}.c $<TARGET_OBJECTS:mbedtls_test>)
    target_link_libraries(test_suite_${data_name} ${libs})
    # Include test-specific header files from ./include and private header
    # files (used by some invasive tests) from ../library. Public header
    # files are automatically included because the library targets declare
    # them as PUBLIC.
    target_include_directories(test_suite_${data_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../library)

    if(${data_name} MATCHES ${SKIP_TEST_SUITES_REGEX})
        message(STATUS "The test suite ${data_name} will not be executed.")
    else()
        add_test(${data_name}-suite test_suite_${data_name} --verbose)
    endif()
endfunction(add_test_suite)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
endif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

if(MSVC)
    # If a warning level has been defined, suppress all warnings for test code
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W0")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX-")
endif(MSVC)

add_test_suite(aes aes.cbc)
add_test_suite(aes aes.cfb)
add_test_suite(aes aes.ecb)
add_test_suite(aes aes.ofb)
add_test_suite(aes aes.rest)
add_test_suite(aes aes.xts)
add_test_suite(arc4)
add_test_suite(aria)
add_test_suite(asn1parse)
add_test_suite(asn1write)
add_test_suite(base64)
add_test_suite(blowfish)
add_test_suite(camellia)
add_test_suite(ccm)
add_test_suite(chacha20)
add_test_suite(chachapoly)
add_test_suite(cipher cipher.aes)
add_test_suite(cipher cipher.arc4)
add_test_suite(cipher cipher.blowfish)
add_test_suite(cipher cipher.camellia)
add_test_suite(cipher cipher.ccm)
add_test_suite(cipher cipher.chacha20)
add_test_suite(cipher cipher.chachapoly)
add_test_suite(cipher cipher.des)
add_test_suite(cipher cipher.gcm)
add_test_suite(cipher cipher.misc)
add_test_suite(cipher cipher.nist_kw)
add_test_suite(cipher cipher.null)
add_test_suite(cipher cipher.padding)
add_test_suite(cmac)
add_test_suite(ctr_drbg)
add_test_suite(debug)
add_test_suite(des)
add_test_suite(dhm)
add_test_suite(ecdh)
add_test_suite(ecdsa)
add_test_suite(ecjpake)
add_test_suite(ecp)
add_test_suite(entropy)
add_test_suite(error)
add_test_suite(gcm gcm.aes128_de)
add_test_suite(gcm gcm.aes128_en)
add_test_suite(gcm gcm.aes192_de)
add_test_suite(gcm gcm.aes192_en)
add_test_suite(gcm gcm.aes256_de)
add_test_suite(gcm gcm.aes256_en)
add_test_suite(gcm gcm.camellia)
add_test_suite(gcm gcm.misc)
add_test_suite(hkdf)
add_test_suite(hmac_drbg hmac_drbg.misc)
add_test_suite(hmac_drbg hmac_drbg.no_reseed)
add_test_suite(hmac_drbg hmac_drbg.nopr)
add_test_suite(hmac_drbg hmac_drbg.pr)
add_test_suite(md)
add_test_suite(mdx)
add_test_suite(memory_buffer_alloc)
add_test_suite(mpi)
add_test_suite(mps)
add_test_suite(net)
add_test_suite(nist_kw)
add_test_suite(oid)
add_test_suite(pem)
add_test_suite(pk)
add_test_suite(pkcs1_v15)
add_test_suite(pkcs1_v21)
add_test_suite(pkcs5)
add_test_suite(pkcs12)
add_test_suite(pkparse)
add_test_suite(pkwrite)
add_test_suite(poly1305)
add_test_suite(psa_crypto)
add_test_suite(psa_crypto_attributes)
add_test_suite(psa_crypto_entropy)
add_test_suite(psa_crypto_hash)
add_test_suite(psa_crypto_init)
add_test_suite(psa_crypto_metadata)
add_test_suite(psa_crypto_not_supported psa_crypto_not_supported.generated)
add_test_suite(psa_crypto_not_supported psa_crypto_not_supported.misc)
add_test_suite(psa_crypto_persistent_key)
add_test_suite(psa_crypto_se_driver_hal)
add_test_suite(psa_crypto_se_driver_hal_mocks)
add_test_suite(psa_crypto_slot_management)
add_test_suite(psa_crypto_storage_format psa_crypto_storage_format.misc)
add_test_suite(psa_crypto_storage_format psa_crypto_storage_format.current)
add_test_suite(psa_crypto_storage_format psa_crypto_storage_format.v0)
add_test_suite(psa_its)
add_test_suite(random)
add_test_suite(rsa)
add_test_suite(shax)
add_test_suite(ssl)
add_test_suite(timing)
add_test_suite(version)
add_test_suite(x509parse)
add_test_suite(x509write)
add_test_suite(xtea)

# Make scripts and data files needed for testing available in an
# out-of-source build.
if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/seedfile")
        link_to_source(seedfile)
    endif()
    link_to_source(compat.sh)
    link_to_source(context-info.sh)
    link_to_source(data_files)
    link_to_source(scripts)
    link_to_source(ssl-opt.sh)
    link_to_source(suites)
endif()
