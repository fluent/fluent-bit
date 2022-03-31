set(libs
    ${mbedtls_target}
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

find_library(FUZZINGENGINE_LIB FuzzingEngine)
if(FUZZINGENGINE_LIB)
    project(fuzz CXX)
endif()

set(executables_no_common_c
    fuzz_privkey
    fuzz_pubkey
    fuzz_x509crl
    fuzz_x509crt
    fuzz_x509csr
)

set(executables_with_common_c
    fuzz_client
    fuzz_dtlsclient
    fuzz_dtlsserver
    fuzz_server
)

foreach(exe IN LISTS executables_no_common_c executables_with_common_c)

    set(exe_sources ${exe}.c $<TARGET_OBJECTS:mbedtls_test>)
    if(NOT FUZZINGENGINE_LIB)
        list(APPEND exe_sources onefile.c)
    endif()

    # This emulates "if ( ... IN_LIST ... )" which becomes available in CMake 3.3
    list(FIND executables_with_common_c ${exe} exe_index)
    if(${exe_index} GREATER -1)
        list(APPEND exe_sources common.c)
    endif()

    add_executable(${exe} ${exe_sources})

    if (NOT FUZZINGENGINE_LIB)
        target_link_libraries(${exe} ${libs})
    else()
        target_link_libraries(${exe} ${libs} FuzzingEngine)
        SET_TARGET_PROPERTIES(${exe} PROPERTIES LINKER_LANGUAGE CXX)
    endif()

endforeach()
