set(THREADS_USE_PTHREADS_WIN32 true)
find_package(Threads)

set(libs
    ${mbedtls_target}
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

set(executables
    dtls_client
    dtls_server
    mini_client
    ssl_client1
    ssl_client2
    ssl_context_info
    ssl_fork_server
    ssl_mail_client
    ssl_server
    ssl_server2
)

foreach(exe IN LISTS executables)
    set(extra_sources "")
    if(exe STREQUAL "ssl_client2" OR exe STREQUAL "ssl_server2")
        list(APPEND extra_sources
            ${CMAKE_CURRENT_SOURCE_DIR}/../test/query_config.c)
    endif()
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:mbedtls_test>
        ${extra_sources})
    target_link_libraries(${exe} ${libs})
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/include)
endforeach()

set_property(TARGET ssl_client2 APPEND PROPERTY SOURCES
    ssl_test_lib.c ${CMAKE_CURRENT_SOURCE_DIR}/../test/query_config.c)
set_property(TARGET ssl_server2 APPEND PROPERTY SOURCES
    ssl_test_lib.c ${CMAKE_CURRENT_SOURCE_DIR}/../test/query_config.c)

if(THREADS_FOUND)
    add_executable(ssl_pthread_server ssl_pthread_server.c $<TARGET_OBJECTS:mbedtls_test>)
    target_link_libraries(ssl_pthread_server ${libs} ${CMAKE_THREAD_LIBS_INIT})
    list(APPEND executables ssl_pthread_server)
endif(THREADS_FOUND)

install(TARGETS ${executables}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
