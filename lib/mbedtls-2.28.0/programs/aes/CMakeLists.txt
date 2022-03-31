set(executables
    crypt_and_hash
)

foreach(exe IN LISTS executables)
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:mbedtls_test>)
    target_link_libraries(${exe} ${mbedcrypto_target})
endforeach()

install(TARGETS ${executables}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
