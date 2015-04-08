add_executable(hello hello.c)
target_link_libraries(hello mbedtls)

add_executable(generic_sum generic_sum.c)
target_link_libraries(generic_sum mbedtls)

add_executable(md5sum md5sum.c)
target_link_libraries(md5sum mbedtls)

add_executable(sha1sum sha1sum.c)
target_link_libraries(sha1sum mbedtls)

add_executable(sha2sum sha2sum.c)
target_link_libraries(sha2sum mbedtls)

install(TARGETS hello md5sum sha1sum sha2sum generic_sum
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
