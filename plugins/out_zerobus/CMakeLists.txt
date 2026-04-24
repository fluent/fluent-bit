set(src
  zerobus.c)

FLB_PLUGIN(out_zerobus "${src}" "")
target_link_libraries(flb-plugin-out_zerobus "${ZEROBUS_LIB_FILE}")

# Platform-specific linker flags required by the Rust FFI static library
if(WIN32)
  target_link_libraries(flb-plugin-out_zerobus
    ws2_32 ntdll userenv advapi32 bcrypt)
elseif(APPLE)
  target_link_libraries(flb-plugin-out_zerobus
    "-framework CoreFoundation"
    "-framework Security"
    -liconv)
elseif(UNIX)
  target_link_libraries(flb-plugin-out_zerobus
    -ldl -lpthread -lm -lresolv -lgcc_s)
endif()
