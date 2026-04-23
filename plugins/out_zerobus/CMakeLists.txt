set(src
  zerobus.c)

FLB_PLUGIN(out_zerobus "${src}" "")

# ZEROBUS_LIB_FILE is set automatically by cmake/zerobus-ffi.cmake or
# can be overridden by the user via -DZEROBUS_LIB_DIR=/path/to/lib.
if(NOT ZEROBUS_LIB_FILE)
  message(FATAL_ERROR
    "ZEROBUS_LIB_FILE is not set. This should not happen when "
    "FLB_OUT_ZEROBUS is ON — check that cmake/zerobus-ffi.cmake is included.")
endif()

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
