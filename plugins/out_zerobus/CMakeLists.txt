set(src
  zerobus.c)

FLB_PLUGIN(out_zerobus "${src}" "")
target_include_directories(flb-plugin-out_zerobus
  PRIVATE ${ZEROBUS_FFI_INCLUDE_DIR})
target_link_libraries(flb-plugin-out_zerobus "${ZEROBUS_LIB_FILE}")

if(ZEROBUS_LIB_BUILD_TARGET)
  add_dependencies(flb-plugin-out_zerobus ${ZEROBUS_LIB_BUILD_TARGET})
endif()

# Platform-specific linker flags required by the Rust FFI static library
if(FLB_SYSTEM_WINDOWS)
  target_link_libraries(flb-plugin-out_zerobus
    ws2_32 ntdll userenv advapi32 bcrypt)
elseif(FLB_SYSTEM_MACOS)
  target_link_libraries(flb-plugin-out_zerobus
    "-framework CoreFoundation"
    "-framework Security"
    -liconv)
elseif(UNIX)
  target_link_libraries(flb-plugin-out_zerobus
    -ldl -lpthread -lm -lresolv -lgcc_s)
else()
  message(FATAL_ERROR "out_zerobus does not define linker dependencies for this platform")
endif()
