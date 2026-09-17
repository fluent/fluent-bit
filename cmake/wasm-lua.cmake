# A portable interpreter, not LuaJIT: do not link host libraries or patch lib/.
set(FLB_WASM_LUA_PREFIX "${CMAKE_BINARY_DIR}/wasm-lua")
file(MAKE_DIRECTORY "${FLB_WASM_LUA_PREFIX}/include")

ExternalProject_Add(flb-wasm-lua-source
  EXCLUDE_FROM_ALL TRUE
  URL https://www.lua.org/ftp/lua-5.4.9.tar.gz
  URL_HASH SHA256=2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6
  PREFIX "${CMAKE_BINARY_DIR}/wasm-lua-source"
  CONFIGURE_COMMAND ${CMAKE_COMMAND}
    -S "${CMAKE_CURRENT_LIST_DIR}/wasm-lua-source" -B <BINARY_DIR>
    "-DLUA_SOURCE_DIR=<SOURCE_DIR>"
    "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
    "-DCMAKE_INSTALL_PREFIX=${FLB_WASM_LUA_PREFIX}"
    "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
    "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -pthread"
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --parallel 8
  INSTALL_COMMAND ${CMAKE_COMMAND} --install <BINARY_DIR>
  BUILD_BYPRODUCTS "${FLB_WASM_LUA_PREFIX}/lib/libflb-lua.a"
  LOG_DOWNLOAD ON LOG_CONFIGURE ON LOG_BUILD ON LOG_INSTALL ON)

add_library(flb-wasm-lua-static STATIC IMPORTED GLOBAL)
set_target_properties(flb-wasm-lua-static PROPERTIES
  IMPORTED_LOCATION "${FLB_WASM_LUA_PREFIX}/lib/libflb-lua.a"
  INTERFACE_INCLUDE_DIRECTORIES "${FLB_WASM_LUA_PREFIX}/include")
add_dependencies(flb-wasm-lua-static flb-wasm-lua-source)
include_directories("${FLB_WASM_LUA_PREFIX}/include")
set(LUAJIT_LIBRARIES flb-wasm-lua-static)
message(STATUS "Browser Lua: portable Lua 5.4.9 interpreter; no LuaJIT/FFI")
