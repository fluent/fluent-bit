# OpenSSL is still needed for hashes and crypto operations when native TLS is
# disabled. Build it for the same target instead of finding host libraries.
find_package(Perl REQUIRED)
find_program(FLB_WASM_MAKE NAMES gmake make REQUIRED)

set(FLB_WASM_CRYPTO_PREFIX "${CMAKE_BINARY_DIR}/wasm-crypto")
file(MAKE_DIRECTORY "${FLB_WASM_CRYPTO_PREFIX}/include")

ExternalProject_Add(flb-wasm-openssl
  EXCLUDE_FROM_ALL TRUE
  URL https://github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz
  URL_HASH SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
  PREFIX "${CMAKE_BINARY_DIR}/wasm-openssl"
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
    "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}" "RANLIB=${CMAKE_RANLIB}"
    "CFLAGS=${CMAKE_C_FLAGS} -pthread"
    ${PERL_EXECUTABLE} <SOURCE_DIR>/Configure linux-generic32
    no-asm no-shared no-dso no-async no-engine no-tests no-ui-console
    no-module no-sock no-secure-memory
    "--prefix=${FLB_WASM_CRYPTO_PREFIX}" --libdir=lib
  BUILD_COMMAND ${FLB_WASM_MAKE} -j8 build_libs
  INSTALL_COMMAND ${FLB_WASM_MAKE} install_dev
  BUILD_BYPRODUCTS "${FLB_WASM_CRYPTO_PREFIX}/lib/libcrypto.a"
  LOG_DOWNLOAD ON
  LOG_CONFIGURE ON
  LOG_BUILD ON
  LOG_INSTALL ON)

add_library(flb-wasm-crypto STATIC IMPORTED GLOBAL)
set_target_properties(flb-wasm-crypto PROPERTIES
  IMPORTED_LOCATION "${FLB_WASM_CRYPTO_PREFIX}/lib/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${FLB_WASM_CRYPTO_PREFIX}/include")
add_dependencies(flb-wasm-crypto flb-wasm-openssl)
