set(wasi_socket_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../core/iwasm/libraries/lib-socket)
set(wasi_socket_header_dir ${wasi_socket_dir}/inc)

set(srcs ${wasi_socket_dir}/src/wasi/wasi_socket_ext.c)
set(headers
    ${wasi_socket_header_dir}/wasi_socket_ext.h
)

add_library(wamr-wasi-socket STATIC ${srcs})
set_property(TARGET wamr-wasi-socket PROPERTY PUBLIC_HEADER ${headers})
target_include_directories(wamr-wasi-socket
                           PUBLIC
                           $<BUILD_INTERFACE:${wasi_socket_header_dir}>
                           $<INSTALL_INTERFACE:include>)

# as this is a library, be extra conservative about wasm features
# to improve compatibilities. as this particular library is just a
# simple static stub, extra wasm features won't benefit us much anyway.
# note that LLVM-19 enables reference-types by default.
target_compile_options(wamr-wasi-socket PRIVATE -mno-reference-types)

install(TARGETS wamr-wasi-socket
        EXPORT wamr-wasi-socket-config
        PUBLIC_HEADER DESTINATION include)
install(EXPORT wamr-wasi-socket-config
        DESTINATION lib/cmake/wamr-wasi-socket)
