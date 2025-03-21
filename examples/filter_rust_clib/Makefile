WASI_SDK_ROOT ?= /opt/wasi-sdk
STACK_SIZE ?= 8192
INITIAL_MEMORY_SIZE ?= 65536

rustclib:
	cargo build --target wasm32-unknown-unknown --release

build: wasm rustclib

wasm: rustclib rust_clib_filter.h
	${WASI_SDK_ROOT}/bin/clang -O3 -nostdlib \
		-z stack-size=${STACK_SIZE} -Wl,--initial-memory=${INITIAL_MEMORY_SIZE} \
		-o rust_clib_filter.wasm rust_clib_filter.c \
		-L ./target/wasm32-unknown-unknown/release -lfilter_rust_clib \
		-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--export=rust_clib_filter \
		-Wl,--no-entry -Wl,--strip-all -Wl,--allow-undefined

rust_clib_filter.h:
	cbindgen --crate filter_rust_clib --output filter_rust_clib.h --lang c


clean:
	rm -f *.wasm
	rm -f *.h
	cargo clean
