WASI_SDK_ROOT ?= /opt/wasi-sdk
STACK_SIZE ?= 8192
INITIAL_MEMORY_SIZE ?= 65536

.PHONY: wasm

wasm:
	${WASI_SDK_ROOT}/bin/clang -O3 -nostdlib \
		-z stack-size=${STACK_SIZE} -Wl,--initial-memory=${INITIAL_MEMORY_SIZE} \
		-o c_filter.wasm c_filter.c \
		-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--export=c_filter \
		-Wl,--no-entry -Wl,--strip-all -Wl,--allow-undefined

clean:
	rm -f *.wasm
