# LLVM clang and wasm-ld are sufficient; no WASI SDK is required.
CLANG ?= clang
WASM_LD ?= wasm-ld

all: ../../data/wasm/filter_v2.wasm

../../data/wasm/filter_v2.wasm: filter_v2.c
	$(CLANG) --target=wasm32 -O2 -nostdlib -c $< -o filter_v2.o
	$(WASM_LD) --no-entry --export-all filter_v2.o -o $@
	rm -f filter_v2.o
