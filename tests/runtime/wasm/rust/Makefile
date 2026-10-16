RUSTC ?= rustc

.PHONY: v2
v2:
	$(RUSTC) --edition=2021 --target=wasm32-unknown-unknown --crate-type=cdylib \
		-C opt-level=s -C panic=abort -o ../../data/wasm/filter_rust_v2.wasm \
		../../../../examples/filter_wasm_rust/filter_v2.rs
