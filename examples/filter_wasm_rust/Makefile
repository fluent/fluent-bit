RUSTC ?= rustc

.PHONY: v2
v2:
	$(RUSTC) --edition=2021 --target=wasm32-unknown-unknown --crate-type=cdylib \
		-C opt-level=s -C panic=abort -o filter_v2.wasm filter_v2.rs
