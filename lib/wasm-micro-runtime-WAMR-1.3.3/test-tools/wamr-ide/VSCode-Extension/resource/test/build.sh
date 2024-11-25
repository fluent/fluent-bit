# compile with debug symbols and no optimization
rustc --target wasm32-wasi ./test.rs -g -C opt-level=0