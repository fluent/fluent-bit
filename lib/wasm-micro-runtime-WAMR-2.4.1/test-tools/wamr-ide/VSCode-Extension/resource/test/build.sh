# compile with debug symbols and no optimization
rustc --target wasm32-wasip1 ./test.rs -g -C opt-level=0