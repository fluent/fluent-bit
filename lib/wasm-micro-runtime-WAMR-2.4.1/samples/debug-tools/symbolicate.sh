#!/bin/bash
set -euox pipefail

# Symbolicate .wasm
python3 ../../../test-tools/addr2line/addr2line.py \
    --wasi-sdk /opt/wasi-sdk \
    --wabt /opt/wabt \
    --wasm-file wasm-apps/trap.wasm \
    call_stack.txt

# Symbolicate .wasm with `--no-addr`
python3 ../../../test-tools/addr2line/addr2line.py \
    --wasi-sdk /opt/wasi-sdk \
    --wabt /opt/wabt \
    --wasm-file wasm-apps/trap.wasm \
    call_stack.txt --no-addr

# Symbolicate .aot
python3 ../../../test-tools/addr2line/addr2line.py \
    --wasi-sdk /opt/wasi-sdk \
    --wabt /opt/wabt \
    --wasm-file wasm-apps/trap.wasm \
    call_stack_aot.txt