#! /bin/sh

set -e

NAME=${1:-test1}

echo "====== Interpreter ${NAME}"
out/native-stack-overflow out/wasm-apps/testapp.wasm ${NAME}

echo
echo "====== Interpreter WAMR_DISABLE_HW_BOUND_CHECK=1 ${NAME}"
out/native-stack-overflow.WAMR_DISABLE_HW_BOUND_CHECK out/wasm-apps/testapp.wasm ${NAME}

echo
echo "====== AOT ${NAME}"
out/native-stack-overflow out/wasm-apps/testapp.wasm.aot ${NAME}

echo
echo "====== AOT w/ signature ${NAME}"
out/native-stack-overflow out/wasm-apps/testapp.wasm.aot.signature ${NAME}

echo
echo "====== AOT WAMR_DISABLE_HW_BOUND_CHECK=1 ${NAME}"
out/native-stack-overflow.WAMR_DISABLE_HW_BOUND_CHECK out/wasm-apps/testapp.wasm.aot.bounds-checks ${NAME}

echo
echo "====== AOT w/ signature WAMR_DISABLE_HW_BOUND_CHECK=1 ${NAME}"
out/native-stack-overflow.WAMR_DISABLE_HW_BOUND_CHECK out/wasm-apps/testapp.wasm.aot.signature.bounds-checks ${NAME}
