#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

. ../../../set_dev_env.sh

CC=/opt/wasi-sdk/bin/clang
APP_DIR=$PWD
WAMR_DIR=${APP_DIR}/../../../../../
SDK_DIR=${WAMR_DIR}/wamr-sdk/out/simple-host-interp
APP_FRAMEWORK_DIR=${SDK_DIR}/app-sdk/wamr-app-framework
DEPS_DIR=${WAMR_DIR}/core/deps

for i in `ls *.c`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm
/opt/wasi-sdk/bin/clang -O3 \
                        -Wno-int-conversion \
                        -I${APP_FRAMEWORK_DIR}/include \
                        -I${DEPS_DIR} \
                        -O3 -z stack-size=4096 -Wl,--initial-memory=65536 \
                        --sysroot=${SDK_DIR}/app-sdk/libc-builtin-sysroot \
                        -L${APP_FRAMEWORK_DIR}/lib -lapp_framework \
                        -Wl,--allow-undefined-file=${SDK_DIR}/app-sdk/libc-builtin-sysroot/share/defined-symbols.txt \
                        -Wl,--strip-all,--no-entry -nostdlib \
                        -Wl,--export=on_init -Wl,--export=on_destroy \
                        -Wl,--export=on_request -Wl,--export=on_response \
                        -Wl,--export=on_sensor_event -Wl,--export=on_timer_callback \
                        -Wl,--export=on_connection_data \
                        -o ${OUT_FILE} \
                        ${APP_SRC}
if [ -f ${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
