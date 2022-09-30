# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CC = /opt/wasi-sdk/bin/clang
APP_DIR = ${shell pwd}
IWASM_DIR = $(APP_DIR)/../../../../core/iwasm
SDK_DIR = $(APP_DIR)/../../../../wamr-sdk/out/gui/app-sdk
APP_FRAMEWORK_DIR = $(APP_DIR)/../../../../wamr-sdk/out/gui/app-sdk/wamr-app-framework
DEPS_DIR = $(APP_DIR)/../../../../core/deps

CFLAGS += -O3 \
    -Wno-int-conversion \
    -I$(APP_DIR)/src \
    -I$(APP_FRAMEWORK_DIR)/include \
    -I${DEPS_DIR}

SRCS += $(APP_DIR)/src/main.c

all:
	@$(CC) $(CFLAGS) $(SRCS) \
    --target=wasm32 -O3 -z stack-size=2048 -Wl,--initial-memory=65536 \
    --sysroot=$(SDK_DIR)/libc-builtin-sysroot       \
    -L$(APP_FRAMEWORK_DIR)/lib -lapp_framework      \
    -Wl,--allow-undefined-file=$(SDK_DIR)/libc-builtin-sysroot/share/defined-symbols.txt \
    -Wl,--strip-all,--no-entry -nostdlib \
    -Wl,--export=on_init -Wl,--export=on_timer_callback \
    -Wl,--export=on_widget_event \
    -Wl,--export=__heap_base,--export=__data_end \
    -o ui_decrease.wasm
