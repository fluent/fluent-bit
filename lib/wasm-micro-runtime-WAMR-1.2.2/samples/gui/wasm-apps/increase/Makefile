# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CC = /opt/wasi-sdk/bin/clang
APP_DIR = ${shell pwd}
IWASM_DIR = ../../../../core/iwasm
APP_FRAMEWORK_DIR = ../../../../core/app-framework
DEPS_DIR = ../../../../core/deps

CFLAGS += -O3 \
	  -Wno-int-conversion \
	  -I$(APP_DIR)/src \
	  -I$(APP_FRAMEWORK_DIR)/base/app \
	  -I$(APP_FRAMEWORK_DIR)/app-native-shared \
	  -I$(APP_FRAMEWORK_DIR)/sensor/app \
	  -I$(APP_FRAMEWORK_DIR)/wgl/app \
	  -I$(APP_FRAMEWORK_DIR)/connection/app \
	  -I${DEPS_DIR}

SRCS += $(APP_DIR)/src/main.c

# For app size consideration, not all but necessary app libs are included
SRCS += $(APP_FRAMEWORK_DIR)/base/app/timer.c
SRCS += $(APP_FRAMEWORK_DIR)/wgl/app/src/*.c

all:
	@$(CC) $(CFLAGS) $(SRCS) \
    --target=wasm32-wasi -O3 -z stack-size=2048 -Wl,--initial-memory=65536 \
    -nostdlib -Wl,--allow-undefined \
    -Wl,--strip-all,--no-entry \
    -Wl,--export=on_init -Wl,--export=on_timer_callback \
    -Wl,--export=on_widget_event \
    -Wl,--export=__heap_base,--export=__data_end \
    -o ui_app.wasm
