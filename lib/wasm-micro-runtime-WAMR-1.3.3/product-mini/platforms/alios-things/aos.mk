# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

NAME := iwasm
CORE_ROOT := wamr/core
IWASM_ROOT := wamr/core/iwasm
SHARED_ROOT := wamr/core/shared

GLOBAL_DEFINES += BH_MALLOC=wasm_runtime_malloc
GLOBAL_DEFINES += BH_FREE=wasm_runtime_free

# Change it to THUMBV7M if you want to build for developerkit
WAMR_BUILD_TARGET := X86_32

WAMR_BUILD_PLATFORM := alios-things

ifeq (${WAMR_BUILD_TARGET}, X86_32)
  GLOBAL_DEFINES += BUILD_TARGET_X86_32
  INVOKE_NATIVE := invokeNative_ia32.s
  AOT_RELOC := aot_reloc_x86_32.c
else ifeq (${WAMR_BUILD_TARGET}, X86_64)
  GLOBAL_DEFINES += BUILD_TARGET_X86_64
  INVOKE_NATIVE := invokeNative_em64.s
  AOT_RELOC := aot_reloc_x86_64.c
else ifeq ($(findstring ARM,$(WAMR_BUILD_TARGET)), ARM)
  GLOBAL_DEFINES += BUILD_TARGET_ARM
  GLOBAL_DEFINES += BUILD_TARGET=\"$(WAMR_BUILD_TARGET)\"
  INVOKE_NATIVE := invokeNative_arm.s
  AOT_RELOC := aot_reloc_arm.c
else ifeq ($(findstring THUMB,$(WAMR_BUILD_TARGET)), THUMB)
  GLOBAL_DEFINES += BUILD_TARGET_THUMB
  GLOBAL_DEFINES += BUILD_TARGET=\"$(WAMR_BUILD_TARGET)\"
  INVOKE_NATIVE := invokeNative_thumb.s
  AOT_RELOC := aot_reloc_thumb.c
else ifeq (${WAMR_BUILD_TARGET}, MIPS)
  GLOBAL_DEFINES += BUILD_TARGET_MIPS
  INVOKE_NATIVE := invokeNative_mips.s
  AOT_RELOC := aot_reloc_mips.c
else ifeq (${WAMR_BUILD_TARGET}, XTENSA)
  GLOBAL_DEFINES += BUILD_TARGET_XTENSA
  INVOKE_NATIVE := invokeNative_xtensa.s
  AOT_RELOC := aot_reloc_xtensa.c
else
  $(error Build target isn't set)
endif

# Enable Interpreter by default.
WAMR_BUILD_INTERP = 1

# Enable AOT by default.
WAMR_BUILD_AOT = 1

# Override the global heap usage
ifndef WAMR_BUILD_GLOBAL_HEAP_POOL
WAMR_BUILD_GLOBAL_HEAP_POOL=1
endif
GLOBAL_DEFINES += WASM_ENABLE_GLOBAL_HEAP_POOL=${WAMR_BUILD_GLOBAL_HEAP_POOL}

# Override the global heap size for small devices
ifndef WAMR_BUILD_GLOBAL_HEAP_SIZE
WAMR_BUILD_GLOBAL_HEAP_SIZE = 262144 # 256 kB
endif
GLOBAL_DEFINES += WASM_GLOBAL_HEAP_SIZE=${WAMR_BUILD_GLOBAL_HEAP_SIZE}

ifeq (${WAMR_BUILD_INTERP}, 1)
GLOBAL_DEFINES += WASM_ENABLE_INTERP=1
endif

ifeq (${WAMR_BUILD_AOT}, 1)
GLOBAL_DEFINES += WASM_ENABLE_AOT=1
endif

GLOBAL_DEFINES += WASM_ENABLE_LIBC_BUILTIN=1

GLOBAL_INCLUDES += ${CORE_ROOT} \
				   ${IWASM_ROOT}/include \
                   ${IWASM_ROOT}/common \
                   ${SHARED_ROOT}/include \
                   ${SHARED_ROOT}/platform/include \
                   ${SHARED_ROOT}/utils \
                   ${SHARED_ROOT}/mem-alloc \
                   ${SHARED_ROOT}/platform/alios

ifeq (${WAMR_BUILD_INTERP}, 1)
GLOBAL_INCLUDES += ${IWASM_ROOT}/interpreter
endif

ifeq (${WAMR_BUILD_AOT}, 1)
GLOBAL_INCLUDES += ${IWASM_ROOT}/aot
endif

$(NAME)_SOURCES := ${SHARED_ROOT}/platform/alios/alios_platform.c \
                   ${SHARED_ROOT}/platform/alios/alios_thread.c \
                   ${SHARED_ROOT}/platform/alios/alios_time.c \
                   ${SHARED_ROOT}/platform/common/math/math.c \
                   ${SHARED_ROOT}/mem-alloc/mem_alloc.c \
                   ${SHARED_ROOT}/mem-alloc/ems/ems_kfc.c \
                   ${SHARED_ROOT}/mem-alloc/ems/ems_alloc.c \
                   ${SHARED_ROOT}/mem-alloc/ems/ems_hmu.c \
                   ${SHARED_ROOT}/utils/bh_assert.c \
                   ${SHARED_ROOT}/utils/bh_bitmap.c \
                   ${SHARED_ROOT}/utils/bh_common.c \
                   ${SHARED_ROOT}/utils/bh_hashmap.c \
                   ${SHARED_ROOT}/utils/bh_list.c \
                   ${SHARED_ROOT}/utils/bh_log.c \
                   ${SHARED_ROOT}/utils/bh_queue.c \
                   ${SHARED_ROOT}/utils/bh_vector.c \
                   ${SHARED_ROOT}/utils/runtime_timer.c \
                   ${IWASM_ROOT}/libraries/libc-builtin/libc_builtin_wrapper.c \
                   ${IWASM_ROOT}/common/wasm_application.c \
                   ${IWASM_ROOT}/common/wasm_runtime_common.c \
                   ${IWASM_ROOT}/common/wasm_native.c \
                   ${IWASM_ROOT}/common/wasm_exec_env.c \
                   ${IWASM_ROOT}/common/wasm_memory.c \
                   ${IWASM_ROOT}/common/wasm_c_api.c \
                   ${IWASM_ROOT}/common/arch/${INVOKE_NATIVE} \
                   src/main.c

ifeq (${WAMR_BUILD_INTERP}, 1)
$(NAME)_SOURCES += ${IWASM_ROOT}/interpreter/wasm_interp_classic.c \
                   ${IWASM_ROOT}/interpreter/wasm_loader.c \
                   ${IWASM_ROOT}/interpreter/wasm_runtime.c
endif

ifeq (${WAMR_BUILD_AOT}, 1)
$(NAME)_SOURCES += ${IWASM_ROOT}/aot/aot_loader.c \
                   ${IWASM_ROOT}/aot/arch/${AOT_RELOC} \
                   ${IWASM_ROOT}/aot/aot_runtime.c \
                   ${IWASM_ROOT}/aot/aot_intrinsic.c
endif

