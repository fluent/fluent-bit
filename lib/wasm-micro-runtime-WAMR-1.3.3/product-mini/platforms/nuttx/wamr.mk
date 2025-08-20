# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CORE_ROOT := wamr/core
IWASM_ROOT := wamr/core/iwasm
SHARED_ROOT := wamr/core/shared

ifeq ($(CONFIG_ARCH_ARMV6M),y)
WAMR_BUILD_TARGET := THUMBV6M
else ifeq ($(CONFIG_ARCH_ARMV7A),y)
WAMR_BUILD_TARGET := THUMBV7
else ifeq ($(CONFIG_ARCH_ARMV7M),y)
WAMR_BUILD_TARGET := THUMBV7EM
else ifeq ($(CONFIG_ARCH_ARMV8M),y)
WAMR_BUILD_TARGET := THUMBV8M
else ifeq ($(CONFIG_ARCH_ARM64),y)
WAMR_BUILD_TARGET := AARCH64
else ifeq ($(CONFIG_ARCH_X86),y)
WAMR_BUILD_TARGET := X86_32
else ifeq ($(CONFIG_ARCH_X86_64),y)
WAMR_BUILD_TARGET := X86_64
else ifeq ($(CONFIG_ARCH_XTENSA),y)
WAMR_BUILD_TARGET := XTENSA
# RV64GC and RV32IM used in older
# version NuttX
else ifeq ($(CONFIG_ARCH_RV64GC),y)
WAMR_BUILD_TARGET := RISCV64
else ifeq ($(CONFIG_ARCH_RV32IM),y)
WAMR_BUILD_TARGET := RISCV32
else ifeq ($(CONFIG_ARCH_RV64),y)
WAMR_BUILD_TARGET := RISCV64
else ifeq ($(CONFIG_ARCH_RV32),y)
WAMR_BUILD_TARGET := RISCV32
else ifeq ($(CONFIG_ARCH_SIM),y)
ifeq ($(CONFIG_SIM_M32),y)
WAMR_BUILD_TARGET := X86_32
else ifeq ($(CONFIG_HOST_X86),y)
WAMR_BUILD_TARGET := X86_32
else ifeq ($(CONFIG_HOST_ARM),y)
WAMR_BUILD_TARGET := ARM
else ifeq ($(CONFIG_HOST_ARM64),y)
WAMR_BUILD_TARGET := AARCH64
else
WAMR_BUILD_TARGET := X86_64
endif
ifeq ($(CONFIG_HOST_MACOS),y)
# Note: invokeNative_em64.s needs BH_PLATFORM_DARWIN
AFLAGS += -DBH_PLATFORM_DARWIN
endif
endif

WAMR_BUILD_PLATFORM := nuttx

CFLAGS += -DBH_MALLOC=wasm_runtime_malloc
CFLAGS += -DBH_FREE=wasm_runtime_free

ifeq ($(WAMR_BUILD_TARGET), X86_32)
  CFLAGS += -DBUILD_TARGET_X86_32
  INVOKE_NATIVE := invokeNative_ia32.s
  AOT_RELOC := aot_reloc_x86_32.c
else ifeq ($(WAMR_BUILD_TARGET), X86_64)
  CFLAGS += -DBUILD_TARGET_X86_64
  INVOKE_NATIVE := invokeNative_em64.s
  AOT_RELOC := aot_reloc_x86_64.c
else ifeq ($(WAMR_BUILD_TARGET), AARCH64)
  CFLAGS += -DBUILD_TARGET_AARCH64
  CFLAGS += -DBUILD_TARGET=\"$(WAMR_BUILD_TARGET)\"
  INVOKE_NATIVE := invokeNative_aarch64.s
  AOT_RELOC := aot_reloc_aarch64.c
else ifeq ($(findstring ARM,$(WAMR_BUILD_TARGET)), ARM)
  CFLAGS += -DBUILD_TARGET_ARM
  CFLAGS += -DBUILD_TARGET=\"$(WAMR_BUILD_TARGET)\"
  INVOKE_NATIVE := invokeNative_arm.s
  AOT_RELOC := aot_reloc_arm.c
else ifeq ($(findstring THUMB,$(WAMR_BUILD_TARGET)), THUMB)
  CFLAGS += -DBUILD_TARGET=\"$(WAMR_BUILD_TARGET)\"
  ifeq ($(CONFIG_ARCH_FPU),y)
  CFLAGS += -DBUILD_TARGET_THUMB_VFP
  INVOKE_NATIVE := invokeNative_thumb_vfp.s
  else
  CFLAGS += -DBUILD_TARGET_THUMB
  INVOKE_NATIVE := invokeNative_thumb.s
  endif
  AOT_RELOC := aot_reloc_thumb.c
else ifeq (${WAMR_BUILD_TARGET}, MIPS)
  CFLAGS += -DBUILD_TARGET_MIPS
  INVOKE_NATIVE := invokeNative_mips.s
  AOT_RELOC := aot_reloc_mips.c
else ifeq (${WAMR_BUILD_TARGET}, XTENSA)
  CFLAGS += -DBUILD_TARGET_XTENSA
  INVOKE_NATIVE := invokeNative_xtensa.s
  AOT_RELOC := aot_reloc_xtensa.c
else ifeq (${WAMR_BUILD_TARGET}, RISCV64)

ifeq (${CONFIG_ARCH_DPFPU},y)
  CFLAGS += -DBUILD_TARGET_RISCV64_LP64D
else ifneq (${CONFIG_ARCH_FPU},y)
  CFLAGS += -DBUILD_TARGET_RISCV64_LP64
else
  $(error riscv64 lp64f is unsupported)
endif
  INVOKE_NATIVE += invokeNative_riscv.S

  AOT_RELOC := aot_reloc_riscv.c

else ifeq (${WAMR_BUILD_TARGET}, RISCV32)

ifeq (${CONFIG_ARCH_DPFPU},y)
  CFLAGS += -DBUILD_TARGET_RISCV32_ILP32D
else ifneq (${CONFIG_ARCH_FPU},y)
  CFLAGS += -DBUILD_TARGET_RISCV32_ILP32
else
  $(error riscv32 ilp32f is unsupported)
endif

  INVOKE_NATIVE += invokeNative_riscv.S
  AOT_RELOC := aot_reloc_riscv.c

else
  $(error Build target is unsupported)
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_LOG),y)
CFLAGS += -DWASM_ENABLE_LOG=1
else
CFLAGS += -DWASM_ENABLE_LOG=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_AOT),y)
CFLAGS += -I$(IWASM_ROOT)/aot
CFLAGS += -DWASM_ENABLE_AOT=1
CSRCS += aot_loader.c \
         $(AOT_RELOC) \
         aot_intrinsic.c \
         aot_runtime.c
ifeq ($(CONFIG_INTERPRETERS_WAMR_DEBUG_AOT),y)
CFLAGS += -DWASM_ENABLE_DEBUG_AOT=1
CSRCS += elf_parser.c \
         jit_debug.c
endif
else
CFLAGS += -DWASM_ENABLE_AOT=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_AOT_QUICK_ENTRY),y)
CFLAGS += -DWASM_ENABLE_QUICK_AOT_ENTRY=1
else
CFLAGS += -DWASM_ENABLE_QUICK_AOT_ENTRY=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_AOT_WORD_ALIGN_READ),y)
CFLAGS += -DWASM_ENABLE_WORD_ALIGN_READ=1
else
CFLAGS += -DWASM_ENABLE_WORD_ALIGN_READ=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_MEM_DUAL_BUS_MIRROR),y)
CFLAGS += -DWASM_MEM_DUAL_BUS_MIRROR=1
else
CFLAGS += -DWASM_MEM_DUAL_BUS_MIRROR=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_FAST), y)
CFLAGS += -DWASM_ENABLE_FAST_INTERP=1
CFLAGS += -DWASM_ENABLE_INTERP=1
CSRCS += wasm_interp_fast.c
CSRCS += wasm_runtime.c
else
CFLAGS += -DWASM_ENABLE_FAST_INTERP=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_CLASSIC), y)
CFLAGS += -DWASM_ENABLE_INTERP=1
CSRCS += wasm_interp_classic.c
CSRCS += wasm_runtime.c
endif

ifeq ($(findstring y,$(CONFIG_INTERPRETERS_WAMR_FAST)$(CONFIG_INTERPRETERS_WAMR_CLASSIC)), y)
ifeq ($(CONFIG_INTERPRETERS_WAMR_MINILOADER),y)
CFLAGS += -DWASM_ENABLE_MINI_LOADER=1
CSRCS += wasm_mini_loader.c
else
CFLAGS += -DWASM_ENABLE_MINI_LOADER=0
CSRCS += wasm_loader.c
endif
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_DEBUG_INTERP),y)
# Note: INTERPRETERS_WAMR_CLASSIC/INTERPRETERS_WAMR_THREAD_MGR
# dependencies are already handled in NuttX apps Kconfig
CFLAGS += -DWASM_ENABLE_DEBUG_INTERP=1
CFLAGS += -I$(IWASM_ROOT)/libraries/debug-engine
CSRCS += debug_engine.c
CSRCS += gdbserver.c
CSRCS += handler.c
CSRCS += packets.c
CSRCS += utils.c
VPATH += $(IWASM_ROOT)/libraries/debug-engine
endif

ifneq ($(CONFIG_INTERPRETERS_WAMR_STACK_GUARD_SIZE),)
CFLAGS += -DWASM_STACK_GUARD_SIZE=CONFIG_INTERPRETERS_WAMR_STACK_GUARD_SIZE
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_SHARED_MEMORY),y)
CFLAGS += -DWASM_ENABLE_SHARED_MEMORY=1
CSRCS += wasm_shared_memory.c
else
CFLAGS += -DWASM_ENABLE_SHARED_MEMORY=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_BULK_MEMORY),y)
CFLAGS += -DWASM_ENABLE_BULK_MEMORY=1
else
CFLAGS += -DWASM_ENABLE_BULK_MEMORY=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_PERF_PROFILING),y)
CFLAGS += -DWASM_ENABLE_PERF_PROFILING=1
else
CFLAGS += -DWASM_ENABLE_PERF_PROFILING=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_MEMORY_PROFILING),y)
CFLAGS += -DWASM_ENABLE_MEMORY_PROFILING=1
else
CFLAGS += -DWASM_ENABLE_MEMORY_PROFILING=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_MEMORY_TRACING),y)
CFLAGS += -DWASM_ENABLE_MEMORY_TRACING=1
else
CFLAGS += -DWASM_ENABLE_MEMORY_TRACING=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_DUMP_CALL_STACK),y)
CFLAGS += -DWASM_ENABLE_DUMP_CALL_STACK=1
else
CFLAGS += -DWASM_ENABLE_DUMP_CALL_STACK=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_LIBC_BUILTIN),y)
CFLAGS += -DWASM_ENABLE_LIBC_BUILTIN=1
CSRCS += libc_builtin_wrapper.c
VPATH += $(IWASM_ROOT)/libraries/libc-builtin
else
CFLAGS += -DWASM_ENABLE_LIBC_BUILTIN=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_CONFIGURABLE_BOUNDS_CHECKS),y)
CFLAGS += -DWASM_CONFIGURABLE_BOUNDS_CHECKS=1
else
CFLAGS += -DWASM_CONFIGURABLE_BOUNDS_CHECKS=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_LIBC_WASI),y)
CFLAGS += -DWASM_ENABLE_LIBC_WASI=1
CFLAGS += -I$(IWASM_ROOT)/libraries/libc-wasi/sandboxed-system-primitives/src
CFLAGS += -I$(IWASM_ROOT)/libraries/libc-wasi/sandboxed-system-primitives/include
CFLAGS += -I${SHARED_ROOT}/platform/common/libc-util
CSRCS += blocking_op.c
CSRCS += posix_socket.c
CSRCS += posix_file.c
CSRCS += posix_clock.c
CSRCS += libc_errno.c
CSRCS += libc_wasi_wrapper.c
VPATH += $(IWASM_ROOT)/libraries/libc-wasi
CSRCS += posix.c
CSRCS += random.c
CSRCS += str.c
VPATH += $(IWASM_ROOT)/libraries/libc-wasi/sandboxed-system-primitives/src
# todo: use Kconfig select instead
CONFIG_INTERPRETERS_WAMR_MODULE_INSTANCE_CONTEXT = y
else
CFLAGS += -DWASM_ENABLE_LIBC_WASI=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_MODULE_INSTANCE_CONTEXT),y)
CFLAGS += -DWASM_ENABLE_MODULE_INST_CONTEXT=1
else
CFLAGS += -DWASM_ENABLE_MODULE_INST_CONTEXT=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_MULTI_MODULE),y)
CFLAGS += -DWASM_ENABLE_MULTI_MODULE=1
else
CFLAGS += -DWASM_ENABLE_MULTI_MODULE=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_THREAD_MGR),y)
CFLAGS += -DWASM_ENABLE_THREAD_MGR=1
CSRCS += thread_manager.c
VPATH += $(IWASM_ROOT)/libraries/thread-mgr
else
CFLAGS += -DWASM_ENABLE_THREAD_MGR=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_LIB_WASI_THREADS),y)
CFLAGS += -DWASM_ENABLE_LIB_WASI_THREADS=1
CSRCS += lib_wasi_threads_wrapper.c
CSRCS += tid_allocator.c
VPATH += $(IWASM_ROOT)/libraries/lib-wasi-threads
else
CFLAGS += -DWASM_ENABLE_LIB_WASI_THREADS=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_LIB_PTHREAD),y)
CFLAGS += -DWASM_ENABLE_LIB_PTHREAD=1
CSRCS += lib_pthread_wrapper.c
else
CFLAGS += -DWASM_ENABLE_LIB_PTHREAD=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_LIB_PTHREAD_SEMAPHORE),y)
CFLAGS += -DWASM_ENABLE_LIB_PTHREAD_SEMAPHORE=1
else
CFLAGS += -DWASM_ENABLE_LIB_PTHREAD_SEMAPHORE=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_DISABLE_HW_BOUND_CHECK),y)
CFLAGS += -DWASM_DISABLE_HW_BOUND_CHECK=1
CFLAGS += -DWASM_DISABLE_STACK_HW_BOUND_CHECK=1
else
CFLAGS += -DWASM_DISABLE_HW_BOUND_CHECK=0
CFLAGS += -DWASM_DISABLE_STACK_HW_BOUND_CHECK=0
endif

# REVISIT: is this worth to have a Kconfig?
CFLAGS += -DWASM_DISABLE_WAKEUP_BLOCKING_OP=0

ifeq ($(CONFIG_INTERPRETERS_WAMR_LOAD_CUSTOM_SECTIONS),y)
CFLAGS += -DWASM_ENABLE_LOAD_CUSTOM_SECTION=1
else
CFLAGS += -DWASM_ENABLE_LOAD_CUSTOM_SECTION=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_CUSTOM_NAME_SECTIONS),y)
CFLAGS += -DWASM_ENABLE_CUSTOM_NAME_SECTION=1
else
CFLAGS += -DWASM_ENABLE_CUSTOM_NAME_SECTION=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_GLOBAL_HEAP_POOL),y)
CFLAGS += -DWASM_ENABLE_GLOBAL_HEAP_POOL=1
CFLAGS += -DWASM_GLOBAL_HEAP_SIZE="$(CONFIG_INTERPRETERS_WAMR_GLOBAL_HEAP_POOL_SIZE) * 1024"
else
CFLAGS += -DWASM_ENABLE_GLOBAL_HEAP_POOL=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_ENABLE_SPEC_TEST),y)
CFLAGS += -DWASM_ENABLE_SPEC_TEST=1
else
CFLAGS += -DWASM_ENABLE_SPEC_TEST=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_REF_TYPES),y)
CFLAGS += -DWASM_ENABLE_REF_TYPES=1
else
CFLAGS += -DWASM_ENABLE_REF_TYPES=0
endif

ifeq ($(CONFIG_INTERPRETERS_WAMR_ENABLE_EXCE_HANDLING),y)
CFLAGS += -DWASM_ENABLE_EXCE_HANDLING=1
CFLAGS += -DWASM_ENABLE_TAGS=1
else
CFLAGS += -DWASM_ENABLE_EXCE_HANDLING=0
CFLAGS += -DWASM_ENABLE_TAGS=0
endif

CFLAGS += -Wno-strict-prototypes -Wno-shadow -Wno-unused-variable
CFLAGS += -Wno-int-conversion -Wno-implicit-function-declaration

CFLAGS += -I${CORE_ROOT} \
          -I${IWASM_ROOT}/include \
          -I${IWASM_ROOT}/interpreter \
          -I${IWASM_ROOT}/common \
          -I${IWASM_ROOT}/libraries/thread-mgr \
          -I${SHARED_ROOT}/include \
          -I${SHARED_ROOT}/platform/include \
          -I${SHARED_ROOT}/utils \
          -I${SHARED_ROOT}/utils/uncommon \
          -I${SHARED_ROOT}/mem-alloc \
          -I${SHARED_ROOT}/platform/nuttx

ifeq ($(WAMR_BUILD_INTERP), 1)
CFLAGS += -I$(IWASM_ROOT)/interpreter
endif

CSRCS += nuttx_platform.c \
         posix_blocking_op.c \
         posix_thread.c \
         posix_time.c \
         posix_sleep.c \
         mem_alloc.c \
         ems_kfc.c \
         ems_alloc.c \
         ems_hmu.c \
         bh_assert.c \
         bh_bitmap.c \
         bh_common.c \
         bh_hashmap.c \
         bh_list.c \
         bh_log.c \
         bh_queue.c \
         bh_vector.c \
         bh_read_file.c \
         runtime_timer.c \
         wasm_application.c \
         wasm_blocking_op.c \
         wasm_runtime_common.c \
         wasm_native.c \
         wasm_exec_env.c \
         wasm_memory.c \
         wasm_c_api.c

ASRCS += $(INVOKE_NATIVE)

VPATH += $(SHARED_ROOT)/platform/nuttx
VPATH += $(SHARED_ROOT)/platform/common/posix
VPATH += $(SHARED_ROOT)/platform/common/libc-util
VPATH += $(SHARED_ROOT)/mem-alloc
VPATH += $(SHARED_ROOT)/mem-alloc/ems
VPATH += $(SHARED_ROOT)/utils
VPATH += $(SHARED_ROOT)/utils/uncommon
VPATH += $(IWASM_ROOT)/common
VPATH += $(IWASM_ROOT)/interpreter
VPATH += $(IWASM_ROOT)/libraries
VPATH += $(IWASM_ROOT)/libraries/lib-pthread
VPATH += $(IWASM_ROOT)/common/arch
VPATH += $(IWASM_ROOT)/aot
VPATH += $(IWASM_ROOT)/aot/arch
VPATH += $(IWASM_ROOT)/aot/debug
