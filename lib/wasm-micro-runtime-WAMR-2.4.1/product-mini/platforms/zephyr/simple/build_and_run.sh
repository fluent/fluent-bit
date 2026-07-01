#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

X86_TARGET="x86"
STM32_TARGET="stm32"
ESP32C3_TARGET="esp32c3"
PARTICLE_ARGON_TARGET="particle_argon"
QEMU_CORTEX_A53="qemu_cortex_a53"
QEMU_XTENSA_TARGET="qemu_xtensa"
QEMU_RISCV64_TARGET="qemu_riscv64"
QEMU_RISCV32_TARGET="qemu_riscv32"
QEMU_ARC_TARGET="qemu_arc"

usage ()
{
        echo "USAGE:"
        echo "$0 $X86_TARGET|$STM32_TARGET|$ESP32C3_TARGET|$PARTICLE_ARGON_TARGET|$QEMU_CORTEX_A53|$QEMU_XTENSA_TARGET|$QEMU_RISCV64_TARGET|$QEMU_RISCV32_TARGET|$QEMU_ARC_TARGET"
        echo "Example:"
        echo "        $0 $X86_TARGET"
        echo "        $0 $STM32_TARGET"
        echo "        $0 $ESP32C3_TARGET"
        echo "        $0 $PARTICLE_ARGON_TARGET"
        echo "        $0 $QEMU_CORTEX_A53"
        echo "        $0 $QEMU_XTENSA_TARGET"
        echo "        $0 $QEMU_RISCV64_TARGET"
        echo "        $0 $QEMU_RISCV32_TARGET"
        echo "        $0 $QEMU_ARC_TARGET"
        exit 1
}

if [ $# != 1 ] ; then
        usage
fi

TARGET=$1

case $TARGET in
        $X86_TARGET)
                west build -b qemu_x86_tiny \
                           . -p always -- \
                           -DWAMR_BUILD_TARGET=X86_32
                west build -t run
                ;;
        $STM32_TARGET)
                west build -b nucleo_f767zi \
                           . -p always -- \
                           -DWAMR_BUILD_TARGET=THUMBV7
                west flash
                ;;
        $ESP32C3_TARGET)
                west build -b esp32c3_devkitm \
                           . -p always -- \
                           -DWAMR_BUILD_TARGET=RISCV32_ILP32 \
                           -DWAMR_BUILD_AOT=0
                # west flash will discover the device
                west flash
                ;;
        $PARTICLE_ARGON_TARGET)
                west build -b  particle_argon \
                           . -p always -- \
                           -DWAMR_BUILD_TARGET=THUMBV7
                # west flash will discover the device
                west flash
                ;;
        $QEMU_XTENSA_TARGET)
                west build -b qemu_xtensa \
                           . -p always -- \
                           -DWAMR_BUILD_TARGET=XTENSA
                west build -t run
                ;;
        $QEMU_CORTEX_A53)
                west build -b qemu_cortex_a53 \
                           . -p always -- \
                           -DWAMR_BUILD_TARGET=AARCH64
                west build -t run
                ;;
        $QEMU_RISCV64_TARGET)
                west build -b qemu_riscv64 \
                            . -p always -- \
                            -DWAMR_BUILD_TARGET=RISCV64_LP64 \
                            -DWAMR_BUILD_AOT=0
                west build -t run
                ;;
        $QEMU_RISCV32_TARGET)
                west build -b qemu_riscv32 \
                            . -p always -- \
                            -DWAMR_BUILD_TARGET=RISCV32_ILP32 \
                            -DWAMR_BUILD_AOT=0
                west build -t run
                ;;
        $QEMU_ARC_TARGET)
                west build -b qemu_arc_em \
                            . -p always -- \
                            -DWAMR_BUILD_TARGET=ARC \
                            -DWAMR_BUILD_AOT=0
                west build -t run
                ;;
        *)
                echo "unsupported target: $TARGET"
                usage
                exit 1
                ;;
esac

