#!/bin/sh

# Do test builds of the yotta module for all supported targets

set -eu

yotta/create-module.sh
cd yotta/module
yt update || true # needs network

yotta_build()
{
    TARGET=$1
    echo; echo "*** $TARGET ***"
    yt -t $TARGET build
}

if uname -a | grep 'Linux.*x86' >/dev/null; then
    yotta_build x86-linux-native
fi
if uname -a | grep 'Darwin.*x86' >/dev/null; then
    yotta_build x86-osx-native
fi
if which armcc >/dev/null && armcc --help >/dev/null 2>&1; then
    yotta_build frdm-k64f-armcc
    #yotta_build nordic-nrf51822-16k-armcc
fi
if which arm-none-eabi-gcc >/dev/null; then
    yotta_build frdm-k64f-gcc
    #yotta_build st-nucleo-f401re-gcc # dirent
    #yotta_build stm32f429i-disco-gcc # fails in mbed-hal-st-stm32f4
    #yotta_build nordic-nrf51822-16k-gcc # fails in minar-platform
    #yotta_build bbc-microbit-classic-gcc # fails in minar-platform
    #yotta_build st-stm32f439zi-gcc # fails in mbed-hal-st-stm32f4
    #yotta_build st-stm32f429i-disco-gcc # fails in mbed-hal-st-stm32f4
fi
