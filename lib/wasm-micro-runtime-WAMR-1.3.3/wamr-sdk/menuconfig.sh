#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception


usage ()
{
    echo "menuconfig.sh [options]"
    echo " -x [config file path name]"
    exit 1
}


while getopts "x:" opt
do
    case $opt in
        x)
        wamr_config_cmake_file=$OPTARG
        ;;
        ?)
        echo "Unknown arg: $arg"
        usage
        exit 1
        ;;
    esac
done


if [  -z $wamr_config_cmake_file ]; then
    usage
    exit
fi


function set_build_target () {
    target=$1

    if [[ "${target}" = "X86_64" ]]; then
        echo -e "set (WAMR_BUILD_TARGET \"X86_64\")" >> ${wamr_config_cmake_file}
    elif [[ "${target}" = "X86_32" ]]; then
        echo -e "set (WAMR_BUILD_TARGET \"X86_32\")" >> ${wamr_config_cmake_file}
    else
        echo "unknown build target."
        exit 1
    fi
}

function set_build_platform () {
    platform=$1

    if [[ "${platform}" = "linux" ]]; then
        echo -e "set (WAMR_BUILD_PLATFORM \"linux\")" >> ${wamr_config_cmake_file}
    # TODO: add other platforms
    else
        echo "${platform} platform currently not supported"
        exit 1
    fi
}

# input: array of selected exec modes [aot jit interp]
function set_exec_mode () {
    modes=($1)

    for mode in ${modes[@]}
    do
        if [[ "$mode" = "aot" ]]; then
            echo "set (WAMR_BUILD_AOT 1)" >> ${wamr_config_cmake_file}
        elif [[ "$mode" = "jit" ]]; then
            echo "set (WAMR_BUILD_JIT 1)" >> ${wamr_config_cmake_file}
            BUILD_LLVM="TRUE"
        elif [[ "$mode" = "interp" ]]; then
            echo "set (WAMR_BUILD_INTERP 1)" >> ${wamr_config_cmake_file}
        else
            echo "unknown execute mode."
            exit 1
        fi
    done
}

function set_libc_support () {
    libc=$1

    if [ "$libc" = "WASI" ]; then
        echo "set (WAMR_BUILD_LIBC_WASI 1)" >> ${wamr_config_cmake_file}
    else
        echo "set (WAMR_BUILD_LIBC_BUILTIN 1)" >> ${wamr_config_cmake_file}
    fi
}

function set_app_framework () {
    app_support=$1

    if [ "$app_support" = "TRUE" ]; then
        echo "set (WAMR_BUILD_APP_FRAMEWORK 1)" >> ${wamr_config_cmake_file}
    fi
}

# input: array of selected app modules
function set_app_module () {
    modules=($1)

    for module in ${modules[*]}
    do
        if [ "${module}" = "all" ]; then
            cmake_app_list="WAMR_APP_BUILD_ALL"
            break
        fi

        cmake_app_list="${cmake_app_list} WAMR_APP_BUILD_${module^^}"
    done

    # APP module list
    if [ -n "${cmake_app_list}" ]; then
        echo "set (WAMR_BUILD_APP_LIST ${cmake_app_list# })" >> ${wamr_config_cmake_file}
    fi
}




sdk_root=$(cd "$(dirname "$0")/" && pwd)
wamr_root=${sdk_root}/..

if [ ! `command -v menuconfig` ]; then
    echo "Can't find kconfiglib python lib on this computer"
    echo "Downloading it through pip"
    echo "If this fails, you can try `pip install kconfiglib` to install it manually"
    echo "Or download the repo from https://github.com/ulfalizer/Kconfiglib"

    pip install kconfiglib
fi

if [ -f ".wamr_modules" ]; then
    rm -f .wamr_modules
fi

# get all modules under core/app-framework
for module in `ls ${wamr_root}/core/app-framework -F | grep "/$" | grep -v "base" | grep -v "app-native-shared" | grep -v "template"`
do
    module=${module%*/}
    echo "config APP_BUILD_${module^^}"   >>  .wamr_modules
    echo "    bool \"enable ${module}\""  >>  .wamr_modules
done

menuconfig Kconfig
[ $? -eq 0 ] || exit $?

if [ ! -e ".config" ]; then
    exit 0
fi

# parse platform
platform=`cat .config | grep "^CONFIG_PLATFORM"`
platform=${platform%*=y}
platform=${platform,,}
platform=${platform#config_platform_}

# parse target
target=`cat .config | grep "^CONFIG_TARGET"`
target=${target%*=y}
target=${target#CONFIG_TARGET_}

# parse execution mode
modes=`cat .config | grep "^CONFIG_EXEC"`
mode_list=""
for mode in ${modes}
do
    mode=${mode%*=y}
    mode=${mode#CONFIG_EXEC_}
    mode_list="${mode_list} ${mode,,}"
done
if [ -z "${mode_list}" ]; then
    echo "execution mode are not selected"
    exit 1
fi

# parse libc support
libc=`cat .config | grep "^CONFIG_LIBC"`
libc=${libc%*=y}
if [ "${libc}" = "CONFIG_LIBC_WASI" ]; then
    libc_support="WASI"
else
    libc_support="BUILTIN"
fi

# parse application framework options
app_option=`cat .config | grep "^CONFIG_APP_FRAMEWORK"`
app_option=${app_option%*=y}
app_option=${app_option#CONFIG_APP_FRAMEWORK_}

if [ "${app_option}" != "DISABLE" ]; then
    app_enable="TRUE"

    # Default components
    if [ "${app_option}" = "DEFAULT" ]; then
        app_list="base connection sensor"
    # All components
    elif [ "${app_option}" = "ALL" ]; then
        app_list="all"
    # Customize
    elif [ "${app_option}" = "CUSTOM" ]; then
        app_option=`cat .config | grep "^CONFIG_APP_BUILD"`
        app_list="base"
        for app in ${app_option}
        do
            app=${app%*=y}
            app=${app#CONFIG_APP_BUILD_}
            app_list="${app_list} ${app,,}"
        done
    fi
fi

if  [[ -f $wamr_config_cmake_file ]]; then
    rm  $wamr_config_cmake_file
fi

set_build_target        ${target}
set_build_platform      ${platform}
set_exec_mode           "${mode_list[*]}"
set_libc_support        ${libc_support}
set_app_module          "${app_list[*]}"
set_app_framework       ${app_enable}
