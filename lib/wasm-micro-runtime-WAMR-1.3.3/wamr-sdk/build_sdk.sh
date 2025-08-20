#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

sdk_root=$(cd "$(dirname "$0")/" && pwd)
wamr_root_dir=${sdk_root}/..
out_dir=${sdk_root}/out
profile_path=${out_dir}/profile.cmake
wamr_config_cmake_file=""
wasi_sdk_home="/opt/wasi-sdk"
# libc support, default builtin-libc
LIBC_SUPPORT="BUILTIN"
CM_DEXTRA_SDK_INCLUDE_PATH=""
CM_BUILD_TYPE="-DCMAKE_BUILD_TYPE=Release"
CM_TOOLCHAIN=""

# menuconfig will pass options to this script
MENUCONFIG=""

usage ()
{
    echo "build.sh [options]"
    echo " -n [profile name]"
    echo " -x [config file path name]"
    echo " -t [cmake toolchain file]"
    echo " -e [extra include path], files under this path will be copied into SDK package"
    echo " -c, clean"
    echo " -d, debug mode"
    echo " -i, enter menu config settings"
    echo " -w [wasi-sdk installation path] it will be '/opt/wasi-sdk' if not set"
    exit 1
}


while getopts "e:x:n:t:icdw:" opt
do
    case $opt in
        n)
        PROFILE=$OPTARG
        ;;
        t)
        CM_TOOLCHAIN="-DCMAKE_TOOLCHAIN_FILE=$OPTARG"
        ;;
        x)
        wamr_config_cmake_file=$OPTARG
        ;;
        e)
        CM_DEXTRA_SDK_INCLUDE_PATH="-DEXTRA_SDK_INCLUDE_PATH=${OPTARG}"
        ;;
        c)
        CLEAN="TRUE"
        ;;
        d)
        CM_BUILD_TYPE="-DCMAKE_BUILD_TYPE=Debug"
        ;;
        i)
        MENUCONFIG="TRUE"
        ;;
        w)
        if [[ -n "${OPTARG}" ]]; then
            wasi_sdk_home=$(realpath "${OPTARG}")
        fi
        ;;
        ?)
        echo "Unknown arg: $arg"
        usage
        exit 1
        ;;
    esac
done


if [ ! -f "${wasi_sdk_home}/bin/clang" ]; then
    echo "Can not find clang under \"${wasi_sdk_home}/bin\"."
    exit 1
else
    echo "Found WASI_SDK HOME ${wasi_sdk_home}"
fi


echo "download dependent external repositories.."
${wamr_root_dir}/core/deps/download.sh
[ $? -eq 0 ] || exit $?



if [ -z "$PROFILE" ]; then
    PROFILE="default"
    echo "PROFILE argument not set, using DEFAULT"
    if [[ -z "$wamr_config_cmake_file" ]]; then
        wamr_config_cmake_file=${sdk_root}/wamr_config_default.cmake
        echo "use default config file: [$wamr_config_cmake_file]"
    fi
fi


if [ ! -d "${out_dir}" ]; then
    mkdir -p ${out_dir}
fi

curr_profile_dir=${out_dir}/${PROFILE}
wamr_app_out_dir=${curr_profile_dir}/app-sdk/wamr-app-framework
sysroot_dir=${curr_profile_dir}/app-sdk/libc-builtin-sysroot


echo "CM_DEXTRA_SDK_INCLUDE_PATH=${CM_DEXTRA_SDK_INCLUDE_PATH}"


if [[ "$CLEAN" = "TRUE" ]]; then
    rm -rf ${curr_profile_dir}
fi



# cmake config file for wamr runtime:
# 1. use the users provided the config cmake file path.
# 2. if user set MENU CONFIG, enter menu config to generate
#    menu_config.cmake in the profile output folder
# 3. If the menu_config.cmake is already in the profile folder, use it
# 4. Use the default config cmake file
#
if [[ -n "$wamr_config_cmake_file" ]]; then
	if  [[ ! -f $wamr_config_cmake_file ]]; then
	   echo "user given file not exist: ${wamr_config_cmake_file}"
	   exit 1
	fi

	echo "User config file: [${wamr_config_cmake_file}]"

else
	wamr_config_cmake_file=${out_dir}/wamr_config_${PROFILE}.cmake
    # always rebuilt the sdk if user is not giving the config file
	if [ -d ${curr_profile_dir} ]; then
	   rm -rf ${curr_profile_dir}
	fi

	if [[ "$MENUCONFIG" = "TRUE" ]] || [[ ! -f $wamr_config_cmake_file ]]; then
		echo "MENUCONFIG: [${wamr_config_cmake_file}]"
		./menuconfig.sh -x ${wamr_config_cmake_file}
		[ $? -eq 0 ] || exit $?
	else
		echo "use existing config file: [$wamr_config_cmake_file]"
    fi
fi


mkdir -p ${curr_profile_dir}
mkdir -p ${curr_profile_dir}/app-sdk
mkdir -p ${curr_profile_dir}/runtime-sdk


if [ "${BUILD_LLVM}" = "TRUE" ]; then
    if [ ! -d "${wamr_root_dir}/core/deps/llvm" ]; then
        echo -e "\n"
        echo "######  build llvm (this will take a long time)  #######"
        echo ""
        cd ${wamr_root_dir}/wamr-compiler
        ./build_llvm.sh
    fi
fi

echo -e "\n\n"
echo "##############  Start to build wasm app sdk  ###############"

# If wgl module is selected, check if the extra SDK include dir is passed by the args, prompt user to input if not.
app_all_selected=`cat ${wamr_config_cmake_file} | grep WAMR_APP_BUILD_ALL`
app_wgl_selected=`cat ${wamr_config_cmake_file} | grep WAMR_APP_BUILD_WGL`

if [[ -n "${app_wgl_selected}" ]] || [[ -n "${app_all_selected}" ]]; then
    if [ -z "${CM_DEXTRA_SDK_INCLUDE_PATH}" ]; then
        echo -e "\033[31mWGL module require lvgl config files, please input the path to the lvgl SDK include path:\033[0m"
        read -a extra_file_path

        if [[ -z "${extra_file_path}" ]] || [[ ! -d "${extra_file_path}" ]]; then
            echo -e "\033[31mThe extra SDK path is empty\033[0m"
        else
            CM_DEXTRA_SDK_INCLUDE_PATH="-DEXTRA_SDK_INCLUDE_PATH=${extra_file_path}"
        fi
    fi

    cd ${wamr_root_dir}/core/app-framework/wgl/app
    ./prepare_headers.sh
fi

cd ${sdk_root}/app
rm -fr build && mkdir build
cd build

out=`grep WAMR_BUILD_LIBC_WASI ${wamr_config_cmake_file} |grep 1`
if [ -n "$out" ]; then
    LIBC_SUPPORT="WASI"
fi
if [ "${LIBC_SUPPORT}" = "WASI" ]; then
    echo "using wasi toolchain"
    cmake .. $CM_DEXTRA_SDK_INCLUDE_PATH \
         -DWAMR_BUILD_SDK_PROFILE=${PROFILE} \
         -DCONFIG_PATH=${wamr_config_cmake_file} \
         -DWASI_SDK_DIR="${wasi_sdk_home}" \
         -DCMAKE_TOOLCHAIN_FILE=../wasi_toolchain.cmake
else
    echo "using builtin libc toolchain"
    cmake .. $CM_DEXTRA_SDK_INCLUDE_PATH \
         -DWAMR_BUILD_SDK_PROFILE=${PROFILE} \
         -DCONFIG_PATH=${wamr_config_cmake_file} \
         -DWASI_SDK_DIR="${wasi_sdk_home}" \
         -DCMAKE_TOOLCHAIN_FILE=../wamr_toolchain.cmake
fi
[ $? -eq 0 ] || exit $?

make
if (( $? == 0 )); then
    echo -e "\033[32mSuccessfully built app-sdk under ${curr_profile_dir}/app-sdk\033[0m"
else
    echo -e "\033[31mFailed to build app-sdk for wasm application\033[0m"
    exit 1
fi

cd ..
rm -fr build
echo -e "\n\n"



echo "##############  Start to build runtime sdk  ###############"
cd ${sdk_root}/runtime
rm -fr build-runtime-sdk && mkdir build-runtime-sdk
cd build-runtime-sdk
cmake .. $CM_DEXTRA_SDK_INCLUDE_PATH \
       -DWAMR_BUILD_SDK_PROFILE=${PROFILE} \
       -DCONFIG_PATH=${wamr_config_cmake_file} \
       $CM_TOOLCHAIN $CM_BUILD_TYPE
[ $? -eq 0 ] || exit $?
make

if (( $? == 0 )); then
    echo -e "\033[32mSuccessfully built runtime library under ${curr_profile_dir}/runtime-sdk/lib\033[0m"
else
    echo -e "\033[31mFailed to build runtime sdk\033[0m"
    exit 1
fi

APP=`grep WAMR_BUILD_APP_FRAMEWORK ${wamr_config_cmake_file} |grep 1`
if [ -n "$APP" ]; then
    # Generate defined-symbol list for app-sdk
    cd ${wamr_app_out_dir}/share
    cat ${curr_profile_dir}/runtime-sdk/include/*.inl | egrep "^ *EXPORT_WASM_API *[(] *[a-zA-Z_][a-zA-Z0-9_]* *?[)]" | cut -d '(' -f2 | cut -d ')' -f1 > defined-symbols.txt
fi


cd ..
rm -fr build-runtime-sdk

exit 0
