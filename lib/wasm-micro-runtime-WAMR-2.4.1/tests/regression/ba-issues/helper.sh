#!/bin/bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

# Function to create a directory
create_directory() {
    dir_name="issue-$1"
    mkdir -p "$dir_name"
    echo "Created directory: $dir_name"

    # Unzip files if unzip option is enabled
    if [ "$unzip" = true ]; then
        if [ -d "$dir_name" ]; then
            # /opt/wabt/bin/wasm2wat --enable-all $dir_name/PoC.wasm -o $dir_name/PoC.wast
            for zipfile in "$dir_name"/*.zip; do
                if [ -f "$zipfile" ]; then
                    echo "Unzipping $zipfile in $dir_name"
                    unzip -o "$zipfile" -d "$dir_name"
                    rm $zipfile
                    # /opt/wabt/bin/wasm2wat --enable-all PoC.wasm -o PoC.wast
                fi
            done
        fi
    fi
}

# Initialize unzip option to false
unzip=false

# Parse options
while getopts ":x" opt; do
    case $opt in
    x)
        unzip=true
        ;;
    \?)
        echo "Invalid option: -$OPTARG" >&2
        exit 1
        ;;
    esac
done

# Remove the parsed options from the arguments
shift $((OPTIND - 1))

# Check if at least one argument is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 [-x] <num1> [num2]"
    exit 1
fi

num1=$1

# Changes work directories to issues
cd issues

# If only one argument is provided
if [ $# -eq 1 ]; then
    create_directory "$num1"
else
    # Extract the second argument
    num2=$2

    # Check if the second argument is greater than the first
    if [ "$num2" -lt "$num1" ]; then
        echo "Second number must be greater than or equal to the first number."
        exit 1
    fi

    # Generate directories from num1 to num2
    for ((i = num1; i <= num2; i++)); do
        create_directory "$i"
    done
fi
