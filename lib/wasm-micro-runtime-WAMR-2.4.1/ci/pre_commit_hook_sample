#!/bin/bash

# Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# This is a sample of pre-commit hook that can be used to make your code fit the WAMR CI code style requirements.
# You need to have clang-format-12 installed to use this hook.
# To add this pre-commit hook, copy it to <path_to_wamr>/.git/hooks/pre-commit
# (you don't need any extensions here)

# Function to check if a file has a C or C++ extension

is_c_or_cpp_file() {
    file="$1"
    if [[ "$filename" =~ \.(h|c|cpp)$  ]]; then
        return 0
    else
        return 1
    fi
}

# Loop through staged files and apply command "abc" to C and C++ files
for staged_file in $(git diff --cached --name-only); do
    if is_c_or_cpp_file "$staged_file"; then
        clang-format-12 -Werror --style file --dry-run "$staged_file" 2>/dev/null
        if [ $? -ne 0 ]; then 
            echo "Issues are found in $staged_file. Applying the fix" 
            clang-format-12 --style file -i "$staged_file"
        fi
        git add "$staged_file"  # Add the modified file back to staging
    fi
done
