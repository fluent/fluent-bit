#!/bin/bash

# Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# This script executes some commands to make your onboarding with WAMR easier.
# For example, setting pre-commit hook that will make your code complaint with the
# code style requirements checked in WAMR CI

echo "Copy the pre-commit hook to your hooks folder"
cp pre_commit_hook_sample ../.git/hooks/pre-commit

# Feel free to propose your commands to this script to make developing WAMR easier

echo "Setup is done"
