#!/bin/sh
# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT
set -e
# Check that all of the base fuzzing corpus parse without errors
./aresfuzz fuzzinput/*
./aresfuzzname fuzznames/*
