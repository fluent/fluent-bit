# -*- coding: utf-8 -*-
#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-module-docstring

from setuptools import setup, find_packages


with open("README.md") as f:
    readme = f.read()

with open("LICENSE") as f:
    license = f.read()

setup(
    name="wamr-python",
    version="0.1.0",
    description="A WebAssembly runtime powered by WAMR",
    long_description=readme,
    author="The WAMR Project Developers",
    author_email="hello@bytecodealliance.org",
    url="https://github.com/bytecodealliance/wamr-python",
    license=license,
    packages=["wamr"],
)
