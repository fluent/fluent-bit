# -*- coding: utf-8 -*-
#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-module-docstring

import pathlib
from setuptools import setup, find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
from subprocess import check_call


def build_library():
    cur_path = pathlib.Path(__file__).parent
    check_call(f"{cur_path}/utils/create_lib.sh".split())


class PreDevelopCommand(develop):
    def run(self):
        build_library()
        develop.run(self)


class PreInstallCommand(install):
    def run(self):
        build_library()
        install.run(self)


class PreEggInfoCommand(egg_info):
    def run(self):
        build_library()
        egg_info.run(self)


with open("README.md") as f:
    readme = f.read()

with open("LICENSE") as f:
    license = f.read()

setup(
    name="wamr-python",
    version="0.1.0",
    description="A WebAssembly runtime powered by WAMR",
    long_description=readme,
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    author="The WAMR Project Developers",
    author_email="hello@bytecodealliance.org",
    url="https://github.com/bytecodealliance/wasm-micro-runtime",
    license=license,
    include_package_data=True,
    cmdclass={
        'develop': PreDevelopCommand,
        'install': PreInstallCommand,
        'egg_info': PreEggInfoCommand,
    },
    python_requires='>=3.9'
)
