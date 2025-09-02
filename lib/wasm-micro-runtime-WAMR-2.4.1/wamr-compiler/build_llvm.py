#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import pathlib
import subprocess
import sys

script = (
    pathlib.Path(__file__).parent.joinpath("../build-scripts/build_llvm.py").resolve()
)
subprocess.check_call([sys.executable, script])
