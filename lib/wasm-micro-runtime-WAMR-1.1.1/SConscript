#
# Copyright (c) 2021, RT-Thread Development Team
#
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

# for module compiling
import os

from building import *

objs = []
cwd  = GetCurrentDir()
list = os.listdir(cwd)

if GetDepend(['PKG_USING_WAMR']):
    wamr_entry_sconscript  = os.path.join(cwd, "product-mini", "platforms", "rt-thread", 'SConscript')
    wamr_runlib_sconscript = os.path.join(cwd, "build-scripts", 'SConscript')

    objs = objs + SConscript(wamr_entry_sconscript)
    objs = objs + SConscript(wamr_runlib_sconscript)

Return('objs')
