#!/usr/bin/python
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import sys
import time
import subprocess
from optparse import OptionParser


# You can run different runtime by changing the arg '-r':
# python malformed_test.py -r /path/to/iwasm
# python malformed_test.py -r /path/to/wasmtime
# python malformed_test.py -r "/path/to/wasmer run"


optParser = OptionParser()
optParser.add_option("-r", "--run", dest="run",
                     default="iwasm",
                     help="specify a runtime [path/to]([iwasm] / wasmtime / wasmer run)")

(options, args) = optParser.parse_args()
#optParser.usage = "%prog [options]"

succ_cnt = 0
fail_cnt = 0

test_start = time.time()
for root, dirs, files in os.walk("."):
    for file in files:
        if len(file.split('.')) < 2 or file.split('.')[1] != 'wasm':
            continue
        filepath=os.path.join(root, file)
        cmd = options.run + " " + filepath
        test_out = subprocess.getoutput(cmd)

        if not test_out.startswith("Segmentation fault"):
            print("test {:40} ........ [PASSED]".format(filepath))
            succ_cnt += 1
        else:
            print("test {:40} ........ [FAILED]".format(filepath))
            print(test_out)
            print('\n')
            fail_cnt += 1
test_end = time.time()

print("\n#####################  MALFORMED TEST  ########################")
print("run {} test cases in {}ms, {} passed, {} failed"
      .format(succ_cnt + fail_cnt, test_end - test_start, succ_cnt, fail_cnt))
