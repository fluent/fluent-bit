from __future__ import print_function
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import datetime
import os
import pprint
import random
import re
import shlex
import subprocess
import signal
import sys
import time

from .test_utils  import *
from .test_api import *




def read_cases_from_file(file_path):
    if not os.path.exists(file_path):
        return False, None

    with open(file_path, 'r') as f:
        content = f.readlines()

    content = [x.strip() for x in content]
    print(content)
    if len(content) == 0:
        return False, None

    return True, content



