#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

ps aux | grep -ie host_tool | awk '{print $2}' | xargs kill -9 &
ps aux | grep -ie simple | awk '{print $2}' | xargs kill -9 &
