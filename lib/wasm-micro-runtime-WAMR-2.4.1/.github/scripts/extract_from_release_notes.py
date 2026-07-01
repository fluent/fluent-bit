#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

"""
Extract the latest release notes content from RELEASE_NOTES.md
"""

import argparse
import os
import sys
import traceback


def latest_content(release_notes_path):
    """
    can't change the format of the original content
    """
    content = ""
    start_extract = False
    with open(release_notes_path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("## "):
                if start_extract:
                    break

                start_extract = True
                continue

            # hit a separated line
            if line.startswith("---"):
                break

            content += line

    content += os.linesep
    return content


def main():
    """
    GO!GO!!GO!!!
    """
    parser = argparse.ArgumentParser(description="run the sample and examine outputs")
    parser.add_argument("release_notes_path", type=str)
    args = parser.parse_args()

    ret = 1
    try:
        print(latest_content(args.release_notes_path))
        ret = 0
    except AssertionError:
        traceback.print_exc()
    return ret


if __name__ == "__main__":
    sys.exit(main())
