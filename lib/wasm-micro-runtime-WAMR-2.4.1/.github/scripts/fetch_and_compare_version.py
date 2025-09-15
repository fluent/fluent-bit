#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import re
import shlex
import subprocess
import sys


def fetch_version_from_code():
    """
    search the semantic version definition in core/version.h
    """
    major, minor, patch = "", "", ""
    with open("core/version.h", encoding="utf-8") as f:
        for line in f:
            if "WAMR_VERSION" not in line:
                continue

            major_match = re.search(r"WAMR_VERSION_MAJOR (\d+)", line)
            if major_match is not None:
                major = major_match.groups()[0]
                continue

            minor_match = re.search(r"WAMR_VERSION_MINOR (\d+)", line)
            if minor_match is not None:
                minor = minor_match.groups()[0]
                continue

            patch_match = re.search(r"WAMR_VERSION_PATCH (\d+)", line)
            if patch_match is not None:
                patch = patch_match.groups()[0]

    if len(major) == 0 or len(minor) == 0 or len(patch) == 0:
        raise Exception(
            "can't find the semantic version definition likes WAMR_VERSION_*"
        )
    return f"WAMR-{major}.{minor}.{patch}"


def fetch_latest_git_tag():
    """
    Get the most recent tag from the HEAD,
    if it's main branch, it should be the latest release tag.
    if it's release/x.x.x branch, it should be the latest release tag of the branch.
    """
    list_tag_cmd = "git describe --tags --abbrev=0 HEAD"
    p = subprocess.run(shlex.split(list_tag_cmd), capture_output=True, check=True)

    all_tags = p.stdout.decode().strip()
    latest_tag = all_tags.split("\n")[-1]
    return latest_tag


def match_version_pattern(v):
    pattern = r"WAMR-\d+\.\d+\.\d+"
    m = re.match(pattern, v)
    return m is not None


def split_version_string(v):
    """
    return the semantic version as an integer list
    """
    pattern = r"WAMR-(\d+)\.(\d+)\.(\d+)"
    m = re.match(pattern, v)
    return [int(x) for x in m.groups()]


def compare_version_string(v1, v2):
    """
    return value:
      - 1. if v1 > v2
      - -1. if v1 < v2
      - 0. if v1 == v2
    """
    if not match_version_pattern(v1):
        raise Exception(f"{v1} doesn't match the version pattern")

    if not match_version_pattern(v2):
        raise Exception(f"{v2} doesn't match the version pattern")

    v1_sem_ver = split_version_string(v1)
    v2_sem_ver = split_version_string(v2)

    return 0 if v1_sem_ver == v2_sem_ver else (1 if v1_sem_ver > v2_sem_ver else -1)


def is_major_or_minor_changed(v1, v2):
    """
    return true if change either major of v2 or minor of v2
    return false or else
    """
    if not match_version_pattern(v1):
        raise Exception(f"{v1} doesn't match the version pattern")

    if not match_version_pattern(v2):
        raise Exception(f"{v2} doesn't match the version pattern")

    v1_major, v1_minor, _ = split_version_string(v1)
    v2_major, v2_minor, _ = split_version_string(v2)

    return v2_major != v1_major or v2_minor != v1_minor


def next_version():
    definition = fetch_version_from_code()
    tag = fetch_latest_git_tag()

    new_version = ""
    minor_changed = False
    if compare_version_string(definition, tag) == 1:
        new_version = definition.split("-")[-1]

        if is_major_or_minor_changed(tag, definition):
            minor_changed = True

    return new_version, "major_minor_change" if minor_changed else "patch_change"


if __name__ == "__main__":
    print(f"{next_version()[0]},{next_version()[1]}")
    sys.exit(0)
