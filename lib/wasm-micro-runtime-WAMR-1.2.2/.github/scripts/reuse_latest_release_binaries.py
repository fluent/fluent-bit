#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import argparse
import json
import os
import shlex
import subprocess
import sys
from urllib.error import HTTPError, URLError
import urllib.request


def get_last_commit(target_path, cwd):
    last_commit_cmd = f"git log -n 1 --pretty=format:%H -- {target_path}"
    p = subprocess.run(
        shlex.split(last_commit_cmd), capture_output=True, check=True, cwd=cwd
    )
    return p.stdout.decode().strip()


def fetch_git_tags():
    list_tag_cmd = (
        'git tag --list WAMR-*.*.* --sort=committerdate --format="%(refname:short)"'
    )
    p = subprocess.run(shlex.split(list_tag_cmd), capture_output=True, check=True)

    all_tags = p.stdout.decode().strip()
    return all_tags.split("\n")


def download_binaries(binary_name_stem, cwd):
    """
    1. find the latest release name
    2. form assets download url:
    """
    try:
        all_tags = fetch_git_tags()
        # *release_process.yml* will create a tag and release at first
        second_last_tag = all_tags[-2]
        latest_tag = all_tags[-1]

        latest_url = "https://api.github.com/repos/bytecodealliance/wasm-micro-runtime/releases/latest"
        print(f"::notice::query the latest release with {latest_url}...")
        with urllib.request.urlopen(latest_url) as response:
            body = response.read()

        release_name = json.loads(body)["name"]

        # WAMR-X.Y.Z -> X.Y.Z
        second_last_sem_ver = second_last_tag[5:]
        latest_sem_ver = latest_tag[5:]
        assert latest_sem_ver in binary_name_stem
        name_stem_in_release = binary_name_stem.replace(
            latest_sem_ver, second_last_sem_ver
        )

        # download and rename
        for file_ext in (".zip", ".tar.gz"):
            assets_url = f"https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/{release_name}/{name_stem_in_release}{file_ext}"
            local_path = f"{binary_name_stem}{file_ext}"
            print(f"::notice::download from {assets_url} and save as {local_path}...")
            urllib.request.urlretrieve(assets_url, local_path)
        return True
    except HTTPError as error:
        print(error.status, error.reason)
    except URLError as error:
        print(error.reason)
    except TimeoutError:
        print("Request timeout")

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Reuse binaries of the latest release if no more modification on the_path since last_commit"
    )
    parser.add_argument("working_directory", type=str)
    parser.add_argument("--binary_name_stem", type=str)
    parser.add_argument("--last_commit", type=str)
    parser.add_argument("--the_path", type=str)
    args = parser.parse_args()

    last_commit = get_last_commit(args.the_path, args.working_directory)
    if last_commit == args.last_commit:
        return download_binaries(args.binary_name_stem, args.working_directory)
    else:
        return False


if __name__ == "__main__":
    # use output to indicate results
    # echo "result=${result}" >> "$GITHUB_OUTPUT"
    with open(os.environ.get("GITHUB_OUTPUT"), 'a') as output_file:
        output_file.write("result=hit\n" if main() else "result=not-hit\n")

    # always return 0
    sys.exit(0)
