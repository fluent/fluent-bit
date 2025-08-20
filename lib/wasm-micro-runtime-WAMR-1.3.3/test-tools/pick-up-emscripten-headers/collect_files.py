#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

"""
The script operates on such directories and files
|-- core
|   `-- deps
|       |-- emscripten
|-- samples
|   `-- workloads
|       |-- include
`-- test-tools
    |-- pick-up-emscripten_headers
    |   |-- collect_files.py
"""

import argparse
import hashlib
import logging
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
import urllib
import urllib.request

logger = logging.getLogger("pick-up-emscripten-headers")

external_repos = {
    "emscripten": {
        "sha256": "c5524755b785d8f4b83eb3214fdd3ac4b2e1b1a4644df4c63f06e5968f48f90e",
        "store_dir": "core/deps/emscripten",
        "strip_prefix": "emscripten-3.0.0",
        "url": "https://github.com/emscripten-core/emscripten/archive/refs/tags/3.0.0.tar.gz",
    }
}

# TOOD: can we use headers from wasi-libc and clang directly ?
emscripten_headers_src_dst = [
    ("include/compat/emmintrin.h", "sse/emmintrin.h"),
    ("include/compat/immintrin.h", "sse/immintrin.h"),
    ("include/compat/smmintrin.h", "sse/smmintrin.h"),
    ("include/compat/xmmintrin.h", "sse/xmmintrin.h"),
    ("lib/libc/musl/include/pthread.h", "libc/musl/pthread.h"),
    ("lib/libc/musl/include/signal.h", "libc/musl/signal.h"),
    ("lib/libc/musl/include/netdb.h", "libc/musl/netdb.h"),
    ("lib/libc/musl/include/sys/wait.h", "libc/musl/sys/wait.h"),
    ("lib/libc/musl/include/sys/socket.h", "libc/musl/sys/socket.h"),
    ("lib/libc/musl/include/setjmp.h", "libc/musl/setjmp.h"),
    ("lib/libc/musl/arch/emscripten/bits/setjmp.h", "libc/musl/bits/setjmp.h"),
]


def checksum(name, local_file):
    sha256 = hashlib.sha256()
    with open(local_file, "rb") as f:
        bytes = f.read(4096)
        while bytes:
            sha256.update(bytes)
            bytes = f.read(4096)

    return sha256.hexdigest() == external_repos[name]["sha256"]


def download(url, local_file):
    logger.debug(f"download from {url}")
    urllib.request.urlretrieve(url, local_file)
    return local_file.exists()


def unpack(tar_file, strip_prefix, dest_dir):
    # extract .tar.gz to /tmp, then move back without strippred prefix directories
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(tar_file) as tar:
            logger.debug(f"extract to {tmp}")

            def is_within_directory(directory, target):

                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)

                prefix = os.path.commonprefix([abs_directory, abs_target])

                return prefix == abs_directory

            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):

                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")

                tar.extractall(path, members, numeric_owner=numeric_owner)

            safe_extract(tar, tmp)

        strip_prefix_dir = (
            pathlib.Path(tmp).joinpath(strip_prefix + os.path.sep).resolve()
        )
        if not strip_prefix_dir.exists():
            logger.error(f"extract {tar_file.name} failed")
            return False

        # mv /tmp/${strip_prefix} dest_dir/*
        logger.debug(f"move {strip_prefix_dir} to {dest_dir}")
        shutil.copytree(
            str(strip_prefix_dir),
            str(dest_dir),
            copy_function=shutil.move,
            dirs_exist_ok=True,
        )

    return True


def download_repo(name, root):
    if not name in external_repos:
        logger.error(f"{name} is not a known repository")
        return False

    store_dir = root.joinpath(f'{external_repos[name]["store_dir"]}').resolve()
    download_flag = store_dir.joinpath("DOWNLOADED")
    if store_dir.exists() and download_flag.exists():
        logger.info(
            f"bypass downloading '{store_dir.relative_to(root)}'. Or to remove it and try again if needs a new release"
        )
        return True

    # download only when the target is neither existed nor broken
    download_dir = pathlib.Path("/tmp/pick-up-emscripten-headers/")
    download_dir.mkdir(exist_ok=True)

    tar_name = pathlib.Path(external_repos[name]["url"]).name
    tar_file = download_dir.joinpath(tar_name)
    if tar_file.exists():
        if checksum(name, tar_file):
            logger.debug(f"use pre-downloaded {tar_file}")
        else:
            logger.debug(f"{tar_file} is broken, remove it")
            tar_file.unlink()

    if not tar_file.exists():
        if not download(external_repos[name]["url"], tar_file) or not checksum(
            name, tar_file
        ):
            logger.error(f"download {name} failed")
            return False

    # unpack and removing *strip_prefix*
    if not unpack(tar_file, external_repos[name]["strip_prefix"], store_dir):
        return False

    # leave a FLAG
    download_flag.touch()

    # leave download files in /tmp
    logger.info(f"Has downloaed and stored in {store_dir.relative_to(root)}")
    return True


def collect_headers(root, install_location):
    if not install_location.exists():
        logger.error(f"{install_location} does not found")
        return False

    install_flag = install_location.joinpath("INSTALLED").resolve()
    if install_flag.exists():
        logger.info(
            f"bypass downloading '{install_location}'. Or to remove it and try again if needs a new one"
        )
        return True

    emscripten_home = root.joinpath(
        f'{external_repos["emscripten"]["store_dir"]}'
    ).resolve()
    if not emscripten_home.exists():
        logger.error(f"{emscripten_home} does not found")
        return False

    emscripten_headers = emscripten_home.joinpath("system").resolve()
    for (src, dst) in emscripten_headers_src_dst:
        src = emscripten_headers.joinpath(src)
        dst = install_location.joinpath(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst)

    install_flag.touch()
    logger.info(f"Has installed in {install_location}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="collect headers from emscripten for workload compilation"
    )
    parser.add_argument(
        "--install",
        type=str,
        required=True,
        help="identify installation location",
    )
    parser.add_argument(
        "--loglevel",
        type=str,
        default="INFO",
        choices=[
            "ERROR",
            "WARNING",
            "INFO",
        ],
        help="the logging level",
    )
    options = parser.parse_args()

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.setLevel(getattr(logging, options.loglevel))
    logger.addHandler(console)
    logger.propagate = False

    # locate the root of WAMR
    current_file = pathlib.Path(__file__)
    if current_file.is_symlink():
        current_file = pathlib.Path(os.readlink(current_file))
    root = current_file.parent.joinpath("../..").resolve()
    logger.info(f"The root of WAMR is {root}")

    # download repos
    for repo in external_repos.keys():
        if not download_repo(repo, root):
            return False

    if not collect_headers(root, pathlib.Path(options.install)):
        return False

    return True


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
