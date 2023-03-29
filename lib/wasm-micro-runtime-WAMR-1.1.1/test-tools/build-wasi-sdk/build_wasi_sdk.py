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
|       `-- wasi-sdk
|           `-- src
|               |-- llvm-project
|               `-- wasi-libc
`-- test-tools
    |-- build-wasi-sdk
    |   |-- build_wasi_sdk.py
    |   |-- include
    |   `-- patches
    `-- wasi-sdk
        |-- bin
        |-- lib
        `-- share
            `-- wasi-sysroot
"""

import hashlib
import logging
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib
import urllib.request

logger = logging.getLogger("build_wasi_sdk")

external_repos = {
    "config": {
        "sha256": "302e5e7f3c4996976c58efde8b2f28f71d51357e784330eeed738e129300dc33",
        "store_dir": "core/deps/wasi-sdk/src/config",
        "strip_prefix": "config-191bcb948f7191c36eefe634336f5fc5c0c4c2be",
        "url": "https://git.savannah.gnu.org/cgit/config.git/snapshot/config-191bcb948f7191c36eefe634336f5fc5c0c4c2be.tar.gz",
    },
    "emscripten": {
        "sha256": "0904a65379aea3ea94087b8c12985b2fee48599b473e3bef914fec2e3941532d",
        "store_dir": "core/deps/emscripten",
        "strip_prefix": "emscripten-2.0.28",
        "url": "https://github.com/emscripten-core/emscripten/archive/refs/tags/2.0.28.tar.gz",
    },
    "llvm-project": {
        "sha256": "dc5169e51919f2817d06615285e9da6a804f0f881dc55d6247baa25aed3cc143",
        "store_dir": "core/deps/wasi-sdk/src/llvm-project",
        "strip_prefix": "llvm-project-34ff6a75f58377f32a5046a29f55c4c0e58bee9e",
        "url": "https://github.com/llvm/llvm-project/archive/34ff6a75f58377f32a5046a29f55c4c0e58bee9e.tar.gz",
    },
    "wasi-sdk": {
        "sha256": "fc4fdb0e97b915241f32209492a7d0fab42c24216f87c1d5d75f46f7c70a553d",
        "store_dir": "core/deps/wasi-sdk",
        "strip_prefix": "wasi-sdk-1a953299860bbcc198ad8c12a21d1b2e2f738355",
        "url": "https://github.com/WebAssembly/wasi-sdk/archive/1a953299860bbcc198ad8c12a21d1b2e2f738355.tar.gz",
    },
    "wasi-libc": {
        "sha256": "f6316ca9479d3463eb1c4f6a1d1f659bf15f67cb3c1e2e83d9d11f188dccd864",
        "store_dir": "core/deps/wasi-sdk/src/wasi-libc",
        "strip_prefix": "wasi-libc-a78cd329aec717f149934d7362f57050c9401f60",
        "url": "https://github.com/WebAssembly/wasi-libc/archive/a78cd329aec717f149934d7362f57050c9401f60.tar.gz",
    },
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
            tar.extractall(tmp)

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
            f"keep using '{store_dir.relative_to(root)}'. Or to remove it and try again"
        )
        return True

    # download only when the target is neither existed nor broken
    download_dir = pathlib.Path("/tmp/build_wasi_sdk/")
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
    return True


def run_patch(patch_file, cwd):
    if not patch_file.exists():
        logger.error(f"{patch_file} not found")
        return False

    with open(patch_file, "r") as f:
        try:
            PATCH_DRY_RUN_CMD = "patch -f -p1 --dry-run"
            if subprocess.check_call(shlex.split(PATCH_DRY_RUN_CMD), stdin=f, cwd=cwd):
                logger.error(f"patch dry-run {cwd} failed")
                return False

            PATCH_CMD = "patch -f -p1"
            f.seek(0)
            if subprocess.check_call(shlex.split(PATCH_CMD), stdin=f, cwd=cwd):
                logger.error(f"patch {cwd} failed")
                return False
        except subprocess.CalledProcessError:
            logger.error(f"patch {cwd} failed")
            return False
    return True


def build_and_install_wasi_sdk(root):
    store_dir = root.joinpath(f'{external_repos["wasi-sdk"]["store_dir"]}').resolve()
    if not store_dir.exists():
        logger.error(f"{store_dir} does not found")
        return False

    # patch wasi-libc and wasi-sdk
    patch_flag = store_dir.joinpath("PATCHED")
    if not patch_flag.exists():
        if not run_patch(
            root.joinpath("test-tools/build-wasi-sdk/patches/wasi_libc.patch"),
            store_dir.joinpath("src/wasi-libc"),
        ):
            return False

        if not run_patch(
            root.joinpath("test-tools/build-wasi-sdk/patches/wasi_sdk.patch"), store_dir
        ):
            return False

        patch_flag.touch()
    else:
        logger.info("bypass the patch phase")

    # build
    build_flag = store_dir.joinpath("BUILDED")
    if not build_flag.exists():
        BUILD_CMD = "make build"
        if subprocess.check_call(shlex.split(BUILD_CMD), cwd=store_dir):
            logger.error(f"build wasi-sdk failed")
            return False

        build_flag.touch()
    else:
        logger.info("bypass the build phase")

    # install
    install_flag = store_dir.joinpath("INSTALLED")
    binary_path = root.joinpath("test-tools").resolve()
    if not install_flag.exists():
        shutil.copytree(
            str(store_dir.joinpath("build/install/opt").resolve()),
            str(binary_path),
            dirs_exist_ok=True,
        )

        # install headers
        emscripten_headers = (
            root.joinpath(external_repos["emscripten"]["store_dir"])
            .joinpath("system")
            .resolve()
        )
        wasi_sysroot_headers = binary_path.joinpath(
            "wasi-sdk/share/wasi-sysroot/include"
        ).resolve()
        for (src, dst) in emscripten_headers_src_dst:
            src = emscripten_headers.joinpath(src)
            dst = wasi_sysroot_headers.joinpath(dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst)

        install_flag.touch()
    else:
        logger.info("bypass the install phase")

    return True


def main():
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.setLevel(logging.INFO)
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

    # build wasi_sdk and install
    if not build_and_install_wasi_sdk(root):
        return False

    # TODO install headers from emscripten

    return True


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
