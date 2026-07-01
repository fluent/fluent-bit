#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import argparse
import os
import pathlib
import requests
import shlex
import shutil
import subprocess
import sysconfig
import sys


def clone_llvm(dst_dir, llvm_repo, llvm_branch):
    """
    any error will raise CallProcessError
    """
    llvm_dir = dst_dir.joinpath("llvm").resolve()

    if not llvm_dir.exists():
        GIT_CLONE_CMD = f"git clone --depth 1 --branch {llvm_branch} {llvm_repo} llvm"
        print(GIT_CLONE_CMD)
        subprocess.check_output(shlex.split(GIT_CLONE_CMD), cwd=dst_dir)

    return llvm_dir


def query_llvm_version(llvm_info):
    github_token = os.environ['GH_TOKEN']
    owner_project = llvm_info['repo'].replace("https://github.com/", "").replace(".git", "")
    url = f"https://api.github.com/repos/{owner_project}/commits/{llvm_info['branch']}"
    headers = {
        'Authorization': f"Bearer {github_token}"
    }

    try:
        response = requests.request("GET", url, headers=headers, data={})
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        print (error) # for debugging purpose
        return None

    response = response.json()
    return response['sha']


def build_llvm(llvm_dir, platform, backends, projects, use_clang=False, extra_flags=''):
    LLVM_COMPILE_OPTIONS = [
        '-DCMAKE_BUILD_TYPE:STRING="Release"',
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DLLVM_APPEND_VC_REV:BOOL=ON",
        "-DLLVM_BUILD_EXAMPLES:BOOL=OFF",
        "-DLLVM_BUILD_LLVM_DYLIB:BOOL=OFF",
        "-DLLVM_ENABLE_BINDINGS:BOOL=OFF",
        "-DLLVM_ENABLE_IDE:BOOL=OFF",
        "-DLLVM_ENABLE_LIBEDIT=OFF",
        "-DLLVM_ENABLE_TERMINFO:BOOL=OFF",
        "-DLLVM_ENABLE_ZLIB:BOOL=ON",
        "-DLLVM_INCLUDE_BENCHMARKS:BOOL=OFF",
        "-DLLVM_INCLUDE_DOCS:BOOL=OFF",
        "-DLLVM_INCLUDE_EXAMPLES:BOOL=OFF",
        "-DLLVM_INCLUDE_UTILS:BOOL=OFF",
        "-DLLVM_INCLUDE_TESTS:BOOL=OFF",
        "-DLLVM_OPTIMIZED_TABLEGEN:BOOL=ON",
    ]

    # ccache is not available on Windows
    if not "windows" == platform:
        LLVM_COMPILE_OPTIONS.append("-DLLVM_CCACHE_BUILD:BOOL=ON")
    # perf support is available on Linux only
    if "linux" == platform:
        LLVM_COMPILE_OPTIONS.append("-DLLVM_USE_PERF:BOOL=ON")

    # use clang/clang++/lld. but macos doesn't support lld
    if not sys.platform.startswith("darwin") and use_clang:
        if shutil.which("clang") and shutil.which("clang++") and shutil.which("lld"):
            os.environ["CC"] = "clang"
            os.environ["CXX"] = "clang++"
            LLVM_COMPILE_OPTIONS.append('-DLLVM_USE_LINKER:STRING="lld"')
            print("Use the clang toolchain")
        else:
            print("Can not find clang, clang++ and lld, keep using the gcc toolchain")
    else:
        print("Use the gcc toolchain")

    LLVM_EXTRA_COMPILE_OPTIONS = {
        "arc": [
            '-DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD:STRING="ARC"',
            "-DLLVM_ENABLE_LIBICUUC:BOOL=OFF",
            "-DLLVM_ENABLE_LIBICUDATA:BOOL=OFF",
        ],
        "xtensa": [
            '-DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD:STRING="Xtensa"',
        ],
        "windows": [
            "-DCMAKE_INSTALL_PREFIX=LLVM-install",
        ],
        "default": [],
    }

    experimental_backends = ["ARC", "Xtensa"]
    normal_backends = [s for s in backends if s not in experimental_backends]

    LLVM_TARGETS_TO_BUILD = [
        '-DLLVM_TARGETS_TO_BUILD:STRING="' + ";".join(normal_backends) + '"'
        if normal_backends
        else '-DLLVM_TARGETS_TO_BUILD:STRING="AArch64;ARM;Mips;RISCV;X86"'
    ]

    # if not on ARC platform, but want to add expeirmental backend ARC as target
    if platform != "ARC" and "ARC" in backends:
        LLVM_TARGETS_TO_BUILD.extend(
            LLVM_EXTRA_COMPILE_OPTIONS["arc"]
        )

    LLVM_PROJECTS_TO_BUILD = [
        '-DLLVM_ENABLE_PROJECTS:STRING="' + ";".join(projects) + '"' if projects else ""
    ]

    # lldb project requires libxml2
    LLVM_LIBXML2_OPTION = [
        "-DLLVM_ENABLE_LIBXML2:BOOL=" + ("ON" if "lldb" in projects else "OFF")
    ]

    # enabling LLVM_INCLUDE_TOOLS will increase ~300M to the final package
    LLVM_INCLUDE_TOOLS_OPTION = [
        "-DLLVM_INCLUDE_TOOLS:BOOL=ON" if projects else "-DLLVM_INCLUDE_TOOLS:BOOL=OFF"
    ]

    if not llvm_dir.exists():
        raise Exception(f"{llvm_dir} doesn't exist")

    build_dir = llvm_dir.joinpath("build").resolve()
    build_dir.mkdir(exist_ok=True)

    lib_llvm_core_library = build_dir.joinpath("lib/libLLVMCore.a").resolve()
    if lib_llvm_core_library.exists():
        print(
            f"It has already been fully compiled. If want to a re-build, please remove {build_dir} manually and try again"
        )
        return None

    compile_options = " ".join(
        LLVM_COMPILE_OPTIONS
        + LLVM_LIBXML2_OPTION
        + LLVM_EXTRA_COMPILE_OPTIONS.get(
            platform, LLVM_EXTRA_COMPILE_OPTIONS["default"]
        )
        + LLVM_TARGETS_TO_BUILD
        + LLVM_PROJECTS_TO_BUILD
        + LLVM_INCLUDE_TOOLS_OPTION
    )

    CONFIG_CMD = f"cmake {compile_options} {extra_flags} ../llvm"
    if "windows" == platform:
        if "mingw" in sysconfig.get_platform().lower():
            CONFIG_CMD += " -G'Unix Makefiles'"
        else:
            CONFIG_CMD += " -A x64"
    else:
        CONFIG_CMD += " -G'Ninja'"
    print(f"Config command: {CONFIG_CMD}")
    subprocess.check_call(shlex.split(CONFIG_CMD), cwd=build_dir)

    BUILD_CMD = "cmake --build . --target package" + (
        " --config Release" if "windows" == platform else ""
    )
    if "windows" == platform:
        BUILD_CMD += " --parallel " + str(os.cpu_count())
    print(f"Build command: {BUILD_CMD}")
    subprocess.check_call(shlex.split(BUILD_CMD), cwd=build_dir)

    return build_dir


def repackage_llvm(llvm_dir):
    build_dir = llvm_dir.joinpath("./build").resolve()

    packs = [f for f in build_dir.glob("LLVM-*.tar.gz")]
    if len(packs) > 1:
        raise Exception("Find more than one LLVM-*.tar.gz")

    if not packs:
        raise Exception("Didn't find any LLVM-* package")
        return

    llvm_package = packs[0].name
    # mv build/LLVM-*.gz .
    shutil.move(str(build_dir.joinpath(llvm_package).resolve()), str(llvm_dir))
    # rm -r build
    shutil.rmtree(str(build_dir))
    # mkdir build
    build_dir.mkdir()
    # tar xf ./LLVM-*.tar.gz --strip-components=1 --directory=build
    CMD = f"tar xf {llvm_dir.joinpath(llvm_package).resolve()} --strip-components=1 --directory={build_dir}"
    subprocess.check_call(shlex.split(CMD), cwd=llvm_dir)
    # rm ./LLVM-1*.gz
    os.remove(llvm_dir.joinpath(llvm_package).resolve())

def repackage_llvm_windows(llvm_dir):
    build_dir = llvm_dir.joinpath("./build").resolve()

    packs_path = [f for f in build_dir.glob("./_CPack_Packages/win64/NSIS/LLVM-*-win64")]
    if len(packs_path) > 1:
        raise Exception("Find more than one LLVM-* package")

    if not packs_path:
        raise Exception("Didn't find any LLVM-* package")
        return

    llvm_package_path = f"_CPack_Packages/win64/NSIS/{packs_path[0].name}"
    windows_package_dir = build_dir.joinpath(llvm_package_path).resolve()

    # mv package dir outside of build
    shutil.move(str(windows_package_dir), str(llvm_dir))
    # rm -r build
    shutil.rmtree(str(build_dir))
    # mkdir build
    build_dir.mkdir()
    # move back all the subdiretories under cpack directory(bin/include/lib) to build dir
    moved_package_dir = llvm_dir.joinpath(packs_path[0].name)
    for sub_dir in moved_package_dir.iterdir():
        shutil.move(str(sub_dir), str(build_dir))
    moved_package_dir.rmdir()

def main():
    parser = argparse.ArgumentParser(description="build necessary LLVM libraries")
    parser.add_argument(
        "--platform",
        type=str,
        choices=["android", "arc", "darwin", "linux", "windows", "xtensa"],
        help="identify current platform",
    )
    parser.add_argument(
        "--arch",
        nargs="+",
        type=str,
        choices=[
            "AArch64",
            "ARC",
            "ARM",
            "Mips",
            "RISCV",
            "WebAssembly",
            "X86",
            "Xtensa",
        ],
        default=[],
        help="identify LLVM supported backends, separate by space, like '--arch ARM Mips X86'",
    )
    parser.add_argument(
        "--project",
        nargs="+",
        type=str,
        default="",
        choices=["clang", "lldb"],
        help="identify extra LLVM projects, separate by space, like '--project clang lldb'",
    )
    parser.add_argument(
        "--llvm-ver",
        action="store_true",
        help="return the version info of generated llvm libraries",
    )
    parser.add_argument(
        "--use-clang",
        action="store_true",
        help="use clang instead of gcc",
    )
    parser.add_argument(
        "--extra-cmake-flags",
        type=str,
        default="",
        help="custom extra cmake flags",
    )
    options = parser.parse_args()

    # if the "platform" is not identified in the command line option,
    # detect it
    if not options.platform:
        if sys.platform.startswith("win32") or sys.platform.startswith("msys"):
            platform = "windows"
        elif sys.platform.startswith("darwin"):
            platform = "darwin"
        else:
            platform = "linux"
    else:
        platform = options.platform

    llvm_repo_and_branch = {
        "arc": {
            "repo": "https://github.com/llvm/llvm-project.git",
            "repo_ssh": "git@github.com:llvm/llvm-project.git",
            "branch": "release/18.x",
        },
        "xtensa": {
            "repo": "https://github.com/espressif/llvm-project.git",
            "repo_ssh": "git@github.com:espressif/llvm-project.git",
            "branch": "xtensa_release_18.1.2",
        },
        "default": {
            "repo": "https://github.com/llvm/llvm-project.git",
            "repo_ssh": "git@github.com:llvm/llvm-project.git",
            "branch": "release/18.x",
        },
    }

    # retrieve the real file
    current_file = pathlib.Path(__file__)
    if current_file.is_symlink():
        current_file = pathlib.Path(os.readlink(current_file))

    current_dir = current_file.parent.resolve()
    deps_dir = current_dir.joinpath("../core/deps").resolve()

    try:
        llvm_info = llvm_repo_and_branch.get(platform, llvm_repo_and_branch["default"])

        if options.llvm_ver:
            commit_hash = query_llvm_version(llvm_info)
            print(commit_hash)
            return commit_hash is not None

        repo_addr = llvm_info["repo"]
        if os.environ.get('USE_GIT_SSH') == "true":
            repo_addr = llvm_info["repo_ssh"]
        else:
            print("To use ssh for git clone, run: export USE_GIT_SSH=true")

        llvm_dir = clone_llvm(deps_dir, repo_addr, llvm_info["branch"])
        if (
            build_llvm(
                llvm_dir, platform, options.arch, options.project, options.use_clang,
                options.extra_cmake_flags
            )
            is not None
        ):
            # TODO: repackage process may change in the future, this work for LLVM 15.x
            if "windows" == platform:
                repackage_llvm_windows(llvm_dir)
            else:
                repackage_llvm(llvm_dir)

        return True
    except subprocess.CalledProcessError:
        return False


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
