#!/bin/bash

set -e

# Slightly modified from:
# https://docs.travis-ci.com/user/reference/windows/#how-do-i-use-msys2
case $TRAVIS_OS_NAME in
    windows)
        [[ ! -f C:/tools/msys64/msys2_shell.cmd ]] && rm -rf C:/tools/msys64
        choco uninstall -y mingw
        choco install -y msys2

        export msys2='cmd //C RefreshEnv.cmd '
        export msys2+='& set MSYS=winsymlinks:nativestrict '
        export msys2+='& C:\\tools\\msys64\\msys2_shell.cmd -defterm -no-start'
        export mingw64="$msys2 -mingw64 -full-path -here -c "\"\$@"\" --"
        export msys2+=" -msys2 -c "\"\$@"\" --"

        # Have to update pacman first or choco upgrade will failure due to migration
        # to zstd instead of xz compression
        $msys2 pacman -Sy --noconfirm pacman
        choco upgrade --no-progress -y msys2

        ## Install more MSYS2 packages from https://packages.msys2.org/base here
        $msys2 pacman --sync --noconfirm --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-make mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-lz4 mingw-w64-x86_64-zstd

        taskkill //IM gpg-agent.exe //F  || true  # https://travis-ci.community/t/4967
        export PATH=/C/tools/msys64/mingw64/bin:$PATH
        export MAKE=mingw32-make  # so that Autotools can find it
        ;;
esac
