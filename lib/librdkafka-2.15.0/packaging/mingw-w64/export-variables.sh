#!/bin/bash

set -e

export msys2='cmd //C RefreshEnv.cmd '
export msys2+='& set MSYS=winsymlinks:nativestrict '
export msys2+='& C:\\msys64\\msys2_shell.cmd -defterm -no-start'
export mingw64="$msys2 -mingw64 -full-path -here -c "\"\$@"\" --"
export msys2+=" -msys2 -c "\"\$@"\" --"

taskkill //IM gpg-agent.exe //F  || true  # https://travis-ci.community/t/4967
export PATH=/C/msys64/mingw64/bin:$PATH
export MAKE=mingw32-make  # so that Autotools can find it
