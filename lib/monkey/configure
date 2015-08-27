#!/bin/bash
#
#  Monkey HTTP Server
#  ==================
#  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

if [ "x$(uname)" = "xLinux" ]; then
 BOLD="\033[1m"
 END_COLOR="\033[0m"
 GREEN="\033[0;32m"
 YELLOW="\033[1;33m"
 RED="\033[0;31m"
 BLUE="\033[0;34m"
 ECHO_OPTS="-en"
 ECHO_LF="\n"
else
  ECHO_OPTS=""
  ECHO_LF=""
fi

#---------------------------#
# Starting configure
#---------------------------#
cmake_opts=""

for arg in $*; do
    case "$arg" in
	-*=*)
	    optarg=`echo "$arg" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
	*)
	    optarg= ;;
    esac
    case "$arg" in
        # Path options
	--prefix*)
            cmake_opts+="-DCMAKE_INSTALL_PREFIX='$optarg' "
	    ;;
	--sbindir*)
            cmake_opts+="-DCMAKE_INSTALL_SBINDIR='$optarg' "
	    ;;
	--mandir*)
	    cmake_opts+="-DCMAKE_INSTALL_MANDIR='$optarg' "
	    ;;
	--sysconfdir*)
	    cmake_opts+="-DINSTALL_SYSCONFDIR='$optarg' "
	    ;;
	--webroot*)
	    cmake_opts+="-DINSTALL_WEBROOTDIR='$optarg' "
	    ;;
	--libdir*)
	    cmake_opts+="-DCMAKE_INSTALL_LIBDIR='$optarg' "
	    ;;
	--includedir*)
	    cmake_opts+="-DINSTALL_INCLUDEDIR='$optarg' "
	    ;;
	--logdir*)
	    cmake_opts+="-DINSTALL_LOGDIR='$optarg' "
	    ;;
        --pidpath*)
            cmake_opts+="-DPID_PATH='$optarg' "
            ;;
	--pidfile*)
            cmake_opts+="-DPID_FILE='$optarg' "
	    ;;
        # Build Options
        --local*)
            cmake_opts+="-DBUILD_LOCAL=1 "
            ;;
	--debug*)
            cmake_opts+="-DWITH_DEBUG=1 "
	    ;;
	--trace*)
	    cmake_opts+="-DWITH_TRACE=1 "
	    ;;
	--no-backtrace*)
	    cmake_opts+="-DWITH_BACKTRACE=0 "
	    ;;
        --linux-trace*)
            cmake_opts+="-DWITH_LINUX_TRACE=1 "
            ;;
        --pthread-tls*)
            cmake_opts+="-DWITH_PTHREAD_TLS=1 "
            ;;
        --malloc-libc*)
            cmake_opts+="-DWITH_SYSTEM_MALLOC=1 "
            ;;
	--uclib-mode*)
            cmake_opts+="-DWITH_UCLIB=1 "
	    ;;
	--musl-mode*)
            cmake_opts+="-DWITH_MUSL=1 "
	    ;;
	--enable-plugins*)
	    cmake_opts+="-DWITH_PLUGINS='$optarg' "
	    ;;
	--disable-plugins*)
            cmake_opts+="-DWITHOUT_PLUGINS='$optarg' "
	    ;;
	--static-plugins*)
	    cmake_opts+="-DSTATIC_PLUGINS='$optarg' "
	    ;;
	--only-accept)
            cmake_opts+="-DWITH_ACCEPT=1 -DWITH_ACCEPT4=0 "
	    ;;
	--only-accept4)
            cmake_opts+="-DWITH_ACCEPT=0 -DWITH_ACCEPT4=1 "
	    ;;
	--linux-kqueue*)
            cmake_opts+="-DWITH_LINUX_KQUEUE=1 "
	    ;;
	--default-port*)
            cmake_opts+="-DDEFAULT_PORT='$optarg' "
	    ;;
	--default-user*)
            cmake_opts+="-DDEFAULT_USER='$optarg' "
	    ;;
	--systemddir*)
            cmake_opts+="-DSYSTEMD_DIR='$optarg' "
	    ;;
        --no-binary*)
            cmake_opts+="-DWITHOUT_BIN=1 "
            ;;
        --static-lib-mode*)
            cmake_opts+="-DWITH_STATIC_LIB_MODE=1 "
            ;;
        --skip-config*)
            cmake_opts+="-DWITHOUT_CONF=1 "
            ;;
        --mbedtls-shared*)
            cmake_opts+="-DWITH_MBEDTLS_SHARED=1 "
            ;;
	--version*)
	    echo -e $bldgrn"Monkey HTTP Server v$VERSION" $txtrst
	    echo "Copyright 2001-2015, Eduardo Silva <eduardo@monkey.io>"
	    echo "http://monkey-project.com"
            echo
	    exit 1
	    ;;
	*)
	    echo "Usage: ./configure [OPTION]... [VAR=VALUE]..."
	    echo
	    echo -e $bldwht"Optional Commands:" $txtrst
	    echo "  --help        Display this help and exit"
	    echo "  --version     Display version information and exit"
	    echo
	    echo -e $bldwht"Build options:"  $txtrst
            echo "  --local                 Build locally, don't install (dev mode)"
	    echo "  --debug                 Compile Monkey with debugging symbols"
	    echo "  --trace                 Enable trace messages (don't use in production)"
	    echo "  --no-backtrace          Disable backtrace feature"
	    echo "  --linux-trace           Enable Linux Trace Toolkit"
	    echo "  --musl-mode             Enable musl compatibility mode"
	    echo "  --uclib-mode            Enable uClib compatibility mode"
            echo "  --malloc-libc           Use system default memory allocator (default is jemalloc)"
	    echo "  --pthread-tls           Use Posix thread keys instead of compiler TLS"
            echo "  --no-binary             Do not build binary"
            echo "  --static-lib-mode       Build static library mode"
            echo "  --skip-config           Do not include configuration files"
            echo "  --mbedtls-shared        Use system mbedtls shared lib instead of the static one"
	    echo
	    echo -e $bldwht"Installation Directories:" $txtrst
	    echo "  --prefix=PREFIX         Root prefix directory"
	    echo "  --sbindir=BINDIR        Binary files (executables)"
	    echo "  --libdir=LIBDIR         Libraries"
	    echo "  --includedir=INCDIR     Header install path"
	    echo "  --sysconfdir=SYSCONFDIR Configuration files"
	    echo "  --webroot=WEB_ROOT      Path to default web site files"
	    echo "  --mandir=MANDIR         Manpages - documentation"
	    echo "  --logdir=LOGDIR         Log files"
	    echo "  --pidfile=PIDFILE       Path to file to store PID"
	    echo "  --systemddir[=DIR]      Systemd directory path"
	    echo "  --enable-plugins=a,b    Enable the listed plugins"
	    echo "  --disable-plugins=a,b   Disable the listed plugins"
	    echo "  --static-plugins=a,b    Build plugins in static mode"
	    echo "  --only-accept           Use only accept(2)"
	    echo "  --only-accept4          Use only accept4(2) (default and preferred)"
	    echo
	    echo -e $bldwht"Override Server Configuration:" $txtrst
	    echo "  --default-port=PORT     Override default TCP port (default: 2001)"
	    echo "  --default-user=USER     Override default web user (default: www-data)"
	    echo
	    exit 1
	    ;;
    esac
done

echo $ECHO_OPTS $RED"********************************************"$ECHO_LF
echo $ECHO_OPTS $RED"*"$GREEN$BOLD"           Monkey HTTP Server             "$RED"*"$ECHO_LF
echo $ECHO_OPTS $RED"*"$YELLOW"           monkey-project.com             "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$BLUE" ---------------------------------------- "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"      Monkey is the next generation       "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"  Web Server for Linux and Unix variants  "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"                                          "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"        Feel free to reach us at:         "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"                                          "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"        irc.freenode.net #monkey          "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"                                          "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"        Thanks for using Monkey!!!        "$RED"*"$ECHO_LF
echo $ECHO_OPTS "*"$YELLOW"                                          "$RED"*"$ECHO_LF
echo $ECHO_OPTS "********************************************"$END_COLOR$ECHO_LF
echo $ECHO_OPTS "Build: $(uname)"$ECHO_LF

cd build/
rm -rf CMakeCache.txt
cmake $cmake_opts ../

exit 0
