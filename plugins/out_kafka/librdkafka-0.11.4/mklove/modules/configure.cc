#!/bin/bash
#
# Compiler detection
# Sets:
#  CC, CXX, CFLAGS, CPPFLAGS, LDFLAGS, ARFLAGS, PKG_CONFIG, INSTALL, MBITS


mkl_require host

function checks {

    # C compiler
    mkl_meta_set "ccenv" "name" "C compiler from CC env"
    if ! mkl_command_check "ccenv" "WITH_CC" cont "$CC --version"; then
        if mkl_command_check "gcc" "WITH_GCC" cont "gcc --version"; then
            CC=gcc
        elif mkl_command_check "clang" "WITH_CLANG" cont "clang --version"; then
            CC=clang
        elif mkl_command_check "cc" "WITH_CC" fail "cc --version"; then
            CC=cc
        fi
    fi
    export CC="${CC}"
    mkl_mkvar_set CC CC "$CC"

    if [[ $MKL_CC_WANT_CXX == 1 ]]; then
    # C++ compiler
        mkl_meta_set "cxxenv" "name" "C++ compiler from CXX env"
        if ! mkl_command_check "cxxenv" "WITH_CXX" cont "$CXX --version" ; then
            mkl_meta_set "gxx" "name" "C++ compiler (g++)"
            mkl_meta_set "clangxx" "name" "C++ compiler (clang++)"
            mkl_meta_set "cxx" "name" "C++ compiler (c++)"
            if mkl_command_check "gxx" "WITH_GXX" cont "g++ --version"; then
                CXX=g++
            elif mkl_command_check "clangxx" "WITH_CLANGXX" cont "clang++ --version"; then
                CXX=clang++
            elif mkl_command_check "cxx" "WITH_CXX" fail "c++ --version"; then
                CXX=c++
            fi
        fi
        export CXX="${CXX}"
        mkl_mkvar_set "CXX" CXX "$CXX"
    fi

    # Handle machine bits, if specified.
    if [[ ! -z "$MBITS" ]]; then
	mkl_meta_set mbits_m name "mbits compiler flag (-m$MBITS)"
	if mkl_compile_check mbits_m "" fail CC "-m$MBITS"; then
	    mkl_mkvar_append CPPFLAGS CPPFLAGS "-m$MBITS"
	    mkl_mkvar_append LDFLAGS LDFLAGS "-m$MBITS"
	fi
	if [[ -z "$ARFLAGS" && $MBITS == 64 && $MKL_DISTRO == "SunOS" ]]; then
	    # Turn on 64-bit archives on SunOS
	    mkl_mkvar_append ARFLAGS ARFLAGS "S"
	fi
    fi

    # Provide prefix and checks for various other build tools.
    local t=
    for t in LD:ld NM:nm OBJDUMP:objdump STRIP:strip ; do
        local tenv=${t%:*}
        t=${t#*:}
	local tval="${!tenv}"

        [[ -z $tval ]] && tval="$t"

        if mkl_prog_check "$t" "" disable "$tval" ; then
            if [[ $tval != ${!tenv} ]]; then
		export "$tenv"="$tval"
	    fi
            mkl_mkvar_set $tenv $tenv "$tval"
        fi
    done

    # Compiler and linker flags
    [[ ! -z $CFLAGS ]]   && mkl_mkvar_set "CFLAGS" "CFLAGS" "$CFLAGS"
    [[ ! -z $CPPFLAGS ]] && mkl_mkvar_set "CPPFLAGS" "CPPFLAGS" "$CPPFLAGS"
    [[ ! -z $CXXFLAGS ]] && mkl_mkvar_set "CXXFLAGS" "CXXFLAGS" "$CXXFLAGS"
    [[ ! -z $LDFLAGS ]]  && mkl_mkvar_set "LDFLAGS" "LDFLAGS" "$LDFLAGS"
    [[ ! -z $ARFLAGS ]]  && mkl_mkvar_set "ARFLAGS" "ARFLAGS" "$ARFLAGS"

    if [[ $MKL_NO_DEBUG_SYMBOLS != "y" ]]; then
        # Add debug symbol flag (-g)
        # OSX 10.9 requires -gstrict-dwarf for some reason.
        mkl_meta_set cc_g_dwarf name "debug symbols compiler flag (-g...)"
        if [[ $MKL_DISTRO == "osx" ]]; then
            if mkl_compile_check cc_g_dwarf "" cont CC "-gstrict-dwarf"; then
                mkl_mkvar_append CPPFLAGS CPPFLAGS "-gstrict-dwarf"
            else
                mkl_mkvar_append CPPFLAGS CPPFLAGS "-g"
            fi
        else
            mkl_mkvar_append CPPFLAGS CPPFLAGS "-g"
        fi
    fi


    # pkg-config
    if [ -z "$PKG_CONFIG" ]; then
        PKG_CONFIG=pkg-config
    fi

    if mkl_command_check "pkgconfig" "WITH_PKGCONFIG" cont "$PKG_CONFIG --version"; then
        export PKG_CONFIG
    fi
    mkl_mkvar_set "pkgconfig" PKG_CONFIG $PKG_CONFIG

    [[ ! -z "$PKG_CONFIG_PATH" ]] && mkl_env_append PKG_CONFIG_PATH "$PKG_CONFIG_PATH"

    # install
    if [ -z "$INSTALL" ]; then
	if [[ $MKL_DISTRO == "SunOS" ]]; then
	    mkl_meta_set ginstall name "GNU install"
	    if mkl_command_check ginstall "" ignore "ginstall --version"; then
		INSTALL=ginstall
	    else
		INSTALL=install
	    fi
        else
            INSTALL=install
	fi
    fi

    if mkl_command_check "install" "WITH_INSTALL" cont "$INSTALL --version"; then
        export INSTALL
    fi
    mkl_mkvar_set "install" INSTALL $INSTALL


    # Enable profiling if desired
    if [[ $WITH_PROFILING == y ]]; then
        mkl_allvar_set "" "WITH_PROFILING" "y"
        mkl_mkvar_append CPPFLAGS CPPFLAGS "-pg"
        mkl_mkvar_append LDFLAGS LDFLAGS   "-pg"
    fi

    # Optimization
    if [[ $WITHOUT_OPTIMIZATION == n ]]; then
        mkl_mkvar_append CPPFLAGS CPPFLAGS "-O2"
    else
        mkl_mkvar_append CPPFLAGS CPPFLAGS "-O0"
    fi

    # Static linking
    if [[ $WITH_STATIC_LINKING == y ]]; then
        # LDFLAGS_STATIC is the LDFLAGS needed to enable static linking
        # of sub-sequent libraries, while
        # LDFLAGS_DYNAMIC is the LDFLAGS needed to enable dynamic linking.
        if [[ $MKL_DISTRO != "osx" ]]; then
            mkl_mkvar_set staticlinking LDFLAGS_STATIC  "-Wl,-Bstatic"
            mkl_mkvar_set staticlinking LDFLAGS_DYNAMIC "-Wl,-Bdynamic"
            mkl_mkvar_set staticlinking HAS_LDFLAGS_STATIC y
        else
            # OSX linker can't enable/disable static linking so we'll
            # need to find the .a through STATIC_LIB_libname env var
            mkl_mkvar_set staticlinking HAS_LDFLAGS_STATIC n
        fi
    fi
}


mkl_option "Compiler" "env:CC" "--cc=CC" "Build using C compiler CC" "\$CC"
mkl_option "Compiler" "env:CXX" "--cxx=CXX" "Build using C++ compiler CXX" "\$CXX"
mkl_option "Compiler" "ARCH" "--arch=ARCH" "Build for architecture" "$(uname -m)"
mkl_option "Compiler" "CPU" "--cpu=CPU" "Build and optimize for specific CPU" "generic"
mkl_option "Compiler" "MBITS" "--mbits=BITS" "Machine bits (32 or 64)" ""

for n in CFLAGS CPPFLAGS CXXFLAGS LDFLAGS ARFLAGS; do
    mkl_option "Compiler" "mk:$n" "--$n=$n" "Add $n flags"
done

mkl_option "Compiler" "env:PKG_CONFIG_PATH" "--pkg-config-path" "Extra paths for pkg-config"

mkl_option "Compiler" "WITH_PROFILING" "--enable-profiling" "Enable profiling"
mkl_option "Compiler" "WITH_STATIC_LINKING" "--enable-static" "Enable static linking"
mkl_option "Compiler" "WITHOUT_OPTIMIZATION" "--disable-optimization" "Disable optimization flag to compiler" "n"
mkl_option "Compiler" "env:MKL_NO_DEBUG_SYMBOLS" "--disable-debug-symbols" "Disable debugging symbols" "n"
mkl_option "Compiler" "env:MKL_WANT_WERROR" "--enable-werror" "Enable compiler warnings as errors" "n"
