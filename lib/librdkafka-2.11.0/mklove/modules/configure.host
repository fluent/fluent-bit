#!/bin/bash
#
# Host OS support
# Sets:
#  HOST
#  BUILD
#  TARGET

# FIXME: No need for this right now
#mkl_require host_linux
#mkl_require host_osx
#mkl_require host_cygwin

#mkl_option "Cross-compilation" "mk:HOST_OS" "--host-os=osname" "Host OS (linux,osx,cygwin,..)" "auto"


# autoconf compatibility - does nothing at this point
mkl_option "Cross-compilation" "mk:HOST" "--host=HOST" "Configure to build programs to run on HOST (no-op)"
mkl_option "Cross-compilation" "mk:BUILD" "--build=BUILD" "Configure for building on BUILD (no-op)"
mkl_option "Cross-compilation" "mk:TARGET" "--target=TARGET" "Configure for building cross-toolkits for platform TARGET (no-op)"


# Resolve the OS/distro at import time, rather than as a check,
# so that MKL_DISTRO is available to other modules at import time.
function resolve_distro {
    solib_ext=.so

    # Try lsb_release
    local sys
    sys=$(lsb_release -is 2>/dev/null)
    if [[ $? -gt 0 ]]; then
        # That didnt work, try uname.
        local kn=$(uname -s)
        case $kn in
            Linux)
                sys=Linux
                solib_ext=.so

                if [[ -f /etc/os-release ]]; then
                    eval $(grep ^ID= /etc/os-release)
                    if [[ -n $ID ]]; then
                        sys="$ID"
                    fi
                elif [[ -f /etc/centos-release ]]; then
                    sys=centos
                elif [[ -f /etc/alpine-release ]]; then
                    sys=alpine
                fi
                ;;
            Darwin)
                sys=osx
                solib_ext=.dylib
                ;;
            CYGWIN*)
                sys=Cygwin
                solib_ext=.dll
                ;;
            *)
                sys="$kn"
                solib_ext=.so
                ;;
        esac
    fi

    # Convert to lower case
    sys=$(echo $sys | tr '[:upper:]' '[:lower:]')
    mkl_mkvar_set "distro" "MKL_DISTRO" "$sys"
    mkl_allvar_set "distro" "SOLIB_EXT" "$solib_ext"
}

resolve_distro


function checks {
    # Try to figure out what OS/distro we are running on.
    mkl_check_begin "distro" "" "no-cache" "OS or distribution"

    if [[ -z $MKL_DISTRO ]]; then
        mkl_check_failed "distro" "" "ignore" ""
    else
        mkl_check_done "distro" "" "ignore" "ok" "$MKL_DISTRO"
    fi
}

#function checks {
#    mkl_check_begin "host" "HOST_OS" "no-cache" "host OS"
#
#    #
#    # If --host-os=.. was not specified then this is most likely not a
#    # a cross-compilation and we can base the host-os on the native OS.
#    #
#    if [[ $HOST_OS != "auto" ]]; then
#        mkl_check_done "host" "HOST_OS" "cont" "ok" "$HOST_OS"
#        return 0
#    fi
#
#    kn=$(uname -s)
#    case $kn in
#        Linux)
#            hostos=linux
#            ;;
#        Darwin)
#            hostos=osx
#            ;;
#        CYGWIN*)
#            hostos=cygwin
#            ;;
#        *)
#            hostos="$(mkl_lower $kn)"
#            mkl_err  "Unknown host OS kernel name: $kn"
#            mkl_err0 "  Will attempt to load module host_$hostos anyway."
#            mkl_err0 "  Please consider writing a configure.host_$hostos"
#            ;;
#    esac
#
#    if ! mkl_require --try "host_$hostos"; then
#        # Module not found
#        mkl_check_done "host" "HOST_OS" "cont" "failed" "$kn?"
#    else
#        # Module loaded
#
#        if mkl_func_exists "host_${hostos}_setup" ; then
#            "host_${hostos}_setup"
#        fi
#
#        mkl_check_done "host" "HOST_OS" "cont" "ok" "$hostos"
#    fi
#
#    # Set HOST_OS var even if probing failed.
#    mkl_mkvar_set "host" "HOST_OS" "$hostos"
#}

