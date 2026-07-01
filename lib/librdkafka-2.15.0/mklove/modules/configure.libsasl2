#!/bin/bash
#
# libsasl2 support (for GSSAPI/Kerberos), without source installer.
#
# Usage:
#   mkl_require libsasl2
#
#
# And then call the following function from the correct place/order in checks:
#   mkl_check libsasl2
#

mkl_toggle_option "Feature" ENABLE_GSSAPI "--enable-gssapi" "Enable SASL GSSAPI support with Cyrus libsasl2" "try"
mkl_toggle_option "Feature" ENABLE_GSSAPI "--enable-sasl" "Deprecated: Alias for --enable-gssapi"

function manual_checks {
    case "$ENABLE_GSSAPI" in
        n) return 0 ;;
        y) local action=fail ;;
        try) local action=disable ;;
        *) mkl_err "mklove internal error: invalid value for ENABLE_GSSAPI: $ENABLE_GSSAPI"; exit 1 ;;
    esac

    mkl_meta_set "libsasl2" "deb" "libsasl2-dev"
    mkl_meta_set "libsasl2" "rpm" "cyrus-sasl"
    mkl_meta_set "libsasl2" "apk" "cyrus-sasl-dev"

    local sasl_includes="
#include <stddef.h>
#include <sasl/sasl.h>
"

    if ! mkl_lib_check "libsasl2" "WITH_SASL_CYRUS" $action CC "-lsasl2" "$sasl_includes" ; then
        mkl_lib_check "libsasl" "WITH_SASL_CYRUS" $action CC "-lsasl" "$sasl_includes"
    fi
}
