#!/bin/bash
#
# Sets version variable from git information.
# Optional arguments:
#   "as"
#   VARIABLE_NAME
#
# Example: Set version in variable named "MYVERSION":
#   mkl_require gitversion as MYVERSION [default DEFVERSION]

if [[ $1 == "as" ]]; then
    shift
    __MKL_GITVERSION_VARNAME="$1"
    shift
else
    __MKL_GITVERSION_VARNAME="VERSION"
fi

if [[ $1 == "default" ]]; then
    shift
    __MKL_GITVERSION_DEFAULT="$1"
    shift
fi


function checks {
    mkl_allvar_set "gitversion" "$__MKL_GITVERSION_VARNAME" \
                   "$(git describe --abbrev=6 --tags HEAD --always 2>/dev/null || echo $__MKL_GITVERSION_DEFAULT)"
}
