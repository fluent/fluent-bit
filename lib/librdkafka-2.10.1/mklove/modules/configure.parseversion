#!/bin/bash
#
# Parses the provided version string and creates variables accordingly.
#  [ "hex2str" <fmt> ]  -- version-string is in hex (e.g., 0x00080300)
#    version-string
#    STR_VERSION_VARIABLE_NAME
#  [ HEX_VERSION_VARIABLE_NAME ]
#
# Note: The version will also be set in MKL_APP_VERSION
#
# Example: Set string version in variable named "MYVERSION_STR" and
#          the hex representation in "MYVERSION"
#   mkl_require parseversion "$(head -1 VERSION.txt)" MYVERSION_STR MYVERSION

if [[ $1 == "hex2str" ]]; then
    parseversion_type="hex"
    parseversion_fmt="${2}:END:%d%d%d%d"
    shift
    shift
else
    parseversion_type=""
    parseversion_fmt="%d.%d.%d.%d"
fi

if [[ -z "$2" ]]; then
    mkl_fail "parseversion" "none" "fail" "Missing argument(s)"
    return 0
fi

parseversion_orig="$1"
parseversion_strvar="$2"
parseversion_hexvar="$3"

function checks {
    mkl_check_begin --verb "parsing" "parseversion" "" "no-cache" \
        "version '$parseversion_orig'"

    # Strip v prefix if any
    orig=${parseversion_orig#v}

    if [[ $orig == 0x* ]]; then
        parseversion_type="hex"
        orig=${orig#0x}
    fi

    if [[ -z $orig ]]; then
        mkl_check_failed "parseversion" "" "fail" "Version string is empty"
        return 1
    fi

    # If orig is in hex we construct a string format instead.
    if [[ $parseversion_type == "hex" ]]; then
        local s=$orig
        local str=""
        local vals=""
        while [[ ! -z $s ]]; do
            local n=${s:0:2}
            s=${s:${#n}}
            vals="${vals}$(printf %d 0x$n) "
        done
        str=$(printf "$parseversion_fmt" $vals)
        orig=${str%:END:*}
    fi


    # Try to decode version string into hex
    # Supported format is "[v]NN.NN.NN[.NN]"
    if [[ ! -z $parseversion_hexvar ]]; then
        local hex=""
        local s=$orig
        local ncnt=0
        local n=
        for n in ${s//./ } ; do
            if [[ ! ( "$n" =~ ^[0-9][0-9]?$ ) ]]; then
                mkl_check_failed "parseversion" "" "fail" \
                    "Could not decode '$parseversion_orig' into hex version, expecting format 'NN.NN.NN[.NN]'"
                return 1
            fi
            hex="$hex$(printf %02x $n)"
            ncnt=$(expr $ncnt + 1)
        done

        if [[ ! -z $hex ]]; then
            # Finish all four bytess
            while [[ ${#hex} -lt 8 ]]; do
                hex="$hex$(printf %02x 0)"
            done
            mkl_allvar_set "parseversion" "$parseversion_hexvar" "0x$hex"
        fi
    fi

    mkl_allvar_set "parseversion" "$parseversion_strvar" "$orig"
    mkl_allvar_set "parseversion" MKL_APP_VERSION "$orig"
    mkl_check_done "parseversion" "" "cont" "ok" "${!parseversion_strvar}"
}
