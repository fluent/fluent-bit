#!/bin/bash
#
# Reads version from file and sets variables accordingly
# The first non-commented line in the file is expected to be the version string.
# Arguments:
#    filename
#    STR_VERSION_VARIABLE_NAME
#  [ HEX_VERSION_VARIABLE_NAME ]
#
# Example: Set string version in variable named "MYVERSION_STR" and
#          the hex representation in "MYVERSION"
#   mkl_require VERSION.txt MYVERSION_STR MYVERSION

if [[ -z "$2" ]]; then
    mkl_fail "fileversion" "none" "fail" "Missing argument(s), expected: FILENAME STR_VER HEX_VER"
    return 0
fi

fileversion_file="$1"
fileversion_strvar="$2"
fileversion_hexvar="$3"

function checks {
    mkl_check_begin "fileversion" "" "no-cache" "version from file $fileversion_file"

    if [[ ! -s $fileversion_file ]]; then
        mkl_check_failed "fileversion" "" "fail" \
            "Version file $fileversion_file is not readable"
        return 1
    fi

    local orig=$(grep -v ^\# "$fileversion_file" | grep -v '^$' | head -1)
    # Strip v prefix if any
    orig=${orig#v}

    # Try to decode version string into hex
    # Supported format is "[v]NN.NN.NN[.NN]"
    if [[ ! -z $fileversion_hexvar ]]; then
        local hex=""
        local s=${orig#v} # Strip v prefix, if any.
        local ncnt=0
        local n=
        for n in ${s//./ } ; do
            if [[ ! ( "$n" =~ ^[0-9][0-9]?$ ) ]]; then
                mkl_check_failed "fileversion" "" "fail" \
                    "$fileversion_file: Could not decode '$orig' into hex version, expecting format 'NN.NN.NN[.NN]'"
                return 1
            fi
            hex="$hex$(printf %02x $n)"
            ncnt=$(expr $ncnt + 1)
        done

        if [[ ! -z $hex ]]; then
            # Finish all four bytess
            for n in {$ncnt..4} ; do
                hex="$hex$(printf %02x 0)"
            done
            mkl_allvar_set "fileversion" "$fileversion_hexvar" "0x$hex"
        fi
    fi

    mkl_allvar_set "fileversion" "$fileversion_strvar" "$orig"

    mkl_check_done "fileversion" "" "cont" "ok" "${!fileversion_strvar}"
}
