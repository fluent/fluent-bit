#! /usr/bin/env sh

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Purpose
#
# Check if generated files are up-to-date.

set -eu

if [ $# -ne 0 ] && [ "$1" = "--help" ]; then
    cat <<EOF
$0 [-u]
This script checks that all generated file are up-to-date. If some aren't, by
default the scripts reports it and exits in error; with the -u option, it just
updates them instead.

  -u    Update the files rather than return an error for out-of-date files.
EOF
    exit
fi

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

UPDATE=
if [ $# -ne 0 ] && [ "$1" = "-u" ]; then
    shift
    UPDATE='y'
fi

# check SCRIPT FILENAME[...]
# check SCRIPT DIRECTORY
# Run SCRIPT and check that it does not modify any of the specified files.
# In the first form, there can be any number of FILENAMEs, which must be
# regular files.
# In the second form, there must be a single DIRECTORY, standing for the
# list of files in the directory. Running SCRIPT must not modify any file
# in the directory and must not add or remove files either.
# If $UPDATE is empty, abort with an error status if a file is modified.
check()
{
    SCRIPT=$1
    shift

    directory=
    if [ -d "$1" ]; then
        directory="$1"
        set -- "$1"/*
    fi

    for FILE in "$@"; do
        cp "$FILE" "$FILE.bak"
    done

    "$SCRIPT"

    # Compare the script output to the old files and remove backups
    for FILE in "$@"; do
        if ! diff "$FILE" "$FILE.bak" >/dev/null 2>&1; then
            echo "'$FILE' was either modified or deleted by '$SCRIPT'"
            if [ -z "$UPDATE" ]; then
                exit 1
            fi
        fi
        if [ -z "$UPDATE" ]; then
            mv "$FILE.bak" "$FILE"
        else
            rm "$FILE.bak"
        fi
    done

    if [ -n "$directory" ]; then
        old_list="$*"
        set -- "$directory"/*
        new_list="$*"
        # Check if there are any new files
        if [ "$old_list" != "$new_list" ]; then
            echo "Files were deleted or created by '$SCRIPT'"
            echo "Before: $old_list"
            echo "After: $new_list"
            if [ -z "$UPDATE" ]; then
                exit 1
            fi
        fi
    fi
}

check scripts/generate_errors.pl library/error.c
check scripts/generate_query_config.pl programs/test/query_config.c
check scripts/generate_features.pl library/version_features.c
check scripts/generate_visualc_files.pl visualc/VS2010
check scripts/generate_psa_constants.py programs/psa/psa_constant_names_generated.c
check tests/scripts/generate_psa_tests.py $(tests/scripts/generate_psa_tests.py --list)
