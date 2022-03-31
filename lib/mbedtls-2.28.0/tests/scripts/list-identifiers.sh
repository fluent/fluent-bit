#!/bin/bash
#
# Create a file named identifiers containing identifiers from internal header
# files, based on the --internal flag.
# Outputs the line count of the file to stdout.
# A very thin wrapper around list_internal_identifiers.py for backwards
# compatibility.
# Must be run from Mbed TLS root.
#
# Usage: list-identifiers.sh [ -i | --internal ]
#
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

set -eu

if [ -d include/mbedtls ]; then :; else
    echo "$0: Must be run from Mbed TLS root" >&2
    exit 1
fi

INTERNAL=""

until [ -z "${1-}" ]
do
  case "$1" in
    -i|--internal)
      INTERNAL="1"
      ;;
    *)
      # print error
      echo "Unknown argument: '$1'"
      exit 1
      ;;
  esac
  shift
done

if [ $INTERNAL ]
then
    tests/scripts/list_internal_identifiers.py
    wc -l identifiers
else
    cat <<EOF
Sorry, this script has to be called with --internal.

This script exists solely for backwards compatibility with the previous
iteration of list-identifiers.sh, of which only the --internal option remains in
use. It is a thin wrapper around list_internal_identifiers.py.

check-names.sh, which used to depend on this script, has been replaced with
check_names.py and is now self-complete.
EOF
fi
