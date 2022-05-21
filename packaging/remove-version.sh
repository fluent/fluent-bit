#!/bin/bash
set -eux
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# VERSION must be defined - this is the version to demote/remove from release
VERSION=${VERSION:-$1}
# Where the base of all the repos is
BASE_PATH=${BASE_PATH:-$2}

# Remove the RPM and DEB packages for this VERSION
find "$BASE_PATH" -type f \( -iname "*-bit-${VERSION}*.rpm" -o -iname "*-bit-${VERSION}*.deb" \) -exec rm -rf {} \;

# Update the repo metadata now
# VERSION is only used to find the RPM to sign so without it will skip signing
"$SCRIPT_DIR/update-repos.sh" "$BASE_PATH"
