#!/bin/bash
set -eux
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Simple script to test a build of all supported targets

# Ensure this is updated for new targets
declare -a TARGETS=("centos/7" "centos/7.arm64v8" "centos/8" "centos/8.arm64v8"
"debian/stretch" "debian/stretch.arm64v8" "debian/buster" "debian/buster.arm64v8" "debian/bullseye" "debian/bullseye.arm64v8"
"raspbian/buster" "raspbian/bullseye"
"ubuntu/16.04" "ubuntu/18.04" "ubuntu/18.04.arm64v8" "ubuntu/20.04" "ubuntu/20.04.arm64v8"
)

# Output checks are easier plus do not want to fill up git
PACKAGING_OUTPUT_DIR=${PACKAGING_OUTPUT_DIR:-test}
echo "Cleaning any existing output"
rm -rf "${PACKAGING_OUTPUT_DIR:?}/*"

# We need a version of the source code to build
FLUENT_BIT_VERSION=${FLUENT_BIT_VERSION:-1.8.11}

# Iterate over each target and attempt to build it.
# Verify that an RPM or DEB is created for the version specified.
for DISTRO in "${TARGETS[@]}"
do
    echo "$DISTRO"
    FLB_OUT_DIR="$PACKAGING_OUTPUT_DIR" /bin/bash "$SCRIPT_DIR"/build.sh -d "$DISTRO" -v "$FLUENT_BIT_VERSION" "$@"
    if [[ -z $(find "${SCRIPT_DIR}/packages/$DISTRO/$FLUENT_BIT_VERSION/$PACKAGING_OUTPUT_DIR/" -type f \( -iname "*-bit-$FLUENT_BIT_VERSION*.rpm" -o -iname "*-bit-$FLUENT_BIT_VERSION*.deb" \) | head -n1) ]]; then
        echo "Unable to find any $FLUENT_BIT_VERSION binary packages in: ${SCRIPT_DIR}/packages/$DISTRO/$FLUENT_BIT_VERSION/$PACKAGING_OUTPUT_DIR"
        exit 1
    fi
done

echo "Success so cleanup"
rm -rf "${PACKAGING_OUTPUT_DIR:?}/*"
