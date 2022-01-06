#!/bin/bash
set -eux
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Simple script to test a build of all supported targets.
# To build multi-arch, QEMU can be used and ideally buildkit support in Docker.
#
# Follow the relevant instructions to do this for your OS, e.g. for Ubuntu it may be:
# $ sudo apt-get install qemu binfmt-support qemu-user-static # Install the qemu packages
# $ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# Confirm you can run a non-native architecture image, e.g.:
# $ docker run --rm -t arm64v8/ubuntu uname -m # Run an executable made for aarch64 on x86_64
# WARNING: The requested image's platform (linux/arm64/v8) does not match the detected host platform (linux/amd64) and no specific platform was requested
# aarch64
#

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
FLB_VERSION=${FLB_VERSION:-1.8.11}

# Iterate over each target and attempt to build it.
# Verify that an RPM or DEB is created.
for DISTRO in "${TARGETS[@]}"
do
    echo "$DISTRO"
    FLB_OUT_DIR="$PACKAGING_OUTPUT_DIR" /bin/bash "$SCRIPT_DIR"/build.sh -d "$DISTRO" -v "$FLB_VERSION" "$@"
    if [[ -z $(find "${SCRIPT_DIR}/packages/$DISTRO/$FLB_VERSION/$PACKAGING_OUTPUT_DIR/" -type f \( -iname "*-bit-*.rpm" -o -iname "*-bit-*.deb" \) | head -n1) ]]; then
        echo "Unable to find any $FLB_VERSION binary packages in: ${SCRIPT_DIR}/packages/$DISTRO/$FLB_VERSION/$PACKAGING_OUTPUT_DIR"
        exit 1
    fi
done

echo "Success so cleanup"
rm -rf "${PACKAGING_OUTPUT_DIR:?}/*"
